import Fastify, { type FastifyError, type FastifyInstance } from "fastify";
import cookie from "@fastify/cookie";
import type { PrismaClient } from "@prisma/client";
import { apiPrefix, type Config } from "./config.js";
import rateLimit from "@fastify/rate-limit";
import { ZodError } from "zod";
import { healthRoutes } from "./routes/health.js";
import { registerAuth } from "./plugins/auth.js";
import { registerOrg } from "./plugins/org.js";
import { orgRoutes } from "./routes/orgs.js";
import { authRoutes } from "./routes/auth.js";
import { meRoutes } from "./routes/me.js";
import { folderRoutes } from "./routes/folders.js";
import { recordRoutes } from "./routes/records.js";
import { syncRoutes } from "./routes/sync.js";
import { userRoutes } from "./routes/users.js";
import { adminRoutes } from "./routes/admin.js";
import { linkRoutes } from "./routes/links.js";
import { recordBatchRoutes } from "./routes/recordBatch.js";
import { pendingMemberRoutes } from "./routes/pendingMembers.js";
import { groupRoutes } from "./routes/groups.js";
import { healthReportRoutes } from "./routes/passwordHealth.js";
import { registerWeb } from "./plugins/web.js";
import { meRecoveryRoutes, recoveryAuthRoutes } from "./routes/recovery.js";
import { meKeyRoutes, membershipKeyRoutes } from "./routes/membershipKeys.js";
import { sweepRecoveryRequests } from "./lib/recovery.js";
import { SWEEP_INTERVAL_MS, sweepExpiredLinks } from "./lib/links.js";
import { BackupService } from "./lib/backup/service.js";
import type { PgRunner } from "./lib/backup/pg.js";
import type { Destination } from "./lib/backup/destinations.js";
import { Mailer } from "./lib/mailer.js";
import { settingsBox, type SettingsBox } from "./lib/settingsBox.js";
import { defaultSsoDeps, OidcClients, type SsoDeps } from "./lib/sso.js";
import { ssoAuthRoutes } from "./routes/sso.js";
import { m365CallbackRoutes } from "./routes/emailSettings.js";
import { BrandCache } from "./lib/brand.js";
import { publicBrandRoutes } from "./routes/brand.js";
import { attachmentRoutes } from "./routes/attachments.js";
import { DbChunkStore, type ChunkStores } from "./lib/attachments/store.js";
import { S3ChunkStore } from "./lib/attachments/s3Store.js";
import { AttachmentSweeper } from "./lib/attachments/sweep.js";
import { attachmentConfig, instanceUsage, MIB } from "./lib/attachments/quota.js";
import { SeatLimitError } from "./lib/seats.js";
import { DEMO_SWEEP_INTERVAL_MS, sweepExpiredDemos } from "./lib/demo.js";
import { gatewayClient, GatewayIdentityChanged, GatewayUnavailable, type GatewayClient } from "./lib/gateway.js";
import { AgentLimitError } from "./lib/agents.js";
import { agentAdminRoutes, orgAgentRoutes } from "./routes/agents.js";
import { registerAgent } from "./plugins/agent.js";
import { agentApiRoutes } from "./routes/agentApi.js";
import { oauthRoutes } from "./routes/oauth.js";

declare module "fastify" {
  interface FastifyInstance { prisma: PrismaClient; config: Config; backups: BackupService;
    /** Sends email with the org's, the instance's or the environment's settings (docs/email.md). */
    mail: Mailer;
    /** Seals secrets stored in admin settings (key derived from SERVER_SECRET). */
    settingsBox: SettingsBox;
    /** OpenID Connect client configurations (discovery cache) for single sign-on. */
    oidc: OidcClients;
    /** DNS lookups for SSO domain verification (tests replace them). */
    ssoDeps: SsoDeps;
    /** Runtime branding set by instance admins (docs/branding.md); `productName()` is what emails and 2FA call the product. */
    brand: BrandCache;
    /** Where attachment chunks live (docs/attachments.md): the database, and S3 when configured. */
    attachmentStores: ChunkStores;
    /** Abandoned uploads, removed files, purged S3 files and orphans (run by the periodic sweep). */
    attachmentSweeper: AttachmentSweeper;
    /** The agent gateway's internal port (docs/agents.md). Decorated only when agent features are on. */
    gateway: GatewayClient }
}

const INVITE_TOKEN = /(\/auth\/invite\/)[^/?#\s]+/g;
/** The SSO callback's query (authorization code, state) never reaches the logs. */
const SSO_CALLBACK = /(\/auth\/sso\/callback|\/admin\/email\/m365\/callback)\?[^#\s]*/g;
export const redactInviteUrl = (url: string): string => url.replace(INVITE_TOKEN, "$1[redacted]").replace(SSO_CALLBACK, "$1?[redacted]");

/** Pino req serializer: same shape as Fastify's default, with invite tokens removed from the URL. */
export function serializeReq(req: { method?: string; url?: string; headers?: unknown; host?: string; ip?: string; socket?: { remotePort?: number } }) {
  return { method: req.method, url: req.url ? redactInviteUrl(req.url) : req.url, host: req.host, remoteAddress: req.ip, remotePort: req.socket?.remotePort };
}

/**
 * Fastify 5 silently ignores a numeric trustProxy (req.ip/req.protocol stay the socket's), so a hop count
 * becomes an explicit proxy-addr trust function: trust the `n` nearest hops (index 0 is the socket peer).
 */
export function trustProxyOption(tp: boolean | number): boolean | ((addr: string, hop: number) => boolean) {
  return typeof tp === "number" ? (_addr: string, hop: number) => hop < tp : tp;
}

export async function buildApp(opts: { config: Config; prisma: PrismaClient; logger?: boolean; webDist?: string;
  /** Tests: where pg tools run and where backups go. */
  backup?: { runner?: PgRunner; destinations?: Destination[] };
  /** Tests: chunk stores to use instead of the configured ones. */
  attachmentStores?: ChunkStores }): Promise<FastifyInstance> {
  const app = Fastify({ logger: opts.logger ? { redact: ["req.headers.authorization", "req.headers.cookie"], serializers: { req: serializeReq } } : false, trustProxy: trustProxyOption(opts.config.trustProxy), bodyLimit: 2 * 1024 * 1024 });
  app.decorate("prisma", opts.prisma);
  app.decorate("config", opts.config);
  const box = settingsBox(opts.config.serverSecret);
  app.decorate("settingsBox", box);
  app.decorate("mail", new Mailer({ prisma: opts.prisma, config: opts.config, box }));
  app.decorate("oidc", new OidcClients(opts.config));
  app.decorate("ssoDeps", defaultSsoDeps());
  app.decorate("brand", new BrandCache(opts.prisma, opts.config.productName));
  const att = attachmentConfig(opts.config);
  const stores: ChunkStores = opts.attachmentStores ?? { db: new DbChunkStore(opts.prisma), current: att.storage, ...(att.s3 ? { s3: new S3ChunkStore(att.s3) } : {}) };
  app.decorate("attachmentStores", stores);
  const sweeper = new AttachmentSweeper(opts.prisma, stores, app.log);
  app.decorate("attachmentSweeper", sweeper);
  const backups = new BackupService({ prisma: opts.prisma, databaseUrl: opts.config.databaseUrl, log: app.log,
    config: opts.config.backup ?? { enabled: false, schedule: "30 2 * * *", retentionDays: 14 }, attachmentStorage: att.storage, ...opts.backup });
  app.decorate("backups", backups);
  if (opts.config.agents) app.decorate("gateway", gatewayClient(opts.config.agents));
  await app.register(cookie);
  await app.register(rateLimit, { max: opts.config.rateLimitPerMinute ?? 300, timeWindow: "1 minute" });
  registerAuth(app);
  registerOrg(app);
  if (opts.config.agents) registerAgent(app);
  app.setErrorHandler((err: FastifyError, _req, reply) => {
    if (err instanceof ZodError) return reply.code(400).send({ error: "invalid_request", issues: err.issues.map((i) => i.path.join(".")) });
    if (err instanceof SeatLimitError) return reply.code(402).send({ error: "seat_limit", used: err.used, allowed: err.allowed });
    if (err instanceof AgentLimitError) return reply.code(402).send({ error: "agent_limit", used: err.used, allowed: err.allowed });
    if (err instanceof GatewayUnavailable) { app.log.warn({ event: "gateway_unavailable" }, err.message); return reply.code(503).send({ error: "gateway_unavailable" }); }
    if (err instanceof GatewayIdentityChanged) { app.log.error({ event: "gateway_identity_changed", pinned: err.pinned.keyId, seen: err.seen.keyId }, err.message); return reply.code(503).send({ error: "gateway_identity_changed" }); }
    if (err.statusCode === 429) return reply.code(429).send({ error: "rate_limited" });
    if (err.code === "FST_ERR_CTP_BODY_TOO_LARGE") return reply.code(413).send({ error: "too_large" });
    if (err.code === "FST_ERR_CTP_INVALID_MEDIA_TYPE") return reply.code(415).send({ error: "unsupported_media_type" });
    if (err.statusCode && err.statusCode < 500) return reply.code(err.statusCode).send({ error: "invalid_request" });
    app.log.error(err);
    return reply.code(500).send({ error: "server_error" });
  });
  app.addHook("onSend", async (_req, reply) => {
    reply.header("x-content-type-options", "nosniff");
    // Routes that may be cached say so themselves (logos, by version); everything else is never stored.
    if (!reply.hasHeader("cache-control")) reply.header("cache-control", "no-store");
    reply.header("referrer-policy", "no-referrer");
  });
  await app.register(async (api) => {
    await api.register(healthRoutes);
    await api.register(publicBrandRoutes);
    await api.register(authRoutes, { prefix: "/auth" });
    await api.register(recoveryAuthRoutes, { prefix: "/auth/recovery" });
    await api.register(ssoAuthRoutes, { prefix: "/auth/sso" });
    await api.register(meRecoveryRoutes);
    await api.register(meRoutes);
    await api.register(orgRoutes);
    await api.register(folderRoutes);
    await api.register(recordRoutes);
    await api.register(attachmentRoutes);
    await api.register(syncRoutes);
    await api.register(userRoutes);
    await api.register(adminRoutes, { prefix: "/admin" });
    // Microsoft's redirect after delegated sign-in: no bearer token (a top-level navigation), so outside the admin guard.
    await api.register(m365CallbackRoutes, { prefix: "/admin/email/m365" });
    await api.register(linkRoutes);
    await api.register(recordBatchRoutes);
    await api.register(pendingMemberRoutes);
    await api.register(groupRoutes);
    await api.register(membershipKeyRoutes);
    await api.register(meKeyRoutes);
    await api.register(healthReportRoutes);
    if (opts.config.agents) {
      await api.register(agentAdminRoutes, { prefix: "/admin/agents" });
      await api.register(orgAgentRoutes);
      await api.register(agentApiRoutes);
      await api.register(oauthRoutes);
    }
  }, { prefix: apiPrefix(opts.config) });
  if (opts.webDist) await registerWeb(app, opts.webDist, opts.config.basePath ?? "");
  // Expired one-time links lose their ciphertext and password material even if nobody looks at them again.
  // Lapsed recovery requests lose their wrapped key and proof hash the same way.
  const sweep = setInterval(() => {
    sweepExpiredLinks(opts.prisma).catch((e: unknown) => app.log.error(e));
    sweepRecoveryRequests(opts.prisma).catch((e: unknown) => app.log.error(e));
    // SSO requests and proofs are short-lived: their PKCE verifiers and nonces don't stay around.
    const old = new Date(Date.now() - 3600e3);
    opts.prisma.ssoLogin.deleteMany({ where: { expiresAt: { lt: old } } }).catch((e: unknown) => app.log.error(e));
    opts.prisma.ssoProof.deleteMany({ where: { expiresAt: { lt: old } } }).catch((e: unknown) => app.log.error(e));
    opts.prisma.m365Connect.deleteMany({ where: { expiresAt: { lt: old } } }).catch((e: unknown) => app.log.error(e));
    // Attachments: abandoned uploads (24 h), removed files and purged S3 objects (docs/attachments.md).
    sweeper.run().catch((e: unknown) => app.log.error(e));
  }, SWEEP_INTERVAL_MS);
  sweep.unref();
  app.addHook("onClose", async () => { clearInterval(sweep); stores.s3?.destroy(); });
  // Attachments kept in the database grow the database and every backup: warn the operator early.
  if (att.enabled && att.storage === "db" && opts.logger) {
    instanceUsage(opts.prisma).then((used) => {
      const quota = att.instanceQuotaMb * MIB;
      if (quota > 0 && used > 0.8 * quota) app.log.warn({ event: "attachments.instance_usage_high", usedBytes: used, quotaBytes: quota }, "Attachments use over 80 % of ATTACHMENT_INSTANCE_QUOTA_MB; consider ATTACHMENT_STORAGE=s3 (docs/attachments.md)");
    }).catch(() => undefined);
  }
  // Demo mode (docs/demo.md): expired sandboxes are hard-deleted, each in one transaction. Their sessions stopped working at
  // expiry already (plugins/auth.ts); this removes the data.
  if (opts.config.demo) {
    const demoSweep = setInterval(() => {
      sweepExpiredDemos(opts.prisma, new Date(), app.log).then((r) => { if (r.sandboxes || r.users) app.log.info({ event: "demo.swept", ...r }, "expired demo sandboxes deleted"); })
        .catch((e: unknown) => app.log.error(e));
    }, DEMO_SWEEP_INTERVAL_MS);
    demoSweep.unref();
    app.addHook("onClose", async () => { clearInterval(demoSweep); });
  }
  backups.startScheduler();
  app.addHook("onClose", () => backups.stop());
  return app;
}
