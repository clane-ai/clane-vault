import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import type { FastifyInstance, FastifyPluginAsync, FastifyReply, FastifyRequest } from "fastify";
import type { Prisma } from "@prisma/client";
import { z } from "zod";
import type { Config } from "../config.js";
import { logEvent } from "../lib/events.js";
import { agentJwks, hashToken, newRefreshToken, signAgentAccess, splitRefresh } from "../lib/tokens.js";
import { fromGateway } from "../plugins/agent.js";

const STATIC = /^cvat_([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})_[A-Za-z0-9_-]{43}$/;
type Form = Record<string, string | undefined>;
const PER_MINUTE = { rateLimit: { max: 30, timeWindow: "1 minute" } };
const CODE_TTL_MS = 5 * 60_000, GRANT_TTL_MS = 30 * 864e5;
/** As /auth/refresh: a concurrent refresh with the just-rotated token is not a replay. */
const REFRESH_GRACE_MS = 30_000;
const CHALLENGE = /^[A-Za-z0-9_-]{43}$/;
const VERIFIER = /^[A-Za-z0-9._~-]{43,128}$/;

/** RFC 8414 metadata. `publicUrl` is the issuer, byte for byte the `iss` signAgentAccess writes. */
export function authServerMetadata(cfg: Config) {
  const u = cfg.publicUrl;
  return { issuer: u, authorization_endpoint: `${u}/oauth/authorize`, token_endpoint: `${u}/api/v1/oauth/token`,
    registration_endpoint: `${u}/api/v1/oauth/register`, revocation_endpoint: `${u}/api/v1/oauth/revoke`,
    jwks_uri: `${u}/api/v1/.well-known/jwks.json`, response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"], code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"] };
}

/** https, or http on loopback (native and CLI clients); never a fragment. */
function redirectAllowed(raw: string): boolean {
  let u: URL;
  try { u = new URL(raw); } catch { return false; }
  if (raw.includes("#")) return false;
  return u.protocol === "https:" || (u.protocol === "http:" && ["127.0.0.1", "[::1]", "localhost"].includes(u.hostname));
}

/** An agent that can be granted now: verified, live, unexpired, its account active. */
export const grantableAgent = (now: Date): Prisma.AgentWhereInput =>
  ({ revokedAt: null, verifiedAt: { not: null }, OR: [{ expiresAt: null }, { expiresAt: { gt: now } }], user: { status: "active" } });

/** Ends a live grant once (the claim logs and drops the gateway's cache); a second call does nothing. */
export async function revokeGrant(app: FastifyInstance, where: Prisma.AgentGrantWhereInput, ev: { actorId?: string; reason?: string; ip?: string }): Promise<boolean> {
  const g = await app.prisma.agentGrant.findFirst({ where: { ...where, revokedAt: null }, select: { id: true, agentId: true, agent: { select: { orgId: true } } } });
  if (!g) return false;
  const done = await app.prisma.$transaction(async (tx) => {
    if ((await tx.agentGrant.updateMany({ where: { id: g.id, revokedAt: null }, data: { revokedAt: new Date() } })).count !== 1) return false;
    await logEvent(tx, { orgId: g.agent.orgId, actorId: ev.actorId, action: "agent.grant_revoke", targetUserId: g.agentId,
      meta: { grantId: g.id, ...(ev.reason ? { reason: ev.reason } : {}) }, ip: ev.ip });
    return true;
  });
  // Preflight #11: the gateway forgets its cached keys now rather than in 60 s (best effort).
  if (done) app.gateway.dropAgent(g.agentId).catch(() => undefined);
  return done;
}
type Grant = (req: FastifyRequest, reply: FastifyReply, form: Form) => Promise<unknown>;

/** OAuth for agents (docs/agents.md), RFC 6749 error bodies. Registered only when agents are on. */
export const oauthRoutes: FastifyPluginAsync = async (app) => {
  // OAuth token requests are form-encoded (RFC 6749 §4.1.3); scoped to this plugin.
  // A repeated parameter is refused (400 invalid_request via the error handler): no first-or-last ambiguity.
  app.addContentTypeParser("application/x-www-form-urlencoded", { parseAs: "string" }, (_req, body, done) => {
    const p = new URLSearchParams(body as string), keys = [...p.keys()];
    if (new Set(keys).size !== keys.length) return done(Object.assign(new Error("repeated parameter"), { statusCode: 400 }), undefined);
    done(null, Object.fromEntries(p));
  });
  const gw = app.config.agents!.gatewayPublicUrl;
  /** RFC 8707: the one resource is the gateway, exactly as configured. */
  const badResource = (r: unknown) => r !== undefined && r !== gw;

  /** RFC 7591. Public clients only; the tighter limit is the per-address cap on registrations. */
  app.post("/oauth/register", { config: { rateLimit: { max: 10, timeWindow: "1 hour" } } }, async (req, reply) => {
    const b = z.object({ client_name: z.string().trim().min(1).max(100),
      redirect_uris: z.array(z.string().max(2000).refine(redirectAllowed)).min(1).max(10) }).parse(req.body);
    const c = await app.prisma.agentOAuthClient.create({ data: { name: b.client_name, redirectUris: b.redirect_uris } });
    return reply.code(201).send({ client_id: c.id, client_name: c.name, redirect_uris: c.redirectUris, token_endpoint_auth_method: "none",
      grant_types: ["authorization_code", "refresh_token"], response_types: ["code"] });
  });

  /** The client, when the redirect URI is one it registered, character for character. */
  async function clientFor(clientId: unknown, redirectUri: unknown): Promise<{ id: string; name: string } | "invalid_client" | "invalid_redirect_uri"> {
    const c = typeof clientId === "string" && z.string().uuid().safeParse(clientId).success
      ? await app.prisma.agentOAuthClient.findUnique({ where: { id: clientId } }) : null;
    if (!c) return "invalid_client";
    return typeof redirectUri === "string" && c.redirectUris.includes(redirectUri) ? c : "invalid_redirect_uri";
  }

  app.get("/oauth/authorize/info", { config: PER_MINUTE, preHandler: app.requireAuth }, async (req, reply) => {
    const q = req.query as Record<string, string | string[] | undefined>;
    if (Object.values(q).some(Array.isArray)) return reply.code(400).send({ error: "invalid_request" });
    const c = await clientFor(q.client_id, q.redirect_uri);
    if (typeof c === "string") return reply.code(400).send({ error: c });
    if (q.response_type !== "code" || q.code_challenge_method !== "S256" || !CHALLENGE.test(String(q.code_challenge ?? ""))) return reply.code(400).send({ error: "invalid_request" });
    if (badResource(q.resource)) return reply.code(400).send({ error: "invalid_target" });
    const rows = await app.prisma.agent.findMany({ where: { ...grantableAgent(new Date()),
      org: { memberships: { some: { userId: req.auth.userId, status: "active", role: { in: ["owner", "admin"] } } } } },
      orderBy: { createdAt: "asc" }, select: { userId: true, orgId: true, user: { select: { name: true } }, org: { select: { name: true } } } });
    return { client: { name: c.name }, issuer: app.config.publicUrl, agents: rows.map((a) => ({ id: a.userId, name: a.user.name, orgId: a.orgId, orgName: a.org.name })) };
  });

  /** Consent by an owner or admin of the agent's org (X-Org-Id, so that org's SSO and IP policies apply). */
  app.post("/oauth/authorize", { config: PER_MINUTE, preHandler: [app.requireAuth, app.orgAdmin] }, async (req, reply) => {
    const b = z.object({ clientId: z.string(), redirectUri: z.string(), codeChallenge: z.string().regex(CHALLENGE), codeChallengeMethod: z.literal("S256"),
      state: z.string().max(1000).optional(), resource: z.string().optional(), agentId: z.string().uuid() }).parse(req.body);
    const c = await clientFor(b.clientId, b.redirectUri);
    if (typeof c === "string") return reply.code(400).send({ error: c });
    if (badResource(b.resource)) return reply.code(400).send({ error: "invalid_target" });
    const now = new Date();
    const a = await app.prisma.agent.findFirst({ where: { userId: b.agentId, orgId: req.org!.id, revokedAt: null, user: { status: "active" } }, select: { verifiedAt: true, expiresAt: true } });
    if (!a) return reply.code(400).send({ error: "invalid_request" });
    if (a.expiresAt && a.expiresAt <= now) return reply.code(403).send({ error: "agent_expired" });
    if (!a.verifiedAt) return reply.code(403).send({ error: "agent_unverified" });
    const code = randomBytes(32).toString("base64url");
    await app.prisma.agentOAuthCode.create({ data: { codeHash: hashToken(code), clientId: c.id, agentId: b.agentId, grantedById: req.auth.userId,
      codeChallenge: b.codeChallenge, redirectUri: b.redirectUri, expiresAt: new Date(now.getTime() + CODE_TTL_MS) } });
    const to = new URL(b.redirectUri);
    to.searchParams.set("code", code);
    if (b.state !== undefined) to.searchParams.set("state", b.state);
    to.searchParams.set("iss", app.config.publicUrl); // RFC 9207
    return { redirectTo: to.href };
  });

  /** RFC 7009 for refresh tokens: 200 whatever the token was. */
  app.post("/oauth/revoke", { config: PER_MINUTE }, async (req) => {
    const p = splitRefresh((req.body as Form | undefined)?.token);
    if (p) {
      const h = hashToken(p.secret);
      await revokeGrant(app, { id: p.sessionId, OR: [{ refreshHash: h }, { prevRefreshHash: h }] }, { reason: "client_revoke", ip: req.ip });
    }
    return {};
  });

  app.get("/.well-known/jwks.json", async (_req, reply) => {
    reply.header("cache-control", "public, max-age=300");
    return agentJwks(app.config);
  });

  /** The gateway trades an admin-issued static token for a 15-minute access token. */
  const agentToken: Grant = async (req, reply, form) => {
    if (!fromGateway(app, req)) return reply.code(401).send({ error: "invalid_client" });
    if (typeof form.token !== "string") return reply.code(400).send({ error: "invalid_request" });
    const id = STATIC.exec(form.token)?.[1];
    const now = new Date();
    const row = id ? await app.prisma.agentToken.findFirst({
      where: { id, revokedAt: null, OR: [{ expiresAt: null }, { expiresAt: { gt: now } }], agent: { revokedAt: null, user: { status: "active" } } },
      select: { id: true, tokenHash: true, agentId: true, agent: { select: { orgId: true } } },
    }) : null;
    const presented = Buffer.from(hashToken(form.token), "hex"), stored = Buffer.from(row?.tokenHash ?? "", "hex");
    if (!row || stored.length !== presented.length || !timingSafeEqual(stored, presented)) return reply.code(400).send({ error: "invalid_grant" });
    await app.prisma.agentToken.update({ where: { id: row.id }, data: { lastUsedAt: now } });
    const { token, expiresIn } = await signAgentAccess(app.config, { agentId: row.agentId, orgId: row.agent.orgId, grant: row.id });
    return { access_token: token, token_type: "Bearer", expires_in: expiresIn };
  };
  const invalidGrant = (reply: FastifyReply) => reply.code(400).send({ error: "invalid_grant" });

  const authorizationCode: Grant = async (req, reply, form) => {
    const { code, code_verifier: verifier, client_id: clientId, redirect_uri: redirectUri } = form;
    if (!code || !verifier || !clientId || !redirectUri) return reply.code(400).send({ error: "invalid_request" });
    if (badResource(form.resource)) return reply.code(400).send({ error: "invalid_target" });
    const now = new Date(), codeHash = hashToken(code);
    const row = await app.prisma.agentOAuthCode.findUnique({ where: { codeHash } });
    if (!row || row.usedAt || row.expiresAt <= now || row.clientId !== clientId || row.redirectUri !== redirectUri || !VERIFIER.test(verifier)
      || createHash("sha256").update(verifier).digest("base64url") !== row.codeChallenge) return invalidGrant(reply);
    const client = await app.prisma.agentOAuthClient.findUnique({ where: { id: row.clientId }, select: { name: true } });
    const id = randomUUID(), refresh = newRefreshToken(id);
    const orgId = await app.prisma.$transaction(async (tx) => {
      // Single use: of two concurrent exchanges only one claims the code.
      if ((await tx.agentOAuthCode.updateMany({ where: { codeHash, usedAt: null }, data: { usedAt: now } })).count !== 1) return null;
      const a = await tx.agent.findFirst({ where: { userId: row.agentId, ...grantableAgent(now) }, select: { orgId: true } });
      if (!a || !client) return null;
      await tx.agentGrant.create({ data: { id, agentId: row.agentId, clientId: row.clientId, grantedById: row.grantedById, refreshHash: refresh.hash, expiresAt: new Date(now.getTime() + GRANT_TTL_MS) } });
      await logEvent(tx, { orgId: a.orgId, actorId: row.grantedById, action: "agent.grant", targetUserId: row.agentId, meta: { clientName: client.name, grantId: id }, ip: req.ip });
      return a.orgId;
    });
    if (!orgId) return invalidGrant(reply);
    const { token, expiresIn } = await signAgentAccess(app.config, { agentId: row.agentId, orgId, grant: id });
    return { access_token: token, token_type: "Bearer", expires_in: expiresIn, refresh_token: refresh.token };
  };

  /** Rotation as /auth/refresh does it (auth.ts): compare-and-swap, a grace window for concurrent callers, a replay revokes the grant. */
  const refreshGrant: Grant = async (req, reply, form) => {
    if (!form.refresh_token || !form.client_id) return reply.code(400).send({ error: "invalid_request" });
    const p = splitRefresh(form.refresh_token);
    if (!p) return invalidGrant(reply);
    const load = () => app.prisma.agentGrant.findFirst({ where: { id: p.sessionId, clientId: form.client_id },
      select: { id: true, agentId: true, refreshHash: true, prevRefreshHash: true, rotatedAt: true, revokedAt: true, expiresAt: true, agent: { select: { orgId: true } } } });
    type Row = NonNullable<Awaited<ReturnType<typeof load>>>;
    const live = async (g: Row) => !g.revokedAt && g.expiresAt > new Date()
      && !!(await app.prisma.agent.findFirst({ where: { userId: g.agentId, ...grantableAgent(new Date()) }, select: { userId: true } }));
    let g = await load();
    if (!g || !(await live(g))) return invalidGrant(reply);
    const h = hashToken(p.secret);
    const sign = async (r: Row, refreshToken?: string) => {
      const { token, expiresIn } = await signAgentAccess(app.config, { agentId: r.agentId, orgId: r.agent.orgId, grant: r.id });
      return { access_token: token, token_type: "Bearer", expires_in: expiresIn, ...(refreshToken ? { refresh_token: refreshToken } : {}) };
    };
    if (h === g.refreshHash) {
      const next = newRefreshToken(g.id);
      const { count } = await app.prisma.agentGrant.updateMany({ where: { id: g.id, refreshHash: h, revokedAt: null }, data: { prevRefreshHash: h, refreshHash: next.hash, rotatedAt: new Date() } });
      if (count === 1) return sign(g, next.token);
      g = await load(); // lost a concurrent rotation; re-evaluate against the fresh row
      if (!g || !(await live(g))) return invalidGrant(reply);
    }
    if (h === g.prevRefreshHash && g.rotatedAt && Date.now() - g.rotatedAt.getTime() <= REFRESH_GRACE_MS)
      return sign(g); // concurrent request: the caller already holds (or is about to receive) the newer refresh token
    if (h === g.prevRefreshHash) await revokeGrant(app, { id: g.id }, { actorId: g.agentId, reason: "refresh_reuse", ip: req.ip });
    return invalidGrant(reply);
  };

  const grants = new Map<string, Grant>([["urn:clane:agent-token", agentToken], ["authorization_code", authorizationCode], ["refresh_token", refreshGrant]]);

  // Preflight #12: the gateway's exchanges all come from one address, so they are counted per token instead.
  const rateKey = (req: FastifyRequest) => {
    const id = fromGateway(app, req) ? STATIC.exec(String((req.body as Form | undefined)?.token ?? ""))?.[1] : undefined;
    return id ? `agent-token:${id}` : req.ip;
  };
  app.post("/oauth/token", { config: { rateLimit: { max: 30, timeWindow: "1 minute", hook: "preHandler", keyGenerator: rateKey } } }, async (req, reply) => {
    const form = (req.body && typeof req.body === "object" ? req.body : {}) as Form;
    if (typeof form.grant_type !== "string") return reply.code(400).send({ error: "invalid_request" });
    const grant = grants.get(form.grant_type);
    return grant ? grant(req, reply, form) : reply.code(400).send({ error: "unsupported_grant_type" });
  });
};
