import type { FastifyInstance, FastifyPluginAsync, FastifyRequest } from "fastify";
import type { EmailSettings, Prisma } from "@prisma/client";
import { createHash, randomUUID } from "node:crypto";
import { z } from "zod";
import { apiPrefix, type Config } from "../config.js";
import { logEvent } from "../lib/events.js";
import { deliver, isDelegated, refreshAad, scopeOf, secretAad, SMTP_PORTS } from "../lib/mailer.js";
import { authorizeUrl, type ConnectError, connectErrorOf, delegatedScope, exchangeCode, hasScope, invalidateM365Token, isClientId, isTenantId,
  M365_GRAPH_SCOPE, pkceChallenge, randomUrlToken } from "../lib/m365.js";
import { isInstanceAdmin, isOrgAdmin } from "../lib/orgs.js";
import { cleanName } from "../lib/names.js";
import { assertPublicHost, PrivateHostError } from "../lib/netGuard.js";
import { last4 } from "../lib/settingsBox.js";

const HOST = /^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$|^\[?[0-9a-fA-F:.]+\]?$/;
const fromName = z.string().max(200).transform(cleanName).refine((s) => s.length <= 80, { message: "too_long" });
const secret = z.string().min(1).max(2048).refine((s) => !/[\r\n]/.test(s), { message: "invalid" });
const body = z.object({
  provider: z.enum(["resend", "smtp", "m365"]),
  fromName: fromName.nullish(),
  /** Empty only for Microsoft 365 delegated sign-in: send as the signed-in account. */
  fromAddress: z.union([z.string().trim().toLowerCase().email().max(254), z.literal("")]),
  smtp: z.object({
    host: z.string().trim().regex(HOST),
    port: z.number().int().min(1).max(65535),
    security: z.enum(["none", "starttls", "tls"]),
    username: z.string().trim().max(254).nullish(),
  }).optional(),
  /** Microsoft 365 (Graph): the Entra tenant (GUID or verified domain) and the app's client ID. The sender is fromAddress. */
  m365: z.object({
    tenantId: z.string().trim().toLowerCase().refine(isTenantId, { message: "invalid_tenant" }),
    clientId: z.string().trim().toLowerCase().refine(isClientId, { message: "invalid_client_id" }),
    /** app: client credentials (Mail.Send application permission). delegated: an admin signs in with Microsoft. */
    authMode: z.enum(["app", "delegated"]).default("app"),
  }).optional(),
  /** Replaces the stored secret (Resend API key, SMTP password or Microsoft 365 client secret). Omitted: keep the stored one. */
  secret: secret.optional(),
});

/** Microsoft 365 delegated sign-in: the redirect URI to register in Entra (a "Web" platform). PUBLIC_URL includes BASE_PATH. */
export const m365RedirectUri = (cfg: Pick<Config, "publicUrl">) => `${cfg.publicUrl}/api/v1/admin/email/m365/callback`;
export const M365_COOKIE = "cv_m365";
export const M365_CONNECT_TTL_MS = 10 * 60e3;
/** The binding cookie only goes back to the callback (under the base path, if any). */
const m365CookiePath = (cfg: Pick<Config, "basePath">) => `${apiPrefix(cfg)}/admin/email/m365`;
const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");
/** Ties a sign-in request to the app registration it was started for. */
const connectFp = (row: Pick<EmailSettings, "id" | "m365TenantId" | "m365ClientId">) => sha256(`${row.id}\0${row.m365TenantId}\0${row.m365ClientId}\0delegated`);
/** Clears a delegated connection (the refresh token goes; the version moves so an in-flight rotation can't bring it back). */
const NO_CONNECTION = { m365RefreshEnc: null, m365RefreshVersion: { increment: 1 }, m365Account: null, m365ConnectedAt: null, m365ConnectedById: null,
  m365GrantedScope: null, m365ReconnectAt: null, m365ReconnectReason: null } satisfies Prisma.EmailSettingsUpdateInput;
const hasConnection = (row: EmailSettings) => !!(row.m365RefreshEnc || row.m365Account || row.m365ReconnectAt);

/** Settings as the API shows them: never the secret, only whether one is set (and an API key's last four characters). */
function view(row: EmailSettings | null, updatedBy: { id: string; name: string } | null, connectedBy: { id: string; name: string } | null = null) {
  if (!row) return null;
  const delegated = isDelegated(row);
  return {
    provider: row.provider, fromName: row.fromName, fromAddress: row.fromAddress,
    smtp: row.provider === "smtp" ? { host: row.smtpHost, port: row.smtpPort, security: row.smtpSecurity, username: row.smtpUsername } : null,
    m365: row.provider === "m365" ? { tenantId: row.m365TenantId, clientId: row.m365ClientId, authMode: row.m365AuthMode ?? "app",
      // Delegated: who is signed in (never the refresh token), and whether it needs signing in again.
      delegated: delegated ? {
        account: row.m365Account, connectedAt: row.m365ConnectedAt?.toISOString() ?? null, connectedBy,
        reconnect: row.m365ReconnectAt ? { at: row.m365ReconnectAt.toISOString(), reason: row.m365ReconnectReason } : null,
        /** A shared mailbox is set as sender but the sign-in didn't grant Mail.Send.Shared: sign in again. */
        sharedScopeMissing: !!row.m365Account && !!row.fromAddress && row.fromAddress !== row.m365Account && !hasScope(row.m365GrantedScope, M365_GRAPH_SCOPE.sendShared),
      } : null } : null,
    secret: { set: !!row.secretEnc, last4: row.provider === "resend" || row.provider === "m365" ? row.secretLast4 : null },
    updatedAt: row.updatedAt.toISOString(), updatedBy,
  };
}

/**
 * Email settings for one scope (docs/email.md): the instance's (instance admins) or the active org's override (its
 * owners and admins). Registered inside a guarded admin group; `orgOf` says which scope a request is about.
 */
function emailSettingsRoutes(orgOf: (req: FastifyRequest) => string | null): FastifyPluginAsync {
  return async (app: FastifyInstance) => {
    const load = (orgId: string | null) => app.prisma.emailSettings.findUnique({ where: { scope: scopeOf(orgId) } });
    const who = async (id: string | null) => (id ? await app.prisma.user.findUnique({ where: { id }, select: { id: true, name: true } }) : null);
    const meta = (req: FastifyRequest) => ({ ip: req.ip, userAgent: String(req.headers["user-agent"] ?? "").slice(0, 300) });

    async function respond(orgId: string | null) {
      const row = await load(orgId);
      const inst = orgId ? await load(null) : null;
      // What applies when this scope has no settings of its own.
      const fallback = orgId && inst ? "instance" : app.mail.envTransport() ? "env" : "none";
      return { scope: orgId ? "org" : "instance", settings: view(row, await who(row?.updatedById ?? null), await who(row?.m365ConnectedById ?? null)), fallback,
        m365RedirectUri: m365RedirectUri(app.config),
        ...(orgId ? {} : { env: app.mail.envTransport() ? { from: app.config.emailFrom } : null }) };
    }

    app.get("/", async (req) => respond(orgOf(req)));

    app.put("/", { config: { rateLimit: { max: 20, timeWindow: "1 minute" } } }, async (req, reply) => {
      const b = body.parse(req.body);
      const orgId = orgOf(req);
      const cur = await load(orgId);
      if (b.provider === "smtp" && !b.smtp) return reply.code(400).send({ error: "invalid_request", issues: ["smtp"] });
      if (b.provider === "m365" && !b.m365) return reply.code(400).send({ error: "invalid_request", issues: ["m365"] });
      const delegated = b.provider === "m365" && b.m365!.authMode === "delegated";
      if (!b.fromAddress && !delegated) return reply.code(400).send({ error: "invalid_request", issues: ["fromAddress"] });
      // A secret belongs to its provider (and SMTP password to its username): switching drops it unless a new one comes.
      const sameProvider = cur?.provider === b.provider;
      const username = b.provider === "smtp" ? (b.smtp!.username || null) : null;
      // An SMTP password is kept only for the same server: a new host, port or security mode needs it typed again, so a
      // stored password can't be sent to a server of someone's choosing.
      const sameServer = b.provider !== "smtp" || (!!cur && cur.smtpHost === b.smtp!.host && cur.smtpPort === b.smtp!.port && cur.smtpSecurity === b.smtp!.security && username === cur.smtpUsername);
      // A Microsoft 365 client secret likewise stays only with the same tenant and app.
      const sameApp = b.provider !== "m365" || (!!cur && cur.m365TenantId === b.m365!.tenantId && cur.m365ClientId === b.m365!.clientId);
      const keepSecret = !!cur?.secretEnc && sameProvider && (b.provider === "resend" || (b.provider === "m365" && sameApp) || (b.provider === "smtp" && !!username && sameServer));
      if ((b.provider === "resend" || b.provider === "m365") && !b.secret && !keepSecret) return reply.code(400).send({ error: "secret_required" });
      // HOSTED_MODE: never a password over an unencrypted connection; organisations only use the usual SMTP ports.
      if (b.provider === "smtp" && app.config.hostedMode && username && b.smtp!.security === "none") return reply.code(400).send({ error: "insecure_auth" });
      if (b.provider === "smtp" && orgId && app.config.hostedMode && !SMTP_PORTS.includes(b.smtp!.port)) return reply.code(400).send({ error: "port_not_allowed" });
      if (b.provider === "smtp" && orgId && app.config.hostedMode) {
        try { await assertPublicHost(b.smtp!.host); }
        catch (e) { return reply.code(400).send({ error: e instanceof PrivateHostError ? "private_host" : "host_not_found" }); }
      }
      const id = cur?.id ?? randomUUID();
      const scope = scopeOf(orgId);
      const sealed = b.secret && (b.provider !== "smtp" || username) ? { secretEnc: app.settingsBox.seal(b.secret, secretAad({ id, scope })), secretLast4: last4(b.secret) }
        : keepSecret ? {} : { secretEnc: null, secretLast4: null };
      const data = {
        provider: b.provider, fromName: b.fromName || null, fromAddress: b.fromAddress,
        smtpHost: b.provider === "smtp" ? b.smtp!.host : null, smtpPort: b.provider === "smtp" ? b.smtp!.port : null,
        smtpSecurity: b.provider === "smtp" ? b.smtp!.security : null, smtpUsername: username,
        m365TenantId: b.provider === "m365" ? b.m365!.tenantId : null, m365ClientId: b.provider === "m365" ? b.m365!.clientId : null,
        m365AuthMode: b.provider === "m365" ? b.m365!.authMode : null,
        updatedById: req.auth.userId, ...sealed,
      };
      // A delegated sign-in belongs to its app registration: another tenant, app, provider or mode drops it.
      const keepConnection = !!cur && isDelegated(cur) && delegated && sameApp;
      const dropConnection = !!cur && hasConnection(cur) && !keepConnection;
      // Which fields changed, for the audit log (never values of secrets).
      const changed = cur ? (Object.keys(data) as (keyof typeof data)[]).filter((k) => k !== "updatedById" && k !== "secretLast4" && (k === "secretEnc" ? "secretEnc" in sealed && !(sealed.secretEnc === null && cur.secretEnc === null) : data[k] !== cur[k])).map((k) => (k === "secretEnc" ? "secret" : k)) : ["created"];
      await app.prisma.emailSettings.upsert({ where: { scope }, create: { id, scope, orgId, ...data }, update: { ...data, ...(dropConnection ? NO_CONNECTION : {}) } });
      invalidateM365Token(id);
      if (dropConnection) await logEvent(app.prisma, { ...(orgId ? { orgId } : {}), actorId: req.auth.userId, action: "email.m365_disconnected", meta: { scope: orgId ? "org" : "instance", account: cur!.m365Account, why: "settings_changed" }, ...meta(req) });
      await logEvent(app.prisma, { ...(orgId ? { orgId } : {}), actorId: req.auth.userId, action: "email.settings_updated", meta: { scope: orgId ? "org" : "instance", provider: b.provider, changed }, ...meta(req) });
      return respond(orgId);
    });

    app.delete("/", async (req, reply) => {
      const orgId = orgOf(req);
      const cur = await load(orgId);
      const n = await app.prisma.emailSettings.deleteMany({ where: { scope: scopeOf(orgId) } });
      if (cur) invalidateM365Token(cur.id);
      if (n.count) await logEvent(app.prisma, { ...(orgId ? { orgId } : {}), actorId: req.auth.userId, action: "email.settings_removed", meta: { scope: orgId ? "org" : "instance" }, ...meta(req) });
      return reply.code(200).send(await respond(orgId));
    });

    /** Sends a test email to the caller's own address with this scope's saved settings. */
    app.post("/test", { config: { rateLimit: { max: 5, timeWindow: "1 minute" } } }, async (req, reply) => {
      const orgId = orgOf(req);
      const row = await load(orgId);
      if (!row) return reply.code(409).send({ error: "not_configured" });
      if (isDelegated(row) && (!row.m365RefreshEnc || row.m365ReconnectAt)) return reply.code(409).send({ error: row.m365ReconnectAt ? "m365_reconnect" : "m365_not_connected" });
      const t = app.mail.transportOf(row, orgId ? "org" : "instance");
      if (!t) return reply.code(409).send({ error: "secret_missing" });
      const me = await app.prisma.user.findUniqueOrThrow({ where: { id: req.auth.userId }, select: { email: true } });
      const org = orgId ? await app.prisma.organization.findUnique({ where: { id: orgId }, select: { name: true } }) : null;
      const r = await deliver(t, me.email, {
        subject: `${await app.brand.productName()}: test email`,
        text: `This is a test email from ${await app.brand.productName()}${org ? ` for ${org.name}` : ""}, sent with the ${row.provider === "smtp" ? `SMTP server ${row.smtpHost}:${row.smtpPort}` : row.provider === "m365" ? `Microsoft 365 (${row.fromAddress || row.m365Account})` : "Resend"} settings.\n\nIf you can read this, email works.`,
      });
      await logEvent(app.prisma, { ...(orgId ? { orgId } : {}), actorId: req.auth.userId, action: "email.test", meta: { scope: orgId ? "org" : "instance", provider: row.provider, ok: r.ok }, ...meta(req) });
      if (!r.ok) return reply.code(502).send({ error: "email_test_failed", detail: r.detail });
      return { ok: true, to: me.email };
    });

    /**
     * Microsoft 365 delegated sign-in, step 1: a single-use request (state, nonce, PKCE verifier; 10 minutes) for this
     * scope by this admin, bound to an httpOnly cookie, and the Microsoft URL to go to. Same authorisation as editing
     * the settings (the group's guard).
     */
    app.post("/m365/connect", { config: { rateLimit: { max: 10, timeWindow: "1 minute" } } }, async (req, reply) => {
      const orgId = orgOf(req);
      const row = await load(orgId);
      if (!row || !isDelegated(row) || !row.m365TenantId || !row.m365ClientId) return reply.code(409).send({ error: "not_delegated" });
      if (!row.secretEnc) return reply.code(409).send({ error: "secret_missing" });
      try { app.settingsBox.open(row.secretEnc, secretAad(row)); } catch { return reply.code(409).send({ error: "secret_missing" }); }
      const state = randomUrlToken(), nonce = randomUrlToken(), codeVerifier = randomUrlToken(48), bind = randomUrlToken();
      // A shared mailbox as sender also needs Mail.Send.Shared; an empty sender means the signed-in account.
      const scope = delegatedScope(!!row.fromAddress);
      await app.prisma.m365Connect.create({ data: { stateHash: sha256(state), bindingHash: sha256(bind), scope: row.scope, orgId, settingsId: row.id, settingsFp: connectFp(row),
        actorId: req.auth.userId, sessionId: req.auth.sessionId, nonce, codeVerifier, requestedScope: scope, expiresAt: new Date(Date.now() + M365_CONNECT_TTL_MS) } });
      // Lax: Microsoft's redirect back is a top-level GET from another site.
      reply.setCookie(M365_COOKIE, bind, { httpOnly: true, secure: app.config.cookieSecure, sameSite: "lax", path: m365CookiePath(app.config), maxAge: M365_CONNECT_TTL_MS / 1000 });
      return { url: authorizeUrl({ tenantId: row.m365TenantId, clientId: row.m365ClientId, redirectUri: m365RedirectUri(app.config), scope, state, nonce, codeChallenge: pkceChallenge(codeVerifier) }) };
    });

    /** Disconnects: deletes the stored refresh token (nothing is called at Microsoft; revoke the app in My Apps if wanted). */
    app.delete("/m365/connection", async (req, reply) => {
      const orgId = orgOf(req);
      const row = await load(orgId);
      if (!row || !isDelegated(row)) return reply.code(409).send({ error: "not_delegated" });
      if (hasConnection(row)) {
        await app.prisma.emailSettings.update({ where: { id: row.id }, data: NO_CONNECTION });
        invalidateM365Token(row.id);
        await logEvent(app.prisma, { ...(orgId ? { orgId } : {}), actorId: req.auth.userId, action: "email.m365_disconnected", meta: { scope: orgId ? "org" : "instance", account: row.m365Account }, ...meta(req) });
      }
      return respond(orgId);
    });
  };
}

/**
 * Microsoft 365 delegated sign-in, step 2: Microsoft's redirect (GET, no bearer token: it is a top-level navigation).
 * Accepts only a live request from this browser (cookie), claims it once, re-checks that its admin may still change
 * that scope's settings from a live session and that the settings still name the same app, redeems the code and stores
 * the refresh token sealed. Never logs the code or tokens (the request logger redacts this URL's query). Redirects back
 * to the settings page with `?m365=connected` or `?m365_error=<code>[&aadsts=<n>]`.
 */
export const m365CallbackRoutes: FastifyPluginAsync = async (app) => {
  const meta = (req: FastifyRequest) => ({ ip: req.ip, userAgent: String(req.headers["user-agent"] ?? "").slice(0, 300) });
  app.get("/callback", { config: { rateLimit: { max: 30, timeWindow: "1 minute" } } }, async (req, reply) => {
    const q = req.query as Record<string, unknown>;
    const bind = req.cookies[M365_COOKIE];
    reply.clearCookie(M365_COOKIE, { path: m365CookiePath(app.config) });
    const state = typeof q.state === "string" && q.state.length <= 200 ? q.state : null;
    const login = state ? await app.prisma.m365Connect.findUnique({ where: { stateHash: sha256(state) } }) : null;
    if (!login) return reply.code(400).type("text/plain; charset=utf-8").send("This Microsoft sign-in can't be completed. Go back to the email settings and choose Sign in with Microsoft again.");
    const org = login.orgId ? await app.prisma.organization.findUnique({ where: { id: login.orgId }, select: { id: true, slug: true } }) : null;
    const page = org ? `${app.config.publicUrl}/o/${encodeURIComponent(org.slug || org.id)}/admin/org/email` : `${app.config.publicUrl}/server/email`;
    const scopeName = login.orgId ? "org" : "instance";
    const fail = async (error: ConnectError | "state" | "forbidden" | "settings_changed" | "secret_missing", aadsts?: number) => {
      await logEvent(app.prisma, { ...(login.orgId ? { orgId: login.orgId } : {}), actorId: login.actorId, action: "email.m365_connect_failed", meta: { scope: scopeName, error, ...(aadsts ? { aadsts } : {}) }, ...meta(req) });
      return reply.redirect(`${page}?${new URLSearchParams({ m365_error: error, ...(aadsts ? { aadsts: String(aadsts) } : {}) })}`, 302);
    };
    // Single use, only from the browser that started it, within 10 minutes.
    if (typeof bind !== "string" || sha256(bind) !== login.bindingHash || login.expiresAt < new Date()) return fail("state");
    const claimed = await app.prisma.m365Connect.updateMany({ where: { id: login.id, usedAt: null }, data: { usedAt: new Date() } });
    if (!claimed.count) return fail("state");
    // Whoever started it must still be allowed to change these settings, from a session that is still live.
    const session = await app.prisma.session.findUnique({ where: { id: login.sessionId }, select: { userId: true, revokedAt: true, expiresAt: true } });
    const allowed = !!session && session.userId === login.actorId && !session.revokedAt && session.expiresAt > new Date()
      && (login.orgId ? await isOrgAdmin(app.prisma, login.actorId, login.orgId) : await isInstanceAdmin(app.prisma, app.config, login.actorId));
    if (!allowed) return fail("forbidden");
    const row = await app.prisma.emailSettings.findUnique({ where: { scope: login.scope } });
    if (!row || row.id !== login.settingsId || !isDelegated(row) || connectFp(row) !== login.settingsFp || !row.m365TenantId || !row.m365ClientId) return fail("settings_changed");
    if (typeof q.error === "string") {
      const e = connectErrorOf(q.error, { error_description: typeof q.error_description === "string" ? q.error_description.slice(0, 1000) : undefined });
      return fail(e.error, e.aadsts);
    }
    if (typeof q.code !== "string" || !q.code || q.code.length > 8192) return fail("failed");
    let clientSecret: string;
    try { clientSecret = app.settingsBox.open(row.secretEnc ?? "", secretAad(row)); } catch { return fail("secret_missing"); }
    const x = await exchangeCode({ tenantId: row.m365TenantId, clientId: row.m365ClientId, clientSecret, code: q.code, codeVerifier: login.codeVerifier,
      redirectUri: m365RedirectUri(app.config), scope: login.requestedScope, nonce: login.nonce });
    if (!x.ok) return fail(x.error, x.aadsts);
    // Sending from a shared mailbox needs Mail.Send.Shared (when Microsoft says what it granted).
    if (row.fromAddress && row.fromAddress !== x.account && x.scope && !hasScope(x.scope, M365_GRAPH_SCOPE.sendShared)) return fail("shared_scope_missing");
    const saved = await app.prisma.emailSettings.updateMany({
      where: { id: row.id, m365TenantId: row.m365TenantId, m365ClientId: row.m365ClientId, m365AuthMode: "delegated" },
      data: { m365RefreshEnc: app.settingsBox.seal(x.refreshToken, refreshAad(row)), m365RefreshVersion: { increment: 1 }, m365Account: x.account, m365ConnectedAt: new Date(),
        m365ConnectedById: login.actorId, m365GrantedScope: (x.scope || login.requestedScope).slice(0, 1000), m365ReconnectAt: null, m365ReconnectReason: null },
    });
    if (!saved.count) return fail("settings_changed");
    invalidateM365Token(row.id);
    await logEvent(app.prisma, { ...(login.orgId ? { orgId: login.orgId } : {}), actorId: login.actorId, action: "email.m365_connected", meta: { scope: scopeName, account: x.account, reconnect: !!row.m365ReconnectAt || !!row.m365Account }, ...meta(req) });
    return reply.redirect(`${page}?m365=connected`, 302);
  });
};

/** /admin/instance/email: instance admins. */
export const instanceEmailRoutes = emailSettingsRoutes(() => null);
/** /admin/settings/email: the active org's owners and admins. */
export const orgEmailRoutes = emailSettingsRoutes((req) => req.org!.id);
