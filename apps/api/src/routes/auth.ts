import type { FastifyInstance, FastifyPluginAsync, FastifyReply } from "fastify";
import { createHmac, randomInt, timingSafeEqual } from "node:crypto";
import argon2 from "argon2";
import { authenticator } from "otplib";
import { z } from "zod";
import { secretBox } from "../lib/secretBox.js";
import { apiPrefix, type Config } from "../config.js";
import { consumeTotp, totpKeyUri } from "../lib/totp.js";
import { hashToken, newRefreshToken, signAccess, signSetup, splitRefresh } from "../lib/tokens.js";
import { logEvent } from "../lib/events.js";
import { lockedFor, registerFailure } from "../lib/lockout.js";
import { adminAddedEmail, sendEmail, signupCodeEmail } from "../lib/email.js";
import { displayName } from "../lib/names.js";
import { getEntitlements, PLAN_SELECT } from "../lib/plans.js";
import { orgsOf } from "../lib/orgs.js";
import { readPolicies } from "../lib/policies.js";
import { linkAndJoin } from "../lib/ssoLink.js";
import type { Db } from "../lib/access.js";
import { applyPendingGroups, invitedRole } from "../lib/invites.js";
import { domainJoinPublicRoutes } from "./provisioning.js";
import { demoExpired, demoOn, demoSkipsTotp, sessionEnd } from "../lib/demo.js";
import { demoRoutes } from "./demo.js";

const DEFAULT_KDF = { alg: "argon2id", m: 65536, t: 3, p: 1 };
const REFRESH_TTL_MS = 12 * 60 * 60 * 1000;
const REFRESH_GRACE_MS = 30_000;

const b64 = z.string().regex(/^[A-Za-z0-9_-]+$/).max(4096);
const envelope = z.string().max(16384);
export const materialSchema = (minMemoryKiB: number) => z.object({
  kdfSalt: b64, kdfParams: z.object({ alg: z.literal("argon2id"), m: z.number().int().min(minMemoryKiB).max(1048576), t: z.number().int().min(1).max(10), p: z.number().int().min(1).max(4) }),
  wrappedUserKey: envelope, publicKey: b64, wrappedPrivateKey: envelope,
});
const email = z.string().trim().toLowerCase().email().max(254);
const code = z.string().regex(/^\d{6}$/);

export const kdfView = (k: unknown) => { const o = k as { alg: string; m: number; t: number; p: number }; return { alg: o.alg, m: o.m, t: o.t, p: o.p }; };
/**
 * `recoveryKit`: whether the user has a recovery kit (the app asks those without one to create it). `demoExpiresAt`: only
 * for a demo sandbox account (docs/demo.md), when it and everything in it is deleted.
 */
export const userView = (u: { id: string; email: string; name: string; recoveryCreatedAt?: Date | null; demoExpiresAt?: Date | null }) =>
  ({ id: u.id, email: u.email, name: u.name, recoveryKit: !!u.recoveryCreatedAt, ...(u.demoExpiresAt ? { demoExpiresAt: u.demoExpiresAt.toISOString() } : {}) });
export const materialView = (u: { kdfSalt: string; kdfParams: unknown; wrappedUserKey: string; publicKey: string; wrappedPrivateKey: string }) =>
  ({ kdfSalt: u.kdfSalt, kdfParams: kdfView(u.kdfParams), wrappedUserKey: u.wrappedUserKey, publicKey: u.publicKey, wrappedPrivateKey: u.wrappedPrivateKey });

/** What a sign-in returns: the token, the account, its key material and its active organisations. */
export async function authView(prisma: Db, cfg: Pick<Config, "billingMode">, accessToken: string, u: Parameters<typeof userView>[0] & Parameters<typeof materialView>[0]) {
  return { accessToken, user: userView(u), material: materialView(u), orgs: await orgsOf(prisma, cfg, u.id) };
}

/**
 * New admins of these orgs (active memberships with an admin role and no adminSince yet) start their admin age now,
 * and every other admin of each org hears about it (admin recovery relies on admins being who they seem).
 */
export async function startAdminAge(app: FastifyInstance, user: { id: string; name: string; email: string }, log: { warn: (o: object, m: string) => void }, meta: { ip?: string; userAgent?: string } = {}) {
  const fresh = await app.prisma.membership.findMany({ where: { userId: user.id, status: "active", role: { in: ["owner", "admin"] }, adminSince: null }, select: { id: true, orgId: true, org: { select: { name: true } } } });
  for (const m of fresh) {
    await app.prisma.membership.update({ where: { id: m.id }, data: { adminSince: new Date() } });
    await logEvent(app.prisma, { orgId: m.orgId, actorId: user.id, action: "admin.added", targetUserId: user.id, ...meta });
    const admins = await app.prisma.user.findMany({ where: { id: { not: user.id }, status: "active", memberships: { some: { orgId: m.orgId, status: "active", role: { in: ["owner", "admin"] } } } }, select: { email: true } });
    for (const a of admins) void sendEmail(app.mail, a.email, adminAddedEmail(await app.brand.productName(), user.name, user.email, m.org.name), log);
  }
}

/** Session label of browser-extension sessions; only these may present their refresh token in a request body. */
export const EXTENSION_LABEL = "Browser extension";
/** Who signs in: the web app keeps the refresh token in an httpOnly cookie; the browser extension gets it in the body. */
export const clientSchema = z.enum(["web", "extension"]).optional();

/** `ssoOrgIds`: organisations whose SSO established this session ("Require SSO for members"). */
/** `totpSkippedForOrg`: the session skipped the authenticator code for that org's trusted IdP MFA (usable there only). */
/** `client: "extension"`: no cookie; the refresh token is returned for the extension to keep (docs/extension.md). */
export async function createSession(app: FastifyInstance, reply: FastifyReply, user: { id: string }, userAgent?: string, opts: { ssoOrgIds?: string[]; totpSkippedForOrg?: string; client?: "web" | "extension" } = {}) {
  const ext = opts.client === "extension";
  // A demo sandbox account's session ends with its sandbox (docs/demo.md).
  const u = await app.prisma.user.findUnique({ where: { id: user.id }, select: { demoExpiresAt: true } });
  const expiresAt = sessionEnd({ demoExpiresAt: u?.demoExpiresAt ?? null }, REFRESH_TTL_MS);
  const session = await app.prisma.session.create({ data: { userId: user.id, refreshHash: `pending-${crypto.randomUUID()}`, userAgent: ext ? EXTENSION_LABEL : userAgent, expiresAt, ssoOrgIds: opts.ssoOrgIds ?? [], totpSkippedForOrg: opts.totpSkippedForOrg ?? null } });
  const refresh = newRefreshToken(session.id);
  await app.prisma.session.update({ where: { id: session.id }, data: { refreshHash: refresh.hash } });
  if (!ext) reply.setCookie("cv_refresh", refresh.token, { httpOnly: true, secure: app.config.cookieSecure, sameSite: "strict", path: `${apiPrefix(app.config)}/auth`, maxAge: Math.max(1, Math.floor((expiresAt.getTime() - Date.now()) / 1000)) });
  return { accessToken: await signAccess(app.config, { userId: user.id, sessionId: session.id }), ...(ext ? { refreshToken: refresh.token } : {}) };
}

/** Open invites from other organisations for the same address become invitations to accept in the app (at registration). */
export async function convertOtherInvites(tx: Db, email: string, userId: string, exceptOrgId: string, now: Date) {
  const others = await tx.invite.findMany({ where: { email, acceptedAt: null, expiresAt: { gt: now }, orgId: { not: exceptOrgId } }, select: { id: true, orgId: true, role: true, source: true, invitedById: true, createdAt: true } });
  for (const o of others) {
    await tx.membership.upsert({ where: { orgId_userId: { orgId: o.orgId, userId } }, create: { orgId: o.orgId, userId, role: invitedRole(o), status: "invited", invitedById: o.invitedById,
      // The invite's own date (and so its expiry): the inviting org can't tell when the account was made.
      createdAt: o.createdAt }, update: {} });
    await tx.invite.update({ where: { id: o.id }, data: { acceptedAt: now } });
  }
}

export const authRoutes: FastifyPluginAsync = async (app) => {
  const box = secretBox(app.config.serverSecret);
  const material = materialSchema(app.config.kdfMinMemoryKiB);
  const dummyHash = await argon2.hash("clane-vault-dummy", { type: argon2.argon2id });
  const fakeSalt = (e: string) => createHmac("sha256", app.config.serverSecret).update(`prelogin:${e}`).digest().subarray(0, 16).toString("base64url");
  const meta = (req: { ip: string; headers: Record<string, unknown> }) => ({ ip: req.ip, userAgent: String(req.headers["user-agent"] ?? "").slice(0, 300) });

  // Email domain auto-join: POST /auth/domain-join (docs/provisioning.md).
  await app.register(domainJoinPublicRoutes);
  // Public demo sandboxes (docs/demo.md): only on a DEMO_MODE=true instance; elsewhere the paths don't exist (404).
  if (demoOn(app.config)) await app.register(demoRoutes);

  app.post("/prelogin", async (req) => {
    const { email: e } = z.object({ email }).parse(req.body);
    const u = await app.prisma.user.findUnique({ where: { email: e }, select: { kdfSalt: true, kdfParams: true } });
    return u ? { kdfSalt: u.kdfSalt, kdfParams: kdfView(u.kdfParams) } : { kdfSalt: fakeSalt(e), kdfParams: kdfView(DEFAULT_KDF) };
  });

  app.get("/invite/:token", async (req, reply) => {
    const { token } = req.params as { token: string };
    const inv = await app.prisma.invite.findUnique({ where: { tokenHash: hashToken(token) }, include: { org: { select: { ...PLAN_SELECT, name: true, adminRecoveryEnabled: true, policies: true } } } });
    if (!inv || inv.acceptedAt || inv.expiresAt < new Date()) return reply.code(404).send({ error: "invite_invalid" });
    // The inviting org's admin-recovery policy, for the disclosure on the sign-up page; and whether an emailed code is needed.
    // Its master password rule too (docs/policies.md): the sign-up form enforces it.
    const pol = readPolicies(inv.org.policies, getEntitlements(app.config, inv.org));
    return { email: inv.email, orgName: inv.org.name, adminRecoveryEnabled: inv.org.adminRecoveryEnabled, emailVerification: !!app.config.hostedMode,
      passwordPolicy: { minLength: pol.minPasswordLength, minScore: pol.minPasswordScore }, ...(inv.nameHint ? { name: inv.nameHint } : {}) };
  });

  // ---- HOSTED_MODE: a 6-digit code emailed to the invited address, needed to register (no account squatting) ----
  const CODE_TTL_MS = 10 * 60e3;
  const MAX_CODE_ATTEMPTS = 5;
  /** Wrong codes over all codes of one invite; at this many the invite itself is burned. */
  const MAX_TOTAL_CODE_ATTEMPTS = 15;
  /** Codes one invite may have sent. */
  const MAX_CODE_ISSUES = 5;
  const burnInvite = (id: string) => app.prisma.invite.update({ where: { id }, data: { expiresAt: new Date(Date.now() - 1), emailCodeHash: null, emailCodeExpiresAt: null } });
  const codeHash = (inviteId: string, code: string) => createHmac("sha256", app.config.serverSecret).update(`signup:${inviteId}:${code}`).digest("hex");

  app.post("/register/code", { config: { rateLimit: { max: 5, timeWindow: "1 minute" } } }, async (req, reply) => {
    const { inviteToken } = z.object({ inviteToken: z.string().min(10).max(200) }).parse(req.body);
    if (!app.config.hostedMode) return reply.code(409).send({ error: "not_needed" });
    const inv = await app.prisma.invite.findUnique({ where: { tokenHash: hashToken(inviteToken) }, include: { org: { select: { name: true } } } });
    if (!inv || inv.acceptedAt || inv.expiresAt < new Date()) return reply.code(400).send({ error: "invite_invalid" });
    const code = String(randomInt(0, 1_000_000)).padStart(6, "0");
    // Issued atomically under both caps (a new code resets the per-code count, never the total).
    const n = await app.prisma.invite.updateMany({ where: { id: inv.id, acceptedAt: null, emailCodeIssues: { lt: MAX_CODE_ISSUES }, emailCodeTotalAttempts: { lt: MAX_TOTAL_CODE_ATTEMPTS } },
      data: { emailCodeHash: codeHash(inv.id, code), emailCodeExpiresAt: new Date(Date.now() + CODE_TTL_MS), emailCodeAttempts: 0, emailCodeIssues: { increment: 1 } } });
    if (n.count === 0) return reply.code(429).send({ error: "code_limit" });
    const sent = await sendEmail(app.mail, inv.email, signupCodeEmail(await app.brand.productName(), inv.org.name, code), req.log);
    if (!sent) return reply.code(503).send({ error: "email_failed" });
    return reply.code(202).send({ sent: true });
  });

  // 10 per minute per address at the default RATE_LIMIT_PER_MINUTE (300); scales with it like the other sensitive routes.
  app.post("/register", { config: { rateLimit: { max: Math.max(10, Math.floor((app.config.rateLimitPerMinute ?? 300) / 30)), timeWindow: "1 minute" } } }, async (req, reply) => {
    const body = z.object({ inviteToken: z.string().min(10).max(200), name: displayName, authKey: b64, material, emailCode: z.string().regex(/^\d{6}$/).optional() }).parse(req.body);
    const inv = await app.prisma.invite.findUnique({ where: { tokenHash: hashToken(body.inviteToken) }, include: { org: { select: { demoExpiresAt: true } } } });
    if (!inv || inv.acceptedAt || inv.expiresAt < new Date()) return reply.code(400).send({ error: "invite_invalid" });
    // A demo instance holds demo sandboxes only (docs/demo.md): an invite to anything else (a bootstrap invite to the
    // default organisation, say) never makes an account there, and a sandbox past its time takes no one new.
    if (demoOn(app.config) && !(inv.org.demoExpiresAt && inv.org.demoExpiresAt > new Date())) return reply.code(400).send({ error: "invite_invalid" });
    if (app.config.hostedMode) {
      // The code proves the person registering reads the invited mailbox. Every try is counted first, atomically and
      // only while the code is live and under both caps (5 per code, 15 per invite), then compared.
      if (!body.emailCode) return reply.code(400).send({ error: "email_code_required" });
      const counted = await app.prisma.invite.updateMany({ where: { id: inv.id, emailCodeHash: { not: null }, emailCodeExpiresAt: { gt: new Date() },
        emailCodeAttempts: { lt: MAX_CODE_ATTEMPTS }, emailCodeTotalAttempts: { lt: MAX_TOTAL_CODE_ATTEMPTS } },
        data: { emailCodeAttempts: { increment: 1 }, emailCodeTotalAttempts: { increment: 1 } } });
      const cur = await app.prisma.invite.findUniqueOrThrow({ where: { id: inv.id }, select: { emailCodeHash: true, emailCodeAttempts: true, emailCodeTotalAttempts: true } });
      const given = Buffer.from(codeHash(inv.id, body.emailCode), "hex"), stored = Buffer.from(cur.emailCodeHash ?? "00", "hex");
      const ok = counted.count === 1 && given.length === stored.length && timingSafeEqual(given, stored);
      if (!ok) {
        if (cur.emailCodeTotalAttempts >= MAX_TOTAL_CODE_ATTEMPTS) await burnInvite(inv.id);
        else if (cur.emailCodeAttempts >= MAX_CODE_ATTEMPTS) await app.prisma.invite.updateMany({ where: { id: inv.id, emailCodeAttempts: { gte: MAX_CODE_ATTEMPTS } }, data: { emailCodeHash: null, emailCodeExpiresAt: null } });
        return reply.code(400).send({ error: "email_code_invalid" });
      }
    }
    const inviteEmail = inv.email.trim().toLowerCase();
    if (await app.prisma.user.findUnique({ where: { email: inviteEmail } })) return reply.code(400).send({ error: "invite_invalid" });
    const authHash = await argon2.hash(body.authKey, { type: argon2.argon2id });
    const user = await app.prisma.$transaction(async (tx) => {
      const now = new Date();
      await tx.invite.update({ where: { id: inv.id }, data: { acceptedAt: now, emailCodeHash: null } });
      const u = await tx.user.create({ data: {
        email: inviteEmail, name: body.name, status: "pending_2fa", authHash, instanceAdmin: inv.instanceAdmin && !inv.org.demoExpiresAt,
        // Joining a demo sandbox makes a demo account: it goes when the sandbox does.
        demoExpiresAt: inv.org.demoExpiresAt,
        kdfSalt: body.material.kdfSalt, kdfParams: body.material.kdfParams, wrappedUserKey: body.material.wrappedUserKey,
        publicKey: body.material.publicKey, wrappedPrivateKey: body.material.wrappedPrivateKey,
      } });
      // The organisation that invited them. An owner invite (bootstrap) only counts while the org has no owner.
      const hasOwner = inv.role === "owner" && !!(await tx.membership.findFirst({ where: { orgId: inv.orgId, role: "owner" }, select: { id: true } }));
      await tx.membership.create({ data: { orgId: inv.orgId, userId: u.id, role: hasOwner ? "admin" : inv.role, status: "active", invitedById: inv.invitedById, joinedAt: now } });
      // Groups the invitation put them in (docs/provisioning.md); folder keys still wait for a key holder's approval.
      await applyPendingGroups(tx, inv.orgId, u.id, inviteEmail);
      await convertOtherInvites(tx, inviteEmail, u.id, inv.orgId, now);
      return u;
    });
    await logEvent(app.prisma, { orgId: inv.orgId, actorId: user.id, action: "auth.register", ...meta(req) });
    if (inv.source === "domain") await logEvent(app.prisma, { orgId: inv.orgId, actorId: user.id, action: "org.domain_join", targetUserId: user.id, meta: { via: "signup" } });
    return reply.code(201).send({ setupToken: await signSetup(app.config, user.id) });
  });

  app.post("/totp/setup", { preHandler: app.requireSetup }, async (req, reply) => {
    const user = await app.prisma.user.findUniqueOrThrow({ where: { id: req.setupUserId } });
    if (user.status !== "pending_2fa") return reply.code(409).send({ error: "already_set_up" });
    const secret = authenticator.generateSecret(20);
    await app.prisma.user.update({ where: { id: user.id }, data: { totpSecretEnc: box.seal(secret) } });
    return { secret, otpauthUrl: totpKeyUri(await app.brand.productName(), user.email, secret) };
  });

  app.post("/totp/verify", { preHandler: app.requireSetup }, async (req, reply) => {
    const { code: c } = z.object({ code }).parse(req.body);
    const user = await app.prisma.user.findUniqueOrThrow({ where: { id: req.setupUserId } });
    if (user.status !== "pending_2fa" || !user.totpSecretEnc) return reply.code(409).send({ error: "totp_not_started" });
    if (!(await consumeTotp(app.prisma, box, user, c))) return reply.code(401).send({ error: "totp_invalid" });
    const active = await app.prisma.user.update({ where: { id: user.id }, data: { status: "active", totpEnabledAt: new Date() } });
    await logEvent(app.prisma, { actorId: user.id, action: "auth.totp_enabled", ...meta(req) });
    await startAdminAge(app, active, req.log, meta(req));
    // An existing account that signed in with SSO while its 2FA was being reset: link and join only now.
    if (req.setupSsoProofId) {
      const p = await app.prisma.ssoProof.findFirst({ where: { id: req.setupSsoProofId, userId: user.id, mode: "login", usedAt: { not: null } } });
      if (p) await linkAndJoin(app, p, active, req.log, meta(req));
    }
    // An account set up from an SSO sign-in: the session counts as that org's SSO (if still a member).
    const sso = req.setupSsoOrgId && await app.prisma.membership.findFirst({ where: { orgId: req.setupSsoOrgId, userId: user.id, status: "active" }, select: { orgId: true } });
    const { accessToken } = await createSession(app, reply, active, meta(req).userAgent, sso ? { ssoOrgIds: [sso.orgId] } : {});
    return authView(app.prisma, app.config, accessToken, active);
  });

  /**
   * TOTP step-up: a session that skipped the authenticator code (trusted IdP MFA) proves the second factor now and may
   * then use every organisation and the private vault.
   */
  app.post("/totp/step-up", { preHandler: app.requireAuth, config: { rateLimit: { max: 10, timeWindow: "1 minute" } } }, async (req, reply) => {
    const { code: c } = z.object({ code }).parse(req.body);
    const user = await app.prisma.user.findUniqueOrThrow({ where: { id: req.auth.userId } });
    const locked = lockedFor(user);
    if (locked) return reply.code(423).send({ error: "locked", retryAfterSeconds: locked });
    if (!(await consumeTotp(app.prisma, box, user, c))) {
      await registerFailure(app.prisma, user.id);
      await logEvent(app.prisma, { actorId: user.id, action: "auth.step_up_failed", ...meta(req) });
      return reply.code(401).send({ error: "totp_invalid" });
    }
    await app.prisma.session.update({ where: { id: req.auth.sessionId }, data: { totpSkippedForOrg: null } });
    await logEvent(app.prisma, { actorId: user.id, action: "auth.step_up", ...meta(req) });
    return { ok: true };
  });

  app.post("/login", { config: { rateLimit: { max: 20, timeWindow: "1 minute" } } }, async (req, reply) => {
    const body = z.object({ email, authKey: z.string().max(4096), code: z.string().max(10).optional(), client: clientSchema }).parse(req.body);
    const user = await app.prisma.user.findUnique({ where: { email: body.email } });
    if (!user || user.status === "disabled" || demoExpired(user)) {
      await argon2.verify(dummyHash, body.authKey).catch(() => false);
      return reply.code(401).send({ error: "invalid_credentials" });
    }
    const locked = lockedFor(user);
    if (locked) return reply.code(423).send({ error: "locked", retryAfterSeconds: locked });

    const fail = async (error: string) => {
      await registerFailure(app.prisma, user.id);
      await logEvent(app.prisma, { actorId: user.id, action: "auth.login_failed", ...meta(req) });
      return reply.code(401).send({ error });
    };

    if (!(await argon2.verify(user.authHash, body.authKey).catch(() => false))) return fail("invalid_credentials");
    // Demo sandbox accounts on a demo instance (both checked by demoSkipsTotp) have no authenticator: no setup, no code.
    if (demoSkipsTotp(app.config, user)) {
      const active = await app.prisma.user.update({ where: { id: user.id }, data: { status: "active", failedLogins: 0, lockedUntil: null } });
      await logEvent(app.prisma, { actorId: user.id, action: "auth.login", ...meta(req), meta: { demo: true } });
      const { accessToken, refreshToken } = await createSession(app, reply, active, meta(req).userAgent, { client: body.client });
      return { ...(await authView(app.prisma, app.config, accessToken, active)), ...(refreshToken ? { refreshToken } : {}) };
    }
    if (user.status === "pending_2fa") return { needsTotpSetup: true, setupToken: await signSetup(app.config, user.id) };
    if (!body.code) return reply.code(401).send({ error: "totp_required" });
    if (!(await consumeTotp(app.prisma, box, user, body.code))) return fail("totp_invalid");

    await app.prisma.user.update({ where: { id: user.id }, data: { failedLogins: 0, lockedUntil: null } });
    await logEvent(app.prisma, { actorId: user.id, action: "auth.login", ...meta(req) });
    const { accessToken, refreshToken } = await createSession(app, reply, user, meta(req).userAgent, { client: body.client });
    return { ...(await authView(app.prisma, app.config, accessToken, user)), ...(refreshToken ? { refreshToken } : {}) };
  });

  /**
   * The refresh token comes from the httpOnly cookie (web) or, only when there is no cookie, from the body (browser
   * extension sessions only). Both share rotation, compare-and-swap, the grace window and reuse detection.
   */
  const presented = (req: { cookies: Record<string, string | undefined>; body: unknown }) => {
    const { refreshToken } = z.object({ refreshToken: z.string().max(512).optional() }).optional().parse(req.body) ?? {};
    const cookie = req.cookies.cv_refresh;
    return cookie ? { token: cookie, fromBody: false } : { token: refreshToken, fromBody: !!refreshToken };
  };

  app.post("/refresh", async (req, reply) => {
    const { token, fromBody } = presented(req);
    const parsed = splitRefresh(token);
    const deny = () => reply.clearCookie("cv_refresh", { path: `${apiPrefix(app.config)}/auth` }).code(401).send({ error: "session_expired" });
    if (!parsed) return deny();
    const load = () => app.prisma.session.findUnique({ where: { id: parsed.sessionId }, include: { user: true } });
    // A body token is only good for an extension session: a cookie session's token never works outside its cookie.
    const valid = (x: Awaited<ReturnType<typeof load>>) => !!x && !x.revokedAt && x.expiresAt >= new Date() && x.user.status === "active" && !demoExpired(x.user) && (!fromBody || x.userAgent === EXTENSION_LABEL);
    let session = await load();
    if (!session || !valid(session)) return deny();
    const h = hashToken(parsed.secret);
    const respond = async (s: NonNullable<typeof session>, refreshToken?: string) =>
      ({ ...(await authView(app.prisma, app.config, await signAccess(app.config, { userId: s.user.id, sessionId: s.id }), s.user)), ...(refreshToken ? { refreshToken } : {}) });
    if (h === session.refreshHash) {
      const refresh = newRefreshToken(session.id);
      const now = new Date();
      const { count } = await app.prisma.session.updateMany({ where: { id: session.id, refreshHash: h, revokedAt: null }, data: { prevRefreshHash: h, rotatedAt: now, refreshHash: refresh.hash, lastSeen: now } });
      if (count === 1) {
        if (fromBody) return respond(session, refresh.token);
        reply.setCookie("cv_refresh", refresh.token, { httpOnly: true, secure: app.config.cookieSecure, sameSite: "strict", path: `${apiPrefix(app.config)}/auth`, maxAge: Math.floor((session.expiresAt.getTime() - Date.now()) / 1000) });
        return respond(session);
      }
      session = await load(); // lost a concurrent rotation; re-evaluate against the fresh row
      if (!session || !valid(session)) return deny();
    }
    if (h === session.prevRefreshHash && session.rotatedAt && Date.now() - session.rotatedAt.getTime() <= REFRESH_GRACE_MS)
      return respond(session); // concurrent request: the caller already holds (or is about to receive) the newer token
    await app.prisma.session.update({ where: { id: session.id }, data: { revokedAt: new Date() } });
    await logEvent(app.prisma, { actorId: session.userId, action: "auth.refresh_reuse", ...meta(req) });
    return deny();
  });

  app.post("/logout", async (req, reply) => {
    const parsed = splitRefresh(presented(req).token);
    // Only the token's holder ends the session: its current (or just-rotated) secret, not merely the session id.
    if (parsed) {
      const h = hashToken(parsed.secret);
      await app.prisma.session.updateMany({ where: { id: parsed.sessionId, revokedAt: null, OR: [{ refreshHash: h }, { prevRefreshHash: h }] }, data: { revokedAt: new Date() } });
    }
    return reply.clearCookie("cv_refresh", { path: `${apiPrefix(app.config)}/auth` }).code(204).send();
  });
};
