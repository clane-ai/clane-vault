import type { FastifyPluginAsync, FastifyReply, FastifyRequest } from "fastify";
import argon2 from "argon2";
import * as oidc from "openid-client";
import { z } from "zod";
import { logEvent } from "../lib/events.js";
import { getEntitlements, PLAN_SELECT } from "../lib/plans.js";
import { lockedFor, registerFailure } from "../lib/lockout.js";
import { displayName, cleanName, nameProblem } from "../lib/names.js";
import { assertSeat, SeatLimitError } from "../lib/seats.js";
import { linkAndJoin } from "../lib/ssoLink.js";
import { secretBox } from "../lib/secretBox.js";
import {
  cleanText, describeOidcError, domainStillVerified, emailDomain, emailVerified, openClientSecret, randomToken, redirectUri, safeReturnTo, sha256,
  SSO_COOKIE, ssoCookiePath, SSO_LOGIN_TTL_MS, SSO_PROOF_MAX_ATTEMPTS, SSO_PROOF_TTL_MS, SSO_SCOPES,
} from "../lib/sso.js";
import { consumeTotp } from "../lib/totp.js";
import { signSetup, splitRefresh } from "../lib/tokens.js";
import { authView, convertOtherInvites, createSession, materialSchema } from "./auth.js";
import { applyPendingGroups } from "../lib/invites.js";
import { notInDemo } from "../lib/demo.js";

const email = z.string().trim().toLowerCase().email().max(254);
const b64 = z.string().regex(/^[A-Za-z0-9_-]+$/).max(4096);
const proofToken = z.string().min(20).max(200);
/** `amr` values that mean the person used a second factor at the identity provider. */
const MFA_AMR = new Set(["mfa", "otp", "hwk", "swk", "fido", "sms"]);
const slug = z.string().trim().toLowerCase().regex(/^[a-z0-9-]{1,80}$/);

/** Codes the sign-in page explains (`/sign-in?sso_error=…`). */
type SsoError = "sso_state" | "sso_denied" | "sso_failed" | "sso_email_unverified" | "sso_domain" | "sso_not_member" | "sso_no_account" | "sso_identity_mismatch" | "sso_org_full";

/**
 * Single sign-on through OpenID Connect (docs/sso.md). The identity provider proves the email address; the master
 * password is still needed (it derives the keys; the server checks the auth key as for any sign-in). Flow:
 * `/discover` → `/start` (state, nonce and PKCE, bound to an httpOnly cookie) → identity provider → `/callback` (code
 * exchange, id_token checks, account mapping) → a single-use proof in the URL fragment of `/sso/complete` →
 * `/proof` (what it is for) → `/login` (master password, maybe TOTP) or `/register` (new account).
 */
export const ssoAuthRoutes: FastifyPluginAsync = async (app) => {
  // Demo mode (docs/demo.md): no single sign-on.
  app.addHook("preHandler", notInDemo(app));
  const box = secretBox(app.config.serverSecret);
  const material = materialSchema(app.config.kdfMinMemoryKiB);
  const meta = (req: FastifyRequest) => ({ ip: req.ip, userAgent: String(req.headers["user-agent"] ?? "").slice(0, 300) });
  const binding = (req: FastifyRequest) => { const v = req.cookies[SSO_COOKIE]; return v && /^[A-Za-z0-9_-]{20,100}$/.test(v) ? sha256(v) : null; };
  const limit = (max: number) => ({ config: { rateLimit: { max, timeWindow: "1 minute" } } });
  /** Orgs with SSO set up for a verified domain. */
  const ssoOrgsFor = async (domain: string) => (await app.prisma.organization.findMany({ where: { sso: { isNot: null }, ssoDomains: { some: { domain, verifiedAt: { not: null } } } },
    select: { ...PLAN_SELECT, slug: true, name: true }, orderBy: { name: "asc" } }))
    // A Team org keeps its SSO row but doesn't offer it.
    .filter((o) => getEntitlements(app.config, o).features.sso).map((o) => ({ slug: o.slug, name: o.name }));

  /** Which organisations offer SSO for this address's domain (verified domains only). Says nothing about accounts. */
  app.post("/discover", limit(30), async (req) => {
    const { email: e } = z.object({ email }).parse(req.body);
    return { orgs: await ssoOrgsFor(emailDomain(e)) };
  });


  /** Authorization requests per organisation per minute (on top of the per-address limit): no flooding one org's table. */
  const START_PER_ORG_PER_MIN = 60;
  const starts = new Map<string, { at: number; n: number }>();
  const orgStartAllowed = (orgId: string) => {
    const now = Date.now(), cur = starts.get(orgId);
    if (!cur || now - cur.at > 60_000) { starts.set(orgId, { at: now, n: 1 }); if (starts.size > 10_000) starts.clear(); return true; }
    cur.n++;
    return cur.n <= START_PER_ORG_PER_MIN;
  };

  /** Starts an authorization request for the org (by slug) and returns the identity provider URL to go to. */
  app.post("/start", limit(20), async (req, reply) => {
    const b = z.object({ org: slug, email: email.optional(), returnTo: z.string().max(512).optional() }).parse(req.body);
    const org = await app.prisma.organization.findUnique({ where: { slug: b.org }, select: { ...PLAN_SELECT, id: true, sso: true } });
    if (!org?.sso || !getEntitlements(app.config, org).features.sso) return reply.code(404).send({ error: "sso_not_configured" });
    if (!orgStartAllowed(org.id)) return reply.code(429).send({ error: "rate_limited" });
    let conf: oidc.Configuration;
    try { conf = await app.oidc.get(org.sso.issuer, org.sso.clientId, openClientSecret(app.settingsBox, org.sso)); }
    catch (e) { req.log.warn({ orgId: org.id, reason: describeOidcError(e) }, "sso discovery failed"); return reply.code(502).send({ error: "sso_unavailable" }); }
    const state = randomToken(), nonce = randomToken(), codeVerifier = oidc.randomPKCECodeVerifier(), bind = randomToken();
    await app.prisma.ssoLogin.create({ data: { stateHash: sha256(state), bindingHash: sha256(bind), orgId: org.id, nonce, codeVerifier, returnTo: safeReturnTo(b.returnTo), expiresAt: new Date(Date.now() + SSO_LOGIN_TTL_MS) } });
    const url = oidc.buildAuthorizationUrl(conf, { redirect_uri: redirectUri(app.config), scope: SSO_SCOPES, response_type: "code", state, nonce,
      code_challenge: await oidc.calculatePKCECodeChallenge(codeVerifier), code_challenge_method: "S256", ...(b.email ? { login_hint: b.email } : {}) });
    // Lax: the identity provider's redirect back is a top-level GET from another site.
    reply.setCookie(SSO_COOKIE, bind, { httpOnly: true, secure: app.config.cookieSecure, sameSite: "lax", path: ssoCookiePath(app.config), maxAge: SSO_LOGIN_TTL_MS / 1000 });
    return { url: url.toString() };
  });

  const fail = async (req: FastifyRequest, reply: FastifyReply, code: SsoError, orgId?: string, detail?: string) => {
    await logEvent(app.prisma, { ...(orgId ? { orgId } : {}), action: "sso.callback_failed", meta: { reason: code, ...(detail ? { detail: cleanText(detail).slice(0, 200) } : {}) }, ...meta(req) });
    return reply.redirect(`${app.config.publicUrl}/sign-in?sso_error=${code}`, 302);
  };

  /** The identity provider's redirect. Never logs the code or tokens (the request logger redacts this URL's query). */
  app.get("/callback", limit(30), async (req, reply) => {
    const q = req.query as Record<string, string | undefined>;
    const bind = binding(req);
    if (!q.state || typeof q.state !== "string" || !bind) return fail(req, reply, "sso_state");
    // Single use: claimed atomically, and only by the browser that started it, within 10 minutes.
    const login = await app.prisma.ssoLogin.findUnique({ where: { stateHash: sha256(q.state) } });
    if (!login || login.bindingHash !== bind || login.expiresAt < new Date()) return fail(req, reply, "sso_state", login?.orgId);
    const claimed = await app.prisma.ssoLogin.updateMany({ where: { id: login.id, usedAt: null }, data: { usedAt: new Date() } });
    if (!claimed.count) return fail(req, reply, "sso_state", login.orgId);
    if (q.error) return fail(req, reply, "sso_denied", login.orgId, String(q.error));
    const sso = await app.prisma.orgSso.findUnique({ where: { orgId: login.orgId } });
    if (!sso) return fail(req, reply, "sso_failed", login.orgId, "sso removed");

    let claims: Record<string, unknown>;
    try {
      const conf = await app.oidc.get(sso.issuer, sso.clientId, openClientSecret(app.settingsBox, sso));
      const current = new URL(redirectUri(app.config));
      for (const [k, v] of Object.entries(q)) if (typeof v === "string") current.searchParams.set(k, v);
      // Checks the state, exchanges the code with the PKCE verifier and validates the id_token: iss, aud, exp, nonce,
      // and its signature against the provider's JWKS (enableNonRepudiationChecks, set at discovery).
      const tokens = await oidc.authorizationCodeGrant(conf, current, { pkceCodeVerifier: login.codeVerifier, expectedState: q.state, expectedNonce: login.nonce, idTokenExpected: true });
      claims = (tokens.claims() ?? {}) as Record<string, unknown>;
    } catch (e) {
      return fail(req, reply, "sso_failed", login.orgId, describeOidcError(e));
    }
    const issuer = String(claims.iss ?? "");
    const subject = typeof claims.sub === "string" ? claims.sub : "";
    const parsed = email.safeParse(claims.email);
    if (!subject || !parsed.success) return fail(req, reply, "sso_email_unverified", login.orgId, "no email claim");
    const e = parsed.data;
    if (!emailVerified(claims, issuer)) return fail(req, reply, "sso_email_unverified", login.orgId);
    const dom = await app.prisma.ssoDomain.findUnique({ where: { orgId_domain: { orgId: login.orgId, domain: emailDomain(e) } }, select: { domain: true } });
    if (!dom) return fail(req, reply, "sso_domain", login.orgId);
    // Anything new (joining, a new account) only for a domain still verified (TXT re-checked at most daily).
    const verifiedNow = () => domainStillVerified(app.prisma, app.ssoDeps, login.orgId, dom.domain);
    // Checked here as well so a full org sends the person back to sign-in with a reason; the join itself checks again.
    const seatFree = () => app.config.billingMode !== "hosted" ? Promise.resolve(true)
      : app.prisma.$transaction((tx) => assertSeat(tx, app.config, login.orgId, 1, e)).then(() => true, (err) => { if (err instanceof SeatLimitError) return false; throw err; });
    // When the IdP says how the person authenticated, trusting its MFA needs a second factor among them.
    const idpMfa = !Array.isArray(claims.amr) || claims.amr.some((m) => MFA_AMR.has(String(m).toLowerCase()));

    // The account: the linked one (by issuer + subject) wins over the email, so a renamed IdP account can't take over another.
    const link = await app.prisma.ssoIdentity.findUnique({ where: { orgId_issuer_subject: { orgId: login.orgId, issuer, subject } }, select: { userId: true } });
    const user = link ? await app.prisma.user.findUnique({ where: { id: link.userId }, select: { id: true, status: true } })
      : await app.prisma.user.findUnique({ where: { email: e }, select: { id: true, status: true } });
    let mode: "login" | "register" = "login", jit = false, inviteId: string | null = null;
    if (user) {
      if (user.status === "disabled") return fail(req, reply, "sso_not_member", login.orgId, "account disabled");
      if (!link) {
        const other = await app.prisma.ssoIdentity.findUnique({ where: { orgId_userId: { orgId: login.orgId, userId: user.id } }, select: { subject: true, issuer: true } });
        if (other) return fail(req, reply, "sso_identity_mismatch", login.orgId);
      }
      const m = await app.prisma.membership.findUnique({ where: { orgId_userId: { orgId: login.orgId, userId: user.id } }, select: { status: true } });
      if (!m) {
        if (!(sso.autoJoin && await verifiedNow())) return fail(req, reply, "sso_not_member", login.orgId);
        if (!(await seatFree())) return fail(req, reply, "sso_org_full", login.orgId);
        jit = true;
      } else if (m.status === "disabled") return fail(req, reply, "sso_not_member", login.orgId, "membership disabled");
    } else {
      // New accounts only for a verified domain: the identity provider is then authoritative for the address.
      const inv = await app.prisma.invite.findFirst({ where: { orgId: login.orgId, email: e, acceptedAt: null, expiresAt: { gt: new Date() } }, orderBy: { createdAt: "desc" }, select: { id: true } });
      if (!inv && !sso.autoJoin) return fail(req, reply, "sso_no_account", login.orgId);
      if (!(await verifiedNow())) return fail(req, reply, "sso_no_account", login.orgId, "domain not verified");
      if (!inv && !(await seatFree())) return fail(req, reply, "sso_org_full", login.orgId);
      mode = "register"; inviteId = inv?.id ?? null; jit = !inv;
    }
    const proof = randomToken();
    const rawName = typeof claims.name === "string" ? cleanName(claims.name) : "";
    await app.prisma.ssoProof.create({ data: { tokenHash: sha256(proof), bindingHash: bind, orgId: login.orgId, mode, userId: user?.id ?? null, email: e, issuer, subject,
      nameHint: rawName && !nameProblem(rawName) ? rawName : null, jit, idpMfa, inviteId, returnTo: login.returnTo, expiresAt: new Date(Date.now() + SSO_PROOF_TTL_MS) } });
    await logEvent(app.prisma, { orgId: login.orgId, ...(user ? { targetUserId: user.id } : {}), action: "sso.callback", meta: { mode, jit }, ...meta(req) });
    // In the fragment: never sent to a server, so it stays out of logs and Referer headers.
    const frag = new URLSearchParams({ proof, ...(login.returnTo !== "/" ? { returnTo: login.returnTo } : {}) });
    return reply.redirect(`${app.config.publicUrl}/sso/complete#${frag.toString()}`, 302);
  });

  /** A live proof for this browser (same cookie), or null. Does not use it up. */
  async function liveProof(req: FastifyRequest, token: string) {
    const bind = binding(req);
    const p = await app.prisma.ssoProof.findUnique({ where: { tokenHash: sha256(token) }, include: { org: { select: { id: true, name: true, slug: true, adminRecoveryEnabled: true, sso: { select: { trustIdpMfa: true, autoJoin: true } } } } } });
    if (!p || !bind || p.bindingHash !== bind || p.usedAt || p.expiresAt < new Date() || p.attempts >= SSO_PROOF_MAX_ATTEMPTS) return null;
    return p;
  }
  type Proof = NonNullable<Awaited<ReturnType<typeof liveProof>>>;
  /**
   * Whether this sign-in may skip the authenticator code (read at use time): the org trusts its IdP's MFA, the IdP
   * reported a second factor (when it says), the address is in a verified domain, it isn't a just-in-time join, and
   * the account's only active membership is this org (a skipped code must not open other organisations).
   */
  async function skipsTotp(p: Proof): Promise<boolean> {
    if (!p.org.sso?.trustIdpMfa || !p.userId || p.jit || !p.idpMfa) return false;
    if (!(await app.prisma.ssoDomain.findFirst({ where: { orgId: p.orgId, domain: emailDomain(p.email), verifiedAt: { not: null } }, select: { id: true } }))) return false;
    const active = await app.prisma.membership.findMany({ where: { userId: p.userId, status: "active" }, select: { orgId: true } });
    return active.length === 1 && active[0]!.orgId === p.orgId;
  }
  /** Just-in-time joins are re-checked when used: auto-join still on and the domain still verified. */
  const jitStillAllowed = async (p: Proof) => !!p.org.sso?.autoJoin && await domainStillVerified(app.prisma, app.ssoDeps, p.orgId, emailDomain(p.email));
  const gone = (reply: FastifyReply) => reply.code(410).send({ error: "sso_proof_invalid" });

  app.post("/proof", limit(30), async (req, reply) => {
    const { proof } = z.object({ proof: proofToken }).parse(req.body);
    const p = await liveProof(req, proof);
    if (!p) return gone(reply);
    const base = { mode: p.mode, email: p.email, org: { name: p.org.name, slug: p.org.slug }, returnTo: p.returnTo };
    if (p.mode === "register") return { ...base, name: p.nameHint, adminRecoveryEnabled: p.org.adminRecoveryEnabled, joins: p.jit ? "member" : "invite" };
    // The account's own email and KDF parameters: the IdP's address may differ (renamed), and the key derivation
    // needs the account's salt.
    const u = await app.prisma.user.findUnique({ where: { id: p.userId! }, select: { email: true, kdfSalt: true, kdfParams: true } });
    if (!u) return gone(reply);
    const k = u.kdfParams as { alg: string; m: number; t: number; p: number };
    return { ...base, accountEmail: u.email, kdf: { kdfSalt: u.kdfSalt, kdfParams: { alg: k.alg, m: k.m, t: k.t, p: k.p } }, totpSkipped: await skipsTotp(p), joins: p.jit ? "member" : null };
  });

  /** Counts a try against the proof first, atomically (5, then it's burned); false when none is left. */
  const countTry = async (id: string) => (await app.prisma.ssoProof.updateMany({ where: { id, usedAt: null, attempts: { lt: SSO_PROOF_MAX_ATTEMPTS }, expiresAt: { gt: new Date() } }, data: { attempts: { increment: 1 } } })).count === 1;
  const refundTry = (id: string) => app.prisma.ssoProof.updateMany({ where: { id, attempts: { gt: 0 } }, data: { attempts: { decrement: 1 } } });
  async function badPassword(req: FastifyRequest, reply: FastifyReply, p: Proof, error: string) {
    if (p.userId) { await registerFailure(app.prisma, p.userId); await logEvent(app.prisma, { orgId: p.orgId, actorId: p.userId, action: "auth.login_failed", meta: { via: "sso" }, ...meta(req) }); }
    return reply.code(401).send({ error });
  }

  /** SSO sign-in, finished with the master password's auth key (and an authenticator code unless the org trusts its IdP's MFA). */
  app.post("/login", limit(20), async (req, reply) => {
    const b = z.object({ proof: proofToken, authKey: z.string().max(4096), code: z.string().max(10).optional() }).parse(req.body);
    const p = await liveProof(req, b.proof);
    if (!p || p.mode !== "login" || !p.userId) return gone(reply);
    const user = await app.prisma.user.findUnique({ where: { id: p.userId } });
    if (!user || user.status === "disabled") return gone(reply);
    const locked = lockedFor(user);
    if (locked) return reply.code(423).send({ error: "locked", retryAfterSeconds: locked });
    if (p.jit && !(await jitStillAllowed(p))) return reply.code(403).send({ error: "sso_not_member" });
    if (!(await countTry(p.id))) return gone(reply);
    if (!(await argon2.verify(user.authHash, b.authKey).catch(() => false))) return badPassword(req, reply, p, "invalid_credentials");
    if (user.status === "pending_2fa") {
      // The identity link and any just-in-time join wait until the new authenticator is set up (totp/verify).
      if (!(await useProof(p.id))) return gone(reply);
      return { needsTotpSetup: true, setupToken: await signSetup(app.config, user.id, { ssoOrgId: p.orgId, ssoProofId: p.id }) };
    }
    const skip = await skipsTotp(p);
    if (!skip) {
      if (!b.code) { await refundTry(p.id); return reply.code(401).send({ error: "totp_required" }); }
      if (!(await consumeTotp(app.prisma, box, user, b.code))) return badPassword(req, reply, p, "totp_invalid");
    }
    if (!(await useProof(p.id))) return gone(reply);
    await app.prisma.user.update({ where: { id: user.id }, data: { failedLogins: 0, lockedUntil: null } });
    await linkAndJoin(app, p, user, req.log, meta(req));
    await endPreviousSession(req, user.id);
    await logEvent(app.prisma, { orgId: p.orgId, actorId: user.id, action: "auth.login", meta: { via: "sso", totpSkipped: skip }, ...meta(req) });
    const { accessToken } = await createSession(app, reply, user, meta(req).userAgent, { ssoOrgIds: [p.orgId], ...(skip ? { totpSkippedForOrg: p.orgId } : {}) });
    clearCookie(reply);
    return { ...(await authView(app.prisma, app.config, accessToken, user)), returnTo: p.returnTo };
  });

  /** A new account through SSO (verified domain: just-in-time, or an open invite). No email code: the IdP verified the address. */
  app.post("/register", limit(10), async (req, reply) => {
    const b = z.object({ proof: proofToken, name: displayName, authKey: b64, material }).parse(req.body);
    const p = await liveProof(req, b.proof);
    if (!p || p.mode !== "register") return gone(reply);
    if (await app.prisma.user.findUnique({ where: { email: p.email }, select: { id: true } })) return reply.code(409).send({ error: "account_exists" });
    const inv = p.inviteId ? await app.prisma.invite.findFirst({ where: { id: p.inviteId, acceptedAt: null, expiresAt: { gt: new Date() } } }) : null;
    if (p.inviteId && !inv) return gone(reply);
    // Re-checked at use time: auto-join still on (just-in-time) and the domain still verified.
    if (p.jit ? !(await jitStillAllowed(p)) : !(await domainStillVerified(app.prisma, app.ssoDeps, p.orgId, emailDomain(p.email)))) return reply.code(403).send({ error: "sso_no_account" });
    if (!(await useProof(p.id))) return gone(reply);
    const authHash = await argon2.hash(b.authKey, { type: argon2.argon2id });
    let user;
    try {
      user = await app.prisma.$transaction(async (tx) => {
        const now = new Date();
        await assertSeat(tx, app.config, p.orgId, 1, p.email);
        if (inv) await tx.invite.update({ where: { id: inv.id }, data: { acceptedAt: now, emailCodeHash: null } });
        const u = await tx.user.create({ data: {
          email: p.email, name: b.name, status: "pending_2fa", authHash, instanceAdmin: inv?.instanceAdmin ?? false,
          kdfSalt: b.material.kdfSalt, kdfParams: b.material.kdfParams, wrappedUserKey: b.material.wrappedUserKey,
          publicKey: b.material.publicKey, wrappedPrivateKey: b.material.wrappedPrivateKey,
        } });
        const hasOwner = inv?.role === "owner" && !!(await tx.membership.findFirst({ where: { orgId: p.orgId, role: "owner" }, select: { id: true } }));
        await tx.membership.create({ data: { orgId: p.orgId, userId: u.id, role: inv ? (hasOwner ? "admin" : inv.role) : "member", status: "active", invitedById: inv?.invitedById ?? null, joinedAt: now } });
        await applyPendingGroups(tx, p.orgId, u.id, p.email);
        await convertOtherInvites(tx, p.email, u.id, p.orgId, now);
        await tx.ssoIdentity.create({ data: { orgId: p.orgId, userId: u.id, issuer: p.issuer, subject: p.subject, email: p.email } });
        return u;
      });
    } catch (e) {
      // Two sign-ups for the same address at once: the second loses the unique constraint.
      if ((e as { code?: string }).code === "P2002") return reply.code(409).send({ error: "account_exists" });
      throw e;
    }
    await logEvent(app.prisma, { orgId: p.orgId, actorId: user.id, action: "auth.register", meta: { via: "sso", jit: p.jit }, ...meta(req) });
    if (p.jit) await logEvent(app.prisma, { orgId: p.orgId, actorId: user.id, action: "sso.jit_join", targetUserId: user.id });
    clearCookie(reply);
    return reply.code(201).send({ setupToken: await signSetup(app.config, user.id, { ssoOrgId: p.orgId }), returnTo: p.returnTo });
  });

  const useProof = async (id: string) => (await app.prisma.ssoProof.updateMany({ where: { id, usedAt: null }, data: { usedAt: new Date() } })).count === 1;
  const clearCookie = (reply: FastifyReply) => reply.clearCookie(SSO_COOKIE, { path: ssoCookiePath(app.config) });

  /** The browser's previous session (same account) ends: the SSO sign-in replaces it. */
  async function endPreviousSession(req: FastifyRequest, userId: string) {
    const prev = splitRefresh(req.cookies.cv_refresh);
    if (prev) await app.prisma.session.updateMany({ where: { id: prev.sessionId, userId, revokedAt: null }, data: { revokedAt: new Date() } });
  }
};
