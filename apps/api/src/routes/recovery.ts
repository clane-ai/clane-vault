import type { FastifyPluginAsync } from "fastify";
import argon2 from "argon2";
import { z } from "zod";
import { secretBox } from "../lib/secretBox.js";
import { logEvent } from "../lib/events.js";
import { lockedFor, registerFailure } from "../lib/lockout.js";
import { recoveryRequestedEmail, recoveryUsedEmail, sendEmail } from "../lib/email.js";
import { adminRecoveryEnabled, adminRecoveryOn, adminSinceIn, BURN_REQUEST, expireOpenRequests, hashSecretValue, linkIsOnlyFactor, approverOldEnough, MAX_PROOF_ATTEMPTS, OPEN, resetDelayLeft, secretValueMatches, twoPersonOk } from "../lib/recovery.js";
import { PLAN_SELECT } from "../lib/plans.js";
import { consumeTotp } from "../lib/totp.js";
import { signRecovery, signSetup, verifyToken } from "../lib/tokens.js";
import { authView, createSession, kdfView, materialView } from "./auth.js";
import { lockUser } from "../lib/orgs.js";
import { ACCT_PREFIX, currentKey, recoverableKey } from "../lib/membershipKeys.js";
import { readOnlyInDemo } from "../lib/demo.js";

/** A 256-bit value in base64url (43 chars): recovery-kit auth values and admin-link proofs. */
const secret256 = z.string().regex(/^[A-Za-z0-9_-]{43}$/);
const b64 = z.string().regex(/^[A-Za-z0-9_-]+$/).max(4096);
const envelope = z.string().max(16384);
const wrappedV1 = z.string().regex(/^v1\.[A-Za-z0-9_-]+$/).max(1024);
const email = z.string().trim().toLowerCase().email().max(254);
const optCode = z.string().max(10).optional();

class RecoveryGone extends Error {}
class TwoPersonRefused extends Error {}
class ApproverTooNew extends Error {}
class WrongKey extends Error {}

/**
 * Public recovery endpoints (docs/recovery.md), under /api/v1/auth/recovery. Every step that touches an account
 * answers the same way for unknown emails, accounts without a kit and wrong codes, and wrong proofs count toward
 * the account's sign-in lockout.
 */
export const recoveryAuthRoutes: FastifyPluginAsync = async (app) => {
  // Demo mode (docs/demo.md): sandbox accounts have no authenticator and a password nobody knows, so recovery (the only
  // way to change a master password) is closed; GET /options still answers.
  app.addHook("preHandler", readOnlyInDemo(app));
  const box = secretBox(app.config.serverSecret);
  const material = z.object({
    kdfSalt: b64, kdfParams: z.object({ alg: z.literal("argon2id"), m: z.number().int().min(app.config.kdfMinMemoryKiB).max(1048576), t: z.number().int().min(1).max(10), p: z.number().int().min(1).max(4) }),
    wrappedUserKey: envelope, publicKey: b64, wrappedPrivateKey: envelope,
  });
  const meta = (req: { ip: string; headers: Record<string, unknown> }) => ({ ip: req.ip, userAgent: String(req.headers["user-agent"] ?? "").slice(0, 300) });
  const totpOk = (user: { id: string; totpSecretEnc: string | null }, code: string | undefined) => consumeTotp(app.prisma, box, user, code);
  const delayHours = () => app.config.adminRecoveryResetDelayHours ?? 24;
  const minAgeDays = () => app.config.adminRecoveryApproverMinAgeDays ?? 7;
  const limit = (max: number) => ({ config: { rateLimit: { max, timeWindow: "1 minute" } } });

  /** Whether "Ask an admin to reset my password" exists here (any organisation has it on), so it says nothing about any account. */
  app.get("/options", async () => ({ adminRecoveryEnabled: await adminRecoveryEnabled(app.prisma, app.config) }));

  /** Recovery kit: email + kit auth value (+ fresh 2FA) → the wrapped user key and a short recovery token. */
  app.post("/kit", limit(10), async (req, reply) => {
    const body = z.object({ email, recoveryAuth: secret256, code: optCode }).parse(req.body);
    const user = await app.prisma.user.findUnique({ where: { email: body.email } });
    const invalid = () => reply.code(401).send({ error: "invalid_recovery" });
    if (!user || user.status === "disabled") { secretValueMatches(null, body.recoveryAuth); return invalid(); }
    const locked = lockedFor(user);
    if (locked) return reply.code(423).send({ error: "locked", retryAfterSeconds: locked });
    if (!user.recoveryCreatedAt || !user.recoveryWrap || !secretValueMatches(user.recoveryAuthHash, body.recoveryAuth)) {
      await registerFailure(app.prisma, user.id);
      await logEvent(app.prisma, { actorId: user.id, action: "auth.recovery_failed", ...meta(req) });
      return invalid();
    }
    // Lost the authenticator too: after an admin's 2FA reset, the kit lets them set up a new one first (docs/recovery.md).
    if (user.status === "pending_2fa") return { needsTotpSetup: true, setupToken: await signSetup(app.config, user.id) };
    if (!body.code) return reply.code(401).send({ error: "totp_required" });
    if (!(await totpOk(user, body.code))) {
      await registerFailure(app.prisma, user.id);
      await logEvent(app.prisma, { actorId: user.id, action: "auth.recovery_failed", ...meta(req) });
      return reply.code(401).send({ error: "totp_invalid" });
    }
    await logEvent(app.prisma, { actorId: user.id, action: "auth.recovery_kit_verified", ...meta(req) });
    return {
      recoveryToken: await signRecovery(app.config, user.id, { via: "kit", ref: String(user.recoveryCreatedAt.getTime()) }),
      userId: user.id, recoveryWrap: user.recoveryWrap, material: materialView(user),
    };
  });

  /**
   * "Ask an admin to reset my password". Always the same answer. One request per organisation where the account is
   * active, the policy is on and the membership is recoverable (current membership key with an escrow): each org's
   * admins can only ever restore what the person holds in that org (docs/design/2026-10-08-per-org-keypairs.md).
   */
  app.post("/admin/request", limit(5), async (req, reply) => {
    const { email: e } = z.object({ email }).parse(req.body);
    const done = () => reply.code(202).send({ ok: true });
    const user = await app.prisma.user.findUnique({ where: { email: e }, select: { id: true, status: true, email: true } });
    if (!user || user.status === "disabled") return done();
    const made = await app.prisma.$transaction(async (tx) => {
      await lockUser(tx, user.id);
      const ms = (await tx.membership.findMany({ where: { userId: user.id, status: "active", org: { adminRecoveryEnabled: true } }, select: { orgId: true, org: { select: { ...PLAN_SELECT, name: true } } } })).filter((m) => adminRecoveryOn(app.config, { ...m.org, adminRecoveryEnabled: true }));
      const out: { id: string; orgId: string; orgName: string }[] = [];
      for (const m of ms) {
        // The current key (a reset), or one a scoped reset archived (restored later, under the current password).
        const current = await recoverableKey(tx, m.orgId, user.id);
        const keys = current ? [current] : (await tx.membershipKey.findMany({ where: { orgId: m.orgId, userId: user.id, state: "archived" }, select: { publicKey: true } })).map((k) => k.publicKey);
        if (!keys.length || !(await tx.membershipEscrow.findFirst({ where: { orgId: m.orgId, userId: user.id, memberPublicKey: { in: keys } }, select: { id: true } }))) continue;
        if (await tx.recoveryRequest.findFirst({ where: { userId: user.id, orgId: m.orgId, ...OPEN }, select: { id: true } })) continue;
        const r = await tx.recoveryRequest.create({ data: { userId: user.id, orgId: m.orgId } });
        out.push({ id: r.id, orgId: m.orgId, orgName: m.org.name });
      }
      return out;
    });
    for (const r of made) {
      await logEvent(app.prisma, { orgId: r.orgId, action: "recovery.request_created", targetUserId: user.id, meta: { requestId: r.id }, ...meta(req) });
      void sendEmail(app.mail, user.email, recoveryRequestedEmail(await app.brand.productName(), r.orgName), req.log);
    }
    return done();
  });

  /**
   * Admin recovery link: request id + proof from the fragment secret (+ fresh 2FA) → the membership key wrapped under
   * the link secret. `mode`: "reset" (a new master password and new account keys; only this org's membership comes
   * back) or "restore" (the account was reset since: the membership is restored under the current master password).
   */
  app.post("/admin/:id", limit(10), async (req, reply) => {
    const { id } = z.object({ id: z.string().uuid() }).parse(req.params);
    const body = z.object({ proof: secret256, code: optCode }).parse(req.body);
    const invalid = () => reply.code(401).send({ error: "invalid_link" });
    const r = await app.prisma.recoveryRequest.findUnique({ where: { id }, include: { user: true } });
    if (!r || r.status !== "approved" || !r.expiresAt || r.expiresAt <= new Date() || !r.proofHash || !r.wrappedMembershipKey || !r.memberPublicKey || !(await adminRecoveryEnabled(app.prisma, app.config, r.orgId))) {
      secretValueMatches(null, body.proof); return invalid();
    }
    /** Wrong proofs and wrong 2FA codes both count against the link; five burn it. */
    const strike = async () => {
      const u = await app.prisma.recoveryRequest.update({ where: { id }, data: { attempts: { increment: 1 } }, select: { attempts: true } });
      if (u.attempts >= MAX_PROOF_ATTEMPTS) {
        const n = await app.prisma.recoveryRequest.updateMany({ where: { id, ...OPEN }, data: { status: "expired", ...BURN_REQUEST } });
        if (n.count) await logEvent(app.prisma, { orgId: r.orgId, action: "recovery.request_expired", targetUserId: r.userId, meta: { requestId: id, reason: "too_many_attempts" }, ...meta(req) });
      }
    };
    if (!secretValueMatches(r.proofHash, body.proof)) { await strike(); return invalid(); }
    const user = r.user;
    if (user.status === "disabled") return invalid();
    const mk = await app.prisma.membershipKey.findFirst({ where: { orgId: r.orgId, userId: user.id, publicKey: r.memberPublicKey, state: { in: ["current", "retiring", "archived"] } } });
    if (!mk || !(await app.prisma.membership.findFirst({ where: { orgId: r.orgId, userId: user.id, status: "active" }, select: { id: true } }))) return invalid();
    const mode = mk.state === "archived" || mk.userKeyGen !== user.userKeyGen ? "restore" as const : "reset" as const;
    const locked = lockedFor(user);
    if (locked) return reply.code(423).send({ error: "locked", retryAfterSeconds: locked });
    if (linkIsOnlyFactor(user, r)) {
      // 2FA was reset: the link alone would take over the account. Two different admins, and a waiting period.
      // The approver's admin age in the request's org (null if they are no longer an admin there).
      const approver = await adminSinceIn(app.prisma, r.orgId, r.approvedBy);
      if (twoPersonOk(user, r) && !approverOldEnough(approver, user, minAgeDays())) {
        await logEvent(app.prisma, { actorId: user.id, action: "recovery.two_person_refused", meta: { requestId: id, approvedBy: r.approvedBy, reason: "approver_too_new" }, ...meta(req) });
        return reply.code(403).send({ error: "approver_too_new" });
      }
      if (!twoPersonOk(user, r)) {
        await logEvent(app.prisma, { actorId: user.id, action: "recovery.two_person_refused", meta: { requestId: id, approvedBy: r.approvedBy, totpResetBy: user.totpResetBy }, ...meta(req) });
        return reply.code(403).send({ error: "two_person_required" });
      }
      const wait = resetDelayLeft(user, delayHours());
      if (wait > 0) return reply.code(423).send({ error: "reset_delay", retryAfterSeconds: wait });
    }
    if (user.status === "pending_2fa") return { needsTotpSetup: true, setupToken: await signSetup(app.config, user.id), email: user.email };
    if (!body.code) return reply.code(401).send({ error: "totp_required", email: user.email });
    if (!(await totpOk(user, body.code))) {
      await registerFailure(app.prisma, user.id);
      await strike();
      await logEvent(app.prisma, { actorId: user.id, action: "auth.recovery_failed", meta: { requestId: id }, ...meta(req) });
      return reply.code(401).send({ error: "totp_invalid", email: user.email });
    }
    const org = await app.prisma.organization.findUniqueOrThrow({ where: { id: r.orgId }, select: { name: true } });
    // Never the wrapped user key: whoever holds the link (its approver knows the secret; after a 2FA reset, two admins can
    // pass the 2FA step) could otherwise guess the current master password offline and open the whole account, not
    // just this org. A reset makes new keys; a restore gets the material only after the current password checks out
    // (POST /restore-membership/material). The KDF parameters are public anyway (prelogin).
    return {
      recoveryToken: await signRecovery(app.config, user.id, { via: "admin", ref: r.id }),
      userId: user.id, email: user.email, mode, orgId: r.orgId, orgName: org.name,
      memberPublicKey: r.memberPublicKey, wrappedMembershipKey: r.wrappedMembershipKey,
      ...(mode === "restore" ? { kdf: { kdfSalt: user.kdfSalt, kdfParams: kdfView(user.kdfParams) } } : {}),
    };
  });

  /**
   * Sets the new master password after a kit or admin-link check, consumes the kit or the request, signs out everywhere
   * and starts one new session.
   * - Kit: only the password-derived parts change (salt, KDF, auth hash, wrapped user key); the key pair stays.
   * - Admin link (scoped reset, docs/design/2026-10-08-per-org-keypairs.md §6.2): new account keys. The old
   *   account material and kit go to the archive, the request's membership key is re-wrapped under the new user key,
   *   every other membership key is archived, and rows sealed to the old account key are marked as such.
   */
  app.post("/finish", limit(10), async (req, reply) => {
    let tok: Awaited<ReturnType<typeof verifyToken>>;
    try { tok = await verifyToken(app.config, req.headers.authorization?.replace(/^Bearer /, "") ?? "", "recovery"); }
    catch { return reply.code(401).send({ error: "unauthorized" }); }
    const via = tok.via === "kit" || tok.via === "admin" ? tok.via : null;
    if (!via || !tok.ref) return reply.code(401).send({ error: "unauthorized" });
    const body = z.object({ authKey: b64, material, membership: z.object({ publicKey: b64, wrappedPrivateKey: wrappedV1 }).optional() }).parse(req.body);
    const user = await app.prisma.user.findUnique({ where: { id: tok.sub } });
    if (!user || user.status !== "active") return reply.code(401).send({ error: "unauthorized" });
    const sameKeys = body.material.publicKey === user.publicKey && body.material.wrappedPrivateKey === user.wrappedPrivateKey;
    if (via === "kit" && !sameKeys) return reply.code(400).send({ error: "key_mismatch" });
    // A scoped reset always brings a new account key pair (the old user key is unknown) and the restored membership key.
    if (via === "admin" && (body.material.publicKey === user.publicKey || !body.membership)) return reply.code(400).send({ error: "key_mismatch" });
    const now = new Date();
    const credentials = {
      authHash: await argon2.hash(body.authKey, { type: argon2.argon2id }),
      kdfSalt: body.material.kdfSalt, kdfParams: body.material.kdfParams, wrappedUserKey: body.material.wrappedUserKey,
      failedLogins: 0, lockedUntil: null,
    };
    let approvedBy: string | null = null, orgOfRequest: string | null = null;
    try {
      await app.prisma.$transaction(async (tx) => {
        if (via === "kit") {
          const ref = Number(tok.ref);
          if (!Number.isFinite(ref)) throw new RecoveryGone();
          // The kit is used up: it only ever works once.
          const n = await tx.user.updateMany({ where: { id: user.id, status: "active", recoveryCreatedAt: new Date(ref) },
            data: { ...credentials, recoveryWrap: null, recoveryAuthHash: null, recoveryCreatedAt: null } });
          if (n.count !== 1) throw new RecoveryGone();
        } else {
          await lockUser(tx, user.id);
          const fresh = await tx.user.findUniqueOrThrow({ where: { id: user.id } });
          const r = await tx.recoveryRequest.findUnique({ where: { id: tok.ref }, select: { userId: true, status: true, expiresAt: true, approvedBy: true, approvedAt: true, orgId: true, memberPublicKey: true } });
          if (!r || r.userId !== user.id || r.status !== "approved" || !r.expiresAt || r.expiresAt <= now || !r.memberPublicKey) throw new RecoveryGone();
          if (linkIsOnlyFactor(fresh, r) && !twoPersonOk(fresh, r)) throw new TwoPersonRefused();
          if (linkIsOnlyFactor(fresh, r) && !approverOldEnough(await adminSinceIn(tx, r.orgId, r.approvedBy), fresh, minAgeDays()))
            throw new ApproverTooNew();
          // The restored membership: the very key the admin's escrow held, still a key of the account's current generation.
          const mk = await tx.membershipKey.findFirst({ where: { orgId: r.orgId, userId: user.id, publicKey: r.memberPublicKey, state: { in: ["current", "retiring"] }, userKeyGen: fresh.userKeyGen } });
          if (!mk || body.membership!.publicKey !== mk.publicKey) throw new WrongKey();
          const n = await tx.recoveryRequest.updateMany({ where: { id: tok.ref, userId: user.id, status: "approved", expiresAt: { gt: now } },
            data: { status: "used", usedAt: now, ...BURN_REQUEST } });
          if (n.count !== 1) throw new RecoveryGone();
          approvedBy = r.approvedBy ?? null; orgOfRequest = r.orgId;
          const oldGen = fresh.userKeyGen, gen = oldGen + 1;
          // What the reset leaves behind (the "restore later" banner is skipped when nothing was lost).
          const privateItems = (await tx.recordAccess.count({ where: { holderType: "user", holderId: user.id, permission: "owner", record: { OR: [{ folderId: null }, { folder: { kind: "private" } }] } } }))
            + (await tx.folder.count({ where: { ownerId: user.id, kind: "private" } }));
          const otherOrgs = await tx.membershipKey.count({ where: { userId: user.id, userKeyGen: oldGen, state: { in: ["current", "retiring"] }, orgId: { not: r.orgId } } });
          await tx.accountKeyArchive.create({ data: { userId: user.id, userKeyGen: oldGen, kdfSalt: fresh.kdfSalt, kdfParams: fresh.kdfParams as object, wrappedUserKey: fresh.wrappedUserKey,
            publicKey: fresh.publicKey, wrappedPrivateKey: fresh.wrappedPrivateKey, recoveryWrap: fresh.recoveryWrap, privateItems, otherOrgs,
            // The archive opens only for the old password or the old kit (checked like a sign-in): never on a session alone.
            authHash: fresh.authHash, recoveryAuthHash: fresh.recoveryWrap ? fresh.recoveryAuthHash : null } });
          await tx.user.update({ where: { id: user.id }, data: { ...credentials, publicKey: body.material.publicKey, wrappedPrivateKey: body.material.wrappedPrivateKey,
            userKeyGen: gen, recoveryWrap: null, recoveryAuthHash: null, recoveryCreatedAt: null } });
          // Restored, and rotated on the next unlock (an admin saw it).
          await tx.membershipKey.update({ where: { id: mk.id }, data: { wrappedPrivateKey: body.membership!.wrappedPrivateKey, userKeyGen: gen, escrowOpenedAt: mk.escrowOpenedAt ?? now } });
          await tx.membershipKey.updateMany({ where: { userId: user.id, userKeyGen: oldGen }, data: { state: "archived" } });
          // Rows sealed to the old account key: only the archive's keys open them now.
          const acct = ACCT_PREFIX + fresh.publicKey;
          await tx.folderMember.updateMany({ where: { userId: user.id, sealedTo: null }, data: { sealedTo: acct } });
          await tx.recordAccess.updateMany({ where: { holderType: "user", holderId: user.id, permission: { not: "owner" }, sealedTo: null }, data: { sealedTo: acct } });
          // Owner rows in team folders are rebuilt from the folder rows by the client, per org.
          await tx.membership.updateMany({ where: { userId: user.id }, data: { keysRepairedGen: oldGen } });
        }
        await expireOpenRequests(tx, { userId: user.id, ...(via === "admin" ? { orgId: orgOfRequest! } : {}) });
        await tx.session.updateMany({ where: { userId: user.id, revokedAt: null }, data: { revokedAt: now } });
      });
    } catch (e) {
      if (e instanceof RecoveryGone) return reply.code(410).send({ error: "recovery_used" });
      if (e instanceof TwoPersonRefused) return reply.code(403).send({ error: "two_person_required" });
      if (e instanceof ApproverTooNew) return reply.code(403).send({ error: "approver_too_new" });
      if (e instanceof WrongKey) return reply.code(409).send({ error: "key_mismatch" });
      throw e;
    }
    await logEvent(app.prisma, { orgId: orgOfRequest ?? undefined, actorId: user.id, action: via === "kit" ? "auth.recovery_kit_used" : "auth.admin_recovery_used",
      ...(via === "admin" ? { meta: { requestId: tok.ref, approvedBy, scope: "membership" } } : {}), ...meta(req) });
    void sendEmail(app.mail, user.email, recoveryUsedEmail(await app.brand.productName(), via, now), req.log);
    const fresh = await app.prisma.user.findUniqueOrThrow({ where: { id: user.id } });
    const { accessToken } = await createSession(app, reply, fresh, meta(req).userAgent);
    return authView(app.prisma, app.config, accessToken, fresh);
  });

  /** Checks the current master password (auth key) of a recovery-token holder: wrong ones count toward the lockout. */
  async function currentPasswordOk(user: { id: string; authHash: string }, authKey: string, ref: string, ip: Parameters<typeof meta>[0]) {
    if (await argon2.verify(user.authHash, authKey).catch(() => false)) return true;
    await registerFailure(app.prisma, user.id);
    await logEvent(app.prisma, { actorId: user.id, action: "auth.reauth_failed", meta: { requestId: ref }, ...meta(ip) });
    return false;
  }

  /**
   * Restore mode, step 1: the account material (wrapped user key) for the current master password, so the page can
   * re-wrap the restored membership key. Only after the auth key checks out, like a sign-in.
   */
  app.post("/restore-membership/material", limit(10), async (req, reply) => {
    let tok: Awaited<ReturnType<typeof verifyToken>>;
    try { tok = await verifyToken(app.config, req.headers.authorization?.replace(/^Bearer /, "") ?? "", "recovery"); }
    catch { return reply.code(401).send({ error: "unauthorized" }); }
    if (tok.via !== "admin" || !tok.ref) return reply.code(401).send({ error: "unauthorized" });
    const { authKey } = z.object({ authKey: b64 }).parse(req.body);
    const user = await app.prisma.user.findUnique({ where: { id: tok.sub } });
    if (!user || user.status !== "active") return reply.code(401).send({ error: "unauthorized" });
    const locked = lockedFor(user);
    if (locked) return reply.code(423).send({ error: "locked", retryAfterSeconds: locked });
    const r = await app.prisma.recoveryRequest.findUnique({ where: { id: tok.ref }, select: { userId: true, status: true, expiresAt: true } });
    if (!r || r.userId !== user.id || r.status !== "approved" || !r.expiresAt || r.expiresAt <= new Date()) return reply.code(410).send({ error: "recovery_used" });
    if (!(await currentPasswordOk(user, authKey, tok.ref, req))) return reply.code(401).send({ error: "invalid_credentials" });
    return { material: materialView(user) };
  });

  /**
   * Restores a membership whose key an earlier scoped reset archived, with that org's admin link (proof and 2FA already
   * checked: recovery token) and the current master password. No password change, no sign-out.
   */
  app.post("/restore-membership", limit(10), async (req, reply) => {
    let tok: Awaited<ReturnType<typeof verifyToken>>;
    try { tok = await verifyToken(app.config, req.headers.authorization?.replace(/^Bearer /, "") ?? "", "recovery"); }
    catch { return reply.code(401).send({ error: "unauthorized" }); }
    if (tok.via !== "admin" || !tok.ref) return reply.code(401).send({ error: "unauthorized" });
    const body = z.object({ authKey: b64, publicKey: b64, wrappedPrivateKey: wrappedV1 }).parse(req.body);
    const user = await app.prisma.user.findUnique({ where: { id: tok.sub } });
    if (!user || user.status !== "active") return reply.code(401).send({ error: "unauthorized" });
    const locked = lockedFor(user);
    if (locked) return reply.code(423).send({ error: "locked", retryAfterSeconds: locked });
    if (!(await currentPasswordOk(user, body.authKey, tok.ref, req))) return reply.code(401).send({ error: "invalid_credentials" });
    const now = new Date();
    const done = await app.prisma.$transaction(async (tx) => {
      await lockUser(tx, user.id);
      const r = await tx.recoveryRequest.findUnique({ where: { id: tok.ref }, select: { orgId: true, memberPublicKey: true, approvedBy: true } });
      if (!r || r.memberPublicKey !== body.publicKey) return "gone" as const;
      const mk = await tx.membershipKey.findFirst({ where: { orgId: r.orgId, userId: user.id, publicKey: body.publicKey, state: "archived" } });
      if (!mk) return "gone" as const;
      const n = await tx.recoveryRequest.updateMany({ where: { id: tok.ref, userId: user.id, status: "approved", expiresAt: { gt: now } }, data: { status: "used", usedAt: now, ...BURN_REQUEST } });
      if (n.count !== 1) return "gone" as const;
      const hasCurrent = !!(await currentKey(tx, r.orgId, user.id));
      const gen = (await tx.user.findUniqueOrThrow({ where: { id: user.id }, select: { userKeyGen: true } })).userKeyGen;
      // An admin saw this key: it retires (rows move to the current key) or, as the current one, is rotated next unlock.
      await tx.membershipKey.update({ where: { id: mk.id }, data: { wrappedPrivateKey: body.wrappedPrivateKey, userKeyGen: gen, escrowOpenedAt: mk.escrowOpenedAt ?? now,
        state: hasCurrent ? "retiring" : "current", retiredAt: hasCurrent ? now : null } });
      return { orgId: r.orgId, approvedBy: r.approvedBy };
    });
    if (done === "gone") return reply.code(410).send({ error: "recovery_used" });
    await logEvent(app.prisma, { orgId: done.orgId, actorId: user.id, action: "recovery.membership_restored", meta: { requestId: tok.ref, approvedBy: done.approvedBy }, ...meta(req) });
    return { ok: true, orgId: done.orgId };
  });
};

/** Signed-in recovery settings, under /api/v1/me. */
export const meRecoveryRoutes: FastifyPluginAsync = async (app) => {
  app.addHook("preHandler", app.requireAuth);
  const meta = (req: { ip: string; headers: Record<string, unknown> }) => ({ ip: req.ip, userAgent: String(req.headers["user-agent"] ?? "").slice(0, 300) });

  const acked = (ackAt: Date | null, p: { adminRecoveryChangedAt: Date | null } | null) => !!ackAt && (!p?.adminRecoveryChangedAt || ackAt >= p.adminRecoveryChangedAt);

  /**
   * Recovery kit status and, per organisation the user is active in with admin recovery on: whether they still have to
   * acknowledge it, whether their membership there is recoverable, and which admins hold an escrow of their current
   * membership key (the client makes the escrows per org: GET /membership-key). Each org's admins can only restore that
   * org's membership (docs/design/2026-10-08-per-org-keypairs.md).
   */
  app.get("/me/security", async (req) => {
    const me = req.auth.userId;
    const u = await app.prisma.user.findUniqueOrThrow({ where: { id: me }, select: { recoveryCreatedAt: true } });
    const ms = (await app.prisma.membership.findMany({ where: { userId: me, status: "active", org: { adminRecoveryEnabled: true } }, orderBy: { createdAt: "asc" },
      select: { adminRecoveryAckAt: true, org: { select: { ...PLAN_SELECT, id: true, name: true, adminRecoveryChangedAt: true } } } })).filter((m) => adminRecoveryOn(app.config, { ...m.org, adminRecoveryEnabled: true }));
    const orgs = [];
    for (const m of ms) {
      const cur = await currentKey(app.prisma, m.org.id, me);
      const holders = cur ? await app.prisma.membershipEscrow.findMany({ where: { orgId: m.org.id, userId: me, memberPublicKey: cur.publicKey, admin: { status: "active" } }, orderBy: { createdAt: "asc" },
        select: { createdAt: true, admin: { select: { id: true, name: true, email: true } } } }) : [];
      const recoverable = !!(await recoverableKey(app.prisma, m.org.id, me)) && holders.length > 0;
      orgs.push({ orgId: m.org.id, orgName: m.org.name, adminRecoveryEnabled: true, ackRequired: !acked(m.adminRecoveryAckAt, m.org), recoverable,
        escrowHolders: holders.map((h) => ({ adminId: h.admin.id, name: h.admin.name, email: h.admin.email, since: h.createdAt.toISOString() })) });
    }
    const archive = await app.prisma.accountKeyArchive.findFirst({ where: { userId: me, restoredAt: null }, orderBy: { archivedAt: "desc" }, select: { id: true, archivedAt: true, privateItems: true, otherOrgs: true } });
    return {
      recoveryKit: u.recoveryCreatedAt ? { createdAt: u.recoveryCreatedAt.toISOString() } : null,
      adminRecoveryEnabled: orgs.length > 0, adminRecoveryAckRequired: orgs.some((o) => o.ackRequired), orgs,
      keyArchive: archive ? { id: archive.id, archivedAt: archive.archivedAt.toISOString(), privateItems: archive.privateItems, otherOrgs: archive.otherOrgs } : null,
    };
  });

  /** "I understand this organisation's admins can recover my account": required once per switch-on, per org, before any escrow. */
  app.post("/me/admin-recovery-ack", async (req, reply) => {
    const { orgId } = z.object({ orgId: z.string().uuid() }).parse(req.body ?? {});
    const m = await app.prisma.membership.findFirst({ where: { orgId, userId: req.auth.userId, status: "active" }, select: { id: true, org: { select: { ...PLAN_SELECT, adminRecoveryEnabled: true } } } });
    if (!m) return reply.code(403).send({ error: "org_forbidden" });
    if (!adminRecoveryOn(app.config, m.org)) return reply.code(409).send({ error: "policy_off" });
    await app.prisma.membership.update({ where: { id: m.id }, data: { adminRecoveryAckAt: new Date() } });
    await logEvent(app.prisma, { orgId, actorId: req.auth.userId, action: "recovery.policy_acknowledged", ...meta(req) });
    return { ok: true };
  });

  /** Creates or replaces the recovery kit. Needs the master password (its auth key): a stolen access token can't swap the kit. */
  // Per client address (a token is attacker-chosen); scales with RATE_LIMIT_PER_MINUTE (10 at the default 300). Wrong proofs also count toward the lockout.
  app.post("/me/recovery-kit", { config: { rateLimit: { max: Math.max(10, Math.floor((app.config.rateLimitPerMinute ?? 300) / 30)), timeWindow: "1 minute" } } }, async (req, reply) => {
    const body = z.object({ authKey: z.string().max(4096), recoveryWrap: z.string().regex(/^v1\.[A-Za-z0-9_-]+$/).max(1024), recoveryAuth: secret256 }).parse(req.body);
    const user = await app.prisma.user.findUniqueOrThrow({ where: { id: req.auth.userId } });
    const locked = lockedFor(user);
    if (locked) return reply.code(423).send({ error: "locked", retryAfterSeconds: locked });
    if (!(await argon2.verify(user.authHash, body.authKey).catch(() => false))) {
      await registerFailure(app.prisma, user.id);
      await logEvent(app.prisma, { actorId: user.id, action: "auth.reauth_failed", ...meta(req) });
      return reply.code(401).send({ error: "invalid_credentials" });
    }
    const createdAt = new Date();
    await app.prisma.user.update({ where: { id: user.id }, data: {
      recoveryWrap: body.recoveryWrap, recoveryAuthHash: hashSecretValue(body.recoveryAuth), recoveryCreatedAt: createdAt, failedLogins: 0,
    } });
    await logEvent(app.prisma, { actorId: user.id, action: user.recoveryCreatedAt ? "auth.recovery_kit_regenerated" : "auth.recovery_kit_created", ...meta(req) });
    return reply.code(201).send({ createdAt: createdAt.toISOString() });
  });
};
