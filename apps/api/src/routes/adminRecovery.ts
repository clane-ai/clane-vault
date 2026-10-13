import type { FastifyPluginAsync } from "fastify";
import argon2 from "argon2";
import { z } from "zod";
import { secretBox } from "../lib/secretBox.js";
import { logEvent } from "../lib/events.js";
import { lockedFor, registerFailure } from "../lib/lockout.js";
import { adminRecoveryEnabled, adminSinceIn, approverOldEnough, BURN_REQUEST, expireOpenRequests, hashSecretValue, OPEN, RECOVERY_LINK_TTL_MS, sweepRecoveryRequests } from "../lib/recovery.js";
import { signApproval, verifyToken } from "../lib/tokens.js";
import { consumeTotp } from "../lib/totp.js";
import { adminRecoveryOnEmail, recoveryAdminActionEmail, sendEmail } from "../lib/email.js";

const idParam = z.object({ id: z.string().uuid() });
/** The admin reset this member's 2FA and it hasn't been set up again: they must not also approve (two-person rule). */
const resetBySelf = (u: { status: string; totpResetBy: string | null }, adminId: string) => u.status === "pending_2fa" && u.totpResetBy === adminId;

/**
 * Admin side of account recovery (docs/recovery.md), for the active org. Registered inside adminRoutes, so every
 * route already needs a live session and the admin role in that org read from the database. Policy, escrows,
 * requests and the approver's admin age are all per org.
 */
export const adminRecoveryRoutes: FastifyPluginAsync = async (app) => {
  const box = secretBox(app.config.serverSecret);
  const minAgeDays = () => app.config.adminRecoveryApproverMinAgeDays ?? 7;
  const meta = (req: { ip: string; headers: Record<string, unknown> }) => ({ ip: req.ip, userAgent: String(req.headers["user-agent"] ?? "").slice(0, 300) });

  const settingsView = async (orgId: string) => {
    const s = await app.prisma.organization.findUnique({ where: { id: orgId } });
    const by = s?.adminRecoveryChangedBy ? await app.prisma.user.findUnique({ where: { id: s.adminRecoveryChangedBy }, select: { id: true, name: true } }) : null;
    const [escrows, members] = await Promise.all([
      app.prisma.membershipEscrow.count({ where: { orgId } }),
      app.prisma.membershipEscrow.groupBy({ by: ["userId"], where: { orgId } }).then((g) => g.length),
    ]);
    return { adminRecovery: { enabled: s?.adminRecoveryEnabled ?? false, changedAt: s?.adminRecoveryChangedAt?.toISOString() ?? null, changedBy: by }, escrows: { total: escrows, members } };
  };

  app.get("/settings", async (req) => settingsView(req.org!.id));

  /**
   * Turning it off deletes every escrow and ends every open request. Turning it on needs the admin's master password
   * (auth key) and a fresh 2FA code; members are emailed and asked to acknowledge before their client escrows.
   */
  app.put("/settings/admin-recovery", { config: { rateLimit: { max: 10, timeWindow: "1 minute" } } }, async (req, reply) => {
    const { enabled, code, authKey } = z.object({ enabled: z.boolean(), code: z.string().max(10).optional(), authKey: z.string().max(4096).optional() }).parse(req.body);
    const me = await app.prisma.user.findUniqueOrThrow({ where: { id: req.auth.userId } });
    const orgId = req.org!.id;
    if (enabled && !(await adminRecoveryEnabled(app.prisma, orgId))) {
      const locked = lockedFor(me);
      if (locked) return reply.code(423).send({ error: "locked", retryAfterSeconds: locked });
      if (!authKey || !(await argon2.verify(me.authHash, authKey).catch(() => false))) {
        await registerFailure(app.prisma, me.id);
        await logEvent(app.prisma, { orgId, actorId: me.id, action: "auth.reauth_failed", ...meta(req) });
        return reply.code(401).send({ error: "invalid_credentials" });
      }
      if (!(await consumeTotp(app.prisma, box, me, code))) {
        await registerFailure(app.prisma, me.id);
        await logEvent(app.prisma, { orgId, actorId: me.id, action: "auth.reauth_failed", ...meta(req) });
        return reply.code(401).send({ error: "totp_invalid" });
      }
    }
    const now = new Date();
    const result = await app.prisma.$transaction(async (tx) => {
      const before = await tx.organization.findUniqueOrThrow({ where: { id: orgId } });
      await tx.organization.update({ where: { id: orgId }, data: { adminRecoveryEnabled: enabled, adminRecoveryChangedBy: req.auth.userId, adminRecoveryChangedAt: now } });
      if (enabled) {
        const changed = !before.adminRecoveryEnabled;
        // The admin who switches it on has just read the warning: that counts as their acknowledgement.
        if (changed) await tx.membership.update({ where: { orgId_userId: { orgId, userId: req.auth.userId } }, data: { adminRecoveryAckAt: new Date(now.getTime() + 1) } });
        else await tx.organization.update({ where: { id: orgId }, data: { adminRecoveryChangedBy: before.adminRecoveryChangedBy ?? null, adminRecoveryChangedAt: before.adminRecoveryChangedAt ?? now } });
        return { changed, escrowsDeleted: 0, requestsEnded: 0 };
      }
      const escrowsDeleted = (await tx.membershipEscrow.deleteMany({ where: { orgId } })).count;
      const requestsEnded = (await expireOpenRequests(tx, { orgId })).length;
      return { changed: before.adminRecoveryEnabled, escrowsDeleted, requestsEnded, orgName: before.name };
    });
    if (enabled && result.changed) {
      const org = await app.prisma.organization.findUniqueOrThrow({ where: { id: orgId }, select: { name: true } });
      const people = await app.prisma.user.findMany({ where: { status: { not: "disabled" }, id: { not: me.id }, memberships: { some: { orgId, status: "active" } } }, select: { email: true } });
      for (const p of people) void sendEmail(app.mail, p.email, adminRecoveryOnEmail(await app.brand.productName(), me.name, org.name), req.log);
    }
    if (result.changed || result.escrowsDeleted || result.requestsEnded)
      await logEvent(app.prisma, { orgId, actorId: req.auth.userId, action: enabled ? "admin.recovery_policy_enabled" : "admin.recovery_policy_disabled",
        meta: enabled ? {} : { escrowsDeleted: result.escrowsDeleted, requestsEnded: result.requestsEnded }, ...meta(req) });
    return settingsView(orgId);
  });

  app.get("/recovery-requests", async (req) => {
    await sweepRecoveryRequests(app.prisma);
    const rows = await app.prisma.recoveryRequest.findMany({ where: { ...OPEN, orgId: req.org!.id }, orderBy: { createdAt: "desc" },
      select: { id: true, status: true, createdAt: true, approvedAt: true, approvedBy: true, expiresAt: true, user: { select: { id: true, name: true, email: true, status: true, totpResetBy: true, totpResetAt: true } } } });
    const meAdmin = { adminSince: req.org!.adminSince };
    const mine = new Set((await app.prisma.membershipEscrow.findMany({ where: { orgId: req.org!.id, adminId: req.auth.userId, userId: { in: rows.map((r) => r.user.id) } }, select: { userId: true } })).map((e) => e.userId));
    return {
      requests: rows.map((r) => ({
        id: r.id, status: r.status, createdAt: r.createdAt.toISOString(), approvedAt: r.approvedAt?.toISOString() ?? null, approvedBy: r.approvedBy, expiresAt: r.expiresAt?.toISOString() ?? null,
        user: { id: r.user.id, name: r.user.name, email: r.user.email },
        canApprove: r.status === "pending" && r.user.id !== req.auth.userId && r.user.status !== "disabled" && mine.has(r.user.id) && !resetBySelf(r.user, req.auth.userId)
          && (r.user.status !== "pending_2fa" || approverOldEnough(meAdmin, r.user, minAgeDays())),
        twoFactorReset: r.user.status === "pending_2fa",
      })),
    };
  });

  /**
   * Step 1 of approving: the admin's fresh 2FA code releases the escrow addressed to this admin (never another
   * admin's): the member's membership key in this org only (docs/design/2026-10-08-per-org-keypairs.md),
   * sealed to the admin's membership key here, and a 5-minute approval token for this one request. The member's client
   * rotates that key on its next unlock.
   */
  app.post("/recovery-requests/:id/escrow", { config: { rateLimit: { max: 10, timeWindow: "1 minute" } } }, async (req, reply) => {
    const { id } = idParam.parse(req.params);
    const { code } = z.object({ code: z.string().max(10) }).parse(req.body);
    const me = req.auth.userId;
    const orgId = req.org!.id;
    if (!(await adminRecoveryEnabled(app.prisma, orgId))) return reply.code(409).send({ error: "policy_off" });
    const r = await app.prisma.recoveryRequest.findFirst({ where: { id, orgId }, include: { user: { select: { id: true, status: true, email: true, totpResetBy: true, totpResetAt: true } } } });
    if (!r) return reply.code(404).send({ error: "not_found" });
    if (r.status !== "pending") return reply.code(409).send({ error: "not_pending" });
    if (r.userId === me) return reply.code(403).send({ error: "self" });
    if (r.user.status === "disabled") return reply.code(409).send({ error: "user_inactive" });
    if (resetBySelf(r.user, me)) return reply.code(403).send({ error: "two_person_required" });
    if (r.user.status === "pending_2fa" && !approverOldEnough(await adminSinceIn(app.prisma, orgId, me), r.user, minAgeDays()))
      return reply.code(403).send({ error: "approver_too_new" });
    const escrow = await app.prisma.membershipEscrow.findUnique({ where: { orgId_userId_adminId: { orgId, userId: r.userId, adminId: me } } });
    // Only an escrow of one of the member's keys in this org (current, or one a later reset archived). Never a retiring
    // key: the member already moved on from it, and a link restoring it would bring back a key their rows left.
    const memberKey = escrow && await app.prisma.membershipKey.findFirst({ where: { orgId, userId: r.userId, publicKey: escrow.memberPublicKey, state: { in: ["current", "archived"] } } });
    if (!escrow || !memberKey) return reply.code(409).send({ error: "no_escrow" });
    const admin = await app.prisma.user.findUniqueOrThrow({ where: { id: me } });
    const locked = lockedFor(admin);
    if (locked) return reply.code(423).send({ error: "locked", retryAfterSeconds: locked });
    if (!(await consumeTotp(app.prisma, box, admin, code))) {
      await registerFailure(app.prisma, me);
      await logEvent(app.prisma, { orgId, actorId: me, action: "auth.reauth_failed", targetUserId: r.userId, ...meta(req) });
      return reply.code(401).send({ error: "totp_invalid" });
    }
    await app.prisma.membershipKey.updateMany({ where: { id: memberKey.id, escrowOpenedAt: null }, data: { escrowOpenedAt: new Date() } });
    await logEvent(app.prisma, { orgId, actorId: me, action: "recovery.escrow_opened", targetUserId: r.userId, meta: { requestId: id }, ...meta(req) });
    const org = await app.prisma.organization.findUniqueOrThrow({ where: { id: orgId }, select: { name: true } });
    void sendEmail(app.mail, r.user.email, recoveryAdminActionEmail(await app.brand.productName(), "escrow_opened", admin.name, org.name), req.log);
    return {
      sealedKey: escrow.sealedKey, memberPublicKey: escrow.memberPublicKey, adminPublicKey: escrow.adminPublicKey,
      member: { id: r.user.id }, approvalToken: await signApproval(app.config, me, id),
    };
  });

  /** Step 2: stores the membership key wrapped under the link secret and the proof hash. The admin never sets the password. */
  app.post("/recovery-requests/:id/approve", { config: { rateLimit: { max: 10, timeWindow: "1 minute" } } }, async (req, reply) => {
    const { id } = idParam.parse(req.params);
    const body = z.object({ approvalToken: z.string().max(2048), memberPublicKey: z.string().regex(/^[A-Za-z0-9_-]{43}$/), wrappedMembershipKey: z.string().regex(/^v1\.[A-Za-z0-9_-]+$/).max(1024), proof: z.string().regex(/^[A-Za-z0-9_-]{43}$/) }).parse(req.body);
    const me = req.auth.userId;
    try {
      const t = await verifyToken(app.config, body.approvalToken, "recovery-approve");
      if (t.sub !== me || t.rid !== id) throw new Error("wrong approval");
    } catch { return reply.code(401).send({ error: "approval_expired" }); }
    const orgId = req.org!.id;
    if (!(await adminRecoveryEnabled(app.prisma, orgId))) return reply.code(409).send({ error: "policy_off" });
    const target = await app.prisma.recoveryRequest.findFirst({ where: { id, orgId }, select: { userId: true, user: { select: { status: true, totpResetBy: true, totpResetAt: true } } } });
    if (!target) return reply.code(409).send({ error: "not_pending" });
    // The key this admin's escrow held (what the link will restore).
    const escrow = await app.prisma.membershipEscrow.findUnique({ where: { orgId_userId_adminId: { orgId, userId: target.userId, adminId: me } }, select: { memberPublicKey: true } });
    if (!escrow || escrow.memberPublicKey !== body.memberPublicKey) return reply.code(409).send({ error: "no_escrow" });
    if (resetBySelf(target.user, me)) return reply.code(403).send({ error: "two_person_required" });
    if (target.user.status === "pending_2fa" && !approverOldEnough(await adminSinceIn(app.prisma, orgId, me), target.user, minAgeDays()))
      return reply.code(403).send({ error: "approver_too_new" });
    const now = new Date();
    // A link for a reset account can't be used before the reset delay ends: give it its 24 h from then.
    const delayMs = (app.config.adminRecoveryResetDelayHours ?? 24) * 3600e3;
    const resetAt = target.user.status === "pending_2fa" ? target.user.totpResetAt : null;
    const expiresAt = new Date(Math.max(now.getTime() + RECOVERY_LINK_TTL_MS, resetAt ? resetAt.getTime() + delayMs + RECOVERY_LINK_TTL_MS : 0));
    const n = await app.prisma.recoveryRequest.updateMany({ where: { id, orgId, status: "pending", userId: { not: me } },
      data: { status: "approved", approvedBy: me, approvedAt: now, expiresAt, memberPublicKey: body.memberPublicKey, wrappedMembershipKey: body.wrappedMembershipKey, proofHash: hashSecretValue(body.proof), attempts: 0 } });
    if (n.count !== 1) return reply.code(409).send({ error: "not_pending" });
    const r = await app.prisma.recoveryRequest.findUniqueOrThrow({ where: { id }, select: { userId: true, user: { select: { email: true } } } });
    const admin = await app.prisma.user.findUniqueOrThrow({ where: { id: me }, select: { name: true } });
    await logEvent(app.prisma, { orgId, actorId: me, action: "recovery.request_approved", targetUserId: r.userId, meta: { requestId: id }, ...meta(req) });
    const org = await app.prisma.organization.findUniqueOrThrow({ where: { id: orgId }, select: { name: true } });
    void sendEmail(app.mail, r.user.email, recoveryAdminActionEmail(await app.brand.productName(), "approved", admin.name, org.name), req.log);
    return { linkBase: `${app.config.publicUrl}/recover/${id}`, expiresAt: expiresAt.toISOString() };
  });

  app.post("/recovery-requests/:id/deny", async (req, reply) => {
    const { id } = idParam.parse(req.params);
    const orgId = req.org!.id;
    const r = await app.prisma.recoveryRequest.findFirst({ where: { id, orgId }, select: { userId: true } });
    if (!r) return reply.code(404).send({ error: "not_found" });
    const n = await app.prisma.recoveryRequest.updateMany({ where: { id, orgId, ...OPEN }, data: { status: "denied", ...BURN_REQUEST } });
    if (n.count !== 1) return reply.code(404).send({ error: "not_found" });
    await logEvent(app.prisma, { orgId, actorId: req.auth.userId, action: "recovery.request_denied", targetUserId: r.userId, meta: { requestId: id }, ...meta(req) });
    return { ok: true };
  });
};
