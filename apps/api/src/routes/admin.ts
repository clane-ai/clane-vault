import type { FastifyPluginAsync, FastifyRequest } from "fastify";
import { z } from "zod";
import { sendEmail, twoFactorResetEmail } from "../lib/email.js";
import { logEvent } from "../lib/events.js";
import { canManageAccount, dropInstanceAdminIfGone, isInstanceAdmin, lockUser, offboard } from "../lib/orgs.js";
import { coolDown, coolingDown, dailyInviteCap, dropPendingGroups, INVITE_TTL_MS, invitesSentToday, sendNewInvite } from "../lib/invites.js";
import { expireOpenRequests } from "../lib/recovery.js";
import { backupRoutes } from "./backups.js";
import { adminRecoveryRoutes } from "./adminRecovery.js";
import { startAdminAge } from "./auth.js";
import { clearTwoFactor } from "../lib/twoFactor.js";
import { instanceAdminRoutes } from "./instanceAdmin.js";
import { instanceEmailRoutes, orgEmailRoutes } from "./emailSettings.js";
import { instanceBrandRoutes } from "./brand.js";
import { ssoSettingsRoutes } from "./ssoSettings.js";
import { groupAdminRoutes } from "./groups.js";
import { policyAdminRoutes } from "./policies.js";
import { healthAdminRoutes } from "./passwordHealth.js";
import { eventAdminRoutes } from "./events.js";
import { provisioningAdminRoutes } from "./provisioning.js";
import { riskAdminRoutes } from "./risk.js";
import { instanceStorageRoutes, storageAdminRoutes } from "./storage.js";
import { notInDemo, readOnlyInDemo } from "../lib/demo.js";

const idParam = z.object({ id: z.string().uuid() });
const userParam = z.object({ userId: z.string().uuid() });

/**
 * /admin. Backups are instance-level (instance admins only, no org). Everything else acts on the active org
 * (X-Org-Id) and needs the caller to be owner or admin of it, read from the database on every call.
 */
export const adminRoutes: FastifyPluginAsync = async (app) => {
  app.addHook("preHandler", app.requireAuth);

  await app.register(async (instance) => {
    // A demo instance has no instance admins (only sandbox accounts); its server pages are closed regardless.
    instance.addHook("preHandler", notInDemo(app));
    instance.addHook("preHandler", async (req, reply) => {
      if (reply.sent) return;
      if (!(await isInstanceAdmin(app.prisma, app.config, req.auth.userId))) await reply.code(403).send({ error: "forbidden" });
    });
    await instance.register(backupRoutes);
    await instance.register(instanceEmailRoutes, { prefix: "/instance/email" });
    await instance.register(instanceBrandRoutes, { prefix: "/instance/brand" });
    await instance.register(instanceStorageRoutes, { prefix: "/instance/storage" });
    // Account tools that work without seeing into any organisation.
    await instance.register(instanceAdminRoutes, { prefix: "/instance" });
  });

  await app.register(async (org) => {
    org.addHook("preHandler", app.orgAdmin);
    await org.register(adminRecoveryRoutes);
    await org.register(orgAdminRoutes);
    // Demo mode (docs/demo.md): email and single sign-on settings can be looked at, never changed or tested.
    await org.register(async (settings) => {
      settings.addHook("preHandler", readOnlyInDemo(app));
      await settings.register(orgEmailRoutes, { prefix: "/settings/email" });
      await settings.register(ssoSettingsRoutes, { prefix: "/settings/sso" });
    });
    await org.register(groupAdminRoutes, { prefix: "/groups" });
    await org.register(policyAdminRoutes, { prefix: "/settings/policies" });
    await org.register(healthAdminRoutes, { prefix: "/health" });
    await org.register(eventAdminRoutes, { prefix: "/events" });
    await org.register(provisioningAdminRoutes);
    await org.register(riskAdminRoutes, { prefix: "/risk" });
    await org.register(storageAdminRoutes, { prefix: "/storage" });
  });
};

const orgAdminRoutes: FastifyPluginAsync = async (app) => {
  const orgId = (req: FastifyRequest) => req.org!.id;

  /**
   * Invites someone to the active org. The answer never says whether the address already has an account, is already a
   * member or already invited (no enumeration): always 201 `{ invited, emailed }`, plus a one-time `inviteUrl` in
   * self-hosted mode. No account: registering through the link creates it. An existing account: an invitation they
   * accept in the app. HOSTED_MODE: links are only ever emailed (refused without email set up).
   */
  app.post("/invites", { config: { rateLimit: { max: 30, timeWindow: "1 minute" } } }, async (req, reply) => {
    const b = z.object({ email: z.string().trim().toLowerCase().email().max(254), role: z.enum(["admin", "member"]).default("member") }).parse(req.body);
    const hosted = !!app.config.hostedMode;
    if (hosted && !(await app.mail.configured(orgId(req)))) return reply.code(409).send({ error: "email_required" });
    const org = await app.prisma.organization.findUniqueOrThrow({ where: { id: orgId(req) }, select: { id: true, name: true } });
    // Invite spam: a daily cap per org (new invitations and resends), and a cooldown after someone declined (or an admin cancelled).
    if ((await invitesSentToday(app.prisma, org.id)) >= dailyInviteCap(app)) return reply.code(429).send({ error: "invite_limit" });
    if (await coolingDown(app.prisma, org.id, b.email)) return reply.code(409).send({ error: "invite_cooldown" });
    // Self-hosted: every invite gets a copyable link, whatever the address (same answer for everyone).
    // Hosted: only addresses without an account get a link, and only by email.
    const { emailed, inviteUrl } = await sendNewInvite(app, { org, actorId: req.auth.userId, email: b.email, role: b.role, log: req.log });
    return reply.code(201).send({ invited: true, email: b.email, role: b.role, emailed, ...(!hosted && inviteUrl ? { inviteUrl } : {}) });
  });

  /**
   * The active org's members (any status but invited) and pending invitations. An invitation shows only its email and
   * role, never whether the address has an account, until it is accepted.
   */
  app.get("/people", async (req) => {
    const [members, rows] = await Promise.all([
      app.prisma.membership.findMany({ where: { orgId: orgId(req) }, orderBy: { createdAt: "asc" },
        select: { id: true, role: true, status: true, createdAt: true, joinedAt: true, user: { select: { id: true, name: true, email: true, status: true, createdAt: true, publicKey: true } } } }),
      app.prisma.invite.findMany({ where: { orgId: orgId(req), acceptedAt: null, expiresAt: { gt: new Date() } }, select: { id: true, email: true, role: true, expiresAt: true, createdAt: true }, orderBy: { createdAt: "desc" } }),
    ]);
    const joined = new Set(members.filter((m) => m.status !== "invited").map((m) => m.user.email));
    const listed = new Set(rows.map((r) => r.email));
    const live = (d: Date) => d.getTime() + INVITE_TTL_MS > Date.now();
    const invites = [
      ...rows.filter((r) => !joined.has(r.email)).map((i) => ({ id: i.id, email: i.email, role: i.role, expiresAt: i.expiresAt.toISOString(), createdAt: i.createdAt.toISOString() })),
      ...members.filter((m) => m.status === "invited" && !listed.has(m.user.email) && live(m.createdAt))
        .map((m) => ({ id: m.id, email: m.user.email, role: m.role, expiresAt: new Date(m.createdAt.getTime() + INVITE_TTL_MS).toISOString(), createdAt: m.createdAt.toISOString() })),
    ].sort((a, b) => b.createdAt.localeCompare(a.createdAt));
    return {
      // `status`: the membership's when disabled, otherwise the account's (active / pending_2fa / disabled).
      users: members.filter((m) => m.status !== "invited").map((m) => ({ id: m.user.id, name: m.user.name, email: m.user.email, publicKey: m.user.publicKey, role: m.role,
        status: m.status === "disabled" ? "disabled" : m.user.status, createdAt: (m.joinedAt ?? m.createdAt).toISOString() })),
      invites,
    };
  });

  /** Revokes an invitation (an invite link, an invitation to an existing account, or both); the address cools down. */
  app.delete("/invites/:id", async (req, reply) => {
    const { id } = idParam.parse(req.params);
    const org = orgId(req);
    const row = await app.prisma.invite.findFirst({ where: { id, orgId: org, acceptedAt: null }, select: { email: true } });
    const m = row ? null : await app.prisma.membership.findFirst({ where: { id, orgId: org, status: "invited" }, select: { user: { select: { email: true } } } });
    const email = row?.email ?? m?.user.email;
    if (!email) return reply.code(404).send({ error: "not_found" });
    await app.prisma.$transaction(async (tx) => {
      await tx.invite.deleteMany({ where: { orgId: org, email, acceptedAt: null } });
      await tx.membership.deleteMany({ where: { orgId: org, status: "invited", user: { email } } });
      await dropPendingGroups(tx, org, email);
      await coolDown(tx, org, email);
    });
    await logEvent(app.prisma, { orgId: org, actorId: req.auth.userId, action: "admin.invite_revoke" });
    return reply.code(204).send();
  });

  /**
   * Another member of the active org (admins can't act on themselves, and nobody but a transfer touches the owner; an
   * owner's authenticator is reset by an instance admin, POST /admin/instance/users/reset-2fa).
   */
  async function target(req: FastifyRequest, id: string) {
    if (id === req.auth.userId) return "self" as const;
    const m = await app.prisma.membership.findUnique({ where: { orgId_userId: { orgId: orgId(req), userId: id } },
      select: { role: true, status: true, user: { select: { id: true, status: true, totpSecretEnc: true, email: true, name: true } } } });
    if (!m) return null;
    if (m.role === "owner") return "owner" as const;
    return m;
  }
  const refuse = (t: "self" | "owner" | null) => (t === "self" ? [400, "self"] : t === "owner" ? [403, "owner"] : [404, "not_found"]) as [number, string];

  /** Disables the membership in this org only: the account, private items and other orgs are untouched. */
  app.post("/users/:id/disable", async (req, reply) => {
    const { id } = idParam.parse(req.params);
    const t = await target(req, id);
    if (t === null || t === "self" || t === "owner") { const [c, e] = refuse(t); return reply.code(c).send({ error: e }); }
    if (t.status === "invited") return reply.code(404).send({ error: "not_found" });
    await app.prisma.$transaction((tx) => offboard(tx, orgId(req), id, "disable"));
    await logEvent(app.prisma, { orgId: orgId(req), actorId: req.auth.userId, action: "admin.disable", targetUserId: id });
    return { ok: true };
  });

  app.post("/users/:id/enable", async (req, reply) => {
    const { id } = idParam.parse(req.params);
    const t = await target(req, id);
    if (t === null || t === "self" || t === "owner") { const [c, e] = refuse(t); return reply.code(c).send({ error: e }); }
    const globallyDisabled = t.user.status === "disabled";
    // An invitation is accepted by its invitee, never "enabled" by an admin.
    if (t.status === "invited" || (t.status !== "disabled" && !globallyDisabled)) return reply.code(409).send({ error: "not_disabled" });
    // A globally disabled account (from before organisations) is the account itself: same rule as a 2FA reset.
    if (globallyDisabled && !(await canManageAccount(app.prisma, app.config, req.auth.userId, id))) return reply.code(403).send({ error: "other_orgs" });
    await app.prisma.$transaction(async (tx) => {
      await lockUser(tx, id);
      // Admin age starts again: a re-enabled admin is a new approver for admin recovery.
      await tx.membership.update({ where: { orgId_userId: { orgId: orgId(req), userId: id } }, data: { status: "active", ...(t.role !== "member" ? { adminSince: new Date() } : {}) } });
      if (globallyDisabled) await tx.user.update({ where: { id }, data: { status: t.user.totpSecretEnc ? "active" : "pending_2fa", failedLogins: 0, lockedUntil: null } });
    });
    await logEvent(app.prisma, { orgId: orgId(req), actorId: req.auth.userId, action: "admin.enable", targetUserId: id });
    return { ok: true };
  });

  /**
   * Resets the account's 2FA. That changes the global account, so only an instance admin or an admin of every org
   * the member belongs to may do it (docs/design/2026-10-07-multi-org-design.md §4).
   */
  app.post("/users/:id/reset-2fa", async (req, reply) => {
    const { id } = idParam.parse(req.params);
    const t = await target(req, id);
    if (t === null || t === "self" || t === "owner") { const [c, e] = refuse(t); return reply.code(c).send({ error: e }); }
    if (t.status !== "active" || t.user.status === "disabled") return reply.code(409).send({ error: "disabled" });
    if (!(await canManageAccount(app.prisma, app.config, req.auth.userId, id))) return reply.code(403).send({ error: "other_orgs" });
    // Who reset it and when: admin recovery then needs a second admin and a waiting period (docs/recovery.md).
    const at = new Date();
    await app.prisma.$transaction((tx) => clearTwoFactor(tx, id, req.auth.userId, at));
    const admin = await app.prisma.user.findUniqueOrThrow({ where: { id: req.auth.userId }, select: { name: true } });
    void sendEmail(app.mail, t.user.email, twoFactorResetEmail(await app.brand.productName(), admin.name, at), req.log);
    await logEvent(app.prisma, { orgId: orgId(req), actorId: req.auth.userId, action: "admin.reset_2fa", targetUserId: id });
    return { ok: true };
  });

  /**
   * One member of the active org for the admin's member page: role and status, two-step sign-in, groups, the team
   * folders they're in (ids and permissions only; names are encrypted and shown when the admin can open the folder),
   * their last password health report and their admin recovery (escrow) status. Never any secret or key.
   */
  app.get("/members/:userId", async (req, reply) => {
    const { userId } = userParam.parse(req.params);
    const org = orgId(req);
    const m = await app.prisma.membership.findUnique({ where: { orgId_userId: { orgId: org, userId } },
      select: { role: true, status: true, createdAt: true, joinedAt: true, adminRecoveryAckAt: true,
        user: { select: { id: true, name: true, email: true, status: true, totpEnabledAt: true, createdAt: true } } } });
    if (!m || m.status === "invited") return reply.code(404).send({ error: "not_found" });
    const [groups, folders, report, escrows, o, requests] = await Promise.all([
      app.prisma.groupMember.findMany({ where: { userId, group: { orgId: org } }, orderBy: { group: { name: "asc" } }, select: { group: { select: { id: true, name: true } } } }),
      app.prisma.folderMember.findMany({ where: { userId, folder: { orgId: org, kind: "team", deletedAt: null } }, orderBy: { createdAt: "asc" },
        select: { folderId: true, permission: true, directPermission: true, folder: { select: { ownerId: true } } } }),
      app.prisma.healthReport.findUnique({ where: { orgId_userId: { orgId: org, userId } }, select: { score: true, total: true, weak: true, reused: true, old: true, breached: true, reportedAt: true } }),
      app.prisma.membershipEscrow.count({ where: { orgId: org, userId } }),
      app.prisma.organization.findUnique({ where: { id: org }, select: { adminRecoveryEnabled: true } }),
      app.prisma.recoveryRequest.count({ where: { orgId: org, userId, status: "pending" } }),
    ]);
    return {
      member: { id: m.user.id, name: m.user.name, email: m.user.email, role: m.role, status: m.status === "disabled" ? "disabled" : m.user.status,
        joinedAt: (m.joinedAt ?? m.createdAt).toISOString(), twoFactor: !!m.user.totpEnabledAt },
      groups: groups.map((g) => g.group),
      folders: folders.map((f) => ({ id: f.folderId, permission: f.permission, direct: f.directPermission, owner: f.folder.ownerId === userId })),
      health: report ? { ...report, reportedAt: report.reportedAt.toISOString() } : null,
      recovery: { enabled: o?.adminRecoveryEnabled ?? false, acknowledged: !!m.adminRecoveryAckAt, escrowed: escrows > 0, pendingRequest: requests > 0 },
    };
  });

  /** Removes someone from the active org (offboarding), or cancels their pending invitation. */
  app.delete("/members/:userId", async (req, reply) => {
    const { userId } = userParam.parse(req.params);
    const t = await target(req, userId);
    if (t === null || t === "self" || t === "owner") { const [c, e] = refuse(t); return reply.code(c).send({ error: e }); }
    await app.prisma.$transaction(async (tx) => {
      if (t.status === "invited") await coolDown(tx, orgId(req), t.user.email);
      await tx.invite.deleteMany({ where: { orgId: orgId(req), email: t.user.email, acceptedAt: null } });
      await offboard(tx, orgId(req), userId, "remove");
    });
    await logEvent(app.prisma, { orgId: orgId(req), actorId: req.auth.userId, action: t.status === "invited" ? "admin.invite_revoke" : "admin.remove_member", targetUserId: userId });
    return reply.code(204).send();
  });

  /** admin ↔ member (never the owner; ownership moves with a transfer). */
  app.patch("/members/:userId", async (req, reply) => {
    const { userId } = userParam.parse(req.params);
    const { role } = z.object({ role: z.enum(["admin", "member"]) }).parse(req.body);
    const t = await target(req, userId);
    if (t === null || t === "self" || t === "owner") { const [c, e] = refuse(t); return reply.code(c).send({ error: e }); }
    if (t.role === role) return { ok: true };
    await app.prisma.$transaction(async (tx) => {
      await tx.membership.update({ where: { orgId_userId: { orgId: orgId(req), userId } }, data: { role, ...(role === "member" ? { adminSince: null } : {}) } });
      // A demoted admin no longer holds this org's escrows, and links they approved stop working.
      if (role === "member") {
        await tx.membershipEscrow.deleteMany({ where: { orgId: orgId(req), adminId: userId } });
        await expireOpenRequests(tx, { orgId: orgId(req), approvedBy: userId, status: "approved" });
        await dropInstanceAdminIfGone(tx, orgId(req), userId);
      }
    });
    // A promoted, active admin starts their admin age now and the other admins are told.
    if (role === "admin" && t.status === "active" && t.user.status === "active") await startAdminAge(app, t.user, req.log);
    await logEvent(app.prisma, { orgId: orgId(req), actorId: req.auth.userId, action: "admin.role_change", targetUserId: userId, meta: { role } });
    return { ok: true };
  });
};

