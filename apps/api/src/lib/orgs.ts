import { randomBytes } from "node:crypto";
import type { OrgRole, PrismaClient } from "@prisma/client";
import type { Config } from "../config.js";
import type { Db } from "./access.js";
import { removeFolderMember, trashFolder } from "./folderMembers.js";
import { BURN, revokeLinksOfLostAccess } from "./links.js";
import { expireOpenRequests } from "./recovery.js";
import { logEvent } from "./events.js";
import { clientPolicies, readPolicies } from "./policies.js";
import { getEntitlements, PLAN_SELECT } from "./plans.js";
import { logoVersion } from "./images.js";

export const isAdminRole = (r: OrgRole) => r === "owner" || r === "admin";

/** The default organisation: the oldest. It can't be deleted; its owner is an instance admin. */
export const defaultOrg = (db: Db) =>
  db.organization.findFirst({ orderBy: [{ createdAt: "asc" }, { id: "asc" }], select: { id: true, name: true } });

export const defaultOrgName = (config: Config) => config.defaultOrgName ?? `${config.productName} org`;

/** A URL-safe, unique-enough slug: the name's words plus a random suffix. */
export function slugFor(name: string): string {
  const base = name.toLowerCase().normalize("NFKD").replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 40) || "org";
  return `${base}-${randomBytes(4).toString("hex")}`;
}

/**
 * On start: a fresh install gets its default organisation, and the one the multi-org migration created (empty name)
 * gets its name (DEFAULT_ORG_NAME, or "<PRODUCT_NAME> org").
 */
export async function ensureDefaultOrg(prisma: PrismaClient, config: Config): Promise<void> {
  const name = defaultOrgName(config);
  const d = await defaultOrg(prisma);
  if (!d) {
    // Two API processes starting at once: the unique slug makes the second insert fail harmlessly.
    await prisma.organization.create({ data: { name, slug: "default" } }).catch(() => undefined);
    return;
  }
  if (d.name === "") await prisma.organization.updateMany({ where: { id: d.id, name: "" }, data: { name } });
}

/**
 * Instance admin (Backups): an active account flagged `instanceAdmin` (the bootstrap invite, the migration for the
 * default org's owner, or the operator's `instance-admin` CLI). Never derived from an email address.
 */
export async function isInstanceAdmin(prisma: Db, _config: Config, userId: string): Promise<boolean> {
  const u = await prisma.user.findUnique({ where: { id: userId }, select: { instanceAdmin: true, status: true } });
  return !!u && u.status === "active" && u.instanceAdmin;
}

/** Active admin (or owner) of this org, from the database. */
export async function isOrgAdmin(prisma: Db, userId: string, orgId: string): Promise<boolean> {
  return !!(await prisma.membership.findFirst({ where: { orgId, userId, status: "active", role: { in: ["owner", "admin"] }, user: { status: "active" } }, select: { id: true } }));
}

/**
 * Whether `actorId` may change `targetId`'s global account (reset 2FA, lift a global disable): an instance admin, or an
 * admin of every organisation the target is a member of (so no single org's admin can take over an account that other
 * organisations rely on).
 */
export async function canManageAccount(prisma: Db, config: Config, actorId: string, targetId: string): Promise<boolean> {
  if (await isInstanceAdmin(prisma, config, actorId)) return true;
  // An owner of any organisation is only ever reset by an instance admin.
  if (await prisma.membership.findFirst({ where: { userId: targetId, role: "owner" }, select: { id: true } })) return false;
  const theirs = await prisma.membership.findMany({ where: { userId: targetId, status: { in: ["active", "disabled"] } }, select: { orgId: true } });
  if (!theirs.length) return false;
  const mine = new Set((await prisma.membership.findMany({ where: { userId: actorId, status: "active", role: { in: ["owner", "admin"] } }, select: { orgId: true } })).map((m) => m.orgId));
  return theirs.every((m) => mine.has(m.orgId));
}

/** The caller's active organisations (for sign-in responses and the org switcher). */
export async function orgsOf(prisma: Db, cfg: Pick<Config, "billingMode">, userId: string) {
  const d = await defaultOrg(prisma);
  const ms = await prisma.membership.findMany({ where: { userId, status: "active" }, orderBy: { createdAt: "asc" },
    select: { role: true, org: { select: { ...PLAN_SELECT, id: true, name: true, slug: true, policies: true, logo: { select: { sha256: true } } } } } });
  // Each org's policies travel with the membership (docs/policies.md): clients enforce the ones that are theirs to.
  return ms.map((m) => ({ id: m.org.id, name: m.org.name, slug: m.org.slug, role: m.role, isDefault: m.org.id === d?.id, policies: clientPolicies(readPolicies(m.org.policies, getEntitlements(cfg, m.org))),
    // The logo's version (docs/branding.md): clients fetch /orgs/:id/logo?v=<it>; null when there's none.
    logoVersion: logoVersion(m.org.logo?.sha256) }));
}

/**
 * Who should own a team folder after its owner leaves the org: an editor (an org admin first, then the longest-standing),
 * else a viewer. Never a use-only member (ownership would show them every secret): then the folder goes to the trash.
 */
async function folderSuccessor(tx: Db, orgId: string, folderId: string, leavingId: string): Promise<string | null> {
  const members = await tx.folderMember.findMany({ where: { folderId, userId: { not: leavingId }, permission: { in: ["edit", "view"] } }, orderBy: { createdAt: "asc" }, select: { userId: true, permission: true } });
  if (!members.length) return null;
  const active = await tx.membership.findMany({ where: { orgId, status: "active", userId: { in: members.map((m) => m.userId) }, user: { status: "active" } }, select: { userId: true, role: true } });
  const roleOf = new Map(active.map((m) => [m.userId, m.role]));
  for (const p of ["edit", "view"] as const) {
    const tier = members.filter((m) => m.permission === p && roleOf.has(m.userId));
    const pick = tier.find((m) => isAdminRole(roleOf.get(m.userId)!)) ?? tier[0];
    if (pick) return pick.userId;
  }
  return null;
}

/**
 * Offboards a member from one organisation (docs/design/2026-10-07-multi-org-design.md §4), inside a
 * transaction. `remove`: they leave the org (folder memberships, shares and the membership go). `disable`: the
 * membership is disabled and their power in the org ends, but folder memberships stay for a later enable.
 */
export async function offboard(tx: Db, orgId: string, userId: string, mode: "remove" | "disable", now = new Date()): Promise<void> {
  if (mode === "remove") {
    const folders = await tx.folder.findMany({ where: { orgId, kind: "team", deletedAt: null, members: { some: { userId } } }, select: { id: true, ownerId: true } });
    for (const f of folders) {
      if (f.ownerId === userId) {
        const next = await folderSuccessor(tx, orgId, f.id, userId);
        if (!next) { await trashFolder(tx, f.id, now); continue; }
        await tx.folderMember.update({ where: { folderId_userId: { folderId: f.id, userId: next } }, data: { permission: "owner", directPermission: "owner" } });
        await tx.folder.update({ where: { id: f.id }, data: { ownerId: next } });
        await removeFolderMember(tx, f.id, next, userId);
      } else await removeFolderMember(tx, f.id, f.ownerId, userId);
    }
    // Direct shares made in this org, to them or from them, end with the membership.
    const shares = await tx.recordAccess.findMany({ where: { orgId, holderType: "user", OR: [{ holderId: userId }, { record: { ownerId: userId } }] }, select: { id: true, recordId: true, holderId: true } });
    if (shares.length) {
      await tx.recordAccess.deleteMany({ where: { id: { in: shares.map((s) => s.id) } } });
      const byHolder = new Map<string, string[]>();
      for (const s of shares) byHolder.set(s.holderId, [...(byHolder.get(s.holderId) ?? []), s.recordId]);
      for (const [holder, ids] of byHolder) await revokeLinksOfLostAccess(tx, holder, ids, now);
    }
    const u = await tx.user.findUnique({ where: { id: userId }, select: { email: true } });
    if (u) await tx.pendingFolderMember.deleteMany({ where: { email: u.email, folder: { orgId } } });
    if (u) await tx.pendingGroupMember.deleteMany({ where: { orgId, email: u.email } });
    // Their groups here go too (folder access through them ended above), and their password health report.
    await tx.groupMember.deleteMany({ where: { userId, group: { orgId } } });
    await tx.healthReport.deleteMany({ where: { orgId, userId } });
  }
  // Their links in this org, the escrows they hold as its admin (and, when leaving, their own), and recovery requests.
  await tx.shareLink.updateMany({ where: { createdBy: userId, orgId, revokedAt: null }, data: { revokedAt: now, ...BURN } });
  await tx.membershipEscrow.deleteMany({ where: { orgId, OR: [{ adminId: userId }, { userId }] } });
  // Leaving the org: its membership keys go with it (rows sealed to them went above).
  if (mode === "remove") await tx.membershipKey.deleteMany({ where: { orgId, userId } });
  await tx.groupAccessDecline.deleteMany({ where: { userId, folder: { orgId } } });
  await expireOpenRequests(tx, { orgId, userId });
  await expireOpenRequests(tx, { orgId, approvedBy: userId, status: "approved" });
  if (mode === "remove") await tx.membership.deleteMany({ where: { orgId, userId } });
  else await tx.membership.updateMany({ where: { orgId, userId }, data: { status: "disabled" } });
  await dropInstanceAdminIfGone(tx, orgId, userId);
}

/**
 * Serialises account-wide changes (joining an org, recovery requests, a scoped reset, membership key rotation): run
 * first in the transaction. Row lock on the account until commit.
 */
export async function lockUser(tx: Db, userId: string): Promise<void> {
  await tx.$queryRaw`SELECT id FROM "User" WHERE id = ${userId}::uuid FOR UPDATE`;
}

/**
 * Instance admin follows the main organisation: once the account is no longer an active owner or admin there (removed,
 * left, demoted, disabled), the flag goes, with an event. Run after such a change in the main org.
 */
export async function dropInstanceAdminIfGone(tx: Db, orgId: string, userId: string): Promise<boolean> {
  const d = await defaultOrg(tx);
  if (!d || d.id !== orgId) return false;
  const u = await tx.user.findUnique({ where: { id: userId }, select: { instanceAdmin: true } });
  if (!u?.instanceAdmin) return false;
  if (await tx.membership.findFirst({ where: { orgId, userId, status: "active", role: { in: ["owner", "admin"] } }, select: { id: true } })) return false;
  await tx.user.update({ where: { id: userId }, data: { instanceAdmin: false } });
  await logEvent(tx, { action: "instance.admin_revoked", targetUserId: userId, meta: { reason: "left_main_org_admins" } });
  return true;
}
