import type { Permission, Prisma, PrismaClient } from "@prisma/client";

/** The client or an interactive transaction: access checks also run inside transactions. */
export type Db = PrismaClient | Prisma.TransactionClient;

const RANK: Record<Permission, number> = { use: 1, view: 2, edit: 3, owner: 4 };
export const maxPermission = (a: Permission | null, b: Permission | null): Permission | null =>
  a === null ? b : b === null ? a : RANK[a] >= RANK[b] ? a : b;

/** A folder membership counts at most as edit on a record; folder owners get record ownership separately (accessFor). */
export const folderToRecordPermission = (p: Permission): Permission => (p === "owner" ? "edit" : p);

/** A record's organisation: its team folder's, or null for a private record (no folder or a private folder). */
export const recordOrgOf = (r: { folder: { kind: string; orgId: string | null } | null }) => (r.folder?.kind === "team" ? r.folder.orgId : null);

/**
 * Effective permission of a user on a record: the max over the user's own row (owner or direct share)
 * and the folder row of any live team folder the user is a member of. `isOwner` (trash, purge, share, move)
 * is true for the holder of the record's owner row, and for the owner of the live team folder the record is in
 * (who reaches the key through the folder row).
 *
 * Organisations (docs/design/2026-10-07-multi-org-design.md): `orgId` is the caller's active org (null: none).
 * A record in another org's team folder is out of reach, and a direct share counts only in the org it was made in.
 * `orgId: undefined` (internal checks such as link revocation) evaluates in the record's own context.
 * `orgId` in the result is the org the access comes through (null: the caller's own private record).
 */
export async function accessFor(prisma: Db, userId: string, recordId: string, orgId?: string | null): Promise<{ permission: Permission; isOwner: boolean; ownerRow: boolean; orgId: string | null } | null> {
  const rec = await prisma.record.findUnique({ where: { id: recordId }, select: { folder: { select: { kind: true, orgId: true } } } });
  if (!rec) return null;
  const recOrg = recordOrgOf(rec);
  if (orgId !== undefined && recOrg !== null && recOrg !== orgId) return null;
  const rows = await prisma.recordAccess.findMany({ where: { recordId, state: "active" }, select: { holderType: true, holderId: true, permission: true, orgId: true } });
  let permission: Permission | null = null;
  let ownerRow = false;
  let via: string | null = recOrg;
  const folderIds: string[] = [];
  for (const r of rows) {
    if (r.holderType === "user" && r.holderId === userId) {
      if (r.permission === "owner") { ownerRow = true; permission = maxPermission(permission, r.permission); continue; }
      // A direct share: only in the org it was made in (internal checks: wherever it was made).
      if (orgId !== undefined && r.orgId !== orgId) continue;
      permission = maxPermission(permission, r.permission);
      if (recOrg === null) via = r.orgId;
    } else if (r.holderType === "folder") folderIds.push(r.holderId);
  }
  let folderOwner = false;
  if (folderIds.length && recOrg !== null) {
    const m = await prisma.folderMember.findMany({ where: { userId, folderId: { in: folderIds }, folder: { kind: "team", deletedAt: null, orgId: recOrg } }, select: { folderId: true, permission: true } });
    for (const x of m) permission = maxPermission(permission, folderToRecordPermission(x.permission));
    const owned = m.filter((x) => x.permission === "owner").map((x) => x.folderId);
    if (owned.length) folderOwner = !!(await prisma.record.findFirst({ where: { id: recordId, folderId: { in: owned } }, select: { id: true } }));
  }
  if (folderOwner) permission = "owner";
  if (ownerRow && recOrg === null) via = null;
  return permission ? { permission, isOwner: ownerRow || folderOwner, ownerRow, orgId: via } : null;
}
export const canEdit = (p: Permission) => p === "owner" || p === "edit";

/** The caller's membership of a live team folder of the active org (none: no team folder is reachable), or null. */
export async function teamMembership(prisma: PrismaClient, userId: string, folderId: string, orgId: string | null) {
  if (!orgId) return null;
  return prisma.folderMember.findFirst({ where: { folderId, userId, folder: { kind: "team", deletedAt: null, orgId } }, select: { permission: true, wrappedFolderKey: true } });
}

/** An active account with an active membership in `orgId` (share and member pickers, folder members, shares). */
export const activeMember = (prisma: Db, userId: string, orgId: string) =>
  prisma.user.findFirst({ where: { id: userId, status: "active", memberships: { some: { orgId, status: "active" } } }, select: { id: true, name: true, email: true } });

export const permissionRank = (p: Permission) => RANK[p];

/** "use" for an agent user, `permission` unchanged for a person (agents hold Use only: docs/agents.md). */
export async function capForAgent(db: Db, userId: string, permission: Permission): Promise<Permission> {
  if (permission === "use") return permission;
  const u = await db.user.findUnique({ where: { id: userId }, select: { kind: true } });
  return u?.kind === "agent" ? "use" : permission;
}

/** Prisma unique-constraint violation (a concurrent duplicate insert). */
export const isUniqueViolation = (e: unknown) => typeof e === "object" && e !== null && (e as { code?: string }).code === "P2002";
