import type { Permission, UserKind } from "@prisma/client";
import { canEdit, capForAgent, maxPermission, type Db } from "./access.js";
import { removeFolderMember } from "./folderMembers.js";
import { revokeLinksOfLostAccess } from "./links.js";
import { currentKeys } from "./membershipKeys.js";

/**
 * Groups (docs/groups.md). A team folder shared with a group gives each group member access at the group's permission;
 * a `FolderMember` row carries the effective permission (the highest of the direct grant and every group grant) and the
 * direct grant on its own (`directPermission`, null when the access comes only through groups). The server never holds
 * a folder key, so group members without a row yet are "pending": someone who holds the key (owner or editor) approves
 * each one explicitly, seeing who it is, and their client seals the key to that person's membership key. Never
 * automatically: whoever manages groups (or a server inventing a group change) must not be able to collect folder keys.
 */

/** Row lock on the folder: every change to who can open it runs one at a time (run first in the transaction). */
export async function lockFolder(tx: Db, folderId: string): Promise<void> {
  await tx.$queryRaw`SELECT id FROM "Folder" WHERE id = ${folderId}::uuid FOR UPDATE`;
}

/** Row lock on a group (membership changes and deletion against grants and sealing). */
export async function lockGroup(tx: Db, groupId: string): Promise<void> {
  await tx.$queryRaw`SELECT id FROM "Group" WHERE id = ${groupId}::uuid FOR UPDATE`;
}

/** The highest permission the user's groups give on the folder, or null. */
export async function groupPermission(tx: Db, folderId: string, userId: string): Promise<Permission | null> {
  const rows = await tx.folderGroup.findMany({ where: { folderId, group: { members: { some: { userId } } } }, select: { permission: true } });
  return rows.reduce<Permission | null>((p, r) => maxPermission(p, r.permission), null);
}

/**
 * Brings one member's row in line with their direct and group grants: removed (offboarded) when neither is left, the
 * effective permission updated otherwise, and their one-time links revoked when they drop below edit. The folder owner's
 * row is never touched. Run inside a transaction holding the folder lock.
 */
export async function recomputeMember(tx: Db, folder: { id: string; ownerId: string }, userId: string): Promise<"removed" | "updated" | "same" | "none"> {
  const m = await tx.folderMember.findUnique({ where: { folderId_userId: { folderId: folder.id, userId } }, select: { permission: true, directPermission: true } });
  if (!m) return "none";
  if (m.permission === "owner" || userId === folder.ownerId) return "same";
  const max = maxPermission(m.directPermission === "owner" ? null : m.directPermission, await groupPermission(tx, folder.id, userId));
  if (!max) { await removeFolderMember(tx, folder.id, folder.ownerId, userId); return "removed"; }
  const eff = await capForAgent(tx, userId, max);
  if (eff === m.permission) return "same";
  await tx.folderMember.update({ where: { folderId_userId: { folderId: folder.id, userId } }, data: { permission: eff } });
  if (canEdit(m.permission) && !canEdit(eff)) {
    const ids = (await tx.record.findMany({ where: { folderId: folder.id }, select: { id: true } })).map((r) => r.id);
    await revokeLinksOfLostAccess(tx, userId, ids);
  }
  return "updated";
}

/** Recomputes the members of one folder (all of them, or `userIds`), locking it first. Returns the users removed. */
export async function recomputeFolder(tx: Db, folderId: string, userIds?: string[]): Promise<string[]> {
  await lockFolder(tx, folderId);
  const folder = await tx.folder.findUnique({ where: { id: folderId }, select: { id: true, ownerId: true } });
  if (!folder) return [];
  const ids = userIds ?? (await tx.folderMember.findMany({ where: { folderId }, select: { userId: true } })).map((m) => m.userId);
  const removed: string[] = [];
  for (const u of ids) if ((await recomputeMember(tx, folder, u)) === "removed") removed.push(u);
  return removed;
}

/** Recomputes every folder the group is shared with (for `userIds`, or every member). Folder ids → removed users. */
export async function recomputeGroupFolders(tx: Db, folderIds: string[], userIds?: string[]): Promise<Map<string, string[]>> {
  const out = new Map<string, string[]>();
  // Fixed order: two transactions touching the same folders lock them the same way round.
  for (const f of [...new Set(folderIds)].sort()) out.set(f, await recomputeFolder(tx, f, userIds));
  return out;
}

/**
 * `membershipKey`: what to seal to (null: their account key, no membership key yet). `declined`: a key holder said no.
 * `via`: each group that gives the access, with who added the person to it, so the approver sees who caused the request.
 */
export interface GroupPending {
  folderId: string; userId: string; name: string; email: string; publicKey: string; kind: UserKind; membershipKey: string | null; permission: Permission; groups: string[]; declined: boolean;
  via: { groupId: string; groupName: string; addedBy: { id: string; name: string } | null }[];
}

/**
 * Group members who should reach a folder but have no key yet, on the live team folders of `orgId` that `sealerId`
 * holds the key of with owner or edit rights (they can seal it). Only active accounts with an active membership.
 */
export async function pendingGroupAccess(db: Db, orgId: string, sealerId: string): Promise<GroupPending[]> {
  const mine = await db.folderMember.findMany({ where: { userId: sealerId, permission: { in: ["owner", "edit"] }, folder: { kind: "team", deletedAt: null, orgId, groups: { some: {} } } }, select: { folderId: true } });
  if (!mine.length) return [];
  const grants = await db.folderGroup.findMany({ where: { folderId: { in: mine.map((m) => m.folderId) } },
    select: { folderId: true, permission: true, group: { select: { id: true, name: true, members: { where: { user: { status: "active", memberships: { some: { orgId, status: "active" } } } },
      select: { addedBy: true, user: { select: { id: true, name: true, email: true, publicKey: true, kind: true } } } } } } } });
  const adderIds = [...new Set(grants.flatMap((g) => g.group.members.map((m) => m.addedBy)).filter((x): x is string => !!x))];
  const adders = new Map((adderIds.length ? await db.user.findMany({ where: { id: { in: adderIds } }, select: { id: true, name: true } }) : []).map((u) => [u.id, u]));
  const members = await db.folderMember.findMany({ where: { folderId: { in: mine.map((m) => m.folderId) } }, select: { folderId: true, userId: true } });
  const has = new Set(members.map((m) => `${m.folderId}:${m.userId}`));
  const declined = new Set((await db.groupAccessDecline.findMany({ where: { folderId: { in: mine.map((m) => m.folderId) } }, select: { folderId: true, userId: true } })).map((d) => `${d.folderId}:${d.userId}`));
  const out = new Map<string, GroupPending>();
  for (const g of grants) for (const { user, addedBy } of g.group.members) {
    const k = `${g.folderId}:${user.id}`;
    if (has.has(k)) continue;
    const via = { groupId: g.group.id, groupName: g.group.name, addedBy: addedBy ? adders.get(addedBy) ?? null : null };
    const cur = out.get(k);
    if (cur) { cur.permission = maxPermission(cur.permission, g.permission)!; cur.groups.push(g.group.name); cur.via.push(via); }
    else out.set(k, { folderId: g.folderId, userId: user.id, name: user.name, email: user.email, publicKey: user.publicKey, kind: user.kind, membershipKey: null, permission: g.permission, groups: [g.group.name], declined: declined.has(k), via: [via] });
  }
  const list = [...out.values()];
  const keys = await currentKeys(db, orgId, list.map((p) => p.userId));
  for (const p of list) {
    p.membershipKey = keys.get(p.userId) ?? null;
    if (p.kind === "agent") p.permission = "use"; // what approval will give it (addViaGroups caps it)
  }
  return list;
}
