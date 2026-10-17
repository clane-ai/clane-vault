import type { Permission, PrismaClient } from "@prisma/client";
import type { Config } from "../config.js";
import { folderToRecordPermission, maxPermission, recordOrgOf } from "./access.js";
import { currentKeys, liveKeys, needsAccess } from "./membershipKeys.js";
import { agentAttestations } from "./agents.js";
import { attachmentConfig } from "./attachments/quota.js";
import { attachmentView, readyAttachments } from "./attachments/view.js";

type Row = { holderType: "user" | "folder"; holderId: string; permission: Permission; wrappedRecordKey: string | null; sealedTo: string | null };

/**
 * What a user can open in one space (docs/design/2026-10-07-multi-org-design.md, section 11): the body of GET /sync, and
 * of GET /agent/sync for an agent (`orgOnly`, never `locked`).
 *
 * - `orgId` null: the Personal space. Private folders and records only; owned records list the orgs they are shared in
 *   (`sharedIn`, ids only: the shares themselves live in those orgs).
 * - `orgOnly`: the organisation only. Its team folders the user belongs to and their records, and records shared
 *   directly in that org (to the user, or the user's own records they shared there). Nothing else personal.
 * - An org without `orgOnly` (clients before 1.3, such as older browser extensions): the org's items plus every private
 *   item, as before.
 * - `locked`: a session confined to one org (privateLock.ts).
 */
export async function syncFor(db: PrismaClient, cfg: Config, o: { userId: string; orgId: string | null; orgOnly: boolean; locked?: boolean }) {
  const { userId, orgId, orgOnly } = o;
  const locked = !!o.locked;
  const memberships = orgId
    ? await db.folderMember.findMany({ where: { userId, folder: { kind: "team", deletedAt: null, orgId } }, select: { folderId: true, permission: true, wrappedFolderKey: true, sealedTo: true } })
    : [];
  const teamIds = memberships.map((m) => m.folderId);
  const myFolderPerm = new Map(memberships.map((m) => [m.folderId, m.permission]));

  const [folders, members, access, grants] = await Promise.all([
    // A session confined to one org (trusted IdP MFA, no TOTP yet) gets no private folders or records of its own.
    db.folder.findMany({ where: { OR: [...(locked || orgOnly ? [] : [{ ownerId: userId, kind: "private" as const }]), { id: { in: teamIds } }] }, orderBy: { createdAt: "asc" } }),
    db.folderMember.findMany({ where: { folderId: { in: teamIds } }, include: { user: { select: { name: true, email: true, publicKey: true, kind: true } } }, orderBy: { createdAt: "asc" } }),
    // Only rows that name me (my owner rows, and shares made in this org), or a team folder of this org I am a member
    // of, are ever read: nothing else can reach the response.
    db.recordAccess.findMany({ where: { state: "active", OR: [
      { holderType: "user", holderId: userId, permission: "owner" },
      { holderType: "user", holderId: userId, permission: { not: "owner" }, orgId },
      { holderType: "folder", holderId: { in: teamIds } },
    ] }, select: { recordId: true, holderType: true, holderId: true, permission: true, wrappedRecordKey: true, sealedTo: true } }),
    // Groups the org's team folders I belong to are shared with (docs/groups.md).
    db.folderGroup.findMany({ where: { folderId: { in: teamIds } }, select: { folderId: true, permission: true, group: { select: { id: true, name: true, members: { select: { userId: true } } } } }, orderBy: { createdAt: "asc" } }),
  ]);

  // My membership keys here (wrapped under my user key) open what is sealed to them; members' current keys are what
  // to seal to, and rows sealed to a key someone lost show as needing access again (per-org key pairs design, §8).
  const user = await db.user.findUniqueOrThrow({ where: { id: userId }, select: { userKeyGen: true } });
  const myKeys = orgId ? await db.membershipKey.findMany({ where: { orgId, userId, state: { in: ["current", "retiring"] }, userKeyGen: user.userKeyGen }, orderBy: { createdAt: "asc" }, select: { publicKey: true, wrappedPrivateKey: true, state: true } }) : [];
  const memberIds = [...new Set(members.map((m) => m.userId))];
  const [memberKeys, live] = orgId ? await Promise.all([currentKeys(db, orgId, memberIds), liveKeys(db, orgId, memberIds)]) : [new Map<string, string>(), new Set<string>()];
  // Re-granting access seals to these keys: an agent's comes with the gateway's attestation (R41).
  const att = await agentAttestations(db, [...new Set(members.filter((m) => m.user.kind === "agent").map((m) => m.userId))]);

  const byRecord = new Map<string, Row[]>();
  for (const a of access) byRecord.set(a.recordId, [...(byRecord.get(a.recordId) ?? []), a]);
  // A record in another org's team folder stays out, even when I hold its owner row.
  let records = (await db.record.findMany({ where: { id: { in: [...byRecord.keys()] } }, include: { owner: { select: { name: true } }, folder: { select: { kind: true, orgId: true } } } }))
    .filter((r) => { const o = recordOrgOf(r); return (o === null || o === orgId) && !(locked && o === null && r.ownerId === userId); });
  if (orgOnly) {
    // The org's space: a private record only when it is shared in this org (to me, or mine shared to someone here).
    const privateIds = records.filter((r) => recordOrgOf(r) === null).map((r) => r.id);
    const sharedHere = new Set(privateIds.length ? (await db.recordAccess.findMany({ where: { recordId: { in: privateIds }, state: "active", holderType: "user", permission: { not: "owner" }, orgId },
      select: { recordId: true, holderId: true } })).filter((x) => x.holderId === userId || records.find((r) => r.id === x.recordId)!.ownerId === userId).map((x) => x.recordId) : []);
    records = records.filter((r) => recordOrgOf(r) !== null || sharedHere.has(r.id));
  }
  // I own a record if I hold its owner row, or if it sits in a live team folder I own (key via the folder row).
  const ownedTeams = new Set(memberships.filter((m) => m.permission === "owner").map((m) => m.folderId));
  const isMine = (r: { id: string; folderId: string | null }) => byRecord.get(r.id)!.some((x) =>
    (x.holderType === "user" && x.permission === "owner") || (x.holderType === "folder" && x.holderId === r.folderId && ownedTeams.has(x.holderId)));
  const ownedIds = records.filter(isMine).map((r) => r.id);
  const shares = ownedIds.length
    ? await db.recordAccess.findMany({ where: { recordId: { in: ownedIds }, holderType: "user", permission: { not: "owner" }, orgId }, select: { recordId: true, holderId: true, permission: true, sealedTo: true } })
    : [];
  const shareLive = orgId ? await liveKeys(db, orgId, shares.map((s) => s.holderId)) : new Set<string>();
  // The Personal space: which of my orgs each of my records is shared in (managed there).
  const sharedIn = new Map<string, string[]>();
  if (!orgId && ownedIds.length) {
    const rows = await db.recordAccess.findMany({ where: { recordId: { in: ownedIds }, state: "active", holderType: "user", permission: { not: "owner" },
      org: { memberships: { some: { userId, status: "active" } } } }, select: { recordId: true, orgId: true }, distinct: ["recordId", "orgId"] });
    for (const x of rows) if (x.orgId) sharedIn.set(x.recordId, [...(sharedIn.get(x.recordId) ?? []), x.orgId]);
  }
  const shareUsers = new Map((await db.user.findMany({ where: { id: { in: [...new Set(shares.map((s) => s.holderId))] } }, select: { id: true, name: true } })).map((u) => [u.id, u.name]));

  // Files on every record in the response: ciphertext metadata only (docs/design/2026-10-12-attachments.md §6.1).
  const files = await readyAttachments(db, attachmentConfig(cfg).enabled ? records.map((r) => r.id) : []);

  const membersOf = new Map<string, typeof members>();
  for (const m of members) membersOf.set(m.folderId, [...(membersOf.get(m.folderId) ?? []), m]);

  return {
    serverTime: new Date().toISOString(),
    ...(locked && !orgOnly ? { privateLocked: true } : {}),
    ...(orgId ? { orgId, membershipKeys: myKeys } : {}),
    folders: folders.map((f) => ({
      id: f.id, kind: f.kind, encName: f.encName, ownerId: f.ownerId, deletedAt: f.deletedAt?.toISOString() ?? null,
      ...(f.kind === "team" ? {
        wrappedFolderKey: memberships.find((m) => m.folderId === f.id)!.wrappedFolderKey,
        sealedTo: memberships.find((m) => m.folderId === f.id)!.sealedTo,
        myPermission: myFolderPerm.get(f.id)!,
        members: (membersOf.get(f.id) ?? []).map((m) => ({ userId: m.userId, name: m.user.name, email: m.user.email, publicKey: m.user.publicKey, kind: m.user.kind, membershipKey: memberKeys.get(m.userId) ?? null, permission: m.permission, directPermission: m.directPermission, ...att.get(m.userId),
          ...(needsAccess(m.sealedTo, live) ? { needsAccess: true } : {}) })),
        groups: grants.filter((g) => g.folderId === f.id).map((g) => ({ id: g.group.id, name: g.group.name, permission: g.permission, memberIds: g.group.members.map((x) => x.userId) })),
      } : {}),
    })),
    records: records.map((r) => {
      const rows = byRecord.get(r.id)!;
      const own = rows.find((x) => x.holderType === "user");
      const viaFolder = rows.find((x) => x.holderType === "folder" && x.holderId === r.folderId) ?? rows.find((x) => x.holderType === "folder");
      let permission: Permission | null = own?.permission ?? null;
      for (const x of rows) if (x.holderType === "folder") permission = maxPermission(permission, folderToRecordPermission(myFolderPerm.get(x.holderId)!));
      const isOwner = isMine(r);
      if (isOwner) permission = "owner";
      // My owner row first; when I own the record through a team folder I own, the folder wrap (never a sealed share);
      // otherwise my own row (direct share) or the folder wrap.
      const ownsViaFolder = isOwner && own?.permission !== "owner" && !!viaFolder;
      const holder = ownsViaFolder ? viaFolder! : own ?? viaFolder!;
      return {
        id: r.id, folderId: r.folderId, type: r.type, encBody: r.encBody, revision: r.revision,
        updatedAt: r.updatedAt.toISOString(), deletedAt: r.deletedAt?.toISOString() ?? null,
        permission: permission!, holderType: holder.holderType, wrappedRecordKey: holder.wrappedRecordKey!,
        keyFolderId: holder.holderType === "folder" ? holder.holderId : null,
        ...(holder.holderType === "user" && holder.permission !== "owner" ? { sealedTo: holder.sealedTo } : {}),
        ownerId: r.ownerId, ownerName: r.owner.name,
        ...(isOwner ? { sharedWith: shares.filter((s) => s.recordId === r.id).map((s) => ({ userId: s.holderId, name: shareUsers.get(s.holderId) ?? "", permission: s.permission, ...(needsAccess(s.sealedTo, shareLive) ? { needsAccess: true } : {}) })) } : {}),
        ...(sharedIn.has(r.id) ? { sharedIn: sharedIn.get(r.id) } : {}),
        ...(!isOwner && own ? { sharedBy: r.owner.name } : {}),
        attachments: (files.rows.get(r.id) ?? []).map((a) => attachmentView(a, files.names, permission!)),
      };
    }),
  };
}

export type SyncBody = Awaited<ReturnType<typeof syncFor>>;
