import type { Prisma } from "@prisma/client";
import type { Db } from "./access.js";

/**
 * Membership key pairs (docs/design/2026-10-08-per-org-keypairs.md). The server never holds a private key:
 * it stores each membership's public key and its private key wrapped under the account user key, and records which
 * key every sealed row (a member's copy of a folder key, a direct share) is addressed to (`sealedTo`).
 *
 * sealedTo: null = the member's current account key (before they had a membership key), a membership public key, or
 * "acct:<public key>" = an account key replaced by a scoped reset (only the archive's keys open it).
 */

export const ACCT_PREFIX = "acct:";
const B64 = /^[A-Za-z0-9_-]{43}$/;
/** A raw X25519 public key in base64url (32 bytes). */
export const isPublicKeyB64 = (s: string) => B64.test(s);

/** The member's current membership key in the org, if they have one. */
export async function currentKey(db: Db, orgId: string, userId: string) {
  return db.membershipKey.findFirst({ where: { orgId, userId, state: "current" } });
}

/** Current membership keys of these users in the org, by user id. */
export async function currentKeys(db: Db, orgId: string, userIds: string[]): Promise<Map<string, string>> {
  if (!userIds.length) return new Map();
  const rows = await db.membershipKey.findMany({ where: { orgId, userId: { in: [...new Set(userIds)] }, state: "current" }, select: { userId: true, publicKey: true } });
  return new Map(rows.map((r) => [r.userId, r.publicKey]));
}

/**
 * Whether a key sealed to `userId` in `orgId` is addressed correctly: to their current membership key when they have
 * one, otherwise to their account key (null). Anything else is a stale recipient key (the client refetches and seals again).
 */
export async function recipientKeyOk(db: Db, orgId: string, userId: string, sealedTo: string | null | undefined): Promise<boolean> {
  const cur = await currentKey(db, orgId, userId);
  return cur ? sealedTo === cur.publicKey : (sealedTo ?? null) === null;
}

/** The membership keys of these users in the org that still open rows (current or retiring). */
export async function liveKeys(db: Db, orgId: string, userIds: string[]): Promise<Set<string>> {
  const rows = userIds.length ? await db.membershipKey.findMany({ where: { orgId, userId: { in: [...new Set(userIds)] }, state: { in: ["current", "retiring"] } }, select: { publicKey: true } }) : [];
  return new Set(rows.map((r) => r.publicKey));
}
/**
 * A row only someone else can fix: sealed to an account key a scoped reset replaced, or to a membership key that was
 * archived (or is gone). (null rows are sealed to the member's current account key.)
 */
export const needsAccess = (sealedTo: string | null, live: Set<string>) => sealedTo !== null && (sealedTo.startsWith(ACCT_PREFIX) || !live.has(sealedTo));

/** Rows of this member in this org that their own client still has to move to the current key (account key or a retiring key). */
export async function blockingRowWhere(db: Db, orgId: string, userId: string) {
  const retiring = (await db.membershipKey.findMany({ where: { orgId, userId, state: "retiring" }, select: { publicKey: true } })).map((k) => k.publicKey);
  const sealed = [{ sealedTo: null }, { sealedTo: { in: retiring } }];
  const folder: Prisma.FolderMemberWhereInput = { userId, folder: { kind: "team", orgId }, OR: sealed };
  const share: Prisma.RecordAccessWhereInput = { holderType: "user", holderId: userId, permission: { not: "owner" }, orgId, OR: sealed };
  return { folder, share };
}

/** How many rows still block this membership from being recoverable. */
export async function blockingRows(db: Db, orgId: string, userId: string): Promise<number> {
  const w = await blockingRowWhere(db, orgId, userId);
  const [a, b] = await Promise.all([db.folderMember.count({ where: w.folder }), db.recordAccess.count({ where: w.share })]);
  return a + b;
}

/** Deletes retiring keys of this member in this org that no row and no escrow references any more. Returns how many. */
export async function dropUnusedRetiring(db: Db, orgId: string, userId: string): Promise<number> {
  const retiring = await db.membershipKey.findMany({ where: { orgId, userId, state: "retiring" }, select: { id: true, publicKey: true } });
  let n = 0;
  for (const k of retiring) {
    const used = (await db.folderMember.count({ where: { userId, sealedTo: k.publicKey } })) + (await db.recordAccess.count({ where: { holderId: userId, holderType: "user", sealedTo: k.publicKey } }))
      + (await db.membershipEscrow.count({ where: { orgId, adminId: userId, adminPublicKey: k.publicKey } }));
    if (!used) { await db.membershipKey.delete({ where: { id: k.id } }); n++; }
  }
  return n;
}

/**
 * Admin recovery for this membership is possible: a current key with no blocking rows. (Escrows are checked separately.)
 */
export async function recoverableKey(db: Db, orgId: string, userId: string): Promise<string | null> {
  const cur = await currentKey(db, orgId, userId);
  if (!cur || cur.userKeyGen !== (await db.user.findUniqueOrThrow({ where: { id: userId }, select: { userKeyGen: true } })).userKeyGen) return null;
  return (await blockingRows(db, orgId, userId)) === 0 ? cur.publicKey : null;
}

/** When a membership ends (removed from the org): its keys and the escrows of and by it go. */
export async function dropMembershipKeys(db: Db, orgId: string, userId: string): Promise<void> {
  await db.membershipEscrow.deleteMany({ where: { orgId, OR: [{ userId }, { adminId: userId }] } });
  await db.membershipKey.deleteMany({ where: { orgId, userId } });
}
