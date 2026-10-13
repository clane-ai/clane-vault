import { createHash, timingSafeEqual } from "node:crypto";
import { accessFor, canEdit, type Db } from "./access.js";

/** Everything a dead link no longer needs: the ciphertext and the password check material. */
export const BURN = { encPayload: null, passwordSalt: null, accessHash: null } as const;

/** Server-side form of the client's access hash. The input is already a 256-bit HKDF output, so SHA-256 is enough. */
export const hashAccess = (accessHash: string) => createHash("sha256").update(accessHash, "utf8").digest("hex");
export function accessMatches(stored: string, given: string | undefined): boolean {
  if (!given) return false;
  const a = Buffer.from(stored, "hex"), b = Buffer.from(hashAccess(given), "hex");
  return a.length === b.length && timingSafeEqual(a, b);
}

export type LinkState = { encPayload: string | null; expiresAt: Date; maxOpens: number | null; opens: number; revokedAt: Date | null; recordDeletedAt?: Date | null };
/** Why a link can no longer be opened, or null if it can. A trashed record counts as revoked. */
export function deadReason(l: LinkState, now = new Date()): "revoked" | "expired" | "used_up" | null {
  if (l.revokedAt || l.recordDeletedAt) return "revoked";
  if (l.maxOpens != null && l.opens >= l.maxOpens) return "used_up";
  if (l.expiresAt <= now) return "expired";
  if (l.encPayload == null) return "expired";
  return null;
}

/** Revokes every live link on the given records (used when records go to the trash). */
export async function revokeLinksForRecords(db: Db, recordIds: string[], now = new Date()): Promise<number> {
  if (!recordIds.length) return 0;
  return (await db.shareLink.updateMany({ where: { recordId: { in: recordIds }, revokedAt: null }, data: { revokedAt: now, ...BURN } })).count;
}

/**
 * Revokes the live links `userId` created on these records wherever they no longer hold edit (or owner) access:
 * a link is only as good as its creator's right to hand the secret out. Run after removing a share or a folder
 * membership (or downgrading one), inside the same transaction when there is one.
 */
export async function revokeLinksOfLostAccess(db: Db, userId: string, recordIds: string[], now = new Date()): Promise<number> {
  if (!recordIds.length) return 0;
  const live = await db.shareLink.findMany({ where: { createdBy: userId, recordId: { in: recordIds }, revokedAt: null }, select: { recordId: true }, distinct: ["recordId"] });
  const lost: string[] = [];
  for (const { recordId } of live) {
    const a = await accessFor(db, userId, recordId);
    if (!a || !canEdit(a.permission)) lost.push(recordId);
  }
  if (!lost.length) return 0;
  return (await db.shareLink.updateMany({ where: { createdBy: userId, recordId: { in: lost }, revokedAt: null }, data: { revokedAt: now, ...BURN } })).count;
}

/** Deletes ciphertext and password material of links that have expired. Returns how many rows changed. */
export async function sweepExpiredLinks(db: Db, now = new Date()): Promise<number> {
  const r = await db.shareLink.updateMany({
    where: { expiresAt: { lte: now }, OR: [{ encPayload: { not: null } }, { passwordSalt: { not: null } }, { accessHash: { not: null } }] },
    data: BURN,
  });
  return r.count;
}

export const SWEEP_INTERVAL_MS = 10 * 60_000;
export { isUniqueViolation } from "./access.js";
