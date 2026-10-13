import type { Db } from "./access.js";
import { revokeLinksForRecords, revokeLinksOfLostAccess } from "./links.js";

/**
 * Removes a member and offboards them from the folder's records (run inside a transaction): their own rows on
 * records in the folder go, records they owned there pass to the folder owner (who keeps the key via the folder),
 * and live one-time links they created on those records are revoked. Returns how many membership rows went.
 */
export async function removeFolderMember(tx: Db, folderId: string, folderOwnerId: string, userId: string): Promise<number> {
  const n = await tx.folderMember.deleteMany({ where: { folderId, userId } });
  if (n.count === 0) return 0;
  const ids = (await tx.record.findMany({ where: { folderId }, select: { id: true } })).map((r) => r.id);
  if (ids.length) {
    const handed = (await tx.record.findMany({ where: { id: { in: ids }, ownerId: userId }, select: { id: true } })).map((r) => r.id);
    await tx.recordAccess.deleteMany({ where: { recordId: { in: ids }, holderType: "user", holderId: userId } });
    if (handed.length) {
      await tx.record.updateMany({ where: { id: { in: handed } }, data: { ownerId: folderOwnerId } });
      // The new owner reaches these records through the folder wrap. A direct share they held (a sealed s1. row)
      // would otherwise be served as the key of a record they own, which clients rightly refuse.
      await tx.recordAccess.deleteMany({ where: { recordId: { in: handed }, holderType: "user", holderId: folderOwnerId, permission: { not: "owner" } } });
    }
    // One-time links they made on these records stop working with their access.
    await revokeLinksOfLostAccess(tx, userId, ids);
  }
  return n.count;
}

/** Moves a live folder and its live records to the trash, revoking their links and pending members. */
export async function trashFolder(tx: Db, folderId: string, now = new Date()): Promise<boolean> {
  const f = await tx.folder.updateMany({ where: { id: folderId, deletedAt: null }, data: { deletedAt: now } });
  if (!f.count) return false;
  const ids = (await tx.record.findMany({ where: { folderId, deletedAt: null }, select: { id: true } })).map((r) => r.id);
  await tx.record.updateMany({ where: { id: { in: ids } }, data: { deletedAt: now } });
  await revokeLinksForRecords(tx, ids, now);
  // People still waiting to join (bulk migration) can no longer be added.
  await tx.pendingFolderMember.deleteMany({ where: { folderId } });
  return true;
}
