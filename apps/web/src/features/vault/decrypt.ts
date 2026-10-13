import {
  decryptFolderName, decryptRecordBody, openFolderKey, openRecordKey, openSharedRecordKeyInOrg, openTeamFolderKey, unlockMembershipKeys,
  type MembershipKeys, type UnlockedKeys,
} from "@clane-vault/crypto";
import type { SyncResponse, VaultFolder, VaultRecord } from "./types";

/**
 * Opens a sync response. Team folder keys are sealed to my membership key in the org (or, from before it existed, to
 * my account key); record keys are wrapped under my user key, under a team folder key, or sealed to me by whoever
 * shared the record. Every item fails on its own.
 *
 * `orgId` is the org this client asked for (X-Org-Id), never the server's word: membership keys and everything sealed
 * to them are bound to it (docs/design/2026-10-08-per-org-keypairs.md). The membership private keys are
 * zeroed before returning; `membershipKey` is my current membership public key there (what others seal to).
 */
export async function decryptSync(sync: SyncResponse, keys: UnlockedKeys, myId?: string, orgId?: string | null): Promise<{ folders: VaultFolder[]; records: VaultRecord[]; membershipKey: string | null }> {
  const ring = new Map<string, MembershipKeys>();
  let membershipKey: string | null = null;
  if (orgId && myId) for (const k of sync.membershipKeys ?? []) {
    // A key that doesn't unwrap under my user key, or whose private key isn't the listed public key, is never used.
    try { ring.set(k.publicKey, await unlockMembershipKeys(keys.userKey, { orgId, userId: myId }, k)); if (k.state === "current") membershipKey = k.publicKey; }
    catch { /* skipped */ }
  }
  try {
    const folderKeys = new Map<string, Uint8Array>();
    const folders = await Promise.all(sync.folders.map(async (f): Promise<VaultFolder> => {
      const base = { id: f.id, kind: f.kind, deleted: f.deletedAt !== null, ownerId: f.ownerId };
      if (f.kind !== "team") return { ...base, myPermission: "owner", name: await decryptFolderName(f.id, f.encName, keys.userKey).catch(() => "Can't open this folder") };
      // Without an org (old callers), only copies sealed to my account key can open.
      const folderKey = !f.wrappedFolderKey ? null
        : orgId ? await openTeamFolderKey({ orgId, folderId: f.id, wrappedFolderKey: f.wrappedFolderKey, sealedTo: f.sealedTo ?? null }, keys, ring).catch(() => null)
        : f.sealedTo ? null : await openFolderKey(f.wrappedFolderKey, f.id, keys).catch(() => null);
      if (folderKey) folderKeys.set(f.id, folderKey);
      return {
        ...base, myPermission: f.myPermission ?? "view", members: f.members ?? [], groups: f.groups ?? [], folderKey,
        name: folderKey ? await decryptFolderName(f.id, f.encName, folderKey).catch(() => "Can't open this folder") : "Can't open this folder",
      };
    }));
    const records = await Promise.all(sync.records.map(async (r): Promise<VaultRecord> => {
      const base = { id: r.id, folderId: r.folderId, type: r.type, revision: r.revision, updatedAt: r.updatedAt, deleted: r.deletedAt !== null, permission: r.permission,
        ownerId: r.ownerId, ownerName: r.ownerName, sharedWith: r.sharedWith, sharedBy: r.sharedBy, ...(r.sharedIn ? { sharedIn: r.sharedIn } : {}),
        attachments: r.attachments ?? [] };
      try {
        // My own records are always wrapped under my user key (v1.). A sealed box there would be one the server
        // planted (anyone can seal to my public key), so it is refused rather than trusted as mine.
        if (myId && r.ownerId === myId && r.wrappedRecordKey.startsWith("s1.")) throw new Error("sealed key on own record");
        const sharedInOrg = r.holderType === "user" && r.wrappedRecordKey.startsWith("s1.") && r.sealedTo;
        const recordKey = sharedInOrg
          ? await (orgId ? openSharedRecordKeyInOrg({ orgId, recordId: r.id, wrappedRecordKey: r.wrappedRecordKey, sealedTo: r.sealedTo! }, keys, ring) : Promise.reject(new Error("no org")))
          : await openRecordKey({ recordId: r.id, holderType: r.holderType, wrappedRecordKey: r.wrappedRecordKey, folderId: r.keyFolderId ?? r.folderId }, keys, folderKeys);
        try { return { ...base, body: await decryptRecordBody(r.id, r.encBody, recordKey), recordKey }; }
        catch (e) { recordKey.fill(0); throw e; }
      } catch {
        return { ...base, body: null, recordKey: null, error: "cannot_open" };
      }
    }));
    return { folders, records, membershipKey };
  } finally {
    for (const k of ring.values()) k.privateKey.fill(0);
  }
}
