import { CryptoError } from "./encoding.js";
import { decryptFolderName, encryptFolderName, unwrapKey, wrapKey } from "./records.js";
import { openFolderKey, openSharedRecordKey, type SealKeys } from "./sharing.js";
import { openOrgFolderKey, openOrgRecordShare, sealOrgFolderKey, sealOrgRecordShare, type MembershipKeys } from "./orgKeys.js";

/**
 * Client-side re-keying steps (docs/design/2026-10-08-per-org-keypairs.md, "Migration"): moving rows from
 * the account key to a membership key, rotating a membership key, and re-wrapping own items under a new user key.
 * Each function handles one row, so a migration can run in small batches and resume anywhere. The plaintext key
 * in between never leaves the function and is zeroed.
 */

async function withKey<T>(k: Uint8Array, f: (k: Uint8Array) => Promise<T>): Promise<T> {
  try { return await f(k); } finally { k.fill(0); }
}

/** Legacy → membership: a team folder key sealed to my account key, re-sealed to my membership key in its organisation. */
export async function resealFolderKeyToMembership(legacySealed: string, ids: { orgId: string; folderId: string }, account: SealKeys, to: MembershipKeys): Promise<string> {
  if (to.orgId !== ids.orgId) throw new CryptoError("bad_key", "membership key of another organisation");
  return withKey(await openFolderKey(legacySealed, ids.folderId, account), (k) => sealOrgFolderKey(k, ids, to.publicKey));
}

/** Legacy → membership: a direct share sealed to my account key, re-sealed to my membership key in the share's organisation. */
export async function resealRecordShareToMembership(legacySealed: string, ids: { orgId: string; recordId: string }, account: SealKeys, to: MembershipKeys): Promise<string> {
  if (to.orgId !== ids.orgId) throw new CryptoError("bad_key", "membership key of another organisation");
  return withKey(await openSharedRecordKey(legacySealed, ids.recordId, account), (k) => sealOrgRecordShare(k, ids, to.publicKey));
}

/** Rotation: a folder key sealed to my old membership key, re-sealed to my new one (same organisation). */
export async function rotateFolderKeySeal(sealed: string, ids: { orgId: string; folderId: string }, from: MembershipKeys, to: MembershipKeys): Promise<string> {
  if (to.orgId !== ids.orgId) throw new CryptoError("bad_key", "membership key of another organisation");
  return withKey(await openOrgFolderKey(sealed, ids, from), (k) => sealOrgFolderKey(k, ids, to.publicKey));
}

/** Rotation: a direct share sealed to my old membership key, re-sealed to my new one (same organisation). */
export async function rotateRecordShareSeal(sealed: string, ids: { orgId: string; recordId: string }, from: MembershipKeys, to: MembershipKeys): Promise<string> {
  if (to.orgId !== ids.orgId) throw new CryptoError("bad_key", "membership key of another organisation");
  return withKey(await openOrgRecordShare(sealed, ids, from), (k) => sealOrgRecordShare(k, ids, to.publicKey));
}

const recordKeyAad = (recordId: string) => `record-key:${recordId}`;

/** My owner row of a record, re-wrapped from an old user key to a new one (restoring items after a scoped reset). */
export async function rewrapOwnerRecordKey(recordId: string, wrapped: string, fromUserKey: Uint8Array, toUserKey: Uint8Array): Promise<string> {
  if (!wrapped.startsWith("v1.")) throw new CryptoError("bad_envelope", "owner rows are wrapped under the user key");
  const k = await unwrapKey(wrapped, fromUserKey, recordKeyAad(recordId));
  return withKey(k, async (rk) => { if (rk.length !== 32) throw new CryptoError("bad_key"); return wrapKey(rk, toUserKey, recordKeyAad(recordId)); });
}

/**
 * Repairs my owner row of a record in a team folder after a scoped reset: the record key comes from the folder's row
 * (under the folder key I can open again) and is wrapped under my new user key.
 */
export async function ownerRecordKeyFromFolder(recordId: string, folderWrapped: string, folderKey: Uint8Array, toUserKey: Uint8Array): Promise<string> {
  return rewrapOwnerRecordKey(recordId, folderWrapped, folderKey, toUserKey);
}

/** A private folder's name, re-encrypted from an old user key to a new one. */
export async function reencryptPrivateFolderName(folderId: string, encName: string, fromUserKey: Uint8Array, toUserKey: Uint8Array): Promise<string> {
  return encryptFolderName(folderId, await decryptFolderName(folderId, encName, fromUserKey), toUserKey);
}
