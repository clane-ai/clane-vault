import { CryptoError, randomBytes } from "./encoding.js";
import { encryptFolderName, unwrapKey } from "./records.js";
import { openSealed, sealTo } from "./seal.js";

/** The holder's asymmetric keys (an UnlockedKeys satisfies this). */
export interface SealKeys { privateKey: Uint8Array; publicKey: Uint8Array }

const aadFolderKey = (folderId: string) => `folder-key:${folderId}`;
const aadRecordShare = (recordId: string) => `record-share:${recordId}`;
const aadRecordKey = (recordId: string) => `record-key:${recordId}`;

function need32(k: Uint8Array): Uint8Array {
  if (k.length !== 32) throw new CryptoError("bad_key", "key must be 32 bytes");
  return k;
}
async function openSealedKey(sealed: string, aad: string, keys: SealKeys): Promise<Uint8Array> {
  if (!sealed.startsWith("s1.")) throw new CryptoError("bad_envelope", "expected a sealed box");
  return need32(await openSealed(keys.privateKey, keys.publicKey, sealed, aad));
}

/** A team folder key is sealed to each member's public key, bound to the folder id. */
export const sealFolderKeyFor = async (folderKey: Uint8Array, folderId: string, recipientPublicKey: Uint8Array) =>
  sealTo(recipientPublicKey, need32(folderKey), aadFolderKey(folderId));
export const openFolderKey = (wrappedFolderKey: string, folderId: string, keys: SealKeys) => openSealedKey(wrappedFolderKey, aadFolderKey(folderId), keys);

export async function createTeamFolder(folderId: string, name: string, myPublicKey: Uint8Array) {
  const folderKey = randomBytes(32);
  const encName = await encryptFolderName(folderId, name, folderKey);
  const wrappedFolderKey = await sealFolderKeyFor(folderKey, folderId, myPublicKey);
  return { folderKey, encName, wrappedFolderKey };
}

/** A direct share seals the record key to the recipient, bound to the record id. */
export const shareRecordKey = async (recordKey: Uint8Array, recordId: string, recipientPublicKey: Uint8Array) =>
  sealTo(recipientPublicKey, need32(recordKey), aadRecordShare(recordId));
export const openSharedRecordKey = (sealed: string, recordId: string, keys: SealKeys) => openSealedKey(sealed, aadRecordShare(recordId), keys);

export interface RecordKeyHolder { recordId: string; holderType: "user" | "folder"; wrappedRecordKey: string; folderId: string | null }

/**
 * Opens a record key whatever holds it:
 * - holderType "folder": a v1 envelope under that folder's key (never the user key);
 * - holderType "user" + "s1.": a direct share sealed to me;
 * - holderType "user" + "v1.": my own key wrapped under my user key.
 */
export async function openRecordKey(h: RecordKeyHolder, keys: SealKeys & { userKey: Uint8Array }, folderKeys: ReadonlyMap<string, Uint8Array>): Promise<Uint8Array> {
  if (h.holderType === "folder") {
    const fk = h.folderId ? folderKeys.get(h.folderId) : undefined;
    if (!fk) throw new CryptoError("bad_key", "folder key not available");
    if (!h.wrappedRecordKey.startsWith("v1.")) throw new CryptoError("bad_envelope");
    return need32(await unwrapKey(h.wrappedRecordKey, fk, aadRecordKey(h.recordId)));
  }
  if (h.wrappedRecordKey.startsWith("s1.")) return openSharedRecordKey(h.wrappedRecordKey, h.recordId, keys);
  if (h.wrappedRecordKey.startsWith("v1.")) return need32(await unwrapKey(h.wrappedRecordKey, keys.userKey, aadRecordKey(h.recordId)));
  throw new CryptoError("bad_envelope", "unknown key envelope");
}
