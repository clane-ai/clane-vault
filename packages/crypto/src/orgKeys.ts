import { aeadDecrypt, aeadEncrypt } from "./aead.js";
import { b64url, CryptoError, randomBytes } from "./encoding.js";
import { hkdf } from "./hkdf.js";
import { generateKeyPair, openSealed, sealTo } from "./seal.js";
import { openFolderKey, openSharedRecordKey, type SealKeys } from "./sharing.js";

/**
 * Per-organisation membership key pairs (docs/design/2026-10-08-per-org-keypairs.md).
 *
 * Every (user, organisation) membership has its own X25519 key pair. Its private key is wrapped under the account's
 * user key; everything the organisation can give the member (team folder keys, direct shares made in the org) is
 * sealed to the membership public key; admin recovery escrows only the membership private key. An organisation's
 * admins can therefore restore what the member holds in that organisation and nothing else.
 *
 * Every label binds the organisation id, so a key or envelope from one organisation never opens in another's context.
 */

/** An unlocked membership key pair. `orgId` is the organisation it belongs to (checked before every use). */
export interface MembershipKeys { orgId: string; publicKey: Uint8Array; privateKey: Uint8Array }
/** What the server stores per membership key: the public key (base64url) and the private key wrapped under the user key. */
export interface MembershipKeyMaterial { publicKey: string; wrappedPrivateKey: string }
export interface MembershipIds { orgId: string; userId: string }

export const membershipKeyAad = (orgId: string, userId: string, publicKeyB64: string) => `membership-private-key:${orgId}:${userId}:${publicKeyB64}`;
export const orgFolderKeyAad = (orgId: string, folderId: string) => `org-folder-key:${orgId}:${folderId}`;
export const orgRecordShareAad = (orgId: string, recordId: string) => `org-record-share:${orgId}:${recordId}`;
export const membershipEscrowAad = (orgId: string, userId: string, adminId: string, memberPublicKeyB64: string) =>
  `escrow-membership-key:${orgId}:${userId}:${adminId}:${memberPublicKeyB64}`;
export const membershipRecoveryAad = (requestId: string, orgId: string, userId: string, memberPublicKeyB64: string) =>
  `admin-recovery-membership:${requestId}:${orgId}:${userId}:${memberPublicKeyB64}`;

const BASEPOINT = (() => { const b = new Uint8Array(32); b[0] = 9; return b; })();

/** The X25519 public key of a PKCS#8 private key (scalar multiplication with the base point). */
export async function publicKeyFromPrivateKey(privatePkcs8: Uint8Array): Promise<Uint8Array> {
  try {
    const priv = await crypto.subtle.importKey("pkcs8", privatePkcs8 as BufferSource, { name: "X25519" }, false, ["deriveBits"]);
    const base = await crypto.subtle.importKey("raw", BASEPOINT as BufferSource, { name: "X25519" }, false, []);
    return new Uint8Array(await crypto.subtle.deriveBits({ name: "X25519", public: base }, priv, 256));
  } catch {
    throw new CryptoError("bad_key", "invalid X25519 private key");
  }
}

const sameBytes = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);

/** Throws `bad_key` unless the private key belongs to the public key. */
export async function assertKeyPair(privateKey: Uint8Array, publicKey: Uint8Array): Promise<void> {
  if (!sameBytes(await publicKeyFromPrivateKey(privateKey), publicKey)) throw new CryptoError("bad_key", "private key does not match the public key");
}

function need32(k: Uint8Array): Uint8Array {
  if (k.length !== 32) throw new CryptoError("bad_key", "key must be 32 bytes");
  return k;
}
function sameOrg(keys: MembershipKeys, orgId: string): MembershipKeys {
  if (keys.orgId !== orgId) throw new CryptoError("bad_key", "membership key of another organisation");
  return keys;
}

/** Wraps a membership private key under the (current) user key, bound to org, user and public key. */
export async function wrapMembershipKeys(userKey: Uint8Array, ids: MembershipIds, keys: MembershipKeys): Promise<MembershipKeyMaterial> {
  sameOrg(keys, ids.orgId);
  const publicKey = b64url.encode(keys.publicKey);
  return { publicKey, wrappedPrivateKey: await aeadEncrypt(userKey, keys.privateKey, membershipKeyAad(ids.orgId, ids.userId, publicKey)) };
}

/** A fresh membership key pair for this user in this organisation, and its material for the server. */
export async function createMembershipKeys(userKey: Uint8Array, ids: MembershipIds): Promise<{ keys: MembershipKeys; material: MembershipKeyMaterial }> {
  const kp = await generateKeyPair();
  const keys: MembershipKeys = { orgId: ids.orgId, ...kp };
  return { keys, material: await wrapMembershipKeys(userKey, ids, keys) };
}

/** Unwraps a membership key pair and checks that the private key really is the stored public key's. */
export async function unlockMembershipKeys(userKey: Uint8Array, ids: MembershipIds, material: MembershipKeyMaterial): Promise<MembershipKeys> {
  const privateKey = await aeadDecrypt(userKey, material.wrappedPrivateKey, membershipKeyAad(ids.orgId, ids.userId, material.publicKey));
  const publicKey = b64url.decode(material.publicKey);
  await assertKeyPair(privateKey, publicKey);
  return { orgId: ids.orgId, publicKey, privateKey };
}

// ---- Sealing to a membership ----

/** A team folder key sealed to a member's membership public key, bound to the organisation and the folder. */
export const sealOrgFolderKey = async (folderKey: Uint8Array, ids: { orgId: string; folderId: string }, recipientMembershipPublicKey: Uint8Array) =>
  sealTo(recipientMembershipPublicKey, need32(folderKey), orgFolderKeyAad(ids.orgId, ids.folderId));

export async function openOrgFolderKey(sealed: string, ids: { orgId: string; folderId: string }, keys: MembershipKeys): Promise<Uint8Array> {
  sameOrg(keys, ids.orgId);
  if (!sealed.startsWith("s1.")) throw new CryptoError("bad_envelope", "expected a sealed box");
  return need32(await openSealed(keys.privateKey, keys.publicKey, sealed, orgFolderKeyAad(ids.orgId, ids.folderId)));
}

/** A direct share made in an organisation: the record key sealed to the recipient's membership key there. */
export const sealOrgRecordShare = async (recordKey: Uint8Array, ids: { orgId: string; recordId: string }, recipientMembershipPublicKey: Uint8Array) =>
  sealTo(recipientMembershipPublicKey, need32(recordKey), orgRecordShareAad(ids.orgId, ids.recordId));

export async function openOrgRecordShare(sealed: string, ids: { orgId: string; recordId: string }, keys: MembershipKeys): Promise<Uint8Array> {
  sameOrg(keys, ids.orgId);
  if (!sealed.startsWith("s1.")) throw new CryptoError("bad_envelope", "expected a sealed box");
  return need32(await openSealed(keys.privateKey, keys.publicKey, sealed, orgRecordShareAad(ids.orgId, ids.recordId)));
}

/**
 * Which key a sealed row is addressed to, as the server records it: `null` for the account key (rows from before
 * the migration), otherwise the base64url membership public key.
 */
export type SealedTo = string | null;
/** The caller's unlocked membership keys, by base64url public key (several during a rotation). */
export type MembershipKeyring = ReadonlyMap<string, MembershipKeys>;

function membershipFor(ring: MembershipKeyring, sealedTo: string, orgId: string): MembershipKeys {
  const k = ring.get(sealedTo);
  if (!k) throw new CryptoError("bad_key", "membership key not available");
  return sameOrg(k, orgId);
}

/** Opens my copy of a team folder key, whether it is still sealed to my account key or already to a membership key. */
export async function openTeamFolderKey(row: { orgId: string; folderId: string; wrappedFolderKey: string; sealedTo: SealedTo }, account: SealKeys, ring: MembershipKeyring): Promise<Uint8Array> {
  if (row.sealedTo === null) return openFolderKey(row.wrappedFolderKey, row.folderId, account);
  return openOrgFolderKey(row.wrappedFolderKey, row, membershipFor(ring, row.sealedTo, row.orgId));
}

/** Opens a record key shared with me directly in an organisation (legacy: sealed to my account key). */
export async function openSharedRecordKeyInOrg(row: { orgId: string; recordId: string; wrappedRecordKey: string; sealedTo: SealedTo }, account: SealKeys, ring: MembershipKeyring): Promise<Uint8Array> {
  if (row.sealedTo === null) return openSharedRecordKey(row.wrappedRecordKey, row.recordId, account);
  return openOrgRecordShare(row.wrappedRecordKey, row, membershipFor(ring, row.sealedTo, row.orgId));
}

// ---- Admin recovery of a membership ----

/** Seals the member's membership private key to one admin's membership public key in the same organisation. */
export async function sealMembershipEscrow(adminMembershipPublicKey: Uint8Array, member: MembershipKeys, ids: { userId: string; adminId: string }): Promise<string> {
  if (ids.userId === ids.adminId) throw new CryptoError("bad_key", "no escrow to oneself");
  return sealTo(adminMembershipPublicKey, member.privateKey, membershipEscrowAad(member.orgId, ids.userId, ids.adminId, b64url.encode(member.publicKey)));
}

/**
 * Admin side: opens an escrow addressed to this admin's membership key (organisation taken from it) and checks that
 * it is the private key of `memberPublicKeyB64`, the member's current membership key as the server lists it.
 */
export async function openMembershipEscrow(admin: MembershipKeys, sealed: string, ids: { userId: string; adminId: string }, memberPublicKeyB64: string): Promise<MembershipKeys> {
  const privateKey = await openSealed(admin.privateKey, admin.publicKey, sealed, membershipEscrowAad(admin.orgId, ids.userId, ids.adminId, memberPublicKeyB64));
  const publicKey = b64url.decode(memberPublicKeyB64);
  await assertKeyPair(privateKey, publicKey);
  return { orgId: admin.orgId, publicKey, privateKey };
}

const empty = new Uint8Array(0);
async function membershipGrantKeys(secret: Uint8Array) {
  // The proof uses the same label as account recovery links, so `adminRecoveryProof(fragment)` serves both.
  const [wrapKey, proof] = await Promise.all([hkdf(secret, empty, "clane-vault/admin-recovery-membership", 32), hkdf(secret, empty, "clane-vault/admin-recovery-proof", 32)]);
  return { wrapKey, proof: b64url.encode(proof) };
}
function fragmentSecret(fragment: string): Uint8Array {
  const s = b64url.decode(fragment);
  if (s.length !== 32) throw new CryptoError("bad_key", "recovery link secret must be 32 bytes");
  return s;
}

export interface MembershipRecoveryGrant {
  /** URL fragment (without `#`): the one-time secret R. Never sent to the server. */
  fragment: string;
  /** The membership private key wrapped under HKDF(R), bound to the request, organisation, user and public key. */
  wrappedMembershipKey: string;
  /** HKDF(R, proof): the server stores only its hash (same derivation as `adminRecoveryProof`). */
  proof: string;
}

/** Admin side: re-wraps a member's membership private key (from `openMembershipEscrow`) under a fresh link secret. */
export async function createMembershipRecoveryGrant(requestId: string, ids: MembershipIds, member: MembershipKeys): Promise<MembershipRecoveryGrant> {
  sameOrg(member, ids.orgId);
  const secret = randomBytes(32);
  const { wrapKey, proof } = await membershipGrantKeys(secret);
  try {
    const aad = membershipRecoveryAad(requestId, ids.orgId, ids.userId, b64url.encode(member.publicKey));
    return { fragment: b64url.encode(secret), wrappedMembershipKey: await aeadEncrypt(wrapKey, member.privateKey, aad), proof };
  } finally { wrapKey.fill(0); secret.fill(0); }
}

/** Member side: unwraps the membership key from the released blob and checks it against the expected public key. */
export async function openMembershipRecoveryGrant(requestId: string, ids: MembershipIds, fragment: string, wrappedMembershipKey: string, memberPublicKeyB64: string): Promise<MembershipKeys> {
  const secret = fragmentSecret(fragment);
  const { wrapKey } = await membershipGrantKeys(secret);
  secret.fill(0);
  let privateKey: Uint8Array;
  try { privateKey = await aeadDecrypt(wrapKey, wrappedMembershipKey, membershipRecoveryAad(requestId, ids.orgId, ids.userId, memberPublicKeyB64)); }
  finally { wrapKey.fill(0); }
  const publicKey = b64url.decode(memberPublicKeyB64);
  await assertKeyPair(privateKey, publicKey);
  return { orgId: ids.orgId, publicKey, privateKey };
}
