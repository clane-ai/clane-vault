import { aeadDecrypt, aeadEncrypt } from "./aead.js";
import { b64url, concat, randomBytes, utf8, CryptoError } from "./encoding.js";
import { hkdf } from "./hkdf.js";
import type { AccountMaterial, UnlockedKeys } from "./account.js";

/**
 * Master-password recovery (docs/recovery.md).
 *
 * Recovery kit: a random 32-byte recovery key, shown once as a Crockford base32 code with a checksum group.
 * It wraps the user key (AAD binds the user id) and yields a separate auth value the server stores only as a hash,
 * so the server can check possession of the kit without ever being able to unwrap anything.
 *
 * Admin recovery (org policy, off by default) escrows a per-organisation membership key, never the user key: see
 * orgKeys.ts (docs/design/2026-10-08-per-org-keypairs.md). The link proof is derived here.
 */

const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"; // Crockford base32: no I, L, O, U
const KEY_BYTES = 32;
const KEY_CHARS = 52; // ceil(256 / 5); the last symbol carries 4 padding bits that must be zero
const CHECK_CHARS = 4; // 20-bit checksum
const GROUP = 4;
export const RECOVERY_CODE_GROUPS = (KEY_CHARS + CHECK_CHARS) / GROUP; // 14

export class RecoveryCodeError extends Error {
  constructor(public readonly reason: "format" | "checksum") {
    super(reason === "format" ? "not a recovery code" : "recovery code checksum does not match");
    this.name = "RecoveryCodeError";
  }
}

function toBase32(bytes: Uint8Array, chars: number): string {
  let out = "", acc = 0, bits = 0;
  for (const b of bytes) {
    acc = (acc << 8) | b; bits += 8;
    while (bits >= 5) { bits -= 5; out += ALPHABET[(acc >> bits) & 31]; }
    acc &= (1 << bits) - 1;
  }
  if (bits > 0) out += ALPHABET[(acc << (5 - bits)) & 31];
  return out.slice(0, chars);
}

async function checksum(key: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", concat(utf8.encode("clane-vault/recovery-code"), key) as BufferSource));
  return toBase32(digest.slice(0, 3), CHECK_CHARS);
}

const group = (s: string) => s.match(new RegExp(`.{1,${GROUP}}`, "g"))!.join("-");

/** The human form of a recovery key: 14 groups of 4 (13 key groups and a checksum group), e.g. `7K3M-…-Q9XA`. */
export async function formatRecoveryCode(key: Uint8Array): Promise<string> {
  if (key.length !== KEY_BYTES) throw new CryptoError("bad_key", "recovery key must be 32 bytes");
  return group(toBase32(key, KEY_CHARS) + (await checksum(key)));
}

/** Upper-cases, drops spaces and dashes, and maps look-alikes (O→0, I/L→1) the way Crockford base32 does. */
export function normalizeRecoveryCode(code: string): string {
  return code.toUpperCase().replace(/[\s-]/g, "").replace(/O/g, "0").replace(/[IL]/g, "1");
}

/** Parses a recovery code back to the 32-byte key. Throws RecoveryCodeError("format" | "checksum"). */
export async function parseRecoveryCode(code: string): Promise<Uint8Array> {
  const s = normalizeRecoveryCode(code);
  if (s.length !== KEY_CHARS + CHECK_CHARS) throw new RecoveryCodeError("format");
  const vals: number[] = [];
  for (const ch of s) {
    const v = ALPHABET.indexOf(ch);
    if (v < 0) throw new RecoveryCodeError("format");
    vals.push(v);
  }
  const key = new Uint8Array(KEY_BYTES);
  let acc = 0, bits = 0, o = 0;
  for (const v of vals.slice(0, KEY_CHARS)) {
    acc = (acc << 5) | v; bits += 5;
    if (bits >= 8) { bits -= 8; if (o < KEY_BYTES) key[o++] = (acc >> bits) & 255; }
    acc &= (1 << bits) - 1;
  }
  if (acc !== 0) throw new RecoveryCodeError("format"); // padding bits must be zero
  if ((await checksum(key)) !== s.slice(KEY_CHARS)) throw new RecoveryCodeError("checksum");
  return key;
}

/** The last group of a formatted code (what the kit screen asks people to type back). */
export const lastRecoveryGroup = (code: string) => code.split("-").at(-1) ?? "";

const empty = new Uint8Array(0);
const aadRecovery = (userId: string) => `recovery-user-key:${userId}`;

/** The value the server hashes and checks; derived from the recovery key, useless for unwrapping. */
export async function recoveryAuthFor(recoveryKey: Uint8Array): Promise<string> {
  return b64url.encode(await hkdf(recoveryKey, empty, "clane-vault/recovery-auth", 32));
}

export interface RecoveryKit { code: string; recoveryWrap: string; recoveryAuth: string }

/** A fresh kit for this user: the code to show once, and what the server stores (wrap + auth for hashing). */
export async function createRecoveryKit(userId: string, userKey: Uint8Array): Promise<RecoveryKit> {
  const recoveryKey = randomBytes(KEY_BYTES);
  try {
    const wrapKey = await hkdf(recoveryKey, empty, "clane-vault/recovery", 32);
    try {
      return { code: await formatRecoveryCode(recoveryKey), recoveryWrap: await aeadEncrypt(wrapKey, userKey, aadRecovery(userId)), recoveryAuth: await recoveryAuthFor(recoveryKey) };
    } finally { wrapKey.fill(0); }
  } finally { recoveryKey.fill(0); }
}

/** Unwraps the user key with a recovery key (from parseRecoveryCode). Fails for another user's wrap. */
export async function openRecoveryWrap(userId: string, recoveryKey: Uint8Array, recoveryWrap: string): Promise<Uint8Array> {
  const wrapKey = await hkdf(recoveryKey, empty, "clane-vault/recovery", 32);
  try { return await aeadDecrypt(wrapKey, recoveryWrap, aadRecovery(userId)); } finally { wrapKey.fill(0); }
}

/** Rebuilds the unlocked keys from a recovered user key; opening the private key proves the user key is the right one. */
export async function keysFromUserKey(userKey: Uint8Array, material: Pick<AccountMaterial, "publicKey" | "wrappedPrivateKey">): Promise<UnlockedKeys> {
  const privateKey = await aeadDecrypt(userKey, material.wrappedPrivateKey, `private-key:${material.publicKey}`);
  return { userKey, privateKey, publicKey: b64url.decode(material.publicKey) };
}

// ---- Admin recovery links ----
// Escrows and grants are of a membership key (orgKeys.ts): an admin restores one organisation, never the account key.
// The proof below is shared by every admin recovery link.

function fragmentSecret(fragment: string): Uint8Array {
  const s = b64url.decode(fragment);
  if (s.length !== 32) throw new CryptoError("bad_key", "recovery link secret must be 32 bytes");
  return s;
}

/** Member side: the proof to send for the link in hand. */
export async function adminRecoveryProof(fragment: string): Promise<string> {
  const secret = fragmentSecret(fragment);
  try { return b64url.encode(await hkdf(secret, empty, "clane-vault/admin-recovery-proof", 32)); } finally { secret.fill(0); }
}
