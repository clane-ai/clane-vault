import { b64url, concat, randomBytes, utf8, CryptoError } from "./encoding.js";

const PREFIX = "v1.";
const IV_LEN = 12;
const TAG_LEN = 16;

async function importAesKey(key: Uint8Array): Promise<CryptoKey> {
  if (key.length !== 32) throw new CryptoError("bad_key", "AES key must be 32 bytes");
  return crypto.subtle.importKey("raw", key as BufferSource, "AES-GCM", false, ["encrypt", "decrypt"]);
}

export async function aeadEncrypt(key: Uint8Array, plaintext: Uint8Array, aad: string): Promise<string> {
  const k = await importAesKey(key);
  const iv = randomBytes(IV_LEN);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv as BufferSource, additionalData: utf8.encode(aad) as BufferSource }, k, plaintext as BufferSource));
  return PREFIX + b64url.encode(concat(iv, ct));
}

export async function aeadDecrypt(key: Uint8Array, envelope: string, aad: string): Promise<Uint8Array> {
  if (!envelope.startsWith(PREFIX)) throw new CryptoError("bad_envelope", "unknown envelope version");
  const raw = b64url.decode(envelope.slice(PREFIX.length));
  if (raw.length < IV_LEN + TAG_LEN) throw new CryptoError("bad_envelope", "envelope too short");
  const k = await importAesKey(key);
  try {
    const pt = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: raw.slice(0, IV_LEN) as BufferSource, additionalData: utf8.encode(aad) as BufferSource }, k, raw.slice(IV_LEN) as BufferSource);
    return new Uint8Array(pt);
  } catch {
    throw new CryptoError("decrypt_failed");
  }
}
