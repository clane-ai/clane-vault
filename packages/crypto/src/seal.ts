import { aeadDecrypt, aeadEncrypt } from "./aead.js";
import { b64url, concat, CryptoError } from "./encoding.js";
import { hkdf } from "./hkdf.js";

export async function generateKeyPair(): Promise<{ publicKey: Uint8Array; privateKey: Uint8Array }> {
  const kp = (await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"])) as CryptoKeyPair;
  return {
    publicKey: new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey)),
    privateKey: new Uint8Array(await crypto.subtle.exportKey("pkcs8", kp.privateKey)),
  };
}

async function shared(privatePkcs8: Uint8Array, publicRaw: Uint8Array): Promise<Uint8Array> {
  try {
    const priv = await crypto.subtle.importKey("pkcs8", privatePkcs8 as BufferSource, { name: "X25519" }, false, ["deriveBits"]);
    const pub = await crypto.subtle.importKey("raw", publicRaw as BufferSource, { name: "X25519" }, false, []);
    return new Uint8Array(await crypto.subtle.deriveBits({ name: "X25519", public: pub }, priv, 256));
  } catch {
    throw new CryptoError("bad_key", "invalid X25519 key");
  }
}

export async function sealTo(recipientPublicKey: Uint8Array, plaintext: Uint8Array, aad: string): Promise<string> {
  const eph = await generateKeyPair();
  const secret = await shared(eph.privateKey, recipientPublicKey);
  const key = await hkdf(secret, concat(eph.publicKey, recipientPublicKey), "clane-vault/seal", 32);
  return `s1.${b64url.encode(eph.publicKey)}.${await aeadEncrypt(key, plaintext, aad)}`;
}

export async function openSealed(privateKey: Uint8Array, recipientPublicKey: Uint8Array, sealed: string, aad: string): Promise<Uint8Array> {
  const parts = sealed.split(".");
  if (parts[0] !== "s1" || parts.length !== 4) throw new CryptoError("bad_envelope", "not a sealed box");
  const ephPub = b64url.decode(parts[1]!);
  const secret = await shared(privateKey, ephPub);
  const key = await hkdf(secret, concat(ephPub, recipientPublicKey), "clane-vault/seal", 32);
  return aeadDecrypt(key, `${parts[2]}.${parts[3]}`, aad);
}

export async function keyFingerprint(publicKey: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", publicKey as BufferSource)).slice(0, 10);
  const hex = Array.from(digest, (b) => b.toString(16).padStart(2, "0")).join("");
  return hex.match(/.{4}/g)!.join("-");
}
