import { aeadDecrypt, aeadEncrypt } from "./aead.js";
import { b64url, randomBytes } from "./encoding.js";
import { DEFAULT_KDF, deriveLoginKeys, type KdfParams } from "./kdf.js";
import { generateKeyPair } from "./seal.js";

export interface AccountMaterial { kdfSalt: string; kdfParams: KdfParams; wrappedUserKey: string; publicKey: string; wrappedPrivateKey: string }
export interface UnlockedKeys { userKey: Uint8Array; privateKey: Uint8Array; publicKey: Uint8Array }

const AAD_USER_KEY = "user-key";
const aadPrivateKey = (publicKeyB64: string) => `private-key:${publicKeyB64}`;

export async function createAccount(password: string, params: KdfParams = DEFAULT_KDF) {
  const kdfSalt = b64url.encode(randomBytes(16));
  const { authKey, wrapKey } = await deriveLoginKeys(password, kdfSalt, params);
  const userKey = randomBytes(32);
  const { publicKey, privateKey } = await generateKeyPair();
  const publicKeyB64 = b64url.encode(publicKey);
  const material: AccountMaterial = {
    kdfSalt, kdfParams: params,
    wrappedUserKey: await aeadEncrypt(wrapKey, userKey, AAD_USER_KEY),
    publicKey: publicKeyB64,
    wrappedPrivateKey: await aeadEncrypt(userKey, privateKey, aadPrivateKey(publicKeyB64)),
  };
  wrapKey.fill(0);
  return { material, authKey, keys: { userKey, privateKey, publicKey } satisfies UnlockedKeys };
}

export async function unlockAccount(wrapKey: Uint8Array, material: AccountMaterial): Promise<UnlockedKeys> {
  const userKey = await aeadDecrypt(wrapKey, material.wrappedUserKey, AAD_USER_KEY);
  const privateKey = await aeadDecrypt(userKey, material.wrappedPrivateKey, aadPrivateKey(material.publicKey));
  return { userKey, privateKey, publicKey: b64url.decode(material.publicKey) };
}

export async function changeMasterPassword(newPassword: string, keys: UnlockedKeys, material: AccountMaterial, params: KdfParams = DEFAULT_KDF) {
  const kdfSalt = b64url.encode(randomBytes(16));
  const { authKey, wrapKey } = await deriveLoginKeys(newPassword, kdfSalt, params);
  const next: AccountMaterial = { ...material, kdfSalt, kdfParams: params, wrappedUserKey: await aeadEncrypt(wrapKey, keys.userKey, AAD_USER_KEY) };
  wrapKey.fill(0);
  return { material: next, authKey };
}
