import { argon2id } from "hash-wasm";
import { b64url, CryptoError } from "./encoding.js";
import { hkdf } from "./hkdf.js";

export interface KdfParams { alg: "argon2id"; m: number; t: number; p: number }
export const DEFAULT_KDF: KdfParams = { alg: "argon2id", m: 65536, t: 3, p: 1 };

const MAX_M = 1048576, MAX_T = 10, MAX_P = 4;
let floor = { m: DEFAULT_KDF.m, t: DEFAULT_KDF.t };
/** TESTS ONLY: lowers the minimum accepted KDF cost so tests can use fast parameters. */
export function configureKdfFloor(f: { m: number; t: number }): void { floor = { m: f.m, t: f.t }; }

export async function deriveMasterKey(password: string, salt: Uint8Array, params: KdfParams): Promise<Uint8Array> {
  if (params.alg !== "argon2id") throw new CryptoError("bad_key", `unsupported kdf ${String(params.alg)}`);
  if (params.m < floor.m || params.t < floor.t || params.p < 1) throw new CryptoError("bad_key", "kdf parameters too weak");
  if (params.m > MAX_M || params.t > MAX_T || params.p > MAX_P) throw new CryptoError("bad_key", "kdf parameters too strong");
  if (salt.length < 16) throw new CryptoError("bad_key", "kdf salt too short");
  return argon2id({ password, salt, memorySize: params.m, iterations: params.t, parallelism: params.p, hashLength: 32, outputType: "binary" });
}

export async function deriveLoginKeys(password: string, kdfSalt: string, params: KdfParams): Promise<{ authKey: string; wrapKey: Uint8Array }> {
  const master = await deriveMasterKey(password, b64url.decode(kdfSalt), params);
  const empty = new Uint8Array(0);
  const [auth, wrapKey] = await Promise.all([hkdf(master, empty, "clane-vault/auth", 32), hkdf(master, empty, "clane-vault/wrap", 32)]);
  master.fill(0);
  return { authKey: b64url.encode(auth), wrapKey };
}
