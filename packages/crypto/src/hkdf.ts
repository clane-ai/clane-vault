import { utf8 } from "./encoding.js";

export async function hkdf(ikm: Uint8Array, salt: Uint8Array, info: string | Uint8Array, length: number): Promise<Uint8Array> {
  const base = await crypto.subtle.importKey("raw", ikm as BufferSource, "HKDF", false, ["deriveBits"]);
  const infoBytes = typeof info === "string" ? utf8.encode(info) : info;
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: salt as BufferSource, info: infoBytes as BufferSource },
    base, length * 8);
  return new Uint8Array(bits);
}
