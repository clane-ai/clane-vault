export type CryptoErrorCode = "decrypt_failed" | "bad_envelope" | "bad_key";

export class CryptoError extends Error {
  constructor(public readonly code: CryptoErrorCode, message?: string) {
    super(message ?? code);
    this.name = "CryptoError";
  }
}

const B64URL = /^[A-Za-z0-9_-]*$/;

export const b64url = {
  encode(u8: Uint8Array): string {
    let bin = "";
    for (const b of u8) bin += String.fromCharCode(b);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  },
  decode(s: string): Uint8Array {
    if (!B64URL.test(s)) throw new CryptoError("bad_envelope", "invalid base64url");
    const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
    let bin: string;
    try {
      bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad);
    } catch {
      throw new CryptoError("bad_envelope", "invalid base64url");
    }
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  },
};

const te = new TextEncoder();
const td = new TextDecoder("utf-8", { fatal: true });
export const utf8 = {
  encode: (s: string): Uint8Array => te.encode(s),
  decode: (u8: Uint8Array): string => {
    try {
      return td.decode(u8);
    } catch {
      throw new CryptoError("bad_envelope", "invalid utf-8");
    }
  },
};

export function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

export function randomBytes(n: number): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(n));
}
