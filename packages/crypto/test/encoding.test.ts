import { describe, expect, it } from "vitest";
import { b64url, utf8, concat, randomBytes, CryptoError } from "../src/index.js";

describe("encoding", () => {
  it("round-trips base64url without padding", () => {
    const bytes = new Uint8Array([0, 1, 2, 250, 251, 252, 253, 254, 255]);
    const s = b64url.encode(bytes);
    expect(s).not.toMatch(/[+/=]/);
    expect(b64url.decode(s)).toEqual(bytes);
  });
  it("matches Node's base64url", () => {
    const bytes = randomBytes(37);
    expect(b64url.encode(bytes)).toBe(Buffer.from(bytes).toString("base64url"));
  });
  it("rejects invalid base64url", () => {
    expect(() => b64url.decode("ab$c")).toThrow(CryptoError);
  });
  it("rejects base64url with invalid length", () => {
    expect(() => b64url.decode("abcde")).toThrow(CryptoError);
  });
  it("round-trips utf8 including non-latin text", () => {
    const s = "Pässwörd · 密码 · ✓";
    expect(utf8.decode(utf8.encode(s))).toBe(s);
  });
  it("rejects invalid utf8 bytes", () => {
    expect(() => utf8.decode(new Uint8Array([0xff, 0xfe]))).toThrow(CryptoError);
  });
  it("concatenates", () => {
    expect(concat(new Uint8Array([1]), new Uint8Array([2, 3]))).toEqual(new Uint8Array([1, 2, 3]));
  });
  it("returns fresh random bytes of the asked length", () => {
    const a = randomBytes(32), b = randomBytes(32);
    expect(a.length).toBe(32);
    expect(a).not.toEqual(b);
  });
});
