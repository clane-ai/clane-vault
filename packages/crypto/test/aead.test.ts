import { describe, expect, it } from "vitest";
import { createDecipheriv } from "node:crypto";
import { aeadEncrypt, aeadDecrypt, randomBytes, utf8, b64url, CryptoError } from "../src/index.js";

describe("aead", () => {
  const key = randomBytes(32);

  it("round-trips with the same AAD", async () => {
    const env = await aeadEncrypt(key, utf8.encode("hunter2"), "record:abc");
    expect(env.startsWith("v1.")).toBe(true);
    expect(utf8.decode(await aeadDecrypt(key, env, "record:abc"))).toBe("hunter2");
  });

  it("uses a fresh IV every time", async () => {
    const a = await aeadEncrypt(key, utf8.encode("x"), "a");
    const b = await aeadEncrypt(key, utf8.encode("x"), "a");
    expect(a).not.toBe(b);
  });

  it("is readable by Node's AES-256-GCM (interop)", async () => {
    const env = await aeadEncrypt(key, utf8.encode("interop"), "aad-1");
    const raw = b64url.decode(env.slice(3));
    const iv = raw.slice(0, 12), tag = raw.slice(raw.length - 16), ct = raw.slice(12, raw.length - 16);
    const d = createDecipheriv("aes-256-gcm", key, iv);
    d.setAAD(Buffer.from("aad-1")); d.setAuthTag(tag);
    expect(Buffer.concat([d.update(ct), d.final()]).toString()).toBe("interop");
  });

  it("rejects the wrong key", async () => {
    const env = await aeadEncrypt(key, utf8.encode("x"), "a");
    await expect(aeadDecrypt(randomBytes(32), env, "a")).rejects.toMatchObject({ code: "decrypt_failed" });
  });

  it("rejects the wrong AAD", async () => {
    const env = await aeadEncrypt(key, utf8.encode("x"), "record:1");
    await expect(aeadDecrypt(key, env, "record:2")).rejects.toMatchObject({ code: "decrypt_failed" });
  });

  it("rejects a tampered ciphertext", async () => {
    const env = await aeadEncrypt(key, utf8.encode("secret"), "a");
    const raw = b64url.decode(env.slice(3));
    raw[20] = raw[20]! ^ 1;
    await expect(aeadDecrypt(key, "v1." + b64url.encode(raw), "a")).rejects.toMatchObject({ code: "decrypt_failed" });
  });

  it("rejects malformed envelopes and wrong key sizes", async () => {
    await expect(aeadDecrypt(key, "v2.abc", "a")).rejects.toBeInstanceOf(CryptoError);
    await expect(aeadDecrypt(key, "v1.", "a")).rejects.toMatchObject({ code: "bad_envelope" });
    await expect(aeadEncrypt(randomBytes(16), utf8.encode("x"), "a")).rejects.toMatchObject({ code: "bad_key" });
  });
});
