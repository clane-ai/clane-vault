import { describe, expect, it } from "vitest";
import { hkdfSync } from "node:crypto";
import { hkdf, randomBytes } from "../src/index.js";

const hex = (s: string) => Uint8Array.from(Buffer.from(s, "hex"));

describe("hkdf", () => {
  it("matches RFC 5869 test case 1", async () => {
    const okm = await hkdf(hex("0b".repeat(22)), hex("000102030405060708090a0b0c"), hex("f0f1f2f3f4f5f6f7f8f9"), 42);
    expect(Buffer.from(okm).toString("hex")).toBe(
      "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
  });
  it("matches Node's hkdfSync for random input", async () => {
    const ikm = randomBytes(32), salt = randomBytes(16);
    const ours = await hkdf(ikm, salt, "clane-vault/wrap", 32);
    const node = new Uint8Array(hkdfSync("sha256", ikm, salt, Buffer.from("clane-vault/wrap"), 32));
    expect(ours).toEqual(node);
  });
});
