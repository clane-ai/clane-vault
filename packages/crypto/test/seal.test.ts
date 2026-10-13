import { describe, expect, it } from "vitest";
import { generateKeyPair, sealTo, openSealed, keyFingerprint, utf8 } from "../src/index.js";

describe("sealed boxes", () => {
  it("only the recipient can open", async () => {
    const alice = await generateKeyPair(), bob = await generateKeyPair();
    const sealed = await sealTo(bob.publicKey, utf8.encode("folder key"), "folder:1");
    expect(sealed.startsWith("s1.")).toBe(true);
    expect(utf8.decode(await openSealed(bob.privateKey, bob.publicKey, sealed, "folder:1"))).toBe("folder key");
    await expect(openSealed(alice.privateKey, alice.publicKey, sealed, "folder:1")).rejects.toMatchObject({ code: "decrypt_failed" });
  });
  it("binds the AAD", async () => {
    const bob = await generateKeyPair();
    const sealed = await sealTo(bob.publicKey, utf8.encode("k"), "folder:1");
    await expect(openSealed(bob.privateKey, bob.publicKey, sealed, "folder:2")).rejects.toMatchObject({ code: "decrypt_failed" });
  });
  it("produces a readable fingerprint", async () => {
    const { publicKey } = await generateKeyPair();
    expect(await keyFingerprint(publicKey)).toMatch(/^[0-9a-f]{4}(-[0-9a-f]{4}){4}$/);
  });
});
