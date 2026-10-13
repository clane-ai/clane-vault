import { describe, expect, it } from "vitest";
import { configureKdfFloor, generateKeyPair, createAccount, unlockAccount, deriveLoginKeys, changeMasterPassword, sealTo, openSealed, utf8, type KdfParams } from "../src/index.js";

const FAST: KdfParams = { alg: "argon2id", m: 1024, t: 2, p: 1 };
configureKdfFloor({ m: 1024, t: 1 });

describe("account", () => {
  it("creates an account that unlocks with the same password", async () => {
    const created = await createAccount("Tr0ub4dor&3 long enough", FAST);
    const { authKey, wrapKey } = await deriveLoginKeys("Tr0ub4dor&3 long enough", created.material.kdfSalt, created.material.kdfParams);
    expect(authKey).toBe(created.authKey);
    const keys = await unlockAccount(wrapKey, created.material);
    expect(keys.userKey).toEqual(created.keys.userKey);
    const sealed = await sealTo(keys.publicKey, utf8.encode("hi"), "t");
    expect(utf8.decode(await openSealed(keys.privateKey, keys.publicKey, sealed, "t"))).toBe("hi");
  });

  it("refuses the wrong password", async () => {
    const created = await createAccount("right password here", FAST);
    const { wrapKey } = await deriveLoginKeys("wrong password here", created.material.kdfSalt, created.material.kdfParams);
    await expect(unlockAccount(wrapKey, created.material)).rejects.toMatchObject({ code: "decrypt_failed" });
  });

  it("rejects a swapped public key", async () => {
    const created = await createAccount("some password here", FAST);
    const { wrapKey } = await deriveLoginKeys("some password here", created.material.kdfSalt, created.material.kdfParams);
    const other = await generateKeyPair();
    const tampered = { ...created.material, publicKey: Buffer.from(other.publicKey).toString("base64url") };
    await expect(unlockAccount(wrapKey, tampered)).rejects.toMatchObject({ code: "decrypt_failed" });
  });

  it("never puts the password or raw keys in the material", async () => {
    const created = await createAccount("SuperSecretPassword!", FAST);
    const json = JSON.stringify(created.material);
    expect(json).not.toContain("SuperSecretPassword");
    expect(json).not.toContain(Buffer.from(created.keys.userKey).toString("base64url"));
  });

  it("changes the master password and keeps the same user key", async () => {
    const created = await createAccount("old password 123", FAST);
    const changed = await changeMasterPassword("new password 456", created.keys, created.material, FAST);
    const { wrapKey, authKey } = await deriveLoginKeys("new password 456", changed.material.kdfSalt, changed.material.kdfParams);
    expect(authKey).toBe(changed.authKey);
    expect(authKey).not.toBe(created.authKey);
    expect((await unlockAccount(wrapKey, changed.material)).userKey).toEqual(created.keys.userKey);
  });
});
