import { describe, expect, it } from "vitest";
import { hash as nodeArgon2 } from "argon2";
import { deriveMasterKey, deriveLoginKeys, DEFAULT_KDF, configureKdfFloor, randomBytes, b64url, type KdfParams } from "../src/index.js";

const FAST: KdfParams = { alg: "argon2id", m: 1024, t: 2, p: 1 };
configureKdfFloor({ m: 1024, t: 1 });

describe("kdf", () => {
  it("default parameters match the spec", () => {
    expect(DEFAULT_KDF).toEqual({ alg: "argon2id", m: 65536, t: 3, p: 1 });
  });

  it("matches the native argon2 implementation (interop)", async () => {
    const salt = randomBytes(16);
    const ours = await deriveMasterKey("correct horse battery staple", salt, FAST);
    const native = await nodeArgon2("correct horse battery staple", {
      type: 2, salt: Buffer.from(salt), memoryCost: FAST.m, timeCost: FAST.t, parallelism: FAST.p, hashLength: 32, raw: true,
    });
    expect(ours).toEqual(new Uint8Array(native));
  });

  it("is deterministic and salt-sensitive", async () => {
    const salt = randomBytes(16);
    const a = await deriveMasterKey("pw", salt, FAST);
    expect(await deriveMasterKey("pw", salt, FAST)).toEqual(a);
    expect(await deriveMasterKey("pw", randomBytes(16), FAST)).not.toEqual(a);
  });

  it("splits auth and wrap keys that differ from each other", async () => {
    const salt = b64url.encode(randomBytes(16));
    const { authKey, wrapKey } = await deriveLoginKeys("pw", salt, FAST);
    expect(b64url.decode(authKey)).toHaveLength(32);
    expect(wrapKey).toHaveLength(32);
    expect(b64url.decode(authKey)).not.toEqual(wrapKey);
  });

  it("rejects non-argon2id params", async () => {
    await expect(deriveMasterKey("pw", randomBytes(16), { ...FAST, alg: "pbkdf2" as "argon2id" })).rejects.toMatchObject({ code: "bad_key" });
  });

  it("enforces the default floor against downgrade", async () => {
    configureKdfFloor({ m: 65536, t: 3 });
    try {
      await expect(deriveMasterKey("pw", randomBytes(16), FAST)).rejects.toMatchObject({ code: "bad_key" });
    } finally {
      configureKdfFloor({ m: 1024, t: 1 });
    }
  });

  it("rejects parameters above the ceiling", async () => {
    await expect(deriveMasterKey("pw", randomBytes(16), { ...FAST, m: 1048577 })).rejects.toMatchObject({ code: "bad_key" });
    await expect(deriveMasterKey("pw", randomBytes(16), { ...FAST, t: 11 })).rejects.toMatchObject({ code: "bad_key" });
    await expect(deriveMasterKey("pw", randomBytes(16), { ...FAST, p: 5 })).rejects.toMatchObject({ code: "bad_key" });
  });

  it("rejects short salts", async () => {
    await expect(deriveMasterKey("pw", randomBytes(8), FAST)).rejects.toMatchObject({ code: "bad_key" });
  });
});
