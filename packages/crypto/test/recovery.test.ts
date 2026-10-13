import { describe, expect, it } from "vitest";
import {
  configureKdfFloor, createAccount, changeMasterPassword, deriveLoginKeys, unlockAccount, generateKeyPair, randomBytes, b64url,
  formatRecoveryCode, parseRecoveryCode, normalizeRecoveryCode, lastRecoveryGroup, RecoveryCodeError, RECOVERY_CODE_GROUPS,
  createRecoveryKit, openRecoveryWrap, recoveryAuthFor, keysFromUserKey,
  adminRecoveryProof,
  type KdfParams,
} from "../src/index.js";

const FAST: KdfParams = { alg: "argon2id", m: 1024, t: 2, p: 1 };
configureKdfFloor({ m: 1024, t: 1 });
const CODE = /^[0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4}){13}$/;

describe("recovery code format", () => {
  it("is 14 groups of 4 Crockford base32 characters and round-trips", async () => {
    for (let i = 0; i < 50; i++) {
      const key = randomBytes(32);
      const code = await formatRecoveryCode(key);
      expect(code).toMatch(CODE);
      expect(code.split("-")).toHaveLength(RECOVERY_CODE_GROUPS);
      expect(await parseRecoveryCode(code)).toEqual(key);
    }
  });

  it("round-trips the all-zero and all-0xff keys", async () => {
    for (const fill of [0, 255]) {
      const key = new Uint8Array(32).fill(fill);
      expect(await parseRecoveryCode(await formatRecoveryCode(key))).toEqual(key);
    }
  });

  it("accepts lower case, spaces, missing dashes and look-alike letters", async () => {
    const key = randomBytes(32);
    const code = await formatRecoveryCode(key);
    expect(await parseRecoveryCode(code.toLowerCase())).toEqual(key);
    expect(await parseRecoveryCode(code.replace(/-/g, " "))).toEqual(key);
    expect(await parseRecoveryCode(` ${code.replace(/-/g, "")} `)).toEqual(key);
    expect(await parseRecoveryCode(code.replace(/0/g, "O").replace(/1/g, "l"))).toEqual(key);
    expect(normalizeRecoveryCode("ab-cd o i l")).toBe("ABCD011");
  });

  it("catches a typo with the checksum", async () => {
    const code = await formatRecoveryCode(randomBytes(32));
    const chars = code.split("");
    const i = 5; // a key character, not a dash
    chars[i] = chars[i] === "A" ? "B" : "A";
    await expect(parseRecoveryCode(chars.join(""))).rejects.toBeInstanceOf(RecoveryCodeError);
    await expect(parseRecoveryCode(chars.join(""))).rejects.toMatchObject({ reason: expect.stringMatching(/checksum|format/) });
    // swapping the checksum group also fails
    const other = await formatRecoveryCode(randomBytes(32));
    await expect(parseRecoveryCode(code.slice(0, -4) + lastRecoveryGroup(other))).rejects.toMatchObject({ reason: "checksum" });
  });

  it("rejects the wrong length, bad characters and non-zero padding", async () => {
    const code = await formatRecoveryCode(randomBytes(32));
    await expect(parseRecoveryCode(code.slice(0, -5))).rejects.toMatchObject({ reason: "format" });
    await expect(parseRecoveryCode(`${code}-AAAA`)).rejects.toMatchObject({ reason: "format" });
    await expect(parseRecoveryCode(code.replace(/^./, "U"))).rejects.toMatchObject({ reason: "format" });
    await expect(parseRecoveryCode("")).rejects.toMatchObject({ reason: "format" });
    // The 52nd character only has 1 meaningful bit; flipping a padding bit must be refused, not silently accepted.
    const flat = normalizeRecoveryCode(code);
    const last = flat[51]!;
    const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    const padded = alphabet[(alphabet.indexOf(last) ^ 1)]!;
    await expect(parseRecoveryCode(flat.slice(0, 51) + padded + flat.slice(52))).rejects.toMatchObject({ reason: "format" });
  });

  it("lastRecoveryGroup is the checksum group", async () => {
    const code = await formatRecoveryCode(randomBytes(32));
    expect(lastRecoveryGroup(code)).toBe(code.slice(-4));
  });
});

describe("recovery kit", () => {
  it("wraps the user key so the code unwraps it, and the auth value is stable", async () => {
    const acct = await createAccount("a master password", FAST);
    const kit = await createRecoveryKit("user-1", acct.keys.userKey);
    expect(kit.code).toMatch(CODE);
    const key = await parseRecoveryCode(kit.code);
    expect(await recoveryAuthFor(key)).toBe(kit.recoveryAuth);
    expect(await openRecoveryWrap("user-1", key, kit.recoveryWrap)).toEqual(acct.keys.userKey);
  });

  it("never exposes the user key or the code in what the server stores", async () => {
    const acct = await createAccount("a master password", FAST);
    const kit = await createRecoveryKit("user-1", acct.keys.userKey);
    const stored = JSON.stringify({ w: kit.recoveryWrap, a: kit.recoveryAuth });
    expect(stored).not.toContain(b64url.encode(acct.keys.userKey));
    expect(stored).not.toContain(b64url.encode(await parseRecoveryCode(kit.code)));
    expect(kit.recoveryAuth).not.toBe(b64url.encode(await parseRecoveryCode(kit.code)));
  });

  it("fails with a wrong key", async () => {
    const acct = await createAccount("a master password", FAST);
    const kit = await createRecoveryKit("user-1", acct.keys.userKey);
    await expect(openRecoveryWrap("user-1", randomBytes(32), kit.recoveryWrap)).rejects.toMatchObject({ code: "decrypt_failed" });
  });

  it("binds the wrap to the user id (AAD)", async () => {
    const acct = await createAccount("a master password", FAST);
    const kit = await createRecoveryKit("user-1", acct.keys.userKey);
    const key = await parseRecoveryCode(kit.code);
    await expect(openRecoveryWrap("user-2", key, kit.recoveryWrap)).rejects.toMatchObject({ code: "decrypt_failed" });
  });

  it("a new kit uses a new key: the old code cannot open the new wrap", async () => {
    const acct = await createAccount("a master password", FAST);
    const a = await createRecoveryKit("u", acct.keys.userKey), b = await createRecoveryKit("u", acct.keys.userKey);
    expect(a.code).not.toBe(b.code);
    await expect(openRecoveryWrap("u", await parseRecoveryCode(a.code), b.recoveryWrap)).rejects.toMatchObject({ code: "decrypt_failed" });
  });

  it("full recovery: kit → user key → new master password → same keys", async () => {
    const acct = await createAccount("forgotten password", FAST);
    const kit = await createRecoveryKit("u", acct.keys.userKey);
    const userKey = await openRecoveryWrap("u", await parseRecoveryCode(kit.code), kit.recoveryWrap);
    const keys = await keysFromUserKey(userKey, acct.material);
    expect(keys.privateKey).toEqual(acct.keys.privateKey);
    const changed = await changeMasterPassword("brand new password", keys, acct.material, FAST);
    const { wrapKey } = await deriveLoginKeys("brand new password", changed.material.kdfSalt, changed.material.kdfParams);
    expect((await unlockAccount(wrapKey, changed.material)).userKey).toEqual(acct.keys.userKey);
  });

  it("keysFromUserKey refuses a wrong user key", async () => {
    const acct = await createAccount("pw pw pw pw", FAST);
    await expect(keysFromUserKey(randomBytes(32), acct.material)).rejects.toMatchObject({ code: "decrypt_failed" });
  });
});

describe("admin recovery link proof", () => {
  it("is derived from the fragment and never equals it; refuses a malformed fragment", async () => {
    const fragment = b64url.encode(randomBytes(32));
    const proof = await adminRecoveryProof(fragment);
    expect(proof).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(proof).not.toBe(fragment);
    expect(await adminRecoveryProof(b64url.encode(randomBytes(32)))).not.toBe(proof);
    await expect(adminRecoveryProof("abcd")).rejects.toMatchObject({ code: "bad_key" });
    await expect(adminRecoveryProof("not base64url!")).rejects.toMatchObject({ code: "bad_envelope" });
  });
});
