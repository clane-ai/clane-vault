import { describe, expect, it } from "vitest";
import {
  b64url, createMembershipKeys, CryptoError, decryptFolderName, encryptFolderName, encryptNewRecord, generateKeyPair, openOrgFolderKey, openOrgRecordShare,
  openRecordKey, ownerRecordKeyFromFolder, randomBytes, reencryptPrivateFolderName, resealFolderKeyToMembership, resealRecordShareToMembership,
  rewrapOwnerRecordKey, rotateFolderKeySeal, rotateRecordShareSeal, sealFolderKeyFor, sealOrgFolderKey, shareRecordKey, unwrapKey, wrapKey,
} from "../src/index.js";

const id = () => crypto.randomUUID();
const account = async () => ({ userKey: randomBytes(32), ...(await generateKeyPair()) });

describe("legacy → membership", () => {
  it("re-seals a folder key from the account key to the membership key of the folder's org", async () => {
    const acct = await account();
    const orgId = id(), folderId = id(), userId = id();
    const m = (await createMembershipKeys(acct.userKey, { orgId, userId })).keys;
    const fk = randomBytes(32);
    const legacy = await sealFolderKeyFor(fk, folderId, acct.publicKey);
    const moved = await resealFolderKeyToMembership(legacy, { orgId, folderId }, acct, m);
    expect(await openOrgFolderKey(moved, { orgId, folderId }, m)).toEqual(fk);
  });

  it("refuses a membership key of another org, a row of another folder, or a row not sealed to me", async () => {
    const acct = await account(), other = await account();
    const orgId = id(), folderId = id(), userId = id();
    const m = (await createMembershipKeys(acct.userKey, { orgId, userId })).keys;
    const mOther = (await createMembershipKeys(acct.userKey, { orgId: id(), userId })).keys;
    const legacy = await sealFolderKeyFor(randomBytes(32), folderId, acct.publicKey);
    await expect(resealFolderKeyToMembership(legacy, { orgId, folderId }, acct, mOther)).rejects.toMatchObject({ code: "bad_key" });
    await expect(resealFolderKeyToMembership(legacy, { orgId, folderId: id() }, acct, m)).rejects.toMatchObject({ code: "decrypt_failed" });
    await expect(resealFolderKeyToMembership(legacy, { orgId, folderId }, other, m)).rejects.toBeInstanceOf(CryptoError);
  });

  it("re-seals a direct share from the account key to the membership key", async () => {
    const acct = await account();
    const orgId = id(), recordId = id();
    const m = (await createMembershipKeys(acct.userKey, { orgId, userId: id() })).keys;
    const rk = randomBytes(32);
    const moved = await resealRecordShareToMembership(await shareRecordKey(rk, recordId, acct.publicKey), { orgId, recordId }, acct, m);
    expect(await openOrgRecordShare(moved, { orgId, recordId }, m)).toEqual(rk);
    await expect(resealRecordShareToMembership(await shareRecordKey(rk, recordId, acct.publicKey), { orgId: id(), recordId }, acct, m)).rejects.toMatchObject({ code: "bad_key" });
  });
});

describe("rotation", () => {
  it("moves folder keys and shares from an old membership key to a new one; the old key can't open the result", async () => {
    const userKey = randomBytes(32), orgId = id(), userId = id(), folderId = id(), recordId = id();
    const oldK = (await createMembershipKeys(userKey, { orgId, userId })).keys;
    const newK = (await createMembershipKeys(userKey, { orgId, userId })).keys;
    const fk = randomBytes(32);
    const rotated = await rotateFolderKeySeal(await sealOrgFolderKey(fk, { orgId, folderId }, oldK.publicKey), { orgId, folderId }, oldK, newK);
    expect(await openOrgFolderKey(rotated, { orgId, folderId }, newK)).toEqual(fk);
    await expect(openOrgFolderKey(rotated, { orgId, folderId }, oldK)).rejects.toBeInstanceOf(CryptoError);

    const rk = randomBytes(32);
    const { sealOrgRecordShare } = await import("../src/index.js");
    const r2 = await rotateRecordShareSeal(await sealOrgRecordShare(rk, { orgId, recordId }, oldK.publicKey), { orgId, recordId }, oldK, newK);
    expect(await openOrgRecordShare(r2, { orgId, recordId }, newK)).toEqual(rk);
    const foreign = (await createMembershipKeys(userKey, { orgId: id(), userId })).keys;
    await expect(rotateFolderKeySeal(rotated, { orgId, folderId }, newK, foreign)).rejects.toMatchObject({ code: "bad_key" });
  });
});

describe("re-wrapping own items under a new user key", () => {
  it("re-wraps an owner row and the record still opens through openRecordKey", async () => {
    const oldUK = randomBytes(32), newUK = randomBytes(32), rid = id();
    const { wrappedRecordKey, recordKey } = await encryptNewRecord(rid, { type: "note", title: "n" }, oldUK);
    const moved = await rewrapOwnerRecordKey(rid, wrappedRecordKey, oldUK, newUK);
    const kp = await generateKeyPair();
    expect(await openRecordKey({ recordId: rid, holderType: "user", wrappedRecordKey: moved, folderId: null }, { ...kp, userKey: newUK }, new Map())).toEqual(recordKey);
    await expect(rewrapOwnerRecordKey(id(), wrappedRecordKey, oldUK, newUK)).rejects.toMatchObject({ code: "decrypt_failed" });
    await expect(rewrapOwnerRecordKey(rid, wrappedRecordKey, randomBytes(32), newUK)).rejects.toMatchObject({ code: "decrypt_failed" });
    await expect(rewrapOwnerRecordKey(rid, "s1.a.b.c", oldUK, newUK)).rejects.toMatchObject({ code: "bad_envelope" });
  });

  it("rebuilds an owner row of a team-folder record from the folder's row", async () => {
    const folderKey = randomBytes(32), newUK = randomBytes(32), rid = id();
    const { wrappedRecordKey, recordKey } = await encryptNewRecord(rid, { type: "note", title: "n" }, folderKey);
    const owner = await ownerRecordKeyFromFolder(rid, wrappedRecordKey, folderKey, newUK);
    expect(await unwrapKey(owner, newUK, `record-key:${rid}`)).toEqual(recordKey);
  });

  it("refuses to re-wrap something that is not a 32-byte key", async () => {
    const oldUK = randomBytes(32), rid = id();
    const odd = await wrapKey(randomBytes(16), oldUK, `record-key:${rid}`);
    await expect(rewrapOwnerRecordKey(rid, odd, oldUK, randomBytes(32))).rejects.toMatchObject({ code: "bad_key" });
  });

  it("re-encrypts a private folder name, bound to the folder id", async () => {
    const oldUK = randomBytes(32), newUK = randomBytes(32), fid = id();
    const enc = await encryptFolderName(fid, "Personal", oldUK);
    const moved = await reencryptPrivateFolderName(fid, enc, oldUK, newUK);
    expect(await decryptFolderName(fid, moved, newUK)).toBe("Personal");
    await expect(reencryptPrivateFolderName(id(), enc, oldUK, newUK)).rejects.toMatchObject({ code: "decrypt_failed" });
    expect(b64url.encode(newUK)).not.toBe(b64url.encode(oldUK));
  });
});
