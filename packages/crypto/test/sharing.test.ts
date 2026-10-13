import { describe, expect, it } from "vitest";
import {
  createTeamFolder, decryptFolderName, decryptRecordBody, encryptNewRecord, generateKeyPair, openFolderKey, openRecordKey,
  openSharedRecordKey, randomBytes, sealFolderKeyFor, shareRecordKey, wrapKey, CryptoError,
} from "../src/index.js";

const keysFor = async () => ({ userKey: randomBytes(32), ...(await generateKeyPair()) });

describe("team folders", () => {
  it("creates a folder whose key the creator can open and whose name decrypts under the folder key", async () => {
    const me = await keysFor();
    const fid = crypto.randomUUID();
    const f = await createTeamFolder(fid, "  Infra team ", me.publicKey);
    expect(f.folderKey).toHaveLength(32);
    expect(f.wrappedFolderKey.startsWith("s1.")).toBe(true);
    const k = await openFolderKey(f.wrappedFolderKey, fid, me);
    expect(k).toEqual(f.folderKey);
    expect(await decryptFolderName(fid, f.encName, k)).toBe("Infra team");
  });

  it("seals the folder key to another member, bound to the folder id", async () => {
    const me = await keysFor(), bob = await keysFor();
    const fid = crypto.randomUUID();
    const f = await createTeamFolder(fid, "Infra", me.publicKey);
    const forBob = await sealFolderKeyFor(f.folderKey, fid, bob.publicKey);
    expect(await openFolderKey(forBob, fid, bob)).toEqual(f.folderKey);
    await expect(openFolderKey(forBob, crypto.randomUUID(), bob)).rejects.toBeInstanceOf(CryptoError); // wrong folder id
    await expect(openFolderKey(forBob, fid, me)).rejects.toBeInstanceOf(CryptoError); // not sealed to me
  });

  it("rejects a folder key that is not sealed (v1 envelope) or not 32 bytes", async () => {
    const me = await keysFor();
    const fid = crypto.randomUUID();
    await expect(openFolderKey(await wrapKey(randomBytes(32), me.userKey, `folder-key:${fid}`), fid, me)).rejects.toBeInstanceOf(CryptoError);
    await expect(sealFolderKeyFor(randomBytes(16), fid, me.publicKey)).rejects.toThrow();
  });
});

describe("direct record shares", () => {
  it("seals a record key to a recipient bound to the record id", async () => {
    const bob = await keysFor(), eve = await keysFor();
    const rid = crypto.randomUUID();
    const rk = randomBytes(32);
    const sealed = await shareRecordKey(rk, rid, bob.publicKey);
    expect(sealed.startsWith("s1.")).toBe(true);
    expect(await openSharedRecordKey(sealed, rid, bob)).toEqual(rk);
    await expect(openSharedRecordKey(sealed, crypto.randomUUID(), bob)).rejects.toBeInstanceOf(CryptoError);
    await expect(openSharedRecordKey(sealed, rid, eve)).rejects.toBeInstanceOf(CryptoError);
  });

  it("does not accept a sealed folder key as a record share (domain separation)", async () => {
    const bob = await keysFor();
    const id = crypto.randomUUID();
    const sealedFolderKey = await sealFolderKeyFor(randomBytes(32), id, bob.publicKey);
    await expect(openSharedRecordKey(sealedFolderKey, id, bob)).rejects.toBeInstanceOf(CryptoError);
  });
});

describe("openRecordKey dispatch", () => {
  it("opens user-wrapped, folder-wrapped and sealed record keys", async () => {
    const owner = await keysFor(), bob = await keysFor();
    const rid = crypto.randomUUID(), fid = crypto.randomUUID();
    const enc = await encryptNewRecord(rid, { type: "login", title: "AWS", password: "pw" }, owner.userKey);
    const folder = await createTeamFolder(fid, "Infra", owner.publicKey);
    const folderWrapped = await wrapKey(enc.recordKey, folder.folderKey, `record-key:${rid}`);
    const sealed = await shareRecordKey(enc.recordKey, rid, bob.publicKey);

    const viaUser = await openRecordKey({ recordId: rid, holderType: "user", wrappedRecordKey: enc.wrappedRecordKey, folderId: null }, owner, new Map());
    const viaFolder = await openRecordKey({ recordId: rid, holderType: "folder", wrappedRecordKey: folderWrapped, folderId: fid }, bob, new Map([[fid, folder.folderKey]]));
    const viaShare = await openRecordKey({ recordId: rid, holderType: "user", wrappedRecordKey: sealed, folderId: null }, bob, new Map());
    for (const k of [viaUser, viaFolder, viaShare]) expect((await decryptRecordBody(rid, enc.encBody, k)).title).toBe("AWS");
  });

  it("fails closed: folder rows need the folder key, wrong ids fail, unknown prefixes fail", async () => {
    const owner = await keysFor();
    const rid = crypto.randomUUID(), fid = crypto.randomUUID();
    const rk = randomBytes(32);
    const folderKey = randomBytes(32);
    const folderWrapped = await wrapKey(rk, folderKey, `record-key:${rid}`);
    await expect(openRecordKey({ recordId: rid, holderType: "folder", wrappedRecordKey: folderWrapped, folderId: fid }, owner, new Map())).rejects.toBeInstanceOf(CryptoError);
    await expect(openRecordKey({ recordId: crypto.randomUUID(), holderType: "folder", wrappedRecordKey: folderWrapped, folderId: fid }, owner, new Map([[fid, folderKey]]))).rejects.toBeInstanceOf(CryptoError);
    // a folder row must never be opened with the user key, even if it were wrapped under it
    const underUser = await wrapKey(rk, owner.userKey, `record-key:${rid}`);
    await expect(openRecordKey({ recordId: rid, holderType: "folder", wrappedRecordKey: underUser, folderId: fid }, owner, new Map([[fid, folderKey]]))).rejects.toBeInstanceOf(CryptoError);
    await expect(openRecordKey({ recordId: rid, holderType: "user", wrappedRecordKey: "x9.abc", folderId: null }, owner, new Map())).rejects.toBeInstanceOf(CryptoError);
    // a sealed blob in a folder row is rejected
    const sealed = await shareRecordKey(rk, rid, owner.publicKey);
    await expect(openRecordKey({ recordId: rid, holderType: "folder", wrappedRecordKey: sealed, folderId: fid }, owner, new Map([[fid, folderKey]]))).rejects.toBeInstanceOf(CryptoError);
  });
});
