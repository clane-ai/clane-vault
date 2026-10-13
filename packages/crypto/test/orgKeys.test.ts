import { describe, expect, it } from "vitest";
import {
  adminRecoveryProof, assertKeyPair, b64url, createMembershipKeys, createMembershipRecoveryGrant, createTeamFolder, CryptoError, encryptNewRecord,
  generateKeyPair, membershipEscrowAad, membershipKeyAad, openMembershipEscrow, openMembershipRecoveryGrant, openOrgFolderKey, openOrgRecordShare,
  openSharedRecordKeyInOrg, openTeamFolderKey, publicKeyFromPrivateKey, randomBytes, sealFolderKeyFor, sealMembershipEscrow, sealOrgFolderKey,
  sealOrgRecordShare, sealTo, shareRecordKey, unlockMembershipKeys, wrapKey, wrapMembershipKeys, aeadEncrypt,
  type MembershipKeys,
} from "../src/index.js";

const id = () => crypto.randomUUID();
const account = async () => ({ userKey: randomBytes(32), ...(await generateKeyPair()) });
const ring = (...ks: MembershipKeys[]) => new Map(ks.map((k) => [b64url.encode(k.publicKey), k]));
const pub = (k: MembershipKeys) => b64url.encode(k.publicKey);

describe("publicKeyFromPrivateKey / assertKeyPair", () => {
  it("derives the public key of a generated pair", async () => {
    for (let i = 0; i < 5; i++) {
      const kp = await generateKeyPair();
      expect(await publicKeyFromPrivateKey(kp.privateKey)).toEqual(kp.publicKey);
      await assertKeyPair(kp.privateKey, kp.publicKey);
    }
  });
  it("rejects a mismatched pair and garbage", async () => {
    const a = await generateKeyPair(), b = await generateKeyPair();
    await expect(assertKeyPair(a.privateKey, b.publicKey)).rejects.toMatchObject({ code: "bad_key" });
    await expect(publicKeyFromPrivateKey(randomBytes(48))).rejects.toBeInstanceOf(CryptoError);
  });
});

describe("membership keys", () => {
  it("are created, wrapped under the user key and unlocked again, bound to org, user and public key", async () => {
    const me = await account();
    const ids = { orgId: id(), userId: id() };
    const { keys, material } = await createMembershipKeys(me.userKey, ids);
    expect(keys.orgId).toBe(ids.orgId);
    expect(material.publicKey).toBe(pub(keys));
    const back = await unlockMembershipKeys(me.userKey, ids, material);
    expect(back.privateKey).toEqual(keys.privateKey);
    expect(back.publicKey).toEqual(keys.publicKey);
    expect(back.orgId).toBe(ids.orgId);
  });

  it("refuses a wrap moved to another org or user, another user key, or a swapped public key", async () => {
    const me = await account();
    const ids = { orgId: id(), userId: id() };
    const { material } = await createMembershipKeys(me.userKey, ids);
    await expect(unlockMembershipKeys(me.userKey, { ...ids, orgId: id() }, material)).rejects.toMatchObject({ code: "decrypt_failed" });
    await expect(unlockMembershipKeys(me.userKey, { ...ids, userId: id() }, material)).rejects.toMatchObject({ code: "decrypt_failed" });
    await expect(unlockMembershipKeys(randomBytes(32), ids, material)).rejects.toMatchObject({ code: "decrypt_failed" });
    const other = await generateKeyPair();
    await expect(unlockMembershipKeys(me.userKey, ids, { ...material, publicKey: b64url.encode(other.publicKey) })).rejects.toBeInstanceOf(CryptoError);
  });

  it("refuses a correctly labelled wrap whose private key is not the public key's (server-planted pair)", async () => {
    const me = await account();
    const ids = { orgId: id(), userId: id() };
    const a = await generateKeyPair(), b = await generateKeyPair();
    const publicKey = b64url.encode(a.publicKey);
    const wrappedPrivateKey = await aeadEncrypt(me.userKey, b.privateKey, membershipKeyAad(ids.orgId, ids.userId, publicKey));
    await expect(unlockMembershipKeys(me.userKey, ids, { publicKey, wrappedPrivateKey })).rejects.toMatchObject({ code: "bad_key" });
  });

  it("re-wraps under a new user key (scoped reset) and refuses a key of another org", async () => {
    const me = await account();
    const ids = { orgId: id(), userId: id() };
    const { keys } = await createMembershipKeys(me.userKey, ids);
    const newUserKey = randomBytes(32);
    const m2 = await wrapMembershipKeys(newUserKey, ids, keys);
    expect((await unlockMembershipKeys(newUserKey, ids, m2)).privateKey).toEqual(keys.privateKey);
    await expect(wrapMembershipKeys(newUserKey, { ...ids, orgId: id() }, keys)).rejects.toMatchObject({ code: "bad_key" });
  });

  it("gives every organisation a different key pair", async () => {
    const me = await account();
    const userId = id();
    const a = await createMembershipKeys(me.userKey, { orgId: id(), userId });
    const b = await createMembershipKeys(me.userKey, { orgId: id(), userId });
    expect(a.keys.publicKey).not.toEqual(b.keys.publicKey);
    expect(a.keys.publicKey).not.toEqual(me.publicKey);
  });
});

describe("sealing to a membership", () => {
  it("seals a folder key bound to org and folder, opened only by that membership", async () => {
    const userKey = randomBytes(32), userId = id();
    const orgA = id(), orgB = id(), folderId = id();
    const a = (await createMembershipKeys(userKey, { orgId: orgA, userId })).keys;
    const b = (await createMembershipKeys(userKey, { orgId: orgB, userId })).keys;
    const folderKey = randomBytes(32);
    const sealed = await sealOrgFolderKey(folderKey, { orgId: orgA, folderId }, a.publicKey);
    expect(await openOrgFolderKey(sealed, { orgId: orgA, folderId }, a)).toEqual(folderKey);
    await expect(openOrgFolderKey(sealed, { orgId: orgA, folderId: id() }, a)).rejects.toMatchObject({ code: "decrypt_failed" });
    // The same box presented in org B's context: refused before decrypting (key of another org) and by the AAD.
    await expect(openOrgFolderKey(sealed, { orgId: orgB, folderId }, a)).rejects.toMatchObject({ code: "bad_key" });
    await expect(openOrgFolderKey(sealed, { orgId: orgB, folderId }, { ...a, orgId: orgB })).rejects.toMatchObject({ code: "decrypt_failed" });
    await expect(openOrgFolderKey(sealed, { orgId: orgB, folderId }, b)).rejects.toBeInstanceOf(CryptoError);
  });

  it("does not confuse org folder keys with legacy folder keys or record shares", async () => {
    const userKey = randomBytes(32), userId = id(), orgId = id(), fid = id();
    const m = (await createMembershipKeys(userKey, { orgId, userId })).keys;
    const k = randomBytes(32);
    const legacy = await sealFolderKeyFor(k, fid, m.publicKey); // AAD folder-key:<fid>
    await expect(openOrgFolderKey(legacy, { orgId, folderId: fid }, m)).rejects.toMatchObject({ code: "decrypt_failed" });
    const share = await sealOrgRecordShare(k, { orgId, recordId: fid }, m.publicKey);
    await expect(openOrgFolderKey(share, { orgId, folderId: fid }, m)).rejects.toMatchObject({ code: "decrypt_failed" });
    await expect(openOrgFolderKey(await wrapKey(k, userKey, "x"), { orgId, folderId: fid }, m)).rejects.toMatchObject({ code: "bad_envelope" });
    await expect(sealOrgFolderKey(randomBytes(16), { orgId, folderId: fid }, m.publicKey)).rejects.toMatchObject({ code: "bad_key" });
  });

  it("seals a direct share bound to org and record", async () => {
    const userKey = randomBytes(32), userId = id(), orgId = id();
    const m = (await createMembershipKeys(userKey, { orgId, userId })).keys;
    const { recordKey } = await encryptNewRecord(id(), { type: "note", title: "x" }, randomBytes(32));
    const rid = id();
    const sealed = await sealOrgRecordShare(recordKey, { orgId, recordId: rid }, m.publicKey);
    expect(await openOrgRecordShare(sealed, { orgId, recordId: rid }, m)).toEqual(recordKey);
    await expect(openOrgRecordShare(sealed, { orgId, recordId: id() }, m)).rejects.toMatchObject({ code: "decrypt_failed" });
    await expect(openOrgRecordShare(sealed, { orgId: id(), recordId: rid }, m)).rejects.toMatchObject({ code: "bad_key" });
  });

  it("opens rows by what the server says they are sealed to: account key (legacy) or a membership key", async () => {
    const acct = await account();
    const userId = id(), orgId = id();
    const m = (await createMembershipKeys(acct.userKey, { orgId, userId })).keys;
    const f = await createTeamFolder(id(), "Ops", acct.publicKey);
    const folderId = id();
    const legacy = await sealFolderKeyFor(f.folderKey, folderId, acct.publicKey);
    const modern = await sealOrgFolderKey(f.folderKey, { orgId, folderId }, m.publicKey);
    expect(await openTeamFolderKey({ orgId, folderId, wrappedFolderKey: legacy, sealedTo: null }, acct, ring(m))).toEqual(f.folderKey);
    expect(await openTeamFolderKey({ orgId, folderId, wrappedFolderKey: modern, sealedTo: pub(m) }, acct, ring(m))).toEqual(f.folderKey);
    // Wrong label for the envelope, unknown key, or a key of another org in the ring.
    await expect(openTeamFolderKey({ orgId, folderId, wrappedFolderKey: modern, sealedTo: null }, acct, ring(m))).rejects.toBeInstanceOf(CryptoError);
    await expect(openTeamFolderKey({ orgId, folderId, wrappedFolderKey: modern, sealedTo: pub(m) }, acct, ring())).rejects.toMatchObject({ code: "bad_key" });
    const other = (await createMembershipKeys(acct.userKey, { orgId: id(), userId })).keys;
    const toOther = await sealOrgFolderKey(f.folderKey, { orgId, folderId }, other.publicKey);
    await expect(openTeamFolderKey({ orgId, folderId, wrappedFolderKey: toOther, sealedTo: pub(other) }, acct, ring(m, other))).rejects.toMatchObject({ code: "bad_key" });

    const rk = randomBytes(32), recordId = id();
    expect(await openSharedRecordKeyInOrg({ orgId, recordId, wrappedRecordKey: await shareRecordKey(rk, recordId, acct.publicKey), sealedTo: null }, acct, ring(m))).toEqual(rk);
    expect(await openSharedRecordKeyInOrg({ orgId, recordId, wrappedRecordKey: await sealOrgRecordShare(rk, { orgId, recordId }, m.publicKey), sealedTo: pub(m) }, acct, ring(m))).toEqual(rk);
  });
});

describe("membership escrow", () => {
  const setup = async () => {
    const orgId = id(), userId = id(), adminId = id();
    const member = (await createMembershipKeys(randomBytes(32), { orgId, userId })).keys;
    const admin = (await createMembershipKeys(randomBytes(32), { orgId, userId: adminId })).keys;
    return { orgId, userId, adminId, member, admin };
  };

  it("seals the member's membership key to an admin's membership key and opens it after checking the public key", async () => {
    const s = await setup();
    const sealed = await sealMembershipEscrow(s.admin.publicKey, s.member, { userId: s.userId, adminId: s.adminId });
    const got = await openMembershipEscrow(s.admin, sealed, { userId: s.userId, adminId: s.adminId }, pub(s.member));
    expect(got.privateKey).toEqual(s.member.privateKey);
    expect(got.orgId).toBe(s.orgId);
  });

  it("is bound to org, member, admin and the member's public key", async () => {
    const s = await setup();
    const ids = { userId: s.userId, adminId: s.adminId };
    const sealed = await sealMembershipEscrow(s.admin.publicKey, s.member, ids);
    await expect(openMembershipEscrow(s.admin, sealed, { ...ids, userId: id() }, pub(s.member))).rejects.toMatchObject({ code: "decrypt_failed" });
    await expect(openMembershipEscrow(s.admin, sealed, { ...ids, adminId: id() }, pub(s.member))).rejects.toMatchObject({ code: "decrypt_failed" });
    await expect(openMembershipEscrow({ ...s.admin, orgId: id() }, sealed, ids, pub(s.member))).rejects.toMatchObject({ code: "decrypt_failed" });
    const otherPub = b64url.encode((await generateKeyPair()).publicKey);
    await expect(openMembershipEscrow(s.admin, sealed, ids, otherPub)).rejects.toMatchObject({ code: "decrypt_failed" });
    // Another admin's key can't open it.
    const admin2 = (await createMembershipKeys(randomBytes(32), { orgId: s.orgId, userId: id() })).keys;
    await expect(openMembershipEscrow(admin2, sealed, ids, pub(s.member))).rejects.toBeInstanceOf(CryptoError);
  });

  it("refuses an escrow whose content is not the private key of the listed public key", async () => {
    const s = await setup();
    const ids = { userId: s.userId, adminId: s.adminId };
    const decoy = await generateKeyPair();
    // Correct label for the member's public key, but someone else's private key inside.
    const sealed = await sealTo(s.admin.publicKey, decoy.privateKey, membershipEscrowAad(s.orgId, s.userId, s.adminId, pub(s.member)));
    await expect(openMembershipEscrow(s.admin, sealed, ids, pub(s.member))).rejects.toMatchObject({ code: "bad_key" });
  });

  it("refuses an escrow to oneself", async () => {
    const s = await setup();
    await expect(sealMembershipEscrow(s.admin.publicKey, s.member, { userId: s.userId, adminId: s.userId })).rejects.toMatchObject({ code: "bad_key" });
  });
});

describe("membership recovery grant", () => {
  it("round-trips through the link fragment and uses the same proof as account recovery links", async () => {
    const ids = { orgId: id(), userId: id() };
    const member = (await createMembershipKeys(randomBytes(32), ids)).keys;
    const rid = id();
    const g = await createMembershipRecoveryGrant(rid, ids, member);
    expect(g.wrappedMembershipKey.startsWith("v1.")).toBe(true);
    expect(await adminRecoveryProof(g.fragment)).toBe(g.proof);
    const got = await openMembershipRecoveryGrant(rid, ids, g.fragment, g.wrappedMembershipKey, pub(member));
    expect(got.privateKey).toEqual(member.privateKey);
    expect(got.orgId).toBe(ids.orgId);
  });

  it("is bound to request, org, user and public key, and needs the right fragment", async () => {
    const ids = { orgId: id(), userId: id() };
    const member = (await createMembershipKeys(randomBytes(32), ids)).keys;
    const rid = id();
    const g = await createMembershipRecoveryGrant(rid, ids, member);
    const p = pub(member);
    await expect(openMembershipRecoveryGrant(id(), ids, g.fragment, g.wrappedMembershipKey, p)).rejects.toMatchObject({ code: "decrypt_failed" });
    await expect(openMembershipRecoveryGrant(rid, { ...ids, orgId: id() }, g.fragment, g.wrappedMembershipKey, p)).rejects.toMatchObject({ code: "decrypt_failed" });
    await expect(openMembershipRecoveryGrant(rid, { ...ids, userId: id() }, g.fragment, g.wrappedMembershipKey, p)).rejects.toMatchObject({ code: "decrypt_failed" });
    await expect(openMembershipRecoveryGrant(rid, ids, g.fragment, g.wrappedMembershipKey, b64url.encode((await generateKeyPair()).publicKey))).rejects.toMatchObject({ code: "decrypt_failed" });
    await expect(openMembershipRecoveryGrant(rid, ids, b64url.encode(randomBytes(32)), g.wrappedMembershipKey, p)).rejects.toMatchObject({ code: "decrypt_failed" });
    await expect(openMembershipRecoveryGrant(rid, ids, b64url.encode(randomBytes(16)), g.wrappedMembershipKey, p)).rejects.toMatchObject({ code: "bad_key" });
    await expect(createMembershipRecoveryGrant(rid, { ...ids, orgId: id() }, member)).rejects.toMatchObject({ code: "bad_key" });
  });

});
