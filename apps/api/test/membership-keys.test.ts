import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { authenticator } from "otplib";
import {
  adminRecoveryProof, b64url, createMembershipKeys, createRecoveryKit, recoveryAuthFor, createTeamFolder, decryptRecordBody, deriveLoginKeys, encryptNewRecord,
  openMembershipRecoveryGrant, openOrgFolderKey, openRecordKey, openRecoveryWrap, openSharedRecordKeyInOrg, ownerRecordKeyFromFolder, parseRecoveryCode,
  rewrapOwnerRecordKey, rotateFolderKeySeal, sealFolderKeyFor, sealOrgFolderKey, sealOrgRecordShare, shareRecordKey, unlockMembershipKeys, unwrapKey,
  wrapKey, wrapMembershipKeys, type MembershipKeys, type UnlockedKeys,
} from "@clane-vault/crypto";
import { makeTestApp, resetDb, createActiveUser, defaultOrgId } from "./helpers.js";
import { approveScoped, escrowKey, keyUp, keysOf, migrateRows, req, scopedReset, type KeyUser } from "./keys.js";
import { newRefreshToken, signAccess } from "../src/lib/tokens.js";

// Per-org key pairs (docs/design/2026-10-08-per-org-keypairs.md): an admin of org A restores what a
// person holds in A, never their private items or another organisation's.
const t = await makeTestApp();
afterAll(() => t.app.close());
beforeEach(() => resetDb(t.prisma));

type U = Awaited<ReturnType<typeof createActiveUser>>;
let ip = 0;
const pub = (url: string, payload: object, headers: Record<string, string> = {}) =>
  t.app.inject({ method: "POST", url: `/api/v1${url}`, payload, headers, remoteAddress: `10.240.${(++ip >> 8) & 255}.${ip & 255}` });
const totp = async (u: { id: string; totpSecret: string }) => { await t.prisma.user.update({ where: { id: u.id }, data: { totpLastStep: null } }); return authenticator.generate(u.totpSecret); };
const newOrg = (name: string) => t.prisma.organization.create({ data: { name, slug: `${name.toLowerCase()}-${crypto.randomUUID().slice(0, 8)}`, adminRecoveryEnabled: true, adminRecoveryChangedAt: new Date(Date.now() - 1000) } });
const policyOn = (orgId: string) => t.prisma.organization.update({ where: { id: orgId }, data: { adminRecoveryEnabled: true, adminRecoveryChangedAt: new Date(Date.now() - 1000) } });
const join = (u: U, orgId: string) => t.prisma.membership.create({ data: { orgId, userId: u.id, role: "member", status: "active", joinedAt: new Date() } });
const sync = async (u: KeyUser, org: string | null) => (await req(t, u, "GET", "/sync", undefined, org)).json();
const ringOf = async (s: { membershipKeys?: { publicKey: string; wrappedPrivateKey: string }[] }, userKey: Uint8Array, orgId: string, userId: string) =>
  new Map(await Promise.all((s.membershipKeys ?? []).map(async (k) => [k.publicKey, await unlockMembershipKeys(userKey, { orgId, userId }, k)] as [string, MembershipKeys])));

/** A team folder in `org`, its owner's copy sealed to the owner's account key (as before membership keys). */
async function teamFolder(owner: U, org: string) {
  const id = crypto.randomUUID();
  const f = await createTeamFolder(id, "Team", owner.keys.publicKey);
  expect((await req(t, owner, "POST", "/folders", { id, kind: "team", encName: f.encName, wrappedFolderKey: f.wrappedFolderKey }, org)).statusCode).toBe(201);
  return { id, folderKey: f.folderKey };
}
const addMember = async (owner: U, f: { id: string; folderKey: Uint8Array }, who: U, org: string) =>
  expect((await req(t, owner, "POST", `/folders/${f.id}/members`, { userId: who.id, permission: "edit", wrappedFolderKey: await sealFolderKeyFor(f.folderKey, f.id, who.keys.publicKey) }, org)).statusCode).toBe(201);
async function teamRecord(u: U, f: { id: string; folderKey: Uint8Array }, org: string, title = "Team login") {
  const id = crypto.randomUUID();
  const enc = await encryptNewRecord(id, { type: "login", title, password: "pw" }, u.keys.userKey);
  expect((await req(t, u, "POST", "/records", { id, folderId: f.id, type: "login", encBody: enc.encBody, wrappedRecordKey: await wrapKey(enc.recordKey, f.folderKey, `record-key:${id}`), ownerWrappedRecordKey: enc.wrappedRecordKey }, org)).statusCode).toBe(201);
  return { id, recordKey: enc.recordKey };
}
async function privateRecord(u: U) {
  const id = crypto.randomUUID();
  const enc = await encryptNewRecord(id, { type: "note", title: "Diary" }, u.keys.userKey);
  expect((await req(t, u, "POST", "/records", { id, folderId: null, type: "note", encBody: enc.encBody, wrappedRecordKey: enc.wrappedRecordKey })).statusCode).toBe(201);
  return id;
}

/** Ana is a member of A and B; adminA and ownerB run them; both have admin recovery on and Ana escrowed in each. */
async function world() {
  const A = await defaultOrgId(t.prisma);
  await policyOn(A);
  const B = (await newOrg("Beta")).id;
  const adminA = await createActiveUser(t, { role: "admin" }), ownerB = await createActiveUser(t, { role: "owner", orgId: B });
  const ana = await createActiveUser(t, { orgId: A });
  await join(ana, B);
  const FA = await teamFolder(adminA, A), FB = await teamFolder(ownerB, B);
  // Admins unlocked once since (their own folder rows move to their membership keys).
  await keyUp(t, adminA, A); await keyUp(t, ownerB, B);
  await migrateRows(t, adminA, A); await migrateRows(t, ownerB, B);
  await addMember(adminA, FA, ana, A); await addMember(ownerB, FB, ana, B);
  const RA = await teamRecord(ana, FA, A, "Ana's A login");
  const RB = await teamRecord(ownerB, FB, B, "B login");
  const priv = await privateRecord(ana);
  expect(await escrowKey(t, ana, A)).toBe(1);
  expect(await escrowKey(t, ana, B)).toBe(1);
  return { A, B, adminA, ownerB, ana, FA, FB, RA, RB, priv };
}

describe("scoped admin recovery for someone in two organisations", () => {
  it("A's admin restores A only; B's admin can restore B later; the old kit restores private items", async () => {
    const w = await world();
    const { authKey } = await deriveLoginKeys(w.ana.password, w.ana.material.kdfSalt, w.ana.material.kdfParams);
    const kit = await createRecoveryKit(w.ana.id, w.ana.keys.userKey);
    expect((await req(t, w.ana, "POST", "/me/recovery-kit", { authKey, recoveryWrap: kit.recoveryWrap, recoveryAuth: kit.recoveryAuth })).statusCode).toBe(201);

    // One request per org.
    expect((await pub("/auth/recovery/admin/request", { email: w.ana.email })).statusCode).toBe(202);
    const reqs = await t.prisma.recoveryRequest.findMany({ where: { userId: w.ana.id } });
    const rA = reqs.find((r) => r.orgId === w.A)!, rB = reqs.find((r) => r.orgId === w.B)!;
    expect(rA && rB).toBeTruthy();

    // A's admin approves; Ana resets with A's link.
    const g = await approveScoped(t, w.adminA, rA.id, await totp(w.adminA), w.A);
    const link = await pub(`/auth/recovery/admin/${rA.id}`, { proof: await adminRecoveryProof(g.fragment), code: await totp(w.ana) });
    expect(link.json()).toMatchObject({ mode: "reset", orgId: w.A });
    expect(link.json()).not.toHaveProperty("material");
    expect(link.json()).not.toHaveProperty("kdf");
    const reset = await scopedReset(rA.id, g.fragment, link.json());
    const fin = await pub("/auth/recovery/finish", reset.payload, { authorization: `Bearer ${link.json().recoveryToken}` });
    expect(fin.statusCode, fin.body).toBe(200);
    const ana2: KeyUser = { id: w.ana.id, email: w.ana.email, totpSecret: w.ana.totpSecret, orgId: w.A, accessToken: fin.json().accessToken, keys: reset.keys };
    const arch = await t.prisma.accountKeyArchive.findFirstOrThrow({ where: { userId: w.ana.id } });
    expect(arch).toMatchObject({ privateItems: 1, otherOrgs: 1, recoveryWrap: kit.recoveryWrap });
    expect((await req(t, ana2, "GET", "/me/security")).json().keyArchive).toMatchObject({ privateItems: 1, otherOrgs: 1 });

    // In A: the team folder opens with the restored membership key.
    const sA = await sync(ana2, w.A);
    const ringA = await ringOf(sA, reset.keys.userKey, w.A, w.ana.id);
    const fa = sA.folders.find((f: { id: string }) => f.id === w.FA.id);
    expect(await openOrgFolderKey(fa.wrappedFolderKey, { orgId: w.A, folderId: w.FA.id }, ringA.get(fa.sealedTo)!)).toEqual(w.FA.folderKey);
    // In B: nothing opens (B's key is archived), and B's owner sees that Ana needs access again.
    const sB = await sync(ana2, w.B);
    expect(sB.membershipKeys).toEqual([]);
    const fbOwner = (await sync(w.ownerB as KeyUser, w.B)).folders.find((f: { id: string }) => f.id === w.FB.id);
    expect(fbOwner.members.find((m: { userId: string }) => m.userId === w.ana.id)).toMatchObject({ needsAccess: true });
    // Private: the owner row is under the old user key: it doesn't open.
    const sNone = await sync(ana2, null);
    const pr = sNone.records.find((r: { id: string }) => r.id === w.priv);
    await expect(openRecordKey({ recordId: pr.id, holderType: "user", wrappedRecordKey: pr.wrappedRecordKey, folderId: null }, reset.keys, new Map())).rejects.toThrow();

    // First unlock in A: rebuild owner rows from folder rows, then rotate (an admin saw the key).
    let st = (await req(t, ana2, "GET", "/membership-key", undefined, w.A)).json();
    expect(st).toMatchObject({ repairNeeded: true, rotateNeeded: true });
    const rows = (await req(t, ana2, "GET", "/membership-key/owner-repair", undefined, w.A)).json().rows;
    expect(rows).toEqual([{ recordId: w.RA.id, ownerWrapped: expect.any(String), folderId: w.FA.id, folderWrapped: expect.any(String) }]);
    const rebuilt = await ownerRecordKeyFromFolder(w.RA.id, rows[0].folderWrapped, w.FA.folderKey, reset.keys.userKey);
    expect((await req(t, ana2, "PUT", "/me/owner-rows", { rows: [{ recordId: w.RA.id, from: rows[0].ownerWrapped, wrappedRecordKey: rebuilt }] }, w.A)).json()).toEqual({ updated: 1 });
    expect((await req(t, ana2, "POST", "/membership-key/repaired", {}, w.A)).statusCode).toBe(200);
    const oldKey = ringA.get(fa.sealedTo)!;
    const next = await createMembershipKeys(reset.keys.userKey, { orgId: w.A, userId: w.ana.id });
    expect((await req(t, ana2, "POST", "/membership-key/rotate", { from: fa.sealedTo, ...next.material }, w.A)).statusCode).toBe(200);
    expect((await req(t, ana2, "POST", "/membership-key/rotate", { from: fa.sealedTo, ...next.material }, w.A)).json()).toEqual({ error: "stale_key" });
    const pend = (await req(t, ana2, "GET", "/membership-key/pending", undefined, w.A)).json();
    expect(pend.folders).toEqual([{ folderId: w.FA.id, sealedTo: fa.sealedTo, wrappedFolderKey: fa.wrappedFolderKey }]);
    const moved = await rotateFolderKeySeal(fa.wrappedFolderKey, { orgId: w.A, folderId: w.FA.id }, oldKey, next.keys);
    expect((await req(t, ana2, "PUT", "/membership-key/rows", { to: next.material.publicKey, folders: [{ folderId: w.FA.id, from: fa.sealedTo, wrappedFolderKey: moved }] }, w.A)).json()).toEqual({ updated: 1, retired: 1, pendingRows: 0 });
    st = (await req(t, ana2, "GET", "/membership-key", undefined, w.A)).json();
    expect(st).toMatchObject({ repairNeeded: false, rotateNeeded: false, keys: [{ publicKey: next.material.publicKey, state: "current" }] });
    // The rotated key isn't escrowed yet (the old escrow went with the rotation): escrow again to A's admin.
    keysOf(ana2).set(w.A, next.keys);
    expect(await escrowKey(t, ana2, w.A)).toBe(1);
    const recA = (await sync(ana2, w.A)).records.find((r: { id: string }) => r.id === w.RA.id);
    expect((await decryptRecordBody(w.RA.id, recA.encBody, await openRecordKey({ recordId: w.RA.id, holderType: recA.holderType, wrappedRecordKey: recA.wrappedRecordKey, folderId: null }, reset.keys, new Map()))).title).toBe("Ana's A login");

    // B's owner approves B's (still open) request later: Ana restores B under her current password, no reset.
    const gB = await approveScoped(t, w.ownerB, rB.id, await totp(w.ownerB), w.B);
    const linkB = await pub(`/auth/recovery/admin/${rB.id}`, { proof: await adminRecoveryProof(gB.fragment), code: await totp(w.ana) });
    expect(linkB.json()).toMatchObject({ mode: "restore", orgId: w.B, kdf: { kdfSalt: reset.payload.material.kdfSalt } });
    // The link never carries the wrapped user key: it comes only for the current master password.
    expect(linkB.json()).not.toHaveProperty("material");
    expect(JSON.stringify(linkB.json())).not.toContain(reset.payload.material.wrappedUserKey);
    const matTok = { authorization: `Bearer ${linkB.json().recoveryToken}` };
    expect((await pub("/auth/recovery/restore-membership/material", { authKey: "AAAA" }, matTok)).json()).toEqual({ error: "invalid_credentials" });
    expect((await pub("/auth/recovery/restore-membership/material", { authKey: reset.payload.authKey }, matTok)).json()).toEqual({ material: reset.payload.material });
    expect((await pub("/auth/recovery/restore-membership/material", { authKey: reset.payload.authKey }, { authorization: `Bearer ${ana2.accessToken}` })).statusCode).toBe(401);
    const bKey = await openMembershipRecoveryGrant(rB.id, { orgId: w.B, userId: w.ana.id }, gB.fragment, linkB.json().wrappedMembershipKey, linkB.json().memberPublicKey);
    const rewrapped = await wrapMembershipKeys(reset.keys.userKey, { orgId: w.B, userId: w.ana.id }, bKey);
    const tok = { authorization: `Bearer ${linkB.json().recoveryToken}` };
    expect((await pub("/auth/recovery/restore-membership", { authKey: "AAAA", ...rewrapped }, tok)).json()).toEqual({ error: "invalid_credentials" });
    expect((await pub("/auth/recovery/restore-membership", { authKey: reset.payload.authKey, ...rewrapped }, tok)).json()).toEqual({ ok: true, orgId: w.B });
    expect((await pub("/auth/recovery/restore-membership", { authKey: reset.payload.authKey, ...rewrapped }, tok)).statusCode).toBe(410);
    expect((await req(t, ana2, "GET", "/me")).statusCode).toBe(200); // still signed in
    const sB2 = await sync(ana2, w.B);
    const ringB = await ringOf(sB2, reset.keys.userKey, w.B, w.ana.id);
    const fb = sB2.folders.find((f: { id: string }) => f.id === w.FB.id);
    expect(await openOrgFolderKey(fb.wrappedFolderKey, { orgId: w.B, folderId: w.FB.id }, ringB.get(fb.sealedTo)!)).toEqual(w.FB.folderKey);
    expect((await req(t, ana2, "GET", "/membership-key", undefined, w.B)).json().rotateNeeded).toBe(true);

    // Private items: the old kit opens the archived user key; the client re-wraps the owner rows.
    const archId = (await req(t, ana2, "GET", "/me/key-archive")).json().archives[0].id as string;
    const kitAuth = await recoveryAuthFor(await parseRecoveryCode(kit.code));
    expect((await req(t, ana2, "POST", "/me/key-archive/open", { code: "000000", id: archId, recoveryAuth: kitAuth })).json()).toEqual({ error: "totp_invalid" });
    // A session and a 2FA code alone never get the old wrapped user key (it would let whoever completed the reset guess
    // the old master password offline); nor do a wrong kit or a wrong old password.
    expect((await req(t, ana2, "POST", "/me/key-archive/open", { code: await totp(w.ana), id: archId })).json()).toEqual({ error: "invalid_credentials" });
    expect((await req(t, ana2, "POST", "/me/key-archive/open", { code: await totp(w.ana), id: archId, recoveryAuth: b64url.encode(new Uint8Array(32).fill(7)) })).json()).toEqual({ error: "invalid_credentials" });
    expect((await req(t, ana2, "POST", "/me/key-archive/open", { code: await totp(w.ana), id: archId, authKey: reset.payload.authKey })).json()).toEqual({ error: "invalid_credentials" });
    await t.prisma.user.update({ where: { id: w.ana.id }, data: { failedLogins: 0, lockedUntil: null } });
    const opened = (await req(t, ana2, "POST", "/me/key-archive/open", { code: await totp(w.ana), id: archId, recoveryAuth: kitAuth })).json();
    expect(opened.archives).toHaveLength(1);
    const oldUserKey = await openRecoveryWrap(w.ana.id, await parseRecoveryCode(kit.code), opened.archives[0].recoveryWrap);
    expect(oldUserKey).toEqual(w.ana.keys.userKey);
    const owners = (await req(t, ana2, "GET", "/me/owner-rows")).json().rows as { recordId: string; wrappedRecordKey: string }[];
    const fixes = [];
    for (const r of owners) { try { fixes.push({ recordId: r.recordId, from: r.wrappedRecordKey, wrappedRecordKey: await rewrapOwnerRecordKey(r.recordId, r.wrappedRecordKey, oldUserKey, reset.keys.userKey) }); } catch { /* already under the new key */ } }
    expect(fixes.map((f) => f.recordId)).toEqual([w.priv]);
    expect((await req(t, ana2, "PUT", "/me/owner-rows", { rows: fixes })).json()).toEqual({ updated: 1 });
    const pr2 = (await sync(ana2, null)).records.find((r: { id: string }) => r.id === w.priv);
    const rk = await unwrapKey(pr2.wrappedRecordKey, reset.keys.userKey, `record-key:${w.priv}`);
    expect((await decryptRecordBody(w.priv, pr2.encBody, rk)).title).toBe("Diary");
    expect((await req(t, ana2, "POST", `/me/key-archive/${opened.archives[0].id}/restored`, {})).statusCode).toBe(200);
    expect((await req(t, ana2, "GET", "/me/security")).json().keyArchive).toBeNull();
    expect((await req(t, ana2, "DELETE", `/me/key-archive/${opened.archives[0].id}`)).statusCode).toBe(204);
    expect(await t.prisma.accountKeyArchive.count()).toBe(0);
  });

  it("an archived membership key comes back from the archive (old password): a share made in that org opens again", async () => {
    const w = await world();
    // A direct share in B made before Ana had a key in B would be on her account key: make one now on her account key.
    const shId = crypto.randomUUID();
    const shEnc = await encryptNewRecord(shId, { type: "note", title: "Shared" }, w.ownerB.keys.userKey);
    expect((await req(t, w.ownerB, "POST", "/records", { id: shId, folderId: null, type: "note", encBody: shEnc.encBody, wrappedRecordKey: shEnc.wrappedRecordKey }, w.B)).statusCode).toBe(201);
    const sh = { id: shId, recordKey: shEnc.recordKey };
    // (B now has a membership key for Ana, so a share must be sealed to it.)
    const anaB = b64url.encode(keysOf(w.ana).get(w.B)!.publicKey);
    expect((await req(t, w.ownerB, "POST", `/records/${sh.id}/shares`, { userId: w.ana.id, permission: "view", sealedRecordKey: await shareRecordKey(sh.recordKey, sh.id, w.ana.keys.publicKey) }, w.B)).json()).toEqual({ error: "stale_recipient_key" });
    expect((await req(t, w.ownerB, "POST", `/records/${sh.id}/shares`, { userId: w.ana.id, permission: "view", sealedTo: anaB, sealedRecordKey: await sealOrgRecordShare(sh.recordKey, { orgId: w.B, recordId: sh.id }, keysOf(w.ana).get(w.B)!.publicKey) }, w.B)).statusCode).toBe(201);
    // Reset through A.
    expect((await pub("/auth/recovery/admin/request", { email: w.ana.email })).statusCode).toBe(202);
    const rA = await t.prisma.recoveryRequest.findFirstOrThrow({ where: { userId: w.ana.id, orgId: w.A } });
    const g = await approveScoped(t, w.adminA, rA.id, await totp(w.adminA), w.A);
    const link = (await pub(`/auth/recovery/admin/${rA.id}`, { proof: await adminRecoveryProof(g.fragment), code: await totp(w.ana) })).json();
    const reset = await scopedReset(rA.id, g.fragment, link);
    const fin = await pub("/auth/recovery/finish", reset.payload, { authorization: `Bearer ${link.recoveryToken}` });
    const ana2: KeyUser = { id: w.ana.id, email: w.ana.email, totpSecret: w.ana.totpSecret, orgId: w.A, accessToken: fin.json().accessToken, keys: reset.keys };
    // B's owner sees the share needs re-sharing.
    const shB = (await sync(w.ownerB as KeyUser, w.B)).records.find((r: { id: string }) => r.id === sh.id);
    expect(shB.sharedWith).toEqual([expect.objectContaining({ userId: w.ana.id, needsAccess: true })]);
    // B's earlier request was denied; asking again after the reset still reaches B (its escrow is of the archived key).
    const rB = await t.prisma.recoveryRequest.findFirstOrThrow({ where: { userId: w.ana.id, orgId: w.B, status: "pending" } });
    expect((await req(t, w.ownerB, "POST", `/admin/recovery-requests/${rB.id}/deny`, {}, w.B)).statusCode).toBe(200);
    expect((await pub("/auth/recovery/admin/request", { email: w.ana.email })).statusCode).toBe(202);
    expect(await t.prisma.recoveryRequest.count({ where: { userId: w.ana.id, orgId: w.B, status: "pending" } })).toBe(1);
    // Old password opens the archive: the archived B key is re-wrapped and becomes current again.
    const listed = (await req(t, ana2, "GET", "/me/key-archive")).json().archives[0];
    expect(listed).not.toHaveProperty("wrappedUserKey");
    const { authKey: oldAuth, wrapKey: wk } = await deriveLoginKeys(w.ana.password, listed.kdfSalt, listed.kdfParams);
    const opened = (await req(t, ana2, "POST", "/me/key-archive/open", { code: await totp(w.ana), id: listed.id, authKey: oldAuth })).json();
    const a = opened.archives[0];
    const { unlockAccount } = await import("@clane-vault/crypto");
    const old: UnlockedKeys = await unlockAccount(wk, a);
    expect(a.membershipKeys).toEqual([{ orgId: w.B, publicKey: anaB, wrappedPrivateKey: expect.any(String) }]);
    const bKey = await unlockMembershipKeys(old.userKey, { orgId: w.B, userId: w.ana.id }, a.membershipKeys[0]);
    const re = await wrapMembershipKeys(reset.keys.userKey, { orgId: w.B, userId: w.ana.id }, bKey);
    expect((await req(t, ana2, "POST", `/me/key-archive/${a.id}/memberships`, { keys: [{ orgId: w.B, ...re }] })).json()).toEqual({ restored: 1 });
    const sB = await sync(ana2, w.B);
    const ring = await ringOf(sB, reset.keys.userKey, w.B, w.ana.id);
    const row = sB.records.find((r: { id: string }) => r.id === sh.id);
    expect(await openSharedRecordKeyInOrg({ orgId: w.B, recordId: sh.id, wrappedRecordKey: row.wrappedRecordKey, sealedTo: row.sealedTo }, reset.keys, ring)).toEqual(sh.recordKey);
    expect((await sync(w.ownerB as KeyUser, w.B)).records.find((r: { id: string }) => r.id === sh.id).sharedWith[0].needsAccess).toBeUndefined();
  });
});

describe("giving access again after a key change", () => {
  it("a folder key holder re-seals explicitly to the member's new key; nothing else can overwrite a working row", async () => {
    const w = await world();
    const viewer = await createActiveUser(t, { orgId: w.B });
    await join(viewer, w.A).catch(() => undefined);
    // Ana's B key is lost (as after a reset nobody in B restored).
    await t.prisma.membershipKey.updateMany({ where: { userId: w.ana.id, orgId: w.B }, data: { state: "archived" } });
    const regrant = (by: U, body: object) => req(t, by, "PUT", `/folders/${w.FB.id}/members/${w.ana.id}/key`, body, w.B);
    const fresh = await createMembershipKeys(w.ana.keys.userKey, { orgId: w.B, userId: w.ana.id });
    const sealedNew = await sealOrgFolderKey(w.FB.folderKey, { orgId: w.B, folderId: w.FB.id }, fresh.keys.publicKey);
    // Ana hasn't unlocked yet (no current key): a key that isn't hers is refused.
    expect((await regrant(w.ownerB, { wrappedFolderKey: sealedNew, sealedTo: fresh.material.publicKey })).json()).toEqual({ error: "stale_recipient_key" });
    expect((await req(t, w.ana, "POST", "/membership-key", fresh.material, w.B)).statusCode).toBe(201);
    // Someone outside the folder can't.
    expect((await regrant(viewer, { wrappedFolderKey: sealedNew, sealedTo: fresh.material.publicKey })).statusCode).toBe(404);
    expect((await regrant(w.ownerB, { wrappedFolderKey: sealedNew, sealedTo: fresh.material.publicKey })).json()).toEqual({ ok: true });
    expect(await t.prisma.event.count({ where: { action: "folder.access_regranted", targetUserId: w.ana.id } })).toBe(1);
    // Now the row works: a second re-seal (e.g. a server pretending she lost it again) is refused.
    expect((await regrant(w.ownerB, { wrappedFolderKey: sealedNew, sealedTo: fresh.material.publicKey })).json()).toEqual({ error: "has_access" });
    const fb = (await sync(w.ana as KeyUser, w.B)).folders.find((f: { id: string }) => f.id === w.FB.id);
    expect(await openOrgFolderKey(fb.wrappedFolderKey, { orgId: w.B, folderId: w.FB.id }, fresh.keys)).toEqual(w.FB.folderKey);
  });
});

describe("membership key endpoints", () => {
  it("a batch sealed to a key that another device just rotated away is refused, and that key isn't dropped (no lost access)", async () => {
    const w = await world();
    const k1 = keysOf(w.ana).get(w.A)!;
    const k1b = b64url.encode(k1.publicKey);
    // A folder row still on Ana's account key (from before her membership key).
    await t.prisma.folderMember.update({ where: { folderId_userId: { folderId: w.FA.id, userId: w.ana.id } }, data: { sealedTo: null, wrappedFolderKey: await sealFolderKeyFor(w.FA.folderKey, w.FA.id, w.ana.keys.publicKey) } });
    // Device 1 seals it to K1; meanwhile device 2 rotates K1 → K2.
    const toK1 = await sealOrgFolderKey(w.FA.folderKey, { orgId: w.A, folderId: w.FA.id }, k1.publicKey);
    const k2 = await createMembershipKeys(w.ana.keys.userKey, { orgId: w.A, userId: w.ana.id });
    expect((await req(t, w.ana, "POST", "/membership-key/rotate", { from: k1b, ...k2.material }, w.A)).statusCode).toBe(200);
    const stale = await req(t, w.ana, "PUT", "/membership-key/rows", { to: k1b, folders: [{ folderId: w.FA.id, from: null, wrappedFolderKey: toK1 }] }, w.A);
    expect(stale.statusCode).toBe(409);
    expect(stale.json()).toEqual({ error: "stale_key" });
    // Nothing was labelled with K2 while sealed to K1, and K1 (retiring) is still there.
    expect(await t.prisma.folderMember.findUniqueOrThrow({ where: { folderId_userId: { folderId: w.FA.id, userId: w.ana.id } } })).toMatchObject({ sealedTo: null });
    expect(await t.prisma.membershipKey.findFirst({ where: { publicKey: k1b } })).toMatchObject({ state: "retiring" });
    // Sealed to the new current key, it goes through.
    const toK2 = await sealOrgFolderKey(w.FA.folderKey, { orgId: w.A, folderId: w.FA.id }, k2.keys.publicKey);
    expect((await req(t, w.ana, "PUT", "/membership-key/rows", { to: k2.material.publicKey, folders: [{ folderId: w.FA.id, from: null, wrappedFolderKey: toK2 }] }, w.A)).json()).toMatchObject({ updated: 1 });
    const row = await t.prisma.folderMember.findUniqueOrThrow({ where: { folderId_userId: { folderId: w.FA.id, userId: w.ana.id } } });
    expect(row.sealedTo).toBe(k2.material.publicKey);
    expect(await openOrgFolderKey(row.wrappedFolderKey, { orgId: w.A, folderId: w.FA.id }, k2.keys)).toEqual(w.FA.folderKey);
  });

  it("an admin can't release an escrow of a key the member has retired", async () => {
    const w = await world();
    const k1b = b64url.encode(keysOf(w.ana).get(w.A)!.publicKey);
    // K1 retiring with its escrow still on file (e.g. an archived key restored next to a newer one).
    await t.prisma.membershipKey.updateMany({ where: { publicKey: k1b }, data: { state: "retiring", retiredAt: new Date() } });
    const k2 = await createMembershipKeys(w.ana.keys.userKey, { orgId: w.A, userId: w.ana.id });
    await t.prisma.membershipKey.create({ data: { orgId: w.A, userId: w.ana.id, publicKey: k2.material.publicKey, wrappedPrivateKey: k2.material.wrappedPrivateKey, userKeyGen: 1 } });
    expect(await t.prisma.membershipEscrow.count({ where: { orgId: w.A, userId: w.ana.id, memberPublicKey: k1b } })).toBe(1);
    const r = await t.prisma.recoveryRequest.create({ data: { userId: w.ana.id, orgId: w.A } });
    const e = await req(t, w.adminA, "POST", `/admin/recovery-requests/${r.id}/escrow`, { code: await totp(w.adminA) }, w.A);
    expect(e.json()).toEqual({ error: "no_escrow" });
  });

  it("create is idempotent; rows of another org can't be moved; a session confined to one org stays there", async () => {
    const w = await world();
    const cur = (await req(t, w.ana, "GET", "/membership-key", undefined, w.A)).json().keys[0];
    const other = await createMembershipKeys(w.ana.keys.userKey, { orgId: w.A, userId: w.ana.id });
    expect((await req(t, w.ana, "POST", "/membership-key", other.material, w.A)).json()).toEqual({ created: false, key: { publicKey: cur.publicKey, wrappedPrivateKey: cur.wrappedPrivateKey, state: "current" } });
    // Moving B's folder row through A's endpoint does nothing.
    const fbRow = await t.prisma.folderMember.findUniqueOrThrow({ where: { folderId_userId: { folderId: w.FB.id, userId: w.ana.id } } });
    expect((await req(t, w.ana, "PUT", "/membership-key/rows", { to: cur.publicKey, folders: [{ folderId: w.FB.id, from: fbRow.sealedTo, wrappedFolderKey: "s1.a.b.c" }] }, w.A)).json()).toMatchObject({ updated: 0 });
    expect(await migrateRows(t, w.ana, w.A)).toBe(0);
    // A session confined to A (trusted IdP MFA, no TOTP yet).
    const s = await t.prisma.session.create({ data: { userId: w.ana.id, refreshHash: newRefreshToken("x").hash, expiresAt: new Date(Date.now() + 3600e3), totpSkippedForOrg: w.A } });
    const confined = { accessToken: await signAccess(t.config, { userId: w.ana.id, sessionId: s.id }) };
    expect((await req(t, confined, "GET", "/membership-key", undefined, w.A)).statusCode).toBe(200);
    expect((await req(t, confined, "GET", "/membership-key", undefined, w.B)).json()).toEqual({ error: "totp_step_up_required" });
    expect((await req(t, confined, "POST", "/me/key-archive/open", { code: "123456" }, w.A)).json()).toEqual({ error: "totp_step_up_required" });
    expect((await req(t, confined, "GET", "/me/owner-rows", undefined, w.A)).json()).toEqual({ error: "totp_step_up_required" });
  });

  it("leaving an org drops that membership's keys and escrows; the other org's stay", async () => {
    const w = await world();
    expect((await req(t, w.ana, "POST", "/org/leave", undefined, w.B)).statusCode).toBe(204);
    expect(await t.prisma.membershipKey.count({ where: { userId: w.ana.id, orgId: w.B } })).toBe(0);
    expect(await t.prisma.membershipEscrow.count({ where: { userId: w.ana.id, orgId: w.B } })).toBe(0);
    expect(await t.prisma.membershipKey.count({ where: { userId: w.ana.id, orgId: w.A } })).toBe(1);
    expect(await t.prisma.membershipEscrow.count({ where: { userId: w.ana.id, orgId: w.A } })).toBe(1);
  });
});
