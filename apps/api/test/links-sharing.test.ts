import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { createLink, createTeamFolder, encryptNewRecord, sealFolderKeyFor, shareRecordKey, wrapKey } from "@clane-vault/crypto";
import { makeTestApp, resetDb, createActiveUser, orgHeader } from "./helpers.js";

// One-time links (phase 3) meet team folders and direct shares (phase 2).
const t = await makeTestApp();
afterAll(() => t.app.close());
beforeEach(() => resetDb(t.prisma));

type U = Awaited<ReturnType<typeof createActiveUser>>;
type Folder = { id: string; folderKey: Uint8Array };
const ipOf = (u: U) => `10.${parseInt(u.id.slice(-6, -4), 16)}.${parseInt(u.id.slice(-4, -2), 16)}.${parseInt(u.id.slice(-2), 16)}`;
const call = (u: U, method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE", url: string, payload?: unknown) =>
  t.app.inject({ method, url: `/api/v1${url}`, payload: payload as object, remoteAddress: ipOf(u), headers: { authorization: `Bearer ${u.accessToken}`, ...orgHeader(u) } });

async function teamFolder(owner: U): Promise<Folder> {
  const id = crypto.randomUUID();
  const f = await createTeamFolder(id, "Infra", owner.keys.publicKey);
  expect((await call(owner, "POST", "/folders", { id, kind: "team", encName: f.encName, wrappedFolderKey: f.wrappedFolderKey })).statusCode).toBe(201);
  return { id, folderKey: f.folderKey };
}
async function addMember(owner: U, f: Folder, who: U, permission: string) {
  expect((await call(owner, "POST", `/folders/${f.id}/members`, { userId: who.id, permission, wrappedFolderKey: await sealFolderKeyFor(f.folderKey, f.id, who.keys.publicKey) })).statusCode).toBe(201);
}
async function teamRecord(u: U, f: Folder) {
  const id = crypto.randomUUID();
  const enc = await encryptNewRecord(id, { type: "login", title: "AWS", password: "team-s3cret" }, u.keys.userKey);
  expect((await call(u, "POST", "/records", { id, folderId: f.id, type: "login", encBody: enc.encBody,
    wrappedRecordKey: await wrapKey(enc.recordKey, f.folderKey, `record-key:${id}`), ownerWrappedRecordKey: enc.wrappedRecordKey })).statusCode).toBe(201);
  return id;
}
async function privateRecord(u: U) {
  const id = crypto.randomUUID();
  const enc = await encryptNewRecord(id, { type: "login", title: "Stripe", password: "mine" }, u.keys.userKey);
  expect((await call(u, "POST", "/records", { id, folderId: null, type: "login", encBody: enc.encBody, wrappedRecordKey: enc.wrappedRecordKey })).statusCode).toBe(201);
  return { id, recordKey: enc.recordKey };
}
async function share(owner: U, rec: { id: string; recordKey: Uint8Array }, who: U, permission: string) {
  expect((await call(owner, "POST", `/records/${rec.id}/shares`, { userId: who.id, permission, sealedRecordKey: await shareRecordKey(rec.recordKey, rec.id, who.keys.publicKey) })).statusCode).toBe(201);
}
async function link(u: U, recordId: string) {
  const id = crypto.randomUUID();
  const l = await createLink(id, { title: "x", password: "y" }, {});
  const res = await call(u, "POST", "/links", { id, recordId, encPayload: l.encPayload, expiresInHours: 24, maxOpens: null });
  return { id, status: res.statusCode };
}
const revoked = async (id: string) => {
  const row = await t.prisma.shareLink.findUniqueOrThrow({ where: { id } });
  return row.revokedAt != null && row.encPayload == null;
};

describe("one-time links follow phase 2 permissions", () => {
  it("only owner and edit holders (direct or through a team folder) can create links", async () => {
    const a = await createActiveUser(t), ed = await createActiveUser(t), vw = await createActiveUser(t), us = await createActiveUser(t), out = await createActiveUser(t);
    const f = await teamFolder(a);
    await addMember(a, f, ed, "edit");
    await addMember(a, f, vw, "view");
    await addMember(a, f, us, "use");
    const tr = await teamRecord(a, f);
    expect((await link(a, tr)).status).toBe(201);
    expect((await link(ed, tr)).status).toBe(201);
    expect((await link(vw, tr)).status).toBe(403);
    expect((await link(us, tr)).status).toBe(403);
    expect((await link(out, tr)).status).toBe(404);

    const p = await privateRecord(a);
    await share(a, p, ed, "edit");
    await share(a, p, vw, "view");
    await share(a, p, us, "use");
    expect((await link(ed, p.id)).status).toBe(201);
    expect((await link(vw, p.id)).status).toBe(403);
    expect((await link(us, p.id)).status).toBe(403);
  });

  it("removing a direct share revokes that person's live links on the record, not the owner's", async () => {
    const a = await createActiveUser(t), b = await createActiveUser(t);
    const p = await privateRecord(a);
    await share(a, p, b, "edit");
    const mine = await link(a, p.id), theirs = await link(b, p.id);
    expect(theirs.status).toBe(201);
    expect((await call(a, "DELETE", `/records/${p.id}/shares/${b.id}`)).statusCode).toBe(204);
    expect(await revoked(theirs.id)).toBe(true);
    expect(await revoked(mine.id)).toBe(false);
  });

  it("downgrading a direct share to view revokes their links, unless a team folder still gives them edit", async () => {
    const a = await createActiveUser(t), b = await createActiveUser(t);
    const p = await privateRecord(a);
    await share(a, p, b, "edit");
    const l1 = await link(b, p.id);
    expect((await call(a, "PATCH", `/records/${p.id}/shares/${b.id}`, { permission: "view" })).statusCode).toBe(200);
    expect(await revoked(l1.id)).toBe(true);

    // A team record b can edit through the folder and also holds a direct share on.
    const f = await teamFolder(a);
    await addMember(a, f, b, "edit");
    const tr = await teamRecord(a, f);
    await t.prisma.recordAccess.create({ data: { recordId: tr, holderType: "user", holderId: b.id, permission: "edit", wrappedRecordKey: "s1.placeholder", orgId: b.orgId } });
    const l2 = await link(b, tr);
    expect((await call(a, "PATCH", `/records/${tr}/shares/${b.id}`, { permission: "view" })).statusCode).toBe(200);
    expect(await revoked(l2.id)).toBe(false);
    expect((await call(a, "DELETE", `/records/${tr}/shares/${b.id}`)).statusCode).toBe(204);
    expect(await revoked(l2.id)).toBe(false);
  });

  it("removing, downgrading or leaving a team folder revokes the member's links on its records", async () => {
    const a = await createActiveUser(t), b = await createActiveUser(t), c = await createActiveUser(t), d = await createActiveUser(t);
    const f = await teamFolder(a);
    for (const u of [b, c, d]) await addMember(a, f, u, "edit");
    const tr = await teamRecord(a, f);
    const own = await teamRecord(b, f); // b's own record: handed to the folder owner on removal
    const la = await link(a, tr), lb1 = await link(b, tr), lb2 = await link(b, own), lc = await link(c, tr), ld = await link(d, tr);
    const other = await privateRecord(b);
    const lbElsewhere = await link(b, other.id);

    expect((await call(a, "DELETE", `/folders/${f.id}/members/${b.id}`)).statusCode).toBe(204);
    expect(await revoked(lb1.id)).toBe(true);
    expect(await revoked(lb2.id)).toBe(true);
    expect(await revoked(lbElsewhere.id)).toBe(false); // links on records outside the folder stay

    expect((await call(c, "DELETE", `/folders/${f.id}/members/${c.id}`)).statusCode).toBe(204); // leaves
    expect(await revoked(lc.id)).toBe(true);

    expect((await call(a, "PATCH", `/folders/${f.id}/members/${d.id}`, { permission: "use" })).statusCode).toBe(200);
    expect(await revoked(ld.id)).toBe(true);

    expect(await revoked(la.id)).toBe(false);
  });

  it("disabling a member revokes every live link they created in the org; links on their own private records stay theirs", async () => {
    const admin = await createActiveUser(t, { role: "admin" }), b = await createActiveUser(t);
    const p = await privateRecord(b);
    const own = await link(b, p.id);
    const f = await teamFolder(admin);
    await addMember(admin, f, b, "edit");
    const tr = await teamRecord(admin, f);
    const l = await link(b, tr);
    expect((await call(admin, "POST", `/admin/users/${b.id}/disable`)).statusCode).toBe(200);
    expect(await revoked(l.id)).toBe(true);
    expect(await revoked(own.id)).toBe(false);
  });
});

