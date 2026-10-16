import { randomUUID } from "node:crypto";
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { createLink, createTeamFolder, encryptLinkLabel, encryptNewRecord, wrapKey } from "@clane-vault/crypto";
import { makeTestApp, resetDb, createActiveUser, createInvite } from "./helpers.js";
import { attReq, bytes, create, prepare } from "./attachmentClient.js";

// Hosted plan limits: pooled storage, the Personal one-time-link cap, and over-limit blocks (new team records and uploads only).
const MiB = 1024 * 1024;
const GiB = 1024 * MiB;
const hosted = await makeTestApp({ billingMode: "hosted" });
afterAll(() => hosted.app.close());
beforeEach(() => resetDb(hosted.prisma));

type U = Awaited<ReturnType<typeof createActiveUser>>;
type T = typeof hosted;
const call = (t: T, u: U, method: "GET" | "POST" | "PUT" | "DELETE", url: string, payload?: unknown) => attReq(t, u, method, url, payload);

async function teamFolder(t: T, owner: U) {
  const id = randomUUID();
  const f = await createTeamFolder(id, "Infra", owner.keys.publicKey);
  expect((await call(t, owner, "POST", "/folders", { id, kind: "team", encName: f.encName, wrappedFolderKey: f.wrappedFolderKey })).statusCode).toBe(201);
  return { id, key: f.folderKey };
}
async function teamRecord(t: T, u: U, f: { id: string; key: Uint8Array }) {
  const id = randomUUID();
  const enc = await encryptNewRecord(id, { type: "login", title: "AWS", password: "s3cret" }, u.keys.userKey);
  const res = await call(t, u, "POST", "/records", { id, folderId: f.id, type: "login", encBody: enc.encBody, wrappedRecordKey: await wrapKey(enc.recordKey, f.key, `record-key:${id}`), ownerWrappedRecordKey: enc.wrappedRecordKey });
  return { id, recordKey: enc.recordKey, enc, res };
}
async function personalRecord(t: T, u: U) {
  const id = randomUUID();
  const enc = await encryptNewRecord(id, { type: "login", title: "P", password: "x" }, u.keys.userKey);
  expect((await attReq(t, u, "POST", "/records", { id, folderId: null, type: "login", encBody: enc.encBody, wrappedRecordKey: enc.wrappedRecordKey }, { org: null })).statusCode).toBe(201);
  return { id, recordKey: enc.recordKey };
}
async function link(t: T, u: U, recordId: string, org: string | null) {
  const id = randomUUID();
  const l = await createLink(id, { title: "x" }, {});
  return attReq(t, u, "POST", "/links", { id, recordId, encPayload: l.encPayload, expiresInHours: 24, maxOpens: 1, labelEnc: await encryptLinkLabel(id, "L", u.keys.userKey) }, { org });
}
const fillStorage = (t: T, recordId: string, owner: U, size: number) =>
  t.prisma.attachment.create({ data: { id: randomUUID(), recordId, createdBy: owner.id, state: "ready", encMeta: "x", wrappedFileKey: "x", nonceBase: "x", chunkSize: 1, chunkCount: 1, size } });

describe("pooled storage", () => {
  it("a 1-member Team org holds 2 GiB: a reservation over it is refused, freeing space admits it again", async () => {
    const owner = await createActiveUser(hosted, { role: "owner" });
    const f = await teamFolder(hosted, owner);
    const filler = await teamRecord(hosted, owner, f);
    const target = await teamRecord(hosted, owner, f);
    await fillStorage(hosted, filler.id, owner, 2 * GiB - 3 * MiB);
    const first = await prepare(target.id, target.recordKey, bytes(2 * MiB));
    expect((await create(hosted, owner, target.id, first)).statusCode).toBe(201);
    const second = await prepare(target.id, target.recordKey, bytes(2 * MiB, 9));
    const r = await create(hosted, owner, target.id, second);
    expect([r.statusCode, r.json().error, r.json().scope, r.json().quota]).toEqual([409, "quota_exceeded", "org", 2 * GiB]);
    expect((await call(hosted, owner, "DELETE", `/records/${target.id}/attachments/${first.id}`)).statusCode).toBe(204);
    expect((await create(hosted, owner, target.id, second)).statusCode).toBe(201);
  });

  it("GET /org/plan reports storage used and limit", async () => {
    const owner = await createActiveUser(hosted, { role: "owner" });
    const f = await teamFolder(hosted, owner);
    await fillStorage(hosted, (await teamRecord(hosted, owner, f)).id, owner, 1000);
    expect((await call(hosted, owner, "GET", "/org/plan")).json().storage).toEqual({ used: 1000, limit: 2 * GiB });
  });
});

describe("Personal one-time links", () => {
  it("5 active links, the 6th is 402 link_limit, revoking frees one; org links are unlimited", async () => {
    const u = await createActiveUser(hosted, { role: "owner" });
    const rid = (await personalRecord(hosted, u)).id;
    const ids: string[] = [];
    for (let i = 0; i < 5; i++) { const r = await link(hosted, u, rid, null); expect(r.statusCode, r.body).toBe(201); ids.push(r.json().id); }
    const sixth = await link(hosted, u, rid, null);
    expect([sixth.statusCode, sixth.json()]).toEqual([402, { error: "link_limit", limit: 5 }]);
    expect((await call(hosted, u, "DELETE", `/links/${ids[0]}`)).statusCode).toBe(204);
    expect((await link(hosted, u, rid, null)).statusCode).toBe(201);
    const rec = await teamRecord(hosted, u, await teamFolder(hosted, u));
    for (let i = 0; i < 6; i++) expect((await link(hosted, u, rec.id, u.orgId!)).statusCode).toBe(201);
  });
});

/** 3 seats used (owner + 2 invites) against seatsPaid 1, as when an operator cuts the paid seats. */
async function overLimitOrg(t: T) {
  const owner = await createActiveUser(t, { role: "owner" });
  const f = await teamFolder(t, owner);
  const rec = await teamRecord(t, owner, f);
  expect(rec.res.statusCode).toBe(201);
  for (const e of ["a@x.test", "b@x.test"]) await createInvite(t.prisma, e, "member", owner.orgId!);
  await t.prisma.organization.update({ where: { id: owner.orgId! }, data: { seatsPaid: 1 } });
  return { owner, f, rec };
}

describe("over the seat limit", () => {
  it("blocks new team records and uploads, never reads, edits, deletes or exports", async () => {
    const { owner, f, rec } = await overLimitOrg(hosted);
    const blocked = await teamRecord(hosted, owner, f);
    expect([blocked.res.statusCode, blocked.res.json()]).toEqual([402, { error: "seat_limit", used: 3, allowed: 1 }]);
    const up = await create(hosted, owner, rec.id, await prepare(rec.id, rec.recordKey, bytes(1000)));
    expect([up.statusCode, up.json().error]).toEqual([402, "seat_limit"]);
    // Vault export is client-side from /sync; the server-side export is the people CSV (backups are instance-admin and unaffected: no seat code there).
    expect((await call(hosted, owner, "GET", "/sync")).statusCode).toBe(200);
    expect((await call(hosted, owner, "GET", "/admin/people/export.csv")).statusCode).toBe(200);
    const upd = await call(hosted, owner, "PUT", `/records/${rec.id}`, { encBody: rec.enc.encBody, revision: 1 });
    expect(upd.statusCode, upd.body).toBe(200);
    expect((await call(hosted, owner, "DELETE", `/records/${rec.id}`)).statusCode).toBeLessThan(300);
  });

  it("a private record's upload is not blocked", async () => {
    const { owner } = await overLimitOrg(hosted);
    const p = await personalRecord(hosted, owner);
    expect((await create(hosted, owner, p.id, await prepare(p.id, p.recordKey, bytes(1000)), { org: null })).statusCode).toBe(201);
  });
});

describe("billing off", () => {
  it("nothing refuses: no seat block, no link cap", async () => {
    const off = await makeTestApp();
    const owner = await createActiveUser(off, { role: "owner" });
    const f = await teamFolder(off, owner);
    const rec = await teamRecord(off, owner, f);
    for (const e of ["a@x.test", "b@x.test"]) await createInvite(off.prisma, e, "member", owner.orgId!);
    await off.prisma.organization.update({ where: { id: owner.orgId! }, data: { seatsPaid: 1 } });
    expect((await teamRecord(off, owner, f)).res.statusCode).toBe(201);
    expect((await create(off, owner, rec.id, await prepare(rec.id, rec.recordKey, bytes(1000)))).statusCode).toBe(201);
    const rid = (await personalRecord(off, owner)).id;
    for (let i = 0; i < 6; i++) expect((await link(off, owner, rid, null)).statusCode).toBe(201);
    await off.app.close();
  });
});
