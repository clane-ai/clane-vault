import { randomUUID } from "node:crypto";
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { createLink, createTeamFolder, encryptLinkLabel, encryptNewRecord, wrapKey } from "@clane-vault/crypto";
import { DEFAULT_ATTACHMENTS } from "../src/config.js";
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

// A large configured cap, so the plan's pooled storage is what limits (the default 2 GiB cap equals Team's per-seat storage).
const big = await makeTestApp({ billingMode: "hosted", attachments: { ...DEFAULT_ATTACHMENTS, orgQuotaMb: 1_000_000, userQuotaMb: 1_000_000, instanceQuotaMb: 10_000_000, dailyUploadMb: 10_000_000 } });
afterAll(() => big.app.close());
const small = await makeTestApp({ billingMode: "hosted", attachments: { ...DEFAULT_ATTACHMENTS, orgQuotaMb: 4 } });
afterAll(() => small.app.close());
const up = async (t: T, u: U, rec: { id: string; recordKey: Uint8Array }, seed: number, org?: string | null) =>
  create(t, u, rec.id, await prepare(rec.id, rec.recordKey, bytes(2 * MiB, seed)), org === undefined ? {} : { org });
const planLimit = async (t: T, u: U) => (await call(t, u, "GET", "/org/plan")).json().storage.limit;

describe("pooled storage", () => {
  it("a 1-member Team org holds 2 GiB (not the large configured cap): a reservation over it is refused, freeing space admits it again", async () => {
    const owner = await createActiveUser(big, { role: "owner" });
    const f = await teamFolder(big, owner);
    const filler = await teamRecord(big, owner, f);
    const target = await teamRecord(big, owner, f);
    await fillStorage(big, filler.id, owner, 2 * GiB - 3 * MiB);
    const first = await prepare(target.id, target.recordKey, bytes(2 * MiB));
    expect((await create(big, owner, target.id, first)).statusCode).toBe(201);
    const r = await up(big, owner, target, 9);
    expect([r.statusCode, r.json().error, r.json().scope, r.json().quota]).toEqual([409, "quota_exceeded", "org", 2 * GiB]);
    expect(await planLimit(big, owner)).toBe(r.json().quota);
    expect((await call(big, owner, "DELETE", `/records/${target.id}/attachments/${first.id}`)).statusCode).toBe(204);
    expect((await up(big, owner, target, 9)).statusCode).toBe(201);
  });

  it("the pool grows with active members: 2 members hold 4 GiB", async () => {
    const owner = await createActiveUser(big, { role: "owner" });
    await createActiveUser(big, { orgId: owner.orgId! });
    const f = await teamFolder(big, owner);
    const target = await teamRecord(big, owner, f);
    await fillStorage(big, (await teamRecord(big, owner, f)).id, owner, 2 * GiB - 1);
    await fillStorage(big, (await teamRecord(big, owner, f)).id, owner, 2 * GiB - 3 * MiB);
    expect((await up(big, owner, target, 1)).statusCode).toBe(201);
    const r = await up(big, owner, target, 2);
    expect([r.statusCode, r.json().scope, r.json().quota]).toEqual([409, "org", 4 * GiB]);
    expect(await planLimit(big, owner)).toBe(4 * GiB);
  });

  it("a personal (user-charged) record is held to 1 GiB", async () => {
    const u = await createActiveUser(big, { role: "owner" });
    const filler = await personalRecord(big, u);
    const target = await personalRecord(big, u);
    await fillStorage(big, filler.id, u, GiB - 3 * MiB);
    expect((await up(big, u, target, 1, null)).statusCode).toBe(201);
    const r = await up(big, u, target, 2, null);
    expect([r.statusCode, r.json().scope, r.json().quota]).toEqual([409, "user", GiB]);
  });

  it("a smaller configured cap wins over the plan, and /org/plan reports what is enforced", async () => {
    const owner = await createActiveUser(small, { role: "owner" });
    const target = await teamRecord(small, owner, await teamFolder(small, owner));
    expect((await up(small, owner, target, 1)).statusCode).toBe(201);
    const r = await up(small, owner, target, 2);
    expect([r.statusCode, r.json().quota]).toEqual([409, 4 * MiB]);
    expect(await planLimit(small, owner)).toBe(4 * MiB);
  });

  it("GET /org/plan reports storage used and limit", async () => {
    const owner = await createActiveUser(big, { role: "owner" });
    const f = await teamFolder(big, owner);
    await fillStorage(big, (await teamRecord(big, owner, f)).id, owner, 1000);
    expect((await call(big, owner, "GET", "/org/plan")).json().storage).toEqual({ used: 1000, limit: 2 * GiB });
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

  it("blocks batch import into a team folder and moves into one, but not private imports or moves out", async () => {
    const { owner, f, rec } = await overLimitOrg(hosted);
    const mk = async (folderId: string | null) => {
      const id = randomUUID();
      const enc = await encryptNewRecord(id, { type: "login", title: "I", password: "x" }, owner.keys.userKey);
      return { id, enc, item: { id, folderId, type: "login", encBody: enc.encBody, wrappedRecordKey: folderId ? await wrapKey(enc.recordKey, f.key, `record-key:${id}`) : enc.wrappedRecordKey, ...(folderId ? { ownerWrappedRecordKey: enc.wrappedRecordKey } : {}) } };
    };
    const t1 = await mk(f.id);
    const blocked = await call(hosted, owner, "POST", "/records/batch", { records: [t1.item] });
    expect([blocked.statusCode, blocked.json().error]).toEqual([402, "seat_limit"]);
    expect(await hosted.prisma.record.count({ where: { id: t1.id } })).toBe(0);
    const priv = await mk(null);
    expect((await attReq(hosted, owner, "POST", "/records/batch", { records: [priv.item] }, { org: null })).statusCode).toBe(201);
    const mv = await call(hosted, owner, "PUT", `/records/${priv.id}/folder`, { folderId: f.id, folderWrappedRecordKey: await wrapKey(priv.enc.recordKey, f.key, `record-key:${priv.id}`), ownerWrappedRecordKey: priv.enc.wrappedRecordKey });
    expect([mv.statusCode, mv.json().error]).toEqual([402, "seat_limit"]);
    const out = await call(hosted, owner, "PUT", `/records/${rec.id}/folder`, { folderId: null });
    expect(out.statusCode).not.toBe(402);
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
