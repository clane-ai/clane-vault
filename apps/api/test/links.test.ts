import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { createLink, openLink, openPasswordLink, deriveLinkAccess, encryptNewRecord, encryptLinkLabel, type KdfParams } from "@clane-vault/crypto";
import { makeTestApp, resetDb, createActiveUser, orgHeader } from "./helpers.js";
import { hashAccess, sweepExpiredLinks } from "../src/lib/links.js";

const t = await makeTestApp();
afterAll(() => t.app.close());
beforeEach(() => resetDb(t.prisma));

const FAST: KdfParams = { alg: "argon2id", m: 1024, t: 2, p: 1 };
type U = Awaited<ReturnType<typeof createActiveUser>>;
const call = (u: U, method: "GET" | "POST" | "PUT" | "DELETE", url: string, payload?: unknown) =>
  t.app.inject({ method, url: `/api/v1${url}`, payload: payload as object, headers: { authorization: `Bearer ${u.accessToken}`, ...orgHeader(u) } });
// Each public call comes from a fresh IP so the 30/min public limit does not interfere with lifecycle tests.
let ipSeq = 0;
const pub = (method: "GET" | "POST", url: string, payload?: unknown, ip = `10.1.${Math.floor(++ipSeq / 250)}.${ipSeq % 250}`) =>
  t.app.inject({ method, url: `/api/v1/public${url}`, payload: payload as object, remoteAddress: ip });

const body = { title: "Customer portal", username: "acme", password: "s3cret-value" };

async function addRecord(u: U) {
  const id = crypto.randomUUID();
  const enc = await encryptNewRecord(id, { type: "login", ...body }, u.keys.userKey);
  await call(u, "POST", "/records", { id, folderId: null, type: "login", encBody: enc.encBody, wrappedRecordKey: enc.wrappedRecordKey });
  return id;
}

async function makeLink(u: U, recordId: string, opts: { maxOpens?: 1 | 3 | null; expiresInHours?: 1 | 24 | 168; password?: string } = {}) {
  const id = crypto.randomUUID();
  const l = await createLink(id, body, opts.password ? { password: opts.password, kdf: FAST } : {});
  const res = await call(u, "POST", "/links", {
    id, recordId, encPayload: l.encPayload, expiresInHours: opts.expiresInHours ?? 24, maxOpens: opts.maxOpens === undefined ? 1 : opts.maxOpens,
    ...(l.passwordSalt ? { passwordSalt: l.passwordSalt, accessHash: l.accessHash } : {}), labelEnc: await encryptLinkLabel(id, "Acme", u.keys.userKey),
  });
  return { id, l, res };
}

describe("one-time links", () => {
  it("creates a link, opens it once, then refuses with used_up and burns the ciphertext", async () => {
    const u = await createActiveUser(t);
    const rid = await addRecord(u);
    const { id, l, res } = await makeLink(u, rid);
    expect(res.statusCode).toBe(201);
    const meta = await pub("GET", `/links/${id}`);
    expect(meta.statusCode).toBe(200);
    expect(meta.json()).toMatchObject({ needsPassword: false, passwordSalt: null, opensLeft: 1 });
    expect(meta.json().encPayload).toBeUndefined(); // looking does not hand out ciphertext
    const open = await pub("POST", `/links/${id}/open`, {});
    expect(open.statusCode).toBe(200);
    expect(open.json().opensLeft).toBe(0);
    expect(await openLink(id, open.json().encPayload, l.fragment)).toEqual(body);
    const again = await pub("POST", `/links/${id}/open`, {});
    expect(again.statusCode).toBe(410);
    expect(again.json()).toEqual({ error: "used_up" });
    expect((await pub("GET", `/links/${id}`)).json()).toEqual({ error: "used_up" });
    const row = await t.prisma.shareLink.findUniqueOrThrow({ where: { id } });
    expect(row.encPayload).toBeNull();
    expect(row.opens).toBe(1);
  });

  it("server never stores plaintext or the link key", async () => {
    const u = await createActiveUser(t);
    const { id, l } = await makeLink(u, await addRecord(u));
    const row = JSON.stringify(await t.prisma.shareLink.findUniqueOrThrow({ where: { id } }));
    expect(row).not.toContain("s3cret-value");
    expect(row).not.toContain(l.fragment);
  });

  it("allows exactly 3 opens, counting concurrent opens atomically", async () => {
    const u = await createActiveUser(t);
    const { id } = await makeLink(u, await addRecord(u), { maxOpens: 3 });
    const results = await Promise.all(Array.from({ length: 6 }, () => pub("POST", `/links/${id}/open`, {})));
    expect(results.filter((r) => r.statusCode === 200)).toHaveLength(3);
    expect(results.filter((r) => r.statusCode === 410)).toHaveLength(3);
    const row = await t.prisma.shareLink.findUniqueOrThrow({ where: { id } });
    expect(row.opens).toBe(3);
    expect(row.encPayload).toBeNull();
  });

  it("until expiry: opens any number of times; after expiry it is refused and burned", async () => {
    const u = await createActiveUser(t);
    const { id } = await makeLink(u, await addRecord(u), { maxOpens: null, expiresInHours: 1 });
    for (let i = 0; i < 4; i++) expect((await pub("POST", `/links/${id}/open`, {})).statusCode).toBe(200);
    expect((await pub("GET", `/links/${id}`)).json().opensLeft).toBeNull();
    await t.prisma.shareLink.update({ where: { id }, data: { expiresAt: new Date(Date.now() - 1000) } });
    const res = await pub("POST", `/links/${id}/open`, {});
    expect(res.statusCode).toBe(410);
    expect(res.json()).toEqual({ error: "expired" });
    expect((await t.prisma.shareLink.findUniqueOrThrow({ where: { id } })).encPayload).toBeNull();
  });

  it("sets expiry from the chosen window and rejects other windows and open counts", async () => {
    const u = await createActiveUser(t);
    const rid = await addRecord(u);
    const { res } = await makeLink(u, rid, { expiresInHours: 168 });
    const ms = new Date(res.json().expiresAt).getTime() - Date.now();
    expect(ms).toBeGreaterThan(167 * 3600_000);
    expect(ms).toBeLessThanOrEqual(168 * 3600_000);
    const l = await createLink(crypto.randomUUID(), body);
    expect((await call(u, "POST", "/links", { id: crypto.randomUUID(), recordId: rid, encPayload: l.encPayload, expiresInHours: 48, maxOpens: 1 })).statusCode).toBe(400);
    expect((await call(u, "POST", "/links", { id: crypto.randomUUID(), recordId: rid, encPayload: l.encPayload, expiresInHours: 1, maxOpens: 2 })).statusCode).toBe(400);
    expect((await call(u, "POST", "/links", { id: crypto.randomUUID(), recordId: rid, encPayload: "plain text", expiresInHours: 1, maxOpens: 1 })).statusCode).toBe(400);
  });

  it("revoke: creator only; revoked links say so and lose their ciphertext", async () => {
    const a = await createActiveUser(t), b = await createActiveUser(t);
    const { id } = await makeLink(a, await addRecord(a));
    expect((await call(b, "DELETE", `/links/${id}`)).statusCode).toBe(404);
    expect((await call(a, "DELETE", `/links/${id}`)).statusCode).toBe(204);
    const res = await pub("POST", `/links/${id}/open`, {});
    expect(res.statusCode).toBe(410);
    expect(res.json()).toEqual({ error: "revoked" });
    expect((await pub("GET", `/links/${id}`)).json()).toEqual({ error: "revoked" });
    expect((await t.prisma.shareLink.findUniqueOrThrow({ where: { id } })).encPayload).toBeNull();
  });

  it("password links: needs the right access hash; wrong attempts do not count as opens", async () => {
    const u = await createActiveUser(t);
    const { id, l } = await makeLink(u, await addRecord(u), { password: "blue cactus" });
    const meta = (await pub("GET", `/links/${id}`)).json();
    expect(meta).toMatchObject({ needsPassword: true, passwordSalt: l.passwordSalt });
    expect((await pub("POST", `/links/${id}/open`, {})).statusCode).toBe(403);
    const bad = await deriveLinkAccess("red cactus", meta.passwordSalt, l.fragment, FAST);
    const wrong = await pub("POST", `/links/${id}/open`, { accessHash: bad.accessHash });
    expect(wrong.statusCode).toBe(403);
    expect(wrong.json()).toEqual({ error: "wrong_password" });
    const row = await t.prisma.shareLink.findUniqueOrThrow({ where: { id } });
    expect(row.opens).toBe(0);
    expect(row.accessHash).toBe(hashAccess(l.accessHash!)); // stored as SHA-256, never as sent
    const good = await deriveLinkAccess("blue cactus", meta.passwordSalt, l.fragment, FAST);
    const open = await pub("POST", `/links/${id}/open`, { accessHash: good.accessHash });
    expect(open.statusCode).toBe(200);
    expect(await openPasswordLink(id, open.json().encPayload, good.wrapKey)).toEqual(body);
    // Used up: says so (410) before any password check, and the password material is gone too.
    const after = await pub("POST", `/links/${id}/open`, { accessHash: bad.accessHash });
    expect(after.statusCode).toBe(410);
    expect(after.json()).toEqual({ error: "used_up" });
    expect(await t.prisma.shareLink.findUniqueOrThrow({ where: { id } })).toMatchObject({ encPayload: null, passwordSalt: null, accessHash: null });
  });

  it("password links: the password with the wrong URL key does not get in", async () => {
    const u = await createActiveUser(t);
    const { id, l } = await makeLink(u, await addRecord(u), { password: "blue cactus" });
    const other = (await createLink(crypto.randomUUID(), body)).fragment;
    const k = await deriveLinkAccess("blue cactus", l.passwordSalt!, other, FAST);
    expect((await pub("POST", `/links/${id}/open`, { accessHash: k.accessHash })).statusCode).toBe(403);
  });

  it("revoked links answer 410 even to a wrong password", async () => {
    const u = await createActiveUser(t);
    const { id } = await makeLink(u, await addRecord(u), { password: "blue cactus" });
    await call(u, "DELETE", `/links/${id}`);
    const res = await pub("POST", `/links/${id}/open`, { accessHash: "x".repeat(43) });
    expect(res.statusCode).toBe(410);
    expect(res.json()).toEqual({ error: "revoked" });
  });

  it("trashing the record revokes its links; a trashed record's link answers revoked and burns", async () => {
    const u = await createActiveUser(t);
    const rid = await addRecord(u);
    const { id } = await makeLink(u, rid, { maxOpens: null });
    expect((await call(u, "DELETE", `/records/${rid}`)).statusCode).toBe(204);
    const res = await pub("POST", `/links/${id}/open`, {});
    expect(res.statusCode).toBe(410);
    expect(res.json()).toEqual({ error: "revoked" });
    expect(await t.prisma.shareLink.findUniqueOrThrow({ where: { id } })).toMatchObject({ encPayload: null });
    expect((await t.prisma.shareLink.findUniqueOrThrow({ where: { id } })).revokedAt).not.toBeNull();
    // Even if the link row was not revoked (e.g. trashed some other way), open still refuses and burns.
    const rid2 = await addRecord(u);
    const { id: id2 } = await makeLink(u, rid2);
    await t.prisma.record.update({ where: { id: rid2 }, data: { deletedAt: new Date() } });
    expect((await pub("GET", `/links/${id2}`)).json()).toEqual({ error: "revoked" });
    expect((await t.prisma.shareLink.findUniqueOrThrow({ where: { id: id2 } })).encPayload).toBeNull();
  });

  it("deleting a folder revokes the links of its records", async () => {
    const u = await createActiveUser(t);
    const fid = crypto.randomUUID();
    await t.prisma.folder.create({ data: { id: fid, ownerId: u.id, encName: "v1.AAAA" } });
    const rid = await addRecord(u);
    await t.prisma.record.update({ where: { id: rid }, data: { folderId: fid } });
    const { id } = await makeLink(u, rid);
    expect((await call(u, "DELETE", `/folders/${fid}`)).statusCode).toBe(204);
    expect((await t.prisma.shareLink.findUniqueOrThrow({ where: { id } })).revokedAt).not.toBeNull();
  });

  it("the record owner lists and revokes every link on the record; others see only their own", async () => {
    const a = await createActiveUser(t), b = await createActiveUser(t), c = await createActiveUser(t);
    const rid = await addRecord(a);
    await t.prisma.recordAccess.create({ data: { recordId: rid, holderType: "user", holderId: b.id, permission: "edit", wrappedRecordKey: "v1.AAAA", orgId: b.orgId } });
    const mine = await makeLink(a, rid);
    const theirs = await makeLink(b, rid);
    const ownerView = (await call(a, "GET", `/records/${rid}/links`)).json().links;
    expect(ownerView.map((x: { id: string }) => x.id).sort()).toEqual([mine.id, theirs.id].sort());
    const other = ownerView.find((x: { id: string }) => x.id === theirs.id);
    expect(other).toMatchObject({ createdByMe: false, labelEnc: null });
    expect((await call(b, "GET", `/records/${rid}/links`)).json().links.map((x: { id: string }) => x.id)).toEqual([theirs.id]);
    expect((await call(c, "GET", `/records/${rid}/links`)).statusCode).toBe(404);
    expect((await call(b, "DELETE", `/links/${mine.id}`)).statusCode).toBe(404); // editor can't revoke the owner's link
    expect((await call(c, "DELETE", `/links/${theirs.id}`)).statusCode).toBe(404);
    expect((await call(a, "DELETE", `/links/${theirs.id}`)).statusCode).toBe(204); // owner can revoke the editor's link
    expect((await pub("GET", `/links/${theirs.id}`)).json()).toEqual({ error: "revoked" });
    const before = await t.prisma.shareLink.findUniqueOrThrow({ where: { id: theirs.id } });
    expect((await call(b, "DELETE", `/links/${theirs.id}`)).statusCode).toBe(204); // second revoke is a no-op
    expect((await t.prisma.shareLink.findUniqueOrThrow({ where: { id: theirs.id } })).revokedAt).toEqual(before.revokedAt);
    expect(await t.prisma.event.count({ where: { action: "link.revoke" } })).toBe(1);
  });

  it("sweep: expired links lose ciphertext and password material; live ones are untouched", async () => {
    const u = await createActiveUser(t);
    const rid = await addRecord(u);
    const old = await makeLink(u, rid, { password: "pw" });
    const live = await makeLink(u, rid, { password: "pw" });
    await t.prisma.shareLink.update({ where: { id: old.id }, data: { expiresAt: new Date(Date.now() - 1000) } });
    expect(await sweepExpiredLinks(t.prisma)).toBe(1);
    expect(await t.prisma.shareLink.findUniqueOrThrow({ where: { id: old.id } })).toMatchObject({ encPayload: null, passwordSalt: null, accessHash: null });
    expect((await t.prisma.shareLink.findUniqueOrThrow({ where: { id: live.id } })).encPayload).not.toBeNull();
    expect(await sweepExpiredLinks(t.prisma)).toBe(0);
  });

  it("a duplicate link id is 409", async () => {
    const u = await createActiveUser(t);
    const rid = await addRecord(u);
    const { id, l } = await makeLink(u, rid);
    expect((await call(u, "POST", "/links", { id, recordId: rid, encPayload: l.encPayload, expiresInHours: 1, maxOpens: 1 })).statusCode).toBe(409);
  });

  it("rejects password fields that do not match the payload kind", async () => {
    const u = await createActiveUser(t);
    const rid = await addRecord(u);
    const plain = await createLink(crypto.randomUUID(), body);
    const pw = await createLink(crypto.randomUUID(), body, { password: "x", kdf: FAST });
    // A password payload without an access hash would hand out the wrapped key to anyone.
    expect((await call(u, "POST", "/links", { id: crypto.randomUUID(), recordId: rid, encPayload: pw.encPayload, expiresInHours: 1, maxOpens: 1 })).statusCode).toBe(400);
    expect((await call(u, "POST", "/links", { id: crypto.randomUUID(), recordId: rid, encPayload: plain.encPayload, expiresInHours: 1, maxOpens: 1, passwordSalt: pw.passwordSalt, accessHash: pw.accessHash })).statusCode).toBe(400);
  });

  it("only people who can edit the record create links; trashed records cannot be linked", async () => {
    const a = await createActiveUser(t), b = await createActiveUser(t);
    const rid = await addRecord(a);
    expect((await makeLink(b, rid)).res.statusCode).toBe(404);
    await t.prisma.recordAccess.create({ data: { recordId: rid, holderType: "user", holderId: b.id, permission: "view", wrappedRecordKey: "v1.AAAA", orgId: b.orgId } });
    expect((await makeLink(b, rid)).res.statusCode).toBe(403);
    await t.prisma.recordAccess.updateMany({ where: { recordId: rid, holderId: b.id }, data: { permission: "use" } });
    expect((await makeLink(b, rid)).res.statusCode).toBe(403);
    await t.prisma.recordAccess.updateMany({ where: { recordId: rid, holderId: b.id }, data: { permission: "edit" } });
    expect((await makeLink(b, rid)).res.statusCode).toBe(201);
    await call(a, "DELETE", `/records/${rid}`);
    expect((await makeLink(a, rid)).res.statusCode).toBe(409);
    expect((await call(a, "POST", "/links", {})).statusCode).toBe(400);
    expect((await t.app.inject({ method: "POST", url: "/api/v1/links", payload: {} })).statusCode).toBe(401);
  });

  it("lists my links only, without secrets, and records events without the opener's IP", async () => {
    const a = await createActiveUser(t), b = await createActiveUser(t);
    const rid = await addRecord(a);
    const { id, l } = await makeLink(a, rid, { password: "pw" });
    await makeLink(b, await addRecord(b));
    const list = (await call(a, "GET", "/links")).json().links;
    expect(list).toHaveLength(1);
    expect(list[0]).toMatchObject({ id, recordId: rid, maxOpens: 1, opens: 0, revokedAt: null, hasPassword: true, state: "active" });
    expect(list[0].labelEnc).toMatch(/^v1\./);
    expect(list[0].encPayload).toBeUndefined();
    expect(list[0].accessHash).toBeUndefined();
    const meta = (await pub("GET", `/links/${id}`)).json();
    await pub("POST", `/links/${id}/open`, { accessHash: (await deriveLinkAccess("pw", meta.passwordSalt, l.fragment, FAST)).accessHash });
    await call(a, "DELETE", `/links/${id}`);
    const events = await t.prisma.event.findMany({ where: { recordId: rid, action: { startsWith: "link." } }, orderBy: { id: "asc" } });
    expect(events.map((e) => e.action)).toEqual(["link.create", "link.open", "link.revoke"]);
    expect(events.every((e) => e.ip == null)).toBe(true);
    expect(events[1]!.actorId).toBeNull();
    expect((await call(a, "GET", "/links")).json().links[0].state).toBe("revoked");
  });

  it("unknown or malformed link ids are 404", async () => {
    expect((await pub("GET", `/links/${crypto.randomUUID()}`)).statusCode).toBe(404);
    expect((await pub("POST", `/links/${crypto.randomUUID()}/open`, {})).statusCode).toBe(404);
    expect((await pub("GET", "/links/not-a-uuid")).statusCode).toBe(404);
  });

  it("purging the record deletes its links", async () => {
    const u = await createActiveUser(t);
    const rid = await addRecord(u);
    const { id } = await makeLink(u, rid);
    await call(u, "DELETE", `/records/${rid}`);
    await call(u, "DELETE", `/records/${rid}/purge`);
    expect(await t.prisma.shareLink.findUnique({ where: { id } })).toBeNull();
  });

  it("rate-limits the public endpoints to 30 per minute per IP across both routes", async () => {
    const ip = "10.99.0.1";
    const id = crypto.randomUUID();
    const codes: number[] = [];
    for (let i = 0; i < 30; i++) codes.push((await pub(i % 2 ? "GET" : "POST", i % 2 ? `/links/${id}` : `/links/${id}/open`, {}, ip)).statusCode);
    expect(codes.every((c) => c === 404)).toBe(true);
    const over = await pub("GET", `/links/${id}`, undefined, ip);
    expect(over.statusCode).toBe(429);
    expect(over.json()).toEqual({ error: "rate_limited" });
    expect((await pub("GET", `/links/${id}`, undefined, "10.99.0.2")).statusCode).toBe(404);
  });
});

describe("record batch (import)", () => {
  async function item(u: U, folderId: string | null = null) {
    const id = crypto.randomUUID();
    const enc = await encryptNewRecord(id, { type: "login", title: "Imported", password: "pw" }, u.keys.userKey);
    return { id, folderId, type: "login", encBody: enc.encBody, wrappedRecordKey: enc.wrappedRecordKey };
  }
  it("creates up to 25 records in one request, all or nothing", async () => {
    const u = await createActiveUser(t);
    const items = await Promise.all(Array.from({ length: 25 }, () => item(u)));
    expect((await call(u, "POST", "/records/batch", { records: items })).statusCode).toBe(201);
    expect((await call(u, "GET", "/sync")).json().records).toHaveLength(25);
    expect((await call(u, "POST", "/records/batch", { records: [...items, await item(u)] })).statusCode).toBe(400);
    const fresh = await item(u);
    expect((await call(u, "POST", "/records/batch", { records: [fresh, items[0]] })).statusCode).toBe(409);
    expect(await t.prisma.record.findUnique({ where: { id: fresh.id } })).toBeNull();
  });
  it("only into my own live private folders", async () => {
    const a = await createActiveUser(t), b = await createActiveUser(t);
    const fid = crypto.randomUUID();
    await t.prisma.folder.create({ data: { id: fid, ownerId: a.id, encName: "v1.AAAA" } });
    expect((await call(b, "POST", "/records/batch", { records: [await item(b, fid)] })).statusCode).toBe(404);
    expect((await call(a, "POST", "/records/batch", { records: [await item(a, fid)] })).statusCode).toBe(201);
  });
});
