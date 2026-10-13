import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { encryptNewRecord, encryptRecordBody, encryptFolderName, decryptRecord } from "@clane-vault/crypto";
import { makeTestApp, resetDb, createActiveUser, orgHeader } from "./helpers.js";

const t = await makeTestApp();
afterAll(() => t.app.close());
beforeEach(() => resetDb(t.prisma));

type U = Awaited<ReturnType<typeof createActiveUser>>;
const call = (u: U, method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE", url: string, payload?: unknown) =>
  t.app.inject({ method, url: `/api/v1${url}`, payload: payload as object, headers: { authorization: `Bearer ${u.accessToken}`, ...orgHeader(u) } });

async function addRecord(u: U, folderId: string | null = null, title = "AWS root") {
  const id = crypto.randomUUID();
  const enc = await encryptNewRecord(id, { type: "login", title, password: "s3cret-value" }, u.keys.userKey);
  const res = await call(u, "POST", "/records", { id, folderId, type: "login", encBody: enc.encBody, wrappedRecordKey: enc.wrappedRecordKey });
  return { id, res, enc };
}

describe("records", () => {
  it("creates, syncs and decrypts a record; the server never sees plaintext", async () => {
    const u = await createActiveUser(t);
    const { id, res } = await addRecord(u);
    expect(res.statusCode).toBe(201);
    const sync = (await call(u, "GET", "/sync")).json();
    const r = sync.records.find((x: { id: string }) => x.id === id);
    expect(r).toMatchObject({ permission: "owner", holderType: "user", revision: 1, deletedAt: null });
    expect(JSON.stringify(sync)).not.toContain("s3cret-value");
    expect((await decryptRecord(id, r.encBody, r.wrappedRecordKey, u.keys.userKey)).body.title).toBe("AWS root");
  });

  it("hides other people's records", async () => {
    const a = await createActiveUser(t), b = await createActiveUser(t);
    const { id } = await addRecord(a);
    expect((await call(b, "GET", "/sync")).json().records).toHaveLength(0);
    expect((await call(b, "PUT", `/records/${id}`, { encBody: "v1.AAAA", revision: 1 })).statusCode).toBe(404);
    expect((await call(b, "DELETE", `/records/${id}`)).statusCode).toBe(404);
  });

  it("detects edit conflicts by revision", async () => {
    const u = await createActiveUser(t);
    const { id, enc } = await addRecord(u);
    const body2 = await encryptRecordBody(id, { type: "login", title: "AWS root", password: "v2" }, enc.recordKey);
    expect((await call(u, "PUT", `/records/${id}`, { encBody: body2, revision: 1 })).json()).toEqual({ revision: 2 });
    const stale = await call(u, "PUT", `/records/${id}`, { encBody: body2, revision: 1 });
    expect(stale.statusCode).toBe(409);
    expect(stale.json()).toMatchObject({ error: "conflict", current: { revision: 2 } });
  });

  it("trashes, restores and purges", async () => {
    const u = await createActiveUser(t);
    const { id } = await addRecord(u);
    expect((await call(u, "DELETE", `/records/${id}/purge`)).statusCode).toBe(409); // must be in trash first
    expect((await call(u, "DELETE", `/records/${id}`)).statusCode).toBe(204);
    expect((await call(u, "GET", "/sync")).json().records[0].deletedAt).not.toBeNull();
    expect((await call(u, "POST", `/records/${id}/restore`)).statusCode).toBe(200);
    expect((await call(u, "GET", "/sync")).json().records[0].deletedAt).toBeNull();
    await call(u, "DELETE", `/records/${id}`);
    expect((await call(u, "DELETE", `/records/${id}/purge`)).statusCode).toBe(204);
    expect((await call(u, "GET", "/sync")).json().records).toHaveLength(0);
  });

  it("puts records in my folders only, and deleting a folder trashes its records", async () => {
    const a = await createActiveUser(t), b = await createActiveUser(t);
    const fid = crypto.randomUUID();
    expect((await call(a, "POST", "/folders", { id: fid, encName: await encryptFolderName(fid, "Infra", a.keys.userKey) })).statusCode).toBe(201);
    expect((await addRecord(b, fid)).res.statusCode).toBe(404);
    const { id } = await addRecord(a, fid);
    expect((await call(a, "DELETE", `/folders/${fid}`)).statusCode).toBe(204);
    const sync = (await call(a, "GET", "/sync")).json();
    expect(sync.folders[0].deletedAt).not.toBeNull();
    expect(sync.records.find((r: { id: string }) => r.id === id).deletedAt).not.toBeNull();
  });

  it("rejects duplicate ids and bad payloads", async () => {
    const u = await createActiveUser(t);
    const { id, enc } = await addRecord(u);
    expect((await call(u, "POST", "/records", { id, folderId: null, type: "login", encBody: enc.encBody, wrappedRecordKey: enc.wrappedRecordKey })).statusCode).toBe(409);
    expect((await call(u, "POST", "/records", { id: "not-a-uuid", folderId: null, type: "login", encBody: "x", wrappedRecordKey: "y" })).statusCode).toBe(400);
  });

  it("logs record events", async () => {
    const u = await createActiveUser(t);
    const { id } = await addRecord(u);
    await call(u, "DELETE", `/records/${id}`);
    const actions = (await t.prisma.event.findMany({ where: { recordId: id }, orderBy: { id: "asc" } })).map((e) => e.action);
    expect(actions).toEqual(["record.create", "record.trash"]);
  });

  it("rejects PUT on a trashed record with in_trash", async () => {
    const u = await createActiveUser(t);
    const { id, enc } = await addRecord(u);
    await call(u, "DELETE", `/records/${id}`);
    const body2 = await encryptRecordBody(id, { type: "login", title: "x", password: "v2" }, enc.recordKey);
    const res = await call(u, "PUT", `/records/${id}`, { encBody: body2, revision: 1 });
    expect(res.statusCode).toBe(409);
    expect(res.json()).toEqual({ error: "in_trash" });
  });

  it("refuses moving a record into another user's folder", async () => {
    const a = await createActiveUser(t), b = await createActiveUser(t);
    const fid = crypto.randomUUID();
    await call(a, "POST", "/folders", { id: fid, encName: await encryptFolderName(fid, "A", a.keys.userKey) });
    const { id, enc } = await addRecord(b);
    const body2 = await encryptRecordBody(id, { type: "login", title: "x", password: "v2" }, enc.recordKey);
    const res = await call(b, "PUT", `/records/${id}`, { encBody: body2, revision: 1, folderId: fid });
    expect(res.statusCode).toBe(404);
    expect(res.json()).toMatchObject({ error: "folder_not_found" });
    expect((await call(b, "GET", "/sync")).json().records[0].folderId).toBeNull();
  });

  it("restores a record whose folder was deleted into no folder", async () => {
    const u = await createActiveUser(t);
    const fid = crypto.randomUUID();
    await call(u, "POST", "/folders", { id: fid, encName: await encryptFolderName(fid, "F", u.keys.userKey) });
    const { id } = await addRecord(u, fid);
    await call(u, "DELETE", `/records/${id}`);
    await call(u, "DELETE", `/folders/${fid}`);
    expect((await call(u, "POST", `/records/${id}/restore`)).statusCode).toBe(200);
    const r = (await call(u, "GET", "/sync")).json().records[0];
    expect(r.folderId).toBeNull();
    expect(r.deletedAt).toBeNull();
  });

  it("stops other users renaming or deleting my folder", async () => {
    const a = await createActiveUser(t), b = await createActiveUser(t);
    const fid = crypto.randomUUID();
    const encName = await encryptFolderName(fid, "Mine", a.keys.userKey);
    await call(a, "POST", "/folders", { id: fid, encName });
    const other = await encryptFolderName(fid, "Hacked", b.keys.userKey);
    expect((await call(b, "PATCH", `/folders/${fid}`, { encName: other })).statusCode).toBe(404);
    expect((await call(b, "DELETE", `/folders/${fid}`)).statusCode).toBe(404);
    const f = (await call(a, "GET", "/sync")).json().folders[0];
    expect(f.encName).toBe(encName);
    expect(f.deletedAt).toBeNull();
  });

  it("logs folder events with folderId", async () => {
    const u = await createActiveUser(t);
    const fid = crypto.randomUUID();
    await call(u, "POST", "/folders", { id: fid, encName: await encryptFolderName(fid, "F", u.keys.userKey) });
    await call(u, "PATCH", `/folders/${fid}`, { encName: await encryptFolderName(fid, "G", u.keys.userKey) });
    await call(u, "DELETE", `/folders/${fid}`);
    const actions = (await t.prisma.event.findMany({ where: { folderId: fid }, orderBy: { id: "asc" } })).map((e) => e.action);
    expect(actions).toEqual(["folder.create", "folder.rename", "folder.delete"]);
  });
});

describe("record type metadata (docs/record-types.md)", () => {
  async function post(u: U, type: unknown, body: Parameters<typeof encryptNewRecord>[1] = { type: "card", title: "Visa", data: { number: "4242424242424242" } }) {
    const id = crypto.randomUUID();
    const enc = await encryptNewRecord(id, body, u.keys.userKey);
    return { id, enc, res: await call(u, "POST", "/records", { id, folderId: null, type, encBody: enc.encBody, wrappedRecordKey: enc.wrappedRecordKey }) };
  }
  const typeOf = async (id: string) => (await t.prisma.record.findUniqueOrThrow({ where: { id } })).type;

  it("stores only login or item; the real type stays in the encrypted body", async () => {
    const u = await createActiveUser(t);
    const card = await post(u, "item");
    expect(card.res.statusCode).toBe(201);
    expect(await typeOf(card.id)).toBe("item");
    const sync = (await call(u, "GET", "/sync")).json();
    const r = sync.records.find((x: { id: string }) => x.id === card.id);
    expect(r.type).toBe("item");
    expect(JSON.stringify(sync)).not.toContain("card");
    expect((await decryptRecord(card.id, r.encBody, r.wrappedRecordKey, u.keys.userKey)).body).toMatchObject({ v: 2, type: "card" });
    const login = await post(u, "login", { type: "login", title: "x", password: "pw" });
    expect(await typeOf(login.id)).toBe("login");
  });

  it("stores \"note\" from clients before record types as item, on create, update and batch", async () => {
    const u = await createActiveUser(t);
    const { id, enc } = await post(u, "note", { type: "note", title: "n", notes: "x" });
    expect(await typeOf(id)).toBe("item");
    const login = await post(u, "login", { type: "login", title: "x", password: "pw" });
    const body2 = await encryptRecordBody(login.id, { type: "note", title: "now a note" }, login.enc.recordKey);
    expect((await call(u, "PUT", `/records/${login.id}`, { encBody: body2, revision: 1, type: "note" })).statusCode).toBe(200);
    expect(await typeOf(login.id)).toBe("item");
    const bid = crypto.randomUUID();
    const benc = await encryptNewRecord(bid, { type: "note", title: "b" }, u.keys.userKey);
    expect((await call(u, "POST", "/records/batch", { records: [{ id: bid, folderId: null, type: "note", encBody: benc.encBody, wrappedRecordKey: benc.wrappedRecordKey }] })).statusCode).toBe(201);
    expect(await typeOf(bid)).toBe("item");
    void enc;
  });

  it("refuses real record types and anything else as server metadata", async () => {
    const u = await createActiveUser(t);
    for (const type of ["card", "server", "sshKey", "", "LOGIN", 1, null]) expect((await post(u, type)).res.statusCode).toBe(400);
    const { id, enc } = await post(u, "item");
    const body2 = await encryptRecordBody(id, { type: "card", title: "Visa 2" }, enc.recordKey);
    expect((await call(u, "PUT", `/records/${id}`, { encBody: body2, revision: 1, type: "card" })).statusCode).toBe(400);
    const bid = crypto.randomUUID();
    expect((await call(u, "POST", "/records/batch", { records: [{ id: bid, folderId: null, type: "bankAccount", encBody: enc.encBody, wrappedRecordKey: enc.wrappedRecordKey }] })).statusCode).toBe(400);
  });

  it("the database refuses any other type (CHECK constraint)", async () => {
    const u = await createActiveUser(t);
    const { id } = await post(u, "item");
    await expect(t.prisma.record.update({ where: { id }, data: { type: "card" } })).rejects.toThrow(/Record_type_check|check constraint/i);
  });
});
