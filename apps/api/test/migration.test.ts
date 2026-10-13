import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { b64url, createTeamFolder, decryptRecordBody, encryptNewRecord, openFolderKey, openRecordKey, sealFolderKeyFor, wrapKey } from "@clane-vault/crypto";
import { makeTestApp, resetDb, createActiveUser, createInvite, orgHeader } from "./helpers.js";

// Bulk migration (Keeper → Clane): batch records straight into team folders, and pending folder members.
const t = await makeTestApp();
afterAll(() => t.app.close());
beforeEach(() => resetDb(t.prisma));

type U = Awaited<ReturnType<typeof createActiveUser>>;
type Folder = { id: string; folderKey: Uint8Array };
const ipOf = (u: U) => `10.${parseInt(u.id.slice(-6, -4), 16)}.${parseInt(u.id.slice(-4, -2), 16)}.${parseInt(u.id.slice(-2), 16)}`;
const call = (u: U, method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE", url: string, payload?: unknown) =>
  t.app.inject({ method, url: `/api/v1${url}`, payload: payload as object, remoteAddress: ipOf(u), headers: { authorization: `Bearer ${u.accessToken}`, ...orgHeader(u) } });

async function teamFolder(owner: U, name = "Infra"): Promise<Folder> {
  const id = crypto.randomUUID();
  const f = await createTeamFolder(id, name, owner.keys.publicKey);
  expect((await call(owner, "POST", "/folders", { id, kind: "team", encName: f.encName, wrappedFolderKey: f.wrappedFolderKey })).statusCode).toBe(201);
  return { id, folderKey: f.folderKey };
}
async function addMember(owner: U, f: Folder, who: U, permission: string) {
  expect((await call(owner, "POST", `/folders/${f.id}/members`, { userId: who.id, permission, wrappedFolderKey: await sealFolderKeyFor(f.folderKey, f.id, who.keys.publicKey) })).statusCode).toBe(201);
}
/** A batch item for a team folder: folder wrap plus the creator's own wrap. */
async function teamItem(u: U, f: Folder, title = "Imported", withOwnerWrap = true) {
  const id = crypto.randomUUID();
  const enc = await encryptNewRecord(id, { type: "login", title, password: `pw-${title}` }, u.keys.userKey);
  return { id, folderId: f.id, type: "login", encBody: enc.encBody, wrappedRecordKey: await wrapKey(enc.recordKey, f.folderKey, `record-key:${id}`),
    ...(withOwnerWrap ? { ownerWrappedRecordKey: enc.wrappedRecordKey } : {}) };
}
async function privateItem(u: U, folderId: string | null = null) {
  const id = crypto.randomUUID();
  const enc = await encryptNewRecord(id, { type: "login", title: "Private", password: "pw" }, u.keys.userKey);
  return { id, folderId, type: "login", encBody: enc.encBody, wrappedRecordKey: enc.wrappedRecordKey };
}
const sync = async (u: U) => (await call(u, "GET", "/sync")).json() as { folders: any[]; records: any[] };
async function open(u: U, s: { folders: any[] }, r: any) {
  const folderKeys = new Map<string, Uint8Array>();
  for (const f of s.folders.filter((x) => x.kind === "team")) folderKeys.set(f.id, await openFolderKey(f.wrappedFolderKey, f.id, u.keys));
  const rk = await openRecordKey({ recordId: r.id, holderType: r.holderType, wrappedRecordKey: r.wrappedRecordKey, folderId: r.keyFolderId }, u.keys, folderKeys);
  return decryptRecordBody(r.id, r.encBody, rk);
}

describe("POST /records/batch into team folders", () => {
  it("owner and editors batch-create into a team folder; members open them through the folder", async () => {
    const a = await createActiveUser(t), b = await createActiveUser(t), c = await createActiveUser(t);
    const f = await teamFolder(a);
    await addMember(a, f, b, "edit");
    await addMember(a, f, c, "view");
    const items = await Promise.all(Array.from({ length: 25 }, (_, i) => teamItem(a, f, `R${i}`)));
    expect((await call(a, "POST", "/records/batch", { records: items })).statusCode).toBe(201);
    const fromB = await teamItem(b, f, "ByEditor");
    expect((await call(b, "POST", "/records/batch", { records: [fromB] })).statusCode).toBe(201);

    const sc = await sync(c);
    expect(sc.records.filter((r) => r.folderId === f.id)).toHaveLength(26);
    const r0 = sc.records.find((r) => r.id === items[0]!.id);
    expect(r0).toMatchObject({ holderType: "folder", permission: "view", ownerId: a.id });
    expect((await open(c, sc, r0)).password).toBe("pw-R0");
    // The creator keeps their own wrap (survives leaving the folder) and is the record owner.
    const rows = await t.prisma.recordAccess.findMany({ where: { recordId: fromB.id }, orderBy: { holderType: "asc" } });
    expect(rows.map((x) => [x.holderType, x.permission])).toEqual([["user", "owner"], ["folder", "edit"]]);
    const sb = await sync(b);
    expect(sb.records.find((r) => r.id === fromB.id)).toMatchObject({ permission: "owner", holderType: "user" });
  });

  it("refuses view members (403), non-members (404) and a team item without the owner wrap (400), all or nothing", async () => {
    const a = await createActiveUser(t), v = await createActiveUser(t), x = await createActiveUser(t);
    const f = await teamFolder(a);
    await addMember(a, f, v, "view");
    const viewer = await call(v, "POST", "/records/batch", { records: [await teamItem(v, f)] });
    expect(viewer.statusCode).toBe(403);
    expect(viewer.json()).toEqual({ error: "forbidden" });
    const outsider = await call(x, "POST", "/records/batch", { records: [await teamItem(x, f)] });
    expect(outsider.statusCode).toBe(404);
    expect(outsider.json()).toEqual({ error: "folder_not_found" });
    const ok = await privateItem(a);
    const noWrap = await call(a, "POST", "/records/batch", { records: [ok, await teamItem(a, f, "x", false)] });
    expect(noWrap.statusCode).toBe(400);
    expect(await t.prisma.record.findUnique({ where: { id: ok.id } })).toBeNull();
  });

  it("mixes private and team folders in one batch; a deleted team folder is refused", async () => {
    const a = await createActiveUser(t);
    const f = await teamFolder(a);
    const pid = crypto.randomUUID();
    await t.prisma.folder.create({ data: { id: pid, ownerId: a.id, encName: "v1.AAAA" } });
    expect((await call(a, "POST", "/records/batch", { records: [await privateItem(a, pid), await teamItem(a, f), await privateItem(a)] })).statusCode).toBe(201);
    expect(await t.prisma.record.count({ where: { ownerId: a.id } })).toBe(3);
    expect((await call(a, "DELETE", `/folders/${f.id}`)).statusCode).toBe(204);
    expect((await call(a, "POST", "/records/batch", { records: [await teamItem(a, f)] })).statusCode).toBe(404);
  });
});

describe("pending folder members", () => {
  it("lifecycle: owner adds by email, sees it ready once the person is active, completes it; the member opens the folder", async () => {
    const a = await createActiveUser(t, { role: "admin" });
    const f = await teamFolder(a, "Clients / Acme");
    const add = await call(a, "POST", `/folders/${f.id}/pending-members`, { email: "New.Person@Clane.ai", permission: "edit" });
    expect(add.statusCode).toBe(201);
    expect((await call(a, "POST", `/folders/${f.id}/pending-members`, { email: "new.person@clane.ai", permission: "view" })).statusCode).toBe(409);
    const before = (await call(a, "GET", "/pending-members")).json().pending;
    expect(before).toEqual([expect.objectContaining({ id: add.json().id, folderId: f.id, email: "new.person@clane.ai", permission: "edit", user: null })]);

    const n = await createActiveUser(t, { email: "new.person@clane.ai" });
    const [p] = (await call(a, "GET", "/pending-members")).json().pending;
    expect(p.user).toEqual({ id: n.id, name: "new.person", publicKey: expect.any(String), membershipKey: null });
    const wrappedFolderKey = await sealFolderKeyFor(f.folderKey, f.id, b64url.decode(p.user.publicKey));
    // Sealed to someone else than the pending email: refused.
    const other = await createActiveUser(t);
    expect((await call(a, "POST", `/folders/${f.id}/pending-members/${p.id}/complete`, { userId: other.id, wrappedFolderKey })).statusCode).toBe(400);
    const done = await call(a, "POST", `/folders/${f.id}/pending-members/${p.id}/complete`, { userId: n.id, wrappedFolderKey });
    expect(done.statusCode).toBe(201);
    expect((await call(a, "GET", "/pending-members")).json().pending).toEqual([]);
    const sn = await sync(n);
    expect(sn.folders.find((x) => x.id === f.id)).toMatchObject({ myPermission: "edit" });
    expect((await call(a, "POST", `/folders/${f.id}/pending-members/${p.id}/complete`, { userId: n.id, wrappedFolderKey })).statusCode).toBe(404);
  });

  it("only the folder owner adds, lists, completes or cancels (editors and admins outside the folder can't)", async () => {
    const a = await createActiveUser(t), ed = await createActiveUser(t), admin = await createActiveUser(t, { role: "admin" });
    const f = await teamFolder(a);
    await addMember(a, f, ed, "edit");
    for (const u of [ed, admin]) expect((await call(u, "POST", `/folders/${f.id}/pending-members`, { email: "x@clane.ai", permission: "view" })).statusCode).toBe(404);
    const { id } = (await call(a, "POST", `/folders/${f.id}/pending-members`, { email: "x@clane.ai", permission: "view" })).json();
    const x = await createActiveUser(t, { email: "x@clane.ai" });
    for (const u of [ed, admin]) {
      expect((await call(u, "GET", "/pending-members")).json().pending).toEqual([]);
      expect((await call(u, "POST", `/folders/${f.id}/pending-members/${id}/complete`, { userId: x.id, wrappedFolderKey: await sealFolderKeyFor(f.folderKey, f.id, x.keys.publicKey) })).statusCode).toBe(404);
      expect((await call(u, "DELETE", `/folders/${f.id}/pending-members/${id}`)).statusCode).toBe(404);
    }
    expect(await t.prisma.folderMember.count({ where: { folderId: f.id, userId: x.id } })).toBe(0);
    expect((await call(a, "DELETE", `/folders/${f.id}/pending-members/${id}`)).statusCode).toBe(204);
    expect(await t.prisma.pendingFolderMember.count()).toBe(0);
  });

  it("is not completable while the person is still pending 2FA; adding them directly removes the pending entry", async () => {
    const a = await createActiveUser(t);
    const f = await teamFolder(a);
    const { id } = (await call(a, "POST", `/folders/${f.id}/pending-members`, { email: "late@clane.ai", permission: "view" })).json();
    const late = await createActiveUser(t, { email: "late@clane.ai" });
    await t.prisma.user.update({ where: { id: late.id }, data: { status: "pending_2fa" } });
    expect((await call(a, "GET", "/pending-members")).json().pending[0].user).toBeNull();
    const res = await call(a, "POST", `/folders/${f.id}/pending-members/${id}/complete`, { userId: late.id, wrappedFolderKey: await sealFolderKeyFor(f.folderKey, f.id, late.keys.publicKey) });
    expect(res.json()).toEqual({ error: "user_not_active" });
    await t.prisma.user.update({ where: { id: late.id }, data: { status: "active" } });
    await addMember(a, f, late, "view");
    expect(await t.prisma.pendingFolderMember.count()).toBe(0);
    // Already a member: adding them as pending again is refused.
    expect((await call(a, "POST", `/folders/${f.id}/pending-members`, { email: "late@clane.ai", permission: "edit" })).json()).toEqual({ error: "already_member" });
  });

  it("is removed when the folder is deleted, and refused on private folders", async () => {
    const a = await createActiveUser(t);
    const f = await teamFolder(a);
    await createInvite(t.prisma, "soon@clane.ai");
    expect((await call(a, "POST", `/folders/${f.id}/pending-members`, { email: "soon@clane.ai", permission: "edit" })).statusCode).toBe(201);
    expect((await call(a, "DELETE", `/folders/${f.id}`)).statusCode).toBe(204);
    expect(await t.prisma.pendingFolderMember.count()).toBe(0);
    expect((await call(a, "GET", "/pending-members")).json().pending).toEqual([]);
    const pid = crypto.randomUUID();
    await t.prisma.folder.create({ data: { id: pid, ownerId: a.id, encName: "v1.AAAA" } });
    expect((await call(a, "POST", `/folders/${pid}/pending-members`, { email: "soon@clane.ai", permission: "edit" })).statusCode).toBe(404);
    expect((await call(a, "POST", `/folders/${f.id}/pending-members`, { email: "not-an-email", permission: "edit" })).statusCode).toBe(400);
  });
});
