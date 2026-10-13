import { afterAll, beforeEach, describe, expect, it } from "vitest";
import {
  b64url, createTeamFolder, decryptFolderName, decryptRecordBody, encryptNewRecord, encryptRecordBody, openFolderKey, openRecordKey,
  sealFolderKeyFor, shareRecordKey, wrapKey,
} from "@clane-vault/crypto";
import { makeTestApp, resetDb, createActiveUser, orgHeader } from "./helpers.js";

const t = await makeTestApp();
afterAll(() => t.app.close());
beforeEach(() => resetDb(t.prisma));

type U = Awaited<ReturnType<typeof createActiveUser>>;
// One client address per user: this file makes enough calls to trip the global per-IP rate limit (300/min) otherwise.
const ipOf = (u: U) => `10.${parseInt(u.id.slice(-6, -4), 16)}.${parseInt(u.id.slice(-4, -2), 16)}.${parseInt(u.id.slice(-2), 16)}`;
const call = (u: U, method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE", url: string, payload?: unknown) =>
  t.app.inject({ method, url: `/api/v1${url}`, payload: payload as object, remoteAddress: ipOf(u), headers: { authorization: `Bearer ${u.accessToken}`, ...orgHeader(u) } });
const sync = async (u: U) => (await call(u, "GET", "/sync")).json() as { folders: any[]; records: any[] };

async function teamFolder(owner: U, name = "Infra") {
  const id = crypto.randomUUID();
  const f = await createTeamFolder(id, name, owner.keys.publicKey);
  const res = await call(owner, "POST", "/folders", { id, kind: "team", encName: f.encName, wrappedFolderKey: f.wrappedFolderKey });
  expect(res.statusCode).toBe(201);
  return { id, folderKey: f.folderKey };
}
async function addMember(owner: U, folder: { id: string; folderKey: Uint8Array }, who: U, permission: string) {
  return call(owner, "POST", `/folders/${folder.id}/members`, { userId: who.id, permission, wrappedFolderKey: await sealFolderKeyFor(folder.folderKey, folder.id, who.keys.publicKey) });
}
async function teamRecord(u: U, folder: { id: string; folderKey: Uint8Array }, title = "AWS root") {
  const id = crypto.randomUUID();
  const enc = await encryptNewRecord(id, { type: "login", title, password: "team-s3cret" }, u.keys.userKey);
  const res = await call(u, "POST", "/records", { id, folderId: folder.id, type: "login", encBody: enc.encBody,
    wrappedRecordKey: await wrapKey(enc.recordKey, folder.folderKey, `record-key:${id}`), ownerWrappedRecordKey: enc.wrappedRecordKey });
  return { id, res, enc };
}
async function privateRecord(u: U, title = "Private") {
  const id = crypto.randomUUID();
  const enc = await encryptNewRecord(id, { type: "login", title, password: "mine" }, u.keys.userKey);
  expect((await call(u, "POST", "/records", { id, folderId: null, type: "login", encBody: enc.encBody, wrappedRecordKey: enc.wrappedRecordKey })).statusCode).toBe(201);
  return { id, enc };
}
/** Decrypts a synced record exactly as the web client does. */
async function open(u: U, s: { folders: any[] }, r: any) {
  const folderKeys = new Map<string, Uint8Array>();
  for (const f of s.folders.filter((x) => x.kind === "team")) folderKeys.set(f.id, await openFolderKey(f.wrappedFolderKey, f.id, u.keys));
  const rk = await openRecordKey({ recordId: r.id, holderType: r.holderType, wrappedRecordKey: r.wrappedRecordKey, folderId: r.keyFolderId }, u.keys, folderKeys);
  return decryptRecordBody(r.id, r.encBody, rk);
}

describe("team folders", () => {
  it("full lifecycle: create, add member, member reads, rename, permission change, remove", async () => {
    const a = await createActiveUser(t), b = await createActiveUser(t), c = await createActiveUser(t);
    const f = await teamFolder(a);
    const { id } = await teamRecord(a, f);
    expect((await addMember(a, f, b, "edit")).statusCode).toBe(201);
    expect((await addMember(a, f, b, "edit")).statusCode).toBe(409);

    const sb = await sync(b);
    const folder = sb.folders.find((x) => x.id === f.id);
    expect(folder).toMatchObject({ kind: "team", myPermission: "edit", ownerId: a.id });
    expect(folder.members.map((m: any) => [m.userId, m.permission]).sort()).toEqual([[a.id, "owner"], [b.id, "edit"]].sort());
    expect(folder.members[0].publicKey).toBeTypeOf("string");
    expect(await decryptFolderName(f.id, folder.encName, await openFolderKey(folder.wrappedFolderKey, f.id, b.keys))).toBe("Infra");
    const rb = sb.records.find((x) => x.id === id);
    expect(rb).toMatchObject({ permission: "edit", holderType: "folder", folderId: f.id, keyFolderId: f.id, ownerId: a.id });
    expect(rb.sharedWith).toBeUndefined();
    expect((await open(b, sb, rb)).password).toBe("team-s3cret");
    // The owner reaches it through their own wrap and sees owner rights.
    const ra = (await sync(a)).records.find((x) => x.id === id);
    expect(ra).toMatchObject({ permission: "owner", holderType: "user" });

    // A non-member sees nothing.
    expect((await sync(c)).folders).toHaveLength(0);
    expect((await sync(c)).records).toHaveLength(0);
    expect((await call(c, "GET", `/records/${id}/activity`)).statusCode).toBe(404);

    expect((await call(a, "PATCH", `/folders/${f.id}/members/${b.id}`, { permission: "view" })).statusCode).toBe(200);
    expect((await sync(b)).records.find((x) => x.id === id).permission).toBe("view");

    expect((await call(a, "DELETE", `/folders/${f.id}/members/${b.id}`)).statusCode).toBe(204);
    const after = await sync(b);
    expect(after.folders).toHaveLength(0);
    expect(after.records).toHaveLength(0);
    expect((await call(b, "PUT", `/records/${id}`, { encBody: "v1.AAAA", revision: 1 })).statusCode).toBe(404);
  });

  it("only the folder owner (or an admin) manages members; members can leave; the owner can't be removed", async () => {
    const a = await createActiveUser(t), b = await createActiveUser(t), c = await createActiveUser(t), admin = await createActiveUser(t, { role: "admin" });
    const f = await teamFolder(a);
    await addMember(a, f, b, "edit");
    expect((await addMember(b, f, c, "view")).statusCode).toBe(403);
    expect((await addMember(c, f, c, "view")).statusCode).toBe(404);
    expect((await call(b, "PATCH", `/folders/${f.id}/members/${b.id}`, { permission: "edit" })).statusCode).toBe(403);
    expect((await call(a, "PATCH", `/folders/${f.id}/members/${a.id}`, { permission: "view" })).statusCode).toBe(400);
    expect((await call(a, "DELETE", `/folders/${f.id}/members/${a.id}`)).statusCode).toBe(400);
    expect((await call(admin, "PATCH", `/folders/${f.id}/members/${b.id}`, { permission: "use" })).statusCode).toBe(200);
    // "owner" can never be granted
    expect((await call(a, "POST", `/folders/${f.id}/members`, { userId: c.id, permission: "owner", wrappedFolderKey: "s1.x.y.z" })).statusCode).toBe(400);
    expect((await call(b, "DELETE", `/folders/${f.id}/members/${b.id}`)).statusCode).toBe(204);
    expect((await sync(b)).folders).toHaveLength(0);
    expect((await call(b, "PATCH", `/folders/${f.id}`, { encName: "v1.AAAA" })).statusCode).toBe(404);
  });

  it("share targets must be active users", async () => {
    const a = await createActiveUser(t), b = await createActiveUser(t);
    const f = await teamFolder(a);
    await t.prisma.user.update({ where: { id: b.id }, data: { status: "disabled" } });
    expect((await addMember(a, f, b, "view")).statusCode).toBe(400);
    const { id, enc } = await privateRecord(a);
    expect((await call(a, "POST", `/records/${id}/shares`, { userId: b.id, permission: "view", sealedRecordKey: await shareRecordKey(enc.recordKey, id, b.keys.publicKey) })).statusCode).toBe(400);
    expect((await call(a, "POST", `/records/${id}/shares`, { userId: crypto.randomUUID(), permission: "view", sealedRecordKey: "s1.a.b.c" })).statusCode).toBe(400);
  });

  it("enforces permissions in team folders: view can't edit or add, edit can, only the record owner trashes and shares", async () => {
    const a = await createActiveUser(t), v = await createActiveUser(t), e = await createActiveUser(t), x = await createActiveUser(t);
    const f = await teamFolder(a);
    await addMember(a, f, v, "view");
    await addMember(a, f, e, "edit");
    const { id, enc } = await teamRecord(a, f);
    const body2 = await encryptRecordBody(id, { type: "login", title: "AWS root", password: "rotated" }, enc.recordKey);
    expect((await call(v, "PUT", `/records/${id}`, { encBody: body2, revision: 1 })).statusCode).toBe(403);
    expect((await teamRecord(v, f)).res.statusCode).toBe(403);
    expect((await call(e, "PUT", `/records/${id}`, { encBody: body2, revision: 1 })).statusCode).toBe(200);
    expect((await teamRecord(e, f)).res.statusCode).toBe(201);
    for (const u of [v, e]) {
      expect((await call(u, "DELETE", `/records/${id}`)).statusCode).toBe(403);
      expect((await call(u, "POST", `/records/${id}/shares`, { userId: x.id, permission: "view", sealedRecordKey: "s1.a.b.c" })).statusCode).toBe(403);
      expect((await call(u, "PUT", `/records/${id}/folder`, { folderId: null })).statusCode).toBe(403);
    }
    // The owner of a live team folder may act as owner of every record in it (review ruling 1).
    const recByE = (await teamRecord(e, f)).id;
    expect((await call(a, "DELETE", `/records/${recByE}`)).statusCode).toBe(204);
    expect((await call(a, "DELETE", `/records/${id}`)).statusCode).toBe(204);
    // A team record without the owner's own wrap is refused
    const rid = crypto.randomUUID();
    const enc2 = await encryptNewRecord(rid, { type: "note", title: "n" }, a.keys.userKey);
    expect((await call(a, "POST", "/records", { id: rid, folderId: f.id, type: "note", encBody: enc2.encBody, wrappedRecordKey: enc2.wrappedRecordKey })).statusCode).toBe(400);
  });

  it("moves records into and out of a team folder, re-wrapping the key", async () => {
    const a = await createActiveUser(t), b = await createActiveUser(t);
    const f = await teamFolder(a);
    await addMember(a, f, b, "view");
    const { id, enc } = await privateRecord(a);
    expect((await sync(b)).records).toHaveLength(0);
    expect((await call(a, "PUT", `/records/${id}/folder`, { folderId: f.id })).statusCode).toBe(400); // folder wrap required
    expect((await call(a, "PUT", `/records/${id}/folder`, { folderId: f.id, folderWrappedRecordKey: await wrapKey(enc.recordKey, f.folderKey, `record-key:${id}`) })).statusCode).toBe(200);
    const sb = await sync(b);
    expect((await open(b, sb, sb.records[0])).title).toBe("Private");
    // the plain PUT can't move a record out of a team folder (that would leave the folder's wrap behind)
    const body = await encryptRecordBody(id, { type: "login", title: "Private", password: "mine" }, enc.recordKey);
    expect((await call(a, "PUT", `/records/${id}`, { encBody: body, revision: 1, folderId: null })).statusCode).toBe(409);
    // A record in an org's team folder stays in the org: moving it out to private is refused (it would escape the org's
    // link policy and event log; the members already know its key).
    expect((await call(a, "PUT", `/records/${id}/folder`, { folderId: null })).json()).toEqual({ error: "org_record" });
    expect((await sync(b)).records).toHaveLength(1);
    expect(await t.prisma.recordAccess.count({ where: { recordId: id, holderType: "folder" } })).toBe(1);
    // Can't move into someone else's private folder or a team folder I only view
    const g = await teamFolder(b);
    await addMember(b, g, a, "view");
    expect((await call(a, "PUT", `/records/${id}/folder`, { folderId: g.id, folderWrappedRecordKey: "v1.AAAA" })).statusCode).toBe(403);
  });

  it("restoring a record out of a deleted team folder drops the folder's access", async () => {
    const a = await createActiveUser(t), b = await createActiveUser(t);
    const f = await teamFolder(a);
    await addMember(a, f, b, "edit");
    const { id } = await teamRecord(a, f);
    expect((await call(a, "DELETE", `/folders/${f.id}`)).statusCode).toBe(204);
    expect((await call(a, "POST", `/records/${id}/restore`)).statusCode).toBe(200);
    expect((await sync(b)).records.find((r) => r.id === id)).toBeUndefined();
  });
});

describe("direct shares", () => {
  it("share is visible to the recipient only, permission is enforced, unshare removes it", async () => {
    const a = await createActiveUser(t), b = await createActiveUser(t), c = await createActiveUser(t);
    const { id, enc } = await privateRecord(a, "Stripe");
    const sealed = await shareRecordKey(enc.recordKey, id, b.keys.publicKey);
    expect((await call(b, "POST", `/records/${id}/shares`, { userId: c.id, permission: "view", sealedRecordKey: sealed })).statusCode).toBe(404);
    expect((await call(a, "POST", `/records/${id}/shares`, { userId: a.id, permission: "view", sealedRecordKey: sealed })).statusCode).toBe(400);
    expect((await call(a, "POST", `/records/${id}/shares`, { userId: b.id, permission: "view", sealedRecordKey: "v1.notsealed" })).statusCode).toBe(400);
    expect((await call(a, "POST", `/records/${id}/shares`, { userId: b.id, permission: "view", sealedRecordKey: sealed })).statusCode).toBe(201);
    expect((await call(a, "POST", `/records/${id}/shares`, { userId: b.id, permission: "view", sealedRecordKey: sealed })).statusCode).toBe(409);

    const sb = await sync(b);
    expect(sb.records).toHaveLength(1);
    expect(sb.records[0]).toMatchObject({ id, permission: "view", holderType: "user", sharedBy: a.email.split("@")[0], ownerId: a.id });
    expect(sb.records[0].wrappedRecordKey.startsWith("s1.")).toBe(true);
    expect((await open(b, sb, sb.records[0])).title).toBe("Stripe");
    expect((await sync(c)).records).toHaveLength(0);
    expect((await sync(a)).records[0].sharedWith).toEqual([{ userId: b.id, name: b.email.split("@")[0], permission: "view" }]);

    const body2 = await encryptRecordBody(id, { type: "login", title: "Stripe 2" }, enc.recordKey);
    expect((await call(b, "PUT", `/records/${id}`, { encBody: body2, revision: 1 })).statusCode).toBe(403);
    expect((await call(b, "DELETE", `/records/${id}`)).statusCode).toBe(403);
    expect((await call(b, "DELETE", `/records/${id}/shares/${b.id}`)).statusCode).toBe(403);

    expect((await call(a, "PATCH", `/records/${id}/shares/${b.id}`, { permission: "edit" })).statusCode).toBe(200);
    expect((await call(a, "PATCH", `/records/${id}/shares/${a.id}`, { permission: "view" })).statusCode).toBe(404); // the owner row is untouchable
    expect((await call(b, "PUT", `/records/${id}`, { encBody: body2, revision: 1 })).statusCode).toBe(200);
    // an editor can't move the record
    expect((await call(b, "PUT", `/records/${id}`, { encBody: body2, revision: 2, folderId: crypto.randomUUID() })).statusCode).toBe(404);

    const act = (await call(b, "GET", `/records/${id}/activity`)).json().events;
    expect(act.map((e: any) => e.action)).toEqual(["record.update", "record.permission", "record.share", "record.create"]);
    expect(act[2]).toMatchObject({ actor: a.email.split("@")[0], target: b.email.split("@")[0] });
    expect(JSON.stringify(act)).not.toMatch(/ip|userAgent/);
    expect((await call(c, "GET", `/records/${id}/activity`)).statusCode).toBe(404);

    expect((await call(a, "DELETE", `/records/${id}/shares/${b.id}`)).statusCode).toBe(204);
    expect((await sync(b)).records).toHaveLength(0);
    expect((await call(b, "GET", `/records/${id}/activity`)).statusCode).toBe(404);
    expect((await call(a, "DELETE", `/records/${id}/shares/${a.id}`)).statusCode).toBe(404);
  });

  it("effective permission is the max of a direct share and folder membership", async () => {
    const a = await createActiveUser(t), b = await createActiveUser(t);
    const f = await teamFolder(a);
    await addMember(a, f, b, "use");
    const { id, enc } = await teamRecord(a, f);
    expect((await sync(b)).records[0].permission).toBe("use");
    await call(a, "POST", `/records/${id}/shares`, { userId: b.id, permission: "edit", sealedRecordKey: await shareRecordKey(enc.recordKey, id, b.keys.publicKey) });
    const sb = await sync(b);
    expect(sb.records).toHaveLength(1);
    expect(sb.records[0]).toMatchObject({ permission: "edit", holderType: "user" });
    expect((await open(b, sb, sb.records[0])).title).toBe("AWS root");
    await call(a, "DELETE", `/folders/${f.id}/members/${b.id}`);
    // Offboarding (review ruling 1) drops every row of theirs on records in the folder, direct shares included.
    expect((await sync(b)).records).toHaveLength(0);
  });
});

describe("sync never leaks", () => {
  it("returns only records reachable by the caller, across a mixed population", async () => {
    const users = await Promise.all([0, 1, 2, 3].map(() => createActiveUser(t)));
    const [a, b, c, d] = users as [U, U, U, U];
    const fa = await teamFolder(a, "A team");
    await addMember(a, fa, b, "view");
    const fc = await teamFolder(c, "C team");
    await addMember(c, fc, d, "edit");
    const ra = await teamRecord(a, fa, "a-team");
    const rc = await teamRecord(c, fc, "c-team");
    const pa = await privateRecord(a, "a-private");
    const pb = await privateRecord(b, "b-private");
    const pd = await privateRecord(d, "d-private");
    await call(d, "POST", `/records/${pd.id}/shares`, { userId: a.id, permission: "view", sealedRecordKey: await shareRecordKey(pd.enc.recordKey, pd.id, a.keys.publicKey) });
    const expected: Record<string, string[]> = {
      [a.id]: [ra.id, pa.id, pd.id], [b.id]: [ra.id, pb.id], [c.id]: [rc.id], [d.id]: [rc.id, pd.id],
    };
    for (const u of users) {
      const s = await sync(u);
      expect(s.records.map((r) => r.id).sort()).toEqual(expected[u.id]!.sort());
      for (const r of s.records) await open(u, s, r); // and every one of them opens
      const teamIds = s.folders.filter((f) => f.kind === "team").map((f) => f.id).sort();
      expect(teamIds).toEqual(([[a.id, fa.id], [b.id, fa.id], [c.id, fc.id], [d.id, fc.id]] as const).filter(([x]) => x === u.id).map(([, y]) => y).sort());
      expect(s.folders.every((f) => f.kind === "team" || f.ownerId === u.id)).toBe(true);
    }
  });

  it("returns public keys for active people only", async () => {
    const a = await createActiveUser(t), b = await createActiveUser(t), c = await createActiveUser(t);
    await t.prisma.user.update({ where: { id: c.id }, data: { status: "disabled" } });
    const users = (await call(a, "GET", "/users")).json().users;
    expect(users.map((u: any) => u.id).sort()).toEqual([a.id, b.id].sort());
    expect(users.find((u: any) => u.id === b.id).publicKey).toBe(b64url.encode(b.keys.publicKey));
    expect(Object.keys(users[0]).sort()).toEqual(["email", "id", "membershipKey", "name", "publicKey"]);
    expect((await t.app.inject({ method: "GET", url: "/api/v1/users" })).statusCode).toBe(401);
  });
});

describe("review fixes", () => {
  it("offboarding: a removed member loses their records in the folder and the folder owner takes them over", async () => {
    const a = await createActiveUser(t), b = await createActiveUser(t), c = await createActiveUser(t);
    const f = await teamFolder(a);
    await addMember(a, f, b, "edit");
    const { id, enc } = await teamRecord(b, f, "B's record");
    expect((await sync(a)).records.find((r) => r.id === id)).toMatchObject({ permission: "owner", holderType: "folder" });
    expect((await call(a, "DELETE", `/folders/${f.id}/members/${b.id}`)).statusCode).toBe(204);
    expect((await sync(b)).records.find((r) => r.id === id)).toBeUndefined();
    const body = await encryptRecordBody(id, { type: "login", title: "x" }, enc.recordKey);
    expect((await call(b, "PUT", `/records/${id}`, { encBody: body, revision: 1 })).statusCode).toBe(404);
    expect((await call(b, "DELETE", `/records/${id}`)).statusCode).toBe(404);
    expect((await t.prisma.record.findUniqueOrThrow({ where: { id } })).ownerId).toBe(a.id);
    const ra = (await sync(a)).records.find((r) => r.id === id);
    expect(ra).toMatchObject({ permission: "owner", ownerId: a.id, sharedWith: [] });
    // the folder owner can share it (key via the folder) and trash it
    expect((await call(a, "POST", `/records/${id}/shares`, { userId: c.id, permission: "view", sealedRecordKey: await shareRecordKey(enc.recordKey, id, c.keys.publicKey) })).statusCode).toBe(201);
    expect((await call(a, "DELETE", `/records/${id}`)).statusCode).toBe(204);
  });

  it("offboarding also applies when a member leaves", async () => {
    const a = await createActiveUser(t), b = await createActiveUser(t);
    const f = await teamFolder(a);
    await addMember(a, f, b, "edit");
    const { id } = await teamRecord(b, f);
    expect((await call(b, "DELETE", `/folders/${f.id}/members/${b.id}`)).statusCode).toBe(204);
    expect((await sync(b)).records).toHaveLength(0);
    expect((await t.prisma.record.findUniqueOrThrow({ where: { id } })).ownerId).toBe(a.id);
  });

  it("only the folder owner adds members; an admin may downgrade and remove but not add or upgrade", async () => {
    const a = await createActiveUser(t), b = await createActiveUser(t), c = await createActiveUser(t), admin = await createActiveUser(t, { role: "admin" });
    const f = await teamFolder(a);
    await addMember(a, f, b, "view");
    const r = await call(admin, "POST", `/folders/${f.id}/members`, { userId: admin.id, permission: "edit", wrappedFolderKey: await sealFolderKeyFor(f.folderKey, f.id, admin.keys.publicKey) });
    expect([403, 404]).toContain(r.statusCode);
    expect((await call(admin, "POST", `/folders/${f.id}/members`, { userId: c.id, permission: "view", wrappedFolderKey: "s1.a.b.c" })).statusCode).toBeGreaterThanOrEqual(403);
    expect((await call(admin, "PATCH", `/folders/${f.id}/members/${b.id}`, { permission: "edit" })).statusCode).toBe(403);
    expect((await call(admin, "PATCH", `/folders/${f.id}/members/${b.id}`, { permission: "use" })).statusCode).toBe(200);
    expect((await call(admin, "DELETE", `/folders/${f.id}/members/${b.id}`)).statusCode).toBe(204);
    expect(await t.prisma.folderMember.count({ where: { folderId: f.id } })).toBe(1);
  });

  it("refuses to delete a team folder holding other people's live records; deleted folders grant no member access", async () => {
    const a = await createActiveUser(t), b = await createActiveUser(t);
    const f = await teamFolder(a);
    await addMember(a, f, b, "edit");
    const { id } = await teamRecord(b, f);
    const own = await teamRecord(a, f, "A's");
    const res = await call(a, "DELETE", `/folders/${f.id}`);
    expect(res.statusCode).toBe(409);
    expect(res.json().error).toBe("folder_has_others_records");
    expect((await call(b, "DELETE", `/records/${id}`)).statusCode).toBe(204); // B trashes theirs
    expect((await call(a, "DELETE", `/folders/${f.id}`)).statusCode).toBe(204);
    expect((await sync(b)).folders).toHaveLength(0);
    expect((await sync(b)).records.find((r) => r.id === own.id)).toBeUndefined();
    expect((await call(b, "GET", `/records/${own.id}/activity`)).statusCode).toBe(404);
  });

  it("duplicate shares and members return 409 exists-style errors; trashed records can't be shared", async () => {
    const a = await createActiveUser(t), b = await createActiveUser(t);
    const { id, enc } = await privateRecord(a);
    const sealed = await shareRecordKey(enc.recordKey, id, b.keys.publicKey);
    const [r1, r2] = await Promise.all([0, 1].map(() => call(a, "POST", `/records/${id}/shares`, { userId: b.id, permission: "view", sealedRecordKey: sealed })));
    expect([r1!.statusCode, r2!.statusCode].sort()).toEqual([201, 409]);
    const p = await privateRecord(a, "trashed");
    await call(a, "DELETE", `/records/${p.id}`);
    const r = await call(a, "POST", `/records/${p.id}/shares`, { userId: b.id, permission: "view", sealedRecordKey: await shareRecordKey(p.enc.recordKey, p.id, b.keys.publicKey) });
    expect(r.statusCode).toBe(409);
    expect(r.json().error).toBe("in_trash");
  });
  it("a folder owner moving someone else's record out takes ownership with their own wrap", async () => {
    const a = await createActiveUser(t), b = await createActiveUser(t);
    const f = await teamFolder(a);
    await addMember(a, f, b, "edit");
    const { id, enc } = await teamRecord(b, f);
    expect((await call(a, "PUT", `/records/${id}/folder`, { folderId: null })).statusCode).toBe(400);
    const ownerWrappedRecordKey = await wrapKey(enc.recordKey, a.keys.userKey, `record-key:${id}`);
    // Out to private: refused for org records. Into another team folder of the org, the takeover works.
    expect((await call(a, "PUT", `/records/${id}/folder`, { folderId: null, ownerWrappedRecordKey })).json()).toEqual({ error: "org_record" });
    const g = await teamFolder(a);
    const folderWrappedRecordKey = await wrapKey(enc.recordKey, g.folderKey, `record-key:${id}`);
    expect((await call(a, "PUT", `/records/${id}/folder`, { folderId: g.id, folderWrappedRecordKey, ownerWrappedRecordKey })).statusCode).toBe(200);
    const sa = await sync(a);
    const ra = sa.records.find((r) => r.id === id);
    expect(ra).toMatchObject({ permission: "owner", holderType: "user", ownerId: a.id });
    expect((await open(a, sa, ra)).title).toBe("AWS root");
    expect((await sync(b)).records.find((r) => r.id === id)).toMatchObject({ permission: "edit", holderType: "user" });
  });
  it("handover: a folder owner who also holds a direct share of the record gets the folder wrap, before and after removal", async () => {
    const a = await createActiveUser(t), b = await createActiveUser(t);
    const f = await teamFolder(a);
    await addMember(a, f, b, "edit");
    const { id, enc } = await teamRecord(b, f, "B shares to A");
    expect((await call(b, "POST", `/records/${id}/shares`, { userId: a.id, permission: "view", sealedRecordKey: await shareRecordKey(enc.recordKey, id, a.keys.publicKey) })).statusCode).toBe(201);
    // While B is still a member, A owns R through the folder: sync must serve the folder wrap, not the sealed share.
    let sa = await sync(a);
    let ra = sa.records.find((r) => r.id === id);
    expect(ra).toMatchObject({ permission: "owner", holderType: "folder", keyFolderId: f.id });
    expect(ra.wrappedRecordKey.startsWith("v1.")).toBe(true);
    expect((await open(a, sa, ra)).title).toBe("B shares to A");
    // After B's removal, A's sealed share row is gone and the folder wrap is used.
    expect((await call(a, "DELETE", `/folders/${f.id}/members/${b.id}`)).statusCode).toBe(204);
    expect(await t.prisma.recordAccess.count({ where: { recordId: id, holderType: "user", holderId: a.id } })).toBe(0);
    sa = await sync(a);
    ra = sa.records.find((r) => r.id === id);
    expect(ra).toMatchObject({ permission: "owner", ownerId: a.id, holderType: "folder", keyFolderId: f.id });
    expect(ra.wrappedRecordKey.startsWith("v1.")).toBe(true);
    expect((await open(a, sa, ra)).title).toBe("B shares to A");
  });
});
