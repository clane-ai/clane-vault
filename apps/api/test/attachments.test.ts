import { randomUUID } from "node:crypto";
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { SignJWT } from "jose";
import {
  b64url, createLink, createTeamFolder, encodeNonceBase, encryptNewRecord, linkSnapshot, openLink, sealFolderKeyFor, shareRecordKey, wrapKey,
  decryptAttachment, decryptAttachmentMeta, type LinkAttachment,
} from "@clane-vault/crypto";
import { DEFAULT_ATTACHMENTS, type AttachmentConfig } from "../src/config.js";
import { orgUsage, userUsage } from "../src/lib/attachments/quota.js";
import { makeTestApp, resetDb, createActiveUser, orgHeader } from "./helpers.js";
import { attReq, bytes, complete, create, download, getChunk, prepare, putChunk, sha, upload, type Who } from "./attachmentClient.js";

const MiB = 1024 * 1024;
const t = await makeTestApp();
afterAll(() => t.app.close());
beforeEach(() => resetDb(t.prisma));

type U = Awaited<ReturnType<typeof createActiveUser>>;
type App = typeof t;
type Folder = { id: string; folderKey: Uint8Array };
type Rec = { id: string; recordKey: Uint8Array };

const call = (a: App, u: Who, method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE", url: string, payload?: unknown, org?: string | null) => attReq(a, u, method, url, payload, { org });

async function teamFolder(a: App, owner: U, name = "Infra"): Promise<Folder> {
  const id = randomUUID();
  const f = await createTeamFolder(id, name, owner.keys.publicKey);
  expect((await call(a, owner, "POST", "/folders", { id, kind: "team", encName: f.encName, wrappedFolderKey: f.wrappedFolderKey })).statusCode).toBe(201);
  return { id, folderKey: f.folderKey };
}
async function addMember(a: App, owner: U, f: Folder, who: U, permission: string) {
  const r = await call(a, owner, "POST", `/folders/${f.id}/members`, { userId: who.id, permission, wrappedFolderKey: await sealFolderKeyFor(f.folderKey, f.id, who.keys.publicKey) });
  expect(r.statusCode, r.body).toBe(201);
}
async function teamRecord(a: App, u: U, f: Folder, type: "login" | "item" = "login"): Promise<Rec> {
  const id = randomUUID();
  const enc = await encryptNewRecord(id, type === "login" ? { type: "login", title: "AWS", password: "team-s3cret" } : { type: "card", title: "Corporate card", data: { cardholder: "Ana" } }, u.keys.userKey);
  const r = await call(a, u, "POST", "/records", { id, folderId: f.id, type, encBody: enc.encBody, wrappedRecordKey: await wrapKey(enc.recordKey, f.folderKey, `record-key:${id}`), ownerWrappedRecordKey: enc.wrappedRecordKey });
  expect(r.statusCode, r.body).toBe(201);
  return { id, recordKey: enc.recordKey };
}
async function privateRecord(a: App, u: U, org: string | null = null): Promise<Rec> {
  const id = randomUUID();
  const enc = await encryptNewRecord(id, { type: "sshKey", title: "Deploy key", data: {} }, u.keys.userKey);
  const r = await call(a, u, "POST", "/records", { id, folderId: null, type: "item", encBody: enc.encBody, wrappedRecordKey: enc.wrappedRecordKey }, org);
  expect(r.statusCode, r.body).toBe(201);
  return { id, recordKey: enc.recordKey };
}
async function share(a: App, owner: U, rec: Rec, who: U, permission: string) {
  const r = await call(a, owner, "POST", `/records/${rec.id}/shares`, { userId: who.id, permission, sealedRecordKey: await shareRecordKey(rec.recordKey, rec.id, who.keys.publicKey) });
  expect(r.statusCode, r.body).toBe(201);
}
const ok = (r: { statusCode: number; body: string }, code: number) => expect(r.statusCode, r.body).toBe(code);
const err = (r: { statusCode: number; json: () => unknown }) => (r.json() as { error?: string }).error;

/** A test app with other attachment limits (same database). */
async function appWith(a: Partial<AttachmentConfig>) {
  const x = await makeTestApp({ attachments: { ...DEFAULT_ATTACHMENTS, ...a } });
  return x;
}

describe("attachments: upload and download", () => {
  it("an owner attaches a file to a private record of any type; it downloads byte for byte, with safe headers", async () => {
    const a = await createActiveUser(t);
    const rec = await privateRecord(t, a);
    const data = bytes(2 * MiB + 1234);
    const p = await upload(t, a, rec.id, rec.recordKey, data, { org: null });
    expect((await download(t, a, rec.id, rec.recordKey, p.id, { org: null })).equals(Buffer.from(data))).toBe(true);
    const r = await getChunk(t, a, rec.id, p.id, 0, { org: null });
    expect(r.headers["content-type"]).toBe("application/octet-stream");
    expect(r.headers["content-disposition"]).toBe(`attachment; filename="${p.id}.0.bin"`);
    expect(r.headers["cache-control"]).toBe("no-store");
    expect(r.headers["x-content-type-options"]).toBe("nosniff");
    // The server never sees the name, type or hash.
    const row = await t.prisma.attachment.findUniqueOrThrow({ where: { id: p.id } });
    expect(JSON.stringify(row)).not.toContain("report.pdf");
    expect(JSON.stringify(row)).not.toContain(sha(data));
    expect(row).toMatchObject({ state: "ready", storage: "db", chunkCount: 3, size: 2 * MiB + 1234 + 48 });
  });

  it("a zero-byte file is one empty chunk", async () => {
    const a = await createActiveUser(t);
    const rec = await privateRecord(t, a);
    const p = await upload(t, a, rec.id, rec.recordKey, new Uint8Array(0), { org: null });
    expect((await download(t, a, rec.id, rec.recordKey, p.id, { org: null })).length).toBe(0);
  });

  it("works on team records of every kind, and lists the person who added it", async () => {
    const owner = await createActiveUser(t, { role: "admin" });
    const f = await teamFolder(t, owner);
    const rec = await teamRecord(t, owner, f, "item");
    const p = await upload(t, owner, rec.id, rec.recordKey, bytes(1000));
    const list = (await call(t, owner, "GET", `/records/${rec.id}/attachments`)).json().attachments;
    expect(list).toEqual([{ id: p.id, encMeta: expect.stringMatching(/^v1\./), wrappedFileKey: expect.stringMatching(/^v1\./), nonceBase: encodeNonceBase(p.nonceBase),
      size: 1016, chunkSize: MiB, chunkCount: 1, createdBy: owner.id, createdByName: owner.email.split("@")[0], createdAt: expect.any(String) }]);
    expect(await decryptAttachmentMeta(rec.id, p.id, list[0].encMeta, rec.recordKey)).toEqual(p.meta);
  });

  it("complete: missing chunks are listed; success sets ready, touches updatedAt, keeps the revision and logs attachment.add", async () => {
    const a = await createActiveUser(t);
    const rec = await privateRecord(t, a);
    const before = await t.prisma.record.findUniqueOrThrow({ where: { id: rec.id } });
    const p = await prepare(rec.id, rec.recordKey, bytes(3 * MiB - 1));
    ok(await create(t, a, rec.id, p, { org: null }), 201);
    ok(await putChunk(t, a, rec.id, p.id, 1, p.chunks[1]!, { org: null }), 200);
    const inc = await complete(t, a, rec.id, p.id, { org: null });
    expect(inc.statusCode).toBe(409);
    expect(inc.json()).toEqual({ error: "incomplete", missing: [0, 2] });
    // Uploading files are neither listed nor downloadable.
    expect((await call(t, a, "GET", `/records/${rec.id}/attachments`, undefined, null)).json().attachments).toEqual([]);
    expect((await getChunk(t, a, rec.id, p.id, 1, { org: null })).statusCode).toBe(404);
    // Resume: the server says which indices it has.
    expect((await call(t, a, "GET", `/records/${rec.id}/attachments/${p.id}/upload`, undefined, null)).json()).toMatchObject({ state: "uploading", received: [1] });
    ok(await putChunk(t, a, rec.id, p.id, 2, p.chunks[2]!, { org: null }), 200);
    ok(await putChunk(t, a, rec.id, p.id, 0, p.chunks[0]!, { org: null }), 200);
    await new Promise((r) => setTimeout(r, 5));
    ok(await complete(t, a, rec.id, p.id, { org: null }), 200);
    const after = await t.prisma.record.findUniqueOrThrow({ where: { id: rec.id } });
    expect(after.revision).toBe(before.revision);
    expect(after.encBody).toBe(before.encBody);
    expect(after.updatedAt.getTime()).toBeGreaterThan(before.updatedAt.getTime());
    const ev = await t.prisma.event.findFirstOrThrow({ where: { action: "attachment.add", recordId: rec.id } });
    expect(ev).toMatchObject({ actorId: a.id, meta: { size: 3 * MiB - 1 + 48, chunkCount: 3 } });
    expect((await complete(t, a, rec.id, p.id, { org: null })).statusCode).toBe(409);
  });
});

describe("attachments: chunk rules", () => {
  it("checks length and index, refuses JSON and oversized bodies, is idempotent for identical bytes and refuses different ones", async () => {
    const a = await createActiveUser(t);
    const rec = await privateRecord(t, a);
    const p = await prepare(rec.id, rec.recordKey, bytes(MiB + 10));
    ok(await create(t, a, rec.id, p, { org: null }), 201);
    const url = `/records/${rec.id}/attachments/${p.id}/chunks`;
    expect(err(await putChunk(t, a, rec.id, p.id, 0, p.chunks[0]!.subarray(1), { org: null }))).toBe("bad_length");
    expect(err(await putChunk(t, a, rec.id, p.id, 1, p.chunks[0]!, { org: null }))).toBe("bad_length");
    expect(err(await putChunk(t, a, rec.id, p.id, 2, p.chunks[1]!, { org: null }))).toBe("bad_index");
    const json = await attReq(t, a, "PUT", `${url}/0`, { data: "x" }, { org: null });
    expect(json.statusCode).toBe(415);
    expect(err(json)).toBe("unsupported_media_type");
    const big = await attReq(t, a, "PUT", `${url}/0`, Buffer.alloc(MiB + 17), { org: null, raw: true });
    expect(big.statusCode).toBe(413);
    ok(await putChunk(t, a, rec.id, p.id, 0, p.chunks[0]!, { org: null }), 200);
    const again = await putChunk(t, a, rec.id, p.id, 0, p.chunks[0]!, { org: null });
    ok(again, 200);
    expect(again.json()).toEqual({ received: 1 });
    const other = p.chunks[0]!.slice(); other[5]! ^= 1;
    const mismatch = await putChunk(t, a, rec.id, p.id, 0, other, { org: null });
    expect(mismatch.statusCode).toBe(409);
    expect(err(mismatch)).toBe("chunk_mismatch");
    expect(await t.prisma.attachmentChunk.findUniqueOrThrow({ where: { attachmentId_index: { attachmentId: p.id, index: 0 } }, select: { sha256: true } })).toEqual({ sha256: sha(p.chunks[0]!) });
  });

  it("two people can't fill one upload; a share downgraded mid-upload stops the next chunk", async () => {
    const a = await createActiveUser(t), b = await createActiveUser(t);
    const rec = await privateRecord(t, a);
    await share(t, a, rec, b, "edit");
    const p = await prepare(rec.id, rec.recordKey, bytes(MiB + 5));
    ok(await create(t, b, rec.id, p), 201);
    expect(err(await putChunk(t, a, rec.id, p.id, 0, p.chunks[0]!, { org: b.orgId }))).toBe("forbidden");
    ok(await putChunk(t, b, rec.id, p.id, 0, p.chunks[0]!), 200);
    ok(await call(t, a, "PATCH", `/records/${rec.id}/shares/${b.id}`, { permission: "view" }), 200);
    expect((await putChunk(t, b, rec.id, p.id, 1, p.chunks[1]!)).statusCode).toBe(403);
    expect((await complete(t, b, rec.id, p.id)).statusCode).toBe(403);
  });

  it("validates the size arithmetic and refuses a reused id", async () => {
    const a = await createActiveUser(t);
    const rec = await privateRecord(t, a);
    const p = await prepare(rec.id, rec.recordKey, bytes(10));
    for (const bad of [{ size: 10 }, { size: 26, chunkCount: 2 }, { size: MiB + 17, chunkCount: 1 }, { chunkSize: 4096 }, { nonceBase: "short" }, { encMeta: "plain" }]) {
      expect((await attReq(t, a, "POST", `/records/${rec.id}/attachments`, { ...p.body, ...bad }, { org: null })).statusCode).toBe(400);
    }
    ok(await create(t, a, rec.id, p, { org: null }), 201);
    expect(err(await create(t, a, rec.id, p, { org: null }))).toBe("exists");
    const rec2 = await privateRecord(t, a);
    expect(err(await attReq(t, a, "POST", `/records/${rec2.id}/attachments`, p.body, { org: null }))).toBe("exists");
  });
});

describe("attachments: permissions", () => {
  it("direct shares: edit adds and removes, view downloads, use sees the list only (403 use_only), others 404; revoked is 404", async () => {
    const a = await createActiveUser(t), ed = await createActiveUser(t), vw = await createActiveUser(t), us = await createActiveUser(t), out = await createActiveUser(t);
    const rec = await privateRecord(t, a);
    for (const [u, perm] of [[ed, "edit"], [vw, "view"], [us, "use"]] as const) await share(t, a, rec, u, perm);
    const p = await upload(t, a, rec.id, rec.recordKey, bytes(4000), { org: null });
    const data = bytes(4000);
    // Editors add files too; viewers and use-only holders can't.
    const pe = await upload(t, ed, rec.id, rec.recordKey, bytes(50, 3));
    for (const u of [vw, us]) expect((await create(t, u, rec.id, await prepare(rec.id, rec.recordKey, bytes(5)))).statusCode).toBe(403);
    expect((await create(t, out, rec.id, await prepare(rec.id, rec.recordKey, bytes(5)))).statusCode).toBe(404);

    for (const u of [ed, vw]) expect((await download(t, u, rec.id, rec.recordKey, p.id)).equals(Buffer.from(data))).toBe(true);
    const useList = (await call(t, us, "GET", `/records/${rec.id}/attachments`)).json().attachments;
    expect(useList).toHaveLength(2);
    expect(useList[0].wrappedFileKey).toBeUndefined();
    expect(useList[0].nonceBase).toBeUndefined();
    const denied = await getChunk(t, us, rec.id, p.id, 0);
    expect(denied.statusCode).toBe(403);
    expect(err(denied)).toBe("use_only");
    expect((await getChunk(t, out, rec.id, p.id, 0)).statusCode).toBe(404);
    expect((await call(t, out, "GET", `/records/${rec.id}/attachments`)).statusCode).toBe(404);

    // Remove: view and use can't; edit can.
    for (const u of [vw, us]) expect((await call(t, u, "DELETE", `/records/${rec.id}/attachments/${pe.id}`)).statusCode).toBe(403);
    ok(await call(t, ed, "DELETE", `/records/${rec.id}/attachments/${pe.id}`), 204);

    // Revocation is the record's: the share goes, the chunks stop at once.
    ok(await call(t, a, "DELETE", `/records/${rec.id}/shares/${vw.id}`), 204);
    expect((await getChunk(t, vw, rec.id, p.id, 0)).statusCode).toBe(404);
  });

  it("team folders and groups: members download per their folder permission; the folder owner removes a member's file", async () => {
    const owner = await createActiveUser(t, { role: "admin" }), ed = await createActiveUser(t), vw = await createActiveUser(t), us = await createActiveUser(t), viaGroup = await createActiveUser(t);
    const f = await teamFolder(t, owner);
    await addMember(t, owner, f, ed, "edit");
    await addMember(t, owner, f, vw, "view");
    await addMember(t, owner, f, us, "use");
    // A member who only has access through a group (docs/groups.md): Can view.
    const g = (await call(t, owner, "POST", "/admin/groups", { name: "Readers" })).json().id as string;
    ok(await call(t, owner, "POST", `/admin/groups/${g}/members`, { userIds: [viaGroup.id] }), 201);
    ok(await call(t, owner, "POST", `/folders/${f.id}/groups`, { groupId: g, permission: "view", wraps: [{ userId: viaGroup.id, wrappedFolderKey: await sealFolderKeyFor(f.folderKey, f.id, viaGroup.keys.publicKey) }] }), 201);
    const rec = await teamRecord(t, owner, f);
    const data = bytes(MiB + 77);
    const p = await upload(t, ed, rec.id, rec.recordKey, data);
    for (const u of [owner, ed, vw, viaGroup]) expect((await download(t, u, rec.id, rec.recordKey, p.id)).equals(Buffer.from(data))).toBe(true);
    expect(err(await getChunk(t, us, rec.id, p.id, 0))).toBe("use_only");
    expect((await create(t, viaGroup, rec.id, await prepare(rec.id, rec.recordKey, bytes(3)))).statusCode).toBe(403);
    // Removing a member from the folder stops their downloads.
    ok(await call(t, owner, "DELETE", `/folders/${f.id}/members/${vw.id}`), 204);
    expect((await getChunk(t, vw, rec.id, p.id, 0)).statusCode).toBe(404);
    // The folder owner (owner of every record in it) removes the editor's file.
    ok(await call(t, owner, "DELETE", `/records/${rec.id}/attachments/${p.id}`), 204);
    expect((await call(t, ed, "GET", `/records/${rec.id}/attachments`)).json().attachments).toEqual([]);
  });

  it("cross-org: a record in another org's team folder is 404, and a direct share only counts in the org it was made in", async () => {
    const orgB = (await t.prisma.organization.create({ data: { name: "Org B", slug: `b-${randomUUID().slice(0, 8)}` } })).id;
    const a = await createActiveUser(t, { role: "admin" });
    const b = await createActiveUser(t);
    // b is also a member of org B.
    await t.prisma.membership.create({ data: { orgId: orgB, userId: b.id, role: "member", status: "active" } });
    const f = await teamFolder(t, a);
    await addMember(t, a, f, b, "edit");
    const rec = await teamRecord(t, a, f);
    const p = await upload(t, a, rec.id, rec.recordKey, bytes(100));
    ok(await getChunk(t, b, rec.id, p.id, 0), 200);
    expect((await getChunk(t, b, rec.id, p.id, 0, { org: orgB })).statusCode).toBe(404);
    expect((await call(t, b, "GET", `/records/${rec.id}/attachments`, undefined, orgB)).statusCode).toBe(404);
    expect((await create(t, b, rec.id, await prepare(rec.id, rec.recordKey, bytes(3)), { org: orgB })).statusCode).toBe(404);
    expect((await getChunk(t, b, rec.id, p.id, 0, { org: null })).statusCode).toBe(404);

    const priv = await privateRecord(t, a);
    const pp = await upload(t, a, priv.id, priv.recordKey, bytes(100), { org: null });
    await share(t, a, priv, b, "view");
    ok(await getChunk(t, b, priv.id, pp.id, 0), 200);
    expect((await getChunk(t, b, priv.id, pp.id, 0, { org: orgB })).statusCode).toBe(404);
    expect((await getChunk(t, b, priv.id, pp.id, 0, { org: null })).statusCode).toBe(404);
  });

  it("a session confined to one org (trusted IdP MFA) can't touch its own private records' files until a step-up", async () => {
    const a = await createActiveUser(t, { role: "admin" });
    const priv = await privateRecord(t, a);
    const pp = await upload(t, a, priv.id, priv.recordKey, bytes(100), { org: null });
    const f = await teamFolder(t, a);
    const rec = await teamRecord(t, a, f);
    const tp = await upload(t, a, rec.id, rec.recordKey, bytes(100));
    const session = await t.prisma.session.findFirstOrThrow({ where: { userId: a.id, revokedAt: null }, orderBy: { createdAt: "desc" } });
    await t.prisma.session.update({ where: { id: session.id }, data: { totpSkippedForOrg: a.orgId } });
    const step = await getChunk(t, a, priv.id, pp.id, 0, { org: a.orgId });
    expect(step.statusCode).toBe(403);
    expect(err(step)).toBe("totp_step_up_required");
    expect(err(await create(t, a, priv.id, await prepare(priv.id, priv.recordKey, bytes(3)), { org: a.orgId }))).toBe("totp_step_up_required");
    expect(err(await call(t, a, "GET", `/records/${priv.id}/attachments`, undefined, a.orgId))).toBe("totp_step_up_required");
    ok(await getChunk(t, a, rec.id, tp.id, 0), 200);
  });

  it("trash: downloads and uploads are refused while the record is in the trash; restore brings everything back", async () => {
    const a = await createActiveUser(t);
    const rec = await privateRecord(t, a);
    const p = await upload(t, a, rec.id, rec.recordKey, bytes(100), { org: null });
    ok(await call(t, a, "DELETE", `/records/${rec.id}`, undefined, null), 204);
    expect(err(await getChunk(t, a, rec.id, p.id, 0, { org: null }))).toBe("in_trash");
    expect(err(await create(t, a, rec.id, await prepare(rec.id, rec.recordKey, bytes(3)), { org: null }))).toBe("in_trash");
    expect(err(await call(t, a, "DELETE", `/records/${rec.id}/attachments/${p.id}`, undefined, null))).toBe("in_trash");
    // Still listed (and still charged): nothing was deleted.
    expect((await call(t, a, "GET", `/records/${rec.id}/attachments`, undefined, null)).json().attachments).toHaveLength(1);
    expect(await userUsage(t.prisma, a.id)).toBe(116);
    ok(await call(t, a, "POST", `/records/${rec.id}/restore`, {}, null), 200);
    ok(await getChunk(t, a, rec.id, p.id, 0, { org: null }), 200);
  });
});

describe("attachments: removal, cancel and garbage collection", () => {
  it("removing a file deletes its chunks and row, lowers usage, logs it and revokes live links that carry it", async () => {
    const a = await createActiveUser(t, { role: "admin" });
    const f = await teamFolder(t, a);
    const rec = await teamRecord(t, a, f);
    const p = await upload(t, a, rec.id, rec.recordKey, bytes(MiB + 1));
    const keep = await upload(t, a, rec.id, rec.recordKey, bytes(10));
    expect(await orgUsage(t.prisma, a.orgId!)).toBe(MiB + 1 + 32 + 26);
    const linkId = randomUUID();
    const l = await createLink(linkId, { title: "x", attachments: [{ fileId: p.id, fileKey: b64url.encode(p.fileKey), nonceBase: encodeNonceBase(p.nonceBase), meta: p.meta }] });
    ok(await call(t, a, "POST", "/links", { id: linkId, recordId: rec.id, encPayload: l.encPayload, expiresInHours: 24, maxOpens: null, attachmentIds: [p.id] }), 201);
    ok(await call(t, a, "DELETE", `/records/${rec.id}/attachments/${p.id}`), 204);
    expect(await t.prisma.attachment.findUnique({ where: { id: p.id } })).toBeNull();
    expect(await t.prisma.attachmentChunk.count({ where: { attachmentId: p.id } })).toBe(0);
    expect(await orgUsage(t.prisma, a.orgId!)).toBe(26);
    expect(await t.prisma.shareLink.findUniqueOrThrow({ where: { id: linkId } })).toMatchObject({ encPayload: null, revokedAt: expect.any(Date) });
    expect(await t.prisma.event.findFirst({ where: { action: "link.revoke", recordId: rec.id, meta: { path: ["reason"], equals: "attachment_removed" } } })).not.toBeNull();
    expect(await t.prisma.event.findFirstOrThrow({ where: { action: "attachment.remove", recordId: rec.id } })).toMatchObject({ actorId: a.id, meta: { size: MiB + 1 + 32 } });
    expect((await call(t, a, "DELETE", `/records/${rec.id}/attachments/${p.id}`)).statusCode).toBe(404);
    ok(await getChunk(t, a, rec.id, keep.id, 0), 200);
  });

  it("cancel: the uploader or the record owner cancels an upload; another editor can't", async () => {
    const a = await createActiveUser(t), b = await createActiveUser(t), c = await createActiveUser(t);
    const rec = await privateRecord(t, a);
    await share(t, a, rec, b, "edit");
    await share(t, a, rec, c, "edit");
    const p1 = await prepare(rec.id, rec.recordKey, bytes(MiB + 3));
    ok(await create(t, b, rec.id, p1), 201);
    ok(await putChunk(t, b, rec.id, p1.id, 0, p1.chunks[0]!), 200);
    expect((await call(t, c, "DELETE", `/records/${rec.id}/attachments/${p1.id}`)).statusCode).toBe(403);
    ok(await call(t, b, "DELETE", `/records/${rec.id}/attachments/${p1.id}`), 204);
    expect(await t.prisma.attachmentChunk.count({ where: { attachmentId: p1.id } })).toBe(0);
    expect(await t.prisma.attachment.findUnique({ where: { id: p1.id } })).toBeNull();
    const p2 = await prepare(rec.id, rec.recordKey, bytes(9));
    ok(await create(t, b, rec.id, p2), 201);
    ok(await call(t, a, "DELETE", `/records/${rec.id}/attachments/${p2.id}`, undefined, null), 204);
  });

  it("an upload past its 24 h expiry takes no more chunks and can't complete; the sweep never touches a file that became ready", async () => {
    const a = await createActiveUser(t);
    const rec = await privateRecord(t, a);
    const p = await prepare(rec.id, rec.recordKey, bytes(MiB + 3));
    ok(await create(t, a, rec.id, p, { org: null }), 201);
    ok(await putChunk(t, a, rec.id, p.id, 0, p.chunks[0]!, { org: null }), 200);
    await t.prisma.attachment.update({ where: { id: p.id }, data: { createdAt: new Date(Date.now() - 24 * 3600e3 - 1000) } });
    const late = await putChunk(t, a, rec.id, p.id, 1, p.chunks[1]!, { org: null });
    ok(late, 410);
    expect(err(late)).toBe("upload_expired");
    const done = await complete(t, a, rec.id, p.id, { org: null });
    ok(done, 410);
    expect(await t.prisma.attachmentChunk.count({ where: { attachmentId: p.id } })).toBe(1);
    // The uploader (or the record owner) can still cancel it.
    ok(await call(t, a, "DELETE", `/records/${rec.id}/attachments/${p.id}`, undefined, null), 204);

    // A ready file whose row is old (completed just before the sweep looked) keeps its chunks.
    const q = await upload(t, a, rec.id, rec.recordKey, bytes(2 * MiB + 1), { org: null });
    await t.prisma.attachment.update({ where: { id: q.id }, data: { createdAt: new Date(Date.now() - 48 * 3600e3) } });
    expect((await t.app.attachmentSweeper.run()).abandoned).toBe(0);
    expect(await t.prisma.attachmentChunk.count({ where: { attachmentId: q.id } })).toBe(3);
    expect((await download(t, a, rec.id, rec.recordKey, q.id, { org: null })).equals(Buffer.from(bytes(2 * MiB + 1)))).toBe(true);
  });

  it("the sweep removes uploads abandoned for 24 h (and logs them), and purging a record removes its chunks", async () => {
    const a = await createActiveUser(t);
    const rec = await privateRecord(t, a);
    const p = await prepare(rec.id, rec.recordKey, bytes(MiB + 3));
    ok(await create(t, a, rec.id, p, { org: null }), 201);
    ok(await putChunk(t, a, rec.id, p.id, 0, p.chunks[0]!, { org: null }), 200);
    const fresh = await prepare(rec.id, rec.recordKey, bytes(5));
    ok(await create(t, a, rec.id, fresh, { org: null }), 201);
    await t.prisma.attachment.update({ where: { id: p.id }, data: { createdAt: new Date(Date.now() - 25 * 3600e3) } });
    const r = await t.app.attachmentSweeper.run();
    expect(r.abandoned).toBe(1);
    expect(await t.prisma.attachment.findUnique({ where: { id: p.id } })).toBeNull();
    expect(await t.prisma.attachmentChunk.count({ where: { attachmentId: p.id } })).toBe(0);
    expect(await t.prisma.attachment.findUnique({ where: { id: fresh.id } })).not.toBeNull();
    expect(await t.prisma.event.findFirstOrThrow({ where: { action: "attachment.upload_abandoned" } })).toMatchObject({ actorId: a.id, recordId: rec.id, meta: { size: MiB + 3 + 32 } });

    const q = await upload(t, a, rec.id, rec.recordKey, bytes(MiB + 9), { org: null });
    ok(await call(t, a, "DELETE", `/records/${rec.id}`, undefined, null), 204);
    ok(await call(t, a, "DELETE", `/records/${rec.id}/purge`, undefined, null), 204);
    expect(await t.prisma.attachment.count({ where: { recordId: rec.id } })).toBe(0);
    expect(await t.prisma.attachmentChunk.count({ where: { attachmentId: q.id } })).toBe(0);
    expect(await t.prisma.attachmentTombstone.count()).toBe(0); // db storage: chunks cascade, nothing to tombstone
  });
});

describe("attachments: sync and logging", () => {
  it("sync carries ready files per record (no key for use-only), nothing for records I can't open", async () => {
    const a = await createActiveUser(t), us = await createActiveUser(t), out = await createActiveUser(t);
    const rec = await privateRecord(t, a);
    await share(t, a, rec, us, "use");
    const p = await upload(t, a, rec.id, rec.recordKey, bytes(10), { org: null });
    ok(await create(t, a, rec.id, await prepare(rec.id, rec.recordKey, bytes(20)), { org: null }), 201); // uploading: not in sync
    const mine = (await call(t, a, "GET", "/sync", undefined, null)).json().records.find((r: { id: string }) => r.id === rec.id);
    expect(mine.attachments).toEqual([expect.objectContaining({ id: p.id, wrappedFileKey: expect.any(String), nonceBase: expect.any(String), size: 26, chunkCount: 1, createdByName: expect.any(String) })]);
    const theirs = (await call(t, us, "GET", "/sync?space=org")).json().records.find((r: { id: string }) => r.id === rec.id);
    expect(theirs.attachments).toHaveLength(1);
    expect(theirs.attachments[0].wrappedFileKey).toBeUndefined();
    expect(JSON.stringify((await call(t, out, "GET", "/sync")).json())).not.toContain(p.id);
  });

  it("chunk 0 is logged once per person and file within 10 minutes; widely shared records are flagged", async () => {
    const a = await createActiveUser(t, { role: "admin" });
    const f = await teamFolder(t, a);
    const rec = await teamRecord(t, a, f);
    const p = await upload(t, a, rec.id, rec.recordKey, bytes(MiB + 1));
    for (let i = 0; i < 3; i++) ok(await getChunk(t, a, rec.id, p.id, 0), 200);
    ok(await getChunk(t, a, rec.id, p.id, 1), 200);
    const evs = await t.prisma.event.findMany({ where: { action: "attachment.download", recordId: rec.id } });
    expect(evs).toHaveLength(1);
    expect(evs[0]).toMatchObject({ actorId: a.id, orgId: a.orgId, meta: { attachmentId: p.id } });
    // Ten or more people can open it: the download counts as a "widely shared" alert.
    const people = await Promise.all(Array.from({ length: 9 }, () => createActiveUser(t)));
    for (const u of people) await addMember(t, a, f, u, "view");
    ok(await getChunk(t, people[0]!, rec.id, p.id, 0), 200);
    expect(await t.prisma.event.findFirstOrThrow({ where: { action: "attachment.download", actorId: people[0]!.id } })).toMatchObject({ meta: { attachmentId: p.id, wide: true } });
    const risk = (await call(t, a, "GET", "/admin/risk")).json();
    expect(risk.alerts.find((x: { action: string }) => x.action === "attachment.download_wide")).toMatchObject({ current: 1 });
    expect(risk.utilisation.storage).toMatchObject({ used: MiB + 1 + 32, quota: 2048 * MiB, files: 1 });
    // No file name, type or hash in any event.
    for (const e of await t.prisma.event.findMany({ where: { recordId: rec.id } })) expect(JSON.stringify(e.meta ?? {})).not.toMatch(/report|pdf|[0-9a-f]{64}/);
  });

  it("the record's activity lists add, download and remove with names", async () => {
    const a = await createActiveUser(t);
    const rec = await privateRecord(t, a);
    const p = await upload(t, a, rec.id, rec.recordKey, bytes(10), { org: null });
    ok(await getChunk(t, a, rec.id, p.id, 0, { org: null }), 200);
    ok(await call(t, a, "DELETE", `/records/${rec.id}/attachments/${p.id}`, undefined, null), 204);
    const acts = (await call(t, a, "GET", `/records/${rec.id}/activity`, undefined, null)).json().events.map((e: { action: string; actor: string }) => `${e.action}:${e.actor}`);
    const name = a.email.split("@")[0];
    expect(acts).toEqual(expect.arrayContaining([`attachment.add:${name}`, `attachment.download:${name}`, `attachment.remove:${name}`]));
  });
});

describe("attachments: one-time links", () => {
  async function linkWithFile(a: U, rec: Rec, files: Awaited<ReturnType<typeof upload>>[], o: { maxOpens?: 1 | 3 | null } = {}) {
    const id = randomUUID();
    const att: LinkAttachment[] = files.map((p) => ({ fileId: p.id, fileKey: b64url.encode(p.fileKey), nonceBase: encodeNonceBase(p.nonceBase), meta: p.meta }));
    const l = await createLink(id, linkSnapshot({ type: "login", title: "x", password: "pw" }, att));
    const r = await call(t, a, "POST", "/links", { id, recordId: rec.id, encPayload: l.encPayload, expiresInHours: 24, maxOpens: o.maxOpens ?? null, attachmentIds: files.map((p) => p.id) });
    return { id, l, r };
  }
  const open = (id: string) => t.app.inject({ method: "POST", url: `/api/v1/public/links/${id}/open`, payload: {}, remoteAddress: `10.250.${Math.floor(Math.random() * 250)}.${Math.floor(Math.random() * 250)}` });
  const pub = (id: string, fid: string, i: number, token: string) => t.app.inject({ method: "GET", url: `/api/v1/public/links/${id}/attachments/${fid}/chunks/${i}`, headers: { authorization: `Bearer ${token}` } });

  it("a link carries chosen files: the recipient opens it, gets a token and downloads identical bytes; revocation stops it", async () => {
    const a = await createActiveUser(t, { role: "admin" });
    const f = await teamFolder(t, a);
    const rec = await teamRecord(t, a, f);
    const data = bytes(MiB + 500);
    const p = await upload(t, a, rec.id, rec.recordKey, data);
    const other = await upload(t, a, rec.id, rec.recordKey, bytes(10));
    const { id, l, r } = await linkWithFile(a, rec, [p], { maxOpens: 1 });
    ok(r, 201);
    expect((await t.prisma.event.findFirstOrThrow({ where: { action: "link.create", recordId: rec.id } })).meta).toEqual({ attachments: 1 });
    expect((await call(t, a, "GET", "/links")).json().links[0]).toMatchObject({ id, files: 1 });
    const o = await open(id);
    ok(o, 200);
    const { encPayload, downloadToken } = o.json();
    expect(downloadToken).toEqual(expect.any(String));
    const body = await openLink(id, encPayload, l.fragment);
    const file = body.attachments![0]!;
    const parts: Uint8Array[] = [];
    await decryptAttachment({ fileId: file.fileId, fileKey: b64url.decode(file.fileKey), nonceBase: b64url.decode(file.nonceBase), meta: file.meta, sink: (x) => { parts.push(x); },
      fetchChunk: async (i) => { const c = await pub(id, file.fileId, i, downloadToken); ok(c, 200); expect(c.headers["content-type"]).toBe("application/octet-stream"); return new Uint8Array(c.rawPayload); } });
    expect(Buffer.concat(parts).equals(Buffer.from(data))).toBe(true);
    // The payload is burned (max one open) but the token still works; a file the link doesn't carry never does.
    expect((await t.prisma.shareLink.findUniqueOrThrow({ where: { id } })).encPayload).toBeNull();
    ok(await pub(id, p.id, 0, downloadToken), 200);
    expect((await pub(id, other.id, 0, downloadToken)).statusCode).toBe(404);
    expect(await t.prisma.event.count({ where: { action: "link.attachment_download", recordId: rec.id } })).toBe(1);
    // Wrong, foreign and expired tokens.
    expect((await pub(id, p.id, 0, "nope")).statusCode).toBe(401);
    const secret = new TextEncoder().encode(t.config.jwtSecret);
    const expired = await new SignJWT({ scope: "link-download" }).setProtectedHeader({ alg: "HS256" }).setSubject(id).setIssuedAt(Math.floor(Date.now() / 1000) - 3600).setExpirationTime(Math.floor(Date.now() / 1000) - 60).sign(secret);
    expect((await pub(id, p.id, 0, expired)).statusCode).toBe(401);
    const access = await new SignJWT({ scope: "access", sid: randomUUID() }).setProtectedHeader({ alg: "HS256" }).setSubject(id).setExpirationTime("5m").sign(secret);
    expect((await pub(id, p.id, 0, access)).statusCode).toBe(401);
    // Revoked: stops at once.
    ok(await call(t, a, "DELETE", `/links/${id}`), 204);
    expect((await pub(id, p.id, 0, downloadToken)).statusCode).toBe(410);
  });

  it("validates files, honours the org policy, and dies with the creator's edit right or the record's trash", async () => {
    const a = await createActiveUser(t, { role: "admin" }), ed = await createActiveUser(t);
    const f = await teamFolder(t, a);
    await addMember(t, a, f, ed, "edit");
    const rec = await teamRecord(t, a, f);
    const rec2 = await teamRecord(t, a, f);
    const p = await upload(t, a, rec.id, rec.recordKey, bytes(100));
    const elsewhere = await upload(t, a, rec2.id, rec2.recordKey, bytes(100));
    expect(err((await linkWithFile(a, rec, [elsewhere])).r)).toBe("bad_attachment");
    const pending = await prepare(rec.id, rec.recordKey, bytes(5));
    ok(await create(t, a, rec.id, pending), 201);
    expect((await call(t, a, "POST", "/links", { id: randomUUID(), recordId: rec.id, encPayload: "v1.abc", expiresInHours: 24, maxOpens: null, attachmentIds: [pending.id] })).statusCode).toBe(400);
    expect((await call(t, a, "POST", "/links", { id: randomUUID(), recordId: rec.id, encPayload: "v1.abc", expiresInHours: 24, maxOpens: null, attachmentIds: [p.id, p.id] })).statusCode).toBe(400);
    // A link without files gets no token.
    const plain = randomUUID();
    ok(await call(t, a, "POST", "/links", { id: plain, recordId: rec.id, encPayload: (await createLink(plain, { title: "x" })).encPayload, expiresInHours: 24, maxOpens: null }), 201);
    expect((await open(plain)).json().downloadToken).toBeUndefined();

    // The editor's link dies when they lose edit.
    const byEd = await linkWithFile(ed, rec, [p]);
    ok(byEd.r, 201);
    const tok = (await open(byEd.id)).json().downloadToken;
    ok(await pub(byEd.id, p.id, 0, tok), 200);
    ok(await call(t, a, "PATCH", `/folders/${f.id}/members/${ed.id}`, { permission: "view" }), 200);
    expect((await pub(byEd.id, p.id, 0, tok)).statusCode).toBe(410);

    // Org policy: no files in links. Switching it off revokes live links that carry files, and new ones are refused.
    const live = await linkWithFile(a, rec, [p]);
    ok(live.r, 201);
    const tok2 = (await open(live.id)).json().downloadToken;
    const pol = (await call(t, a, "GET", "/admin/settings/policies")).json().policies;
    ok(await call(t, a, "PUT", "/admin/settings/policies", { ...pol, links: { ...pol.links, allowAttachments: false } }), 200);
    expect((await pub(live.id, p.id, 0, tok2)).statusCode).toBe(410);
    expect((await t.prisma.shareLink.findUniqueOrThrow({ where: { id: plain } })).revokedAt).toBeNull(); // links without files stay
    expect(err((await linkWithFile(a, rec, [p])).r)).toBe("link_attachments_disabled");
    ok(await call(t, a, "PUT", "/admin/settings/policies", { ...pol, links: { ...pol.links, allowAttachments: true } }), 200);

    // Trashing the record stops its files on links.
    const last = await linkWithFile(a, rec, [p]);
    const tok3 = (await open(last.id)).json().downloadToken;
    ok(await call(t, a, "DELETE", `/records/${rec.id}`), 204);
    expect((await pub(last.id, p.id, 0, tok3)).statusCode).toBe(410);
  });
});

describe("attachments: quotas and limits", () => {
  it("refuses files over the server's limit and the org's lower one, too many files and too much per record", async () => {
    const lim = await appWith({ maxFileMb: 3, maxPerRecord: 2, maxRecordMb: 4 });
    try {
      const a = await createActiveUser(lim, { role: "admin" });
      const rec = await privateRecord(lim, a);
      const big = await prepare(rec.id, rec.recordKey, bytes(3 * MiB + 1));
      const r = await create(lim, a, rec.id, big, { org: null });
      expect(r.statusCode).toBe(413);
      expect(r.json()).toEqual({ error: "file_too_large", max: 3 });
      ok(await create(lim, a, rec.id, await prepare(rec.id, rec.recordKey, bytes(3 * MiB)), { org: null }), 201);
      expect(err(await create(lim, a, rec.id, await prepare(rec.id, rec.recordKey, bytes(2 * MiB)), { org: null }))).toBe("record_too_large");
      ok(await create(lim, a, rec.id, await prepare(rec.id, rec.recordKey, bytes(10)), { org: null }), 201);
      expect(err(await create(lim, a, rec.id, await prepare(rec.id, rec.recordKey, bytes(10)), { org: null }))).toBe("too_many_files");
      // The org may lower the per-file limit (never raise it), or turn new uploads off.
      const f = await teamFolder(lim, a);
      const tr = await teamRecord(lim, a, f);
      const pol = (await call(lim, a, "GET", "/admin/settings/policies")).json().policies;
      ok(await call(lim, a, "PUT", "/admin/settings/policies", { ...pol, attachments: { ...pol.attachments, maxFileMb: 1 } }), 200);
      const lower = await create(lim, a, tr.id, await prepare(tr.id, tr.recordKey, bytes(MiB + 1)));
      expect(lower.json()).toEqual({ error: "file_too_large", max: 1 });
      const p = await upload(lim, a, tr.id, tr.recordKey, bytes(100));
      ok(await call(lim, a, "PUT", "/admin/settings/policies", { ...pol, attachments: { ...pol.attachments, allowed: false } }), 200);
      const off = await create(lim, a, tr.id, await prepare(tr.id, tr.recordKey, bytes(10)));
      expect(off.statusCode).toBe(403);
      expect(err(off)).toBe("attachments_disabled");
      ok(await getChunk(lim, a, tr.id, p.id, 0), 200); // existing files stay downloadable
    } finally { await lim.app.close(); }
  });

  it("org, person and instance quotas; quota refusals are logged; concurrent reservations can't both squeeze in", async () => {
    const lim = await appWith({ orgQuotaMb: 5, userQuotaMb: 3, instanceQuotaMb: 7 });
    try {
      const a = await createActiveUser(lim, { role: "admin" }), b = await createActiveUser(lim);
      const f = await teamFolder(lim, a);
      const [r1, r2, r3] = [await teamRecord(lim, a, f), await teamRecord(lim, a, f), await teamRecord(lim, a, f)];
      // Two 3 MiB reservations at once against a 5 MiB org quota: exactly one wins.
      const [x, y] = await Promise.all([create(lim, a, r1.id, await prepare(r1.id, r1.recordKey, bytes(3 * MiB))), create(lim, a, r2.id, await prepare(r2.id, r2.recordKey, bytes(3 * MiB)))]);
      expect([x.statusCode, y.statusCode].sort()).toEqual([201, 409]);
      const refused = [x, y].find((q) => q.statusCode === 409)!;
      expect(refused.json()).toMatchObject({ error: "quota_exceeded", scope: "org", quota: 5 * MiB });
      expect(await lim.prisma.event.findFirstOrThrow({ where: { action: "attachment.quota_exceeded" } })).toMatchObject({ orgId: a.orgId, actorId: a.id, meta: { scope: "org" } });
      ok(await create(lim, a, r3.id, await prepare(r3.id, r3.recordKey, bytes(MiB))), 201);
      // A private record is charged to its owner.
      const priv = await privateRecord(lim, b);
      ok(await create(lim, b, priv.id, await prepare(priv.id, priv.recordKey, bytes(2 * MiB)), { org: null }), 201);
      expect((await create(lim, b, priv.id, await prepare(priv.id, priv.recordKey, bytes(MiB + 1)), { org: null })).json()).toMatchObject({ error: "quota_exceeded", scope: "user" });
      // Instance: 3 + 1 + 2 MiB reserved of 7.
      const c = await createActiveUser(lim);
      const pc = await privateRecord(lim, c);
      expect((await create(lim, c, pc.id, await prepare(pc.id, pc.recordKey, bytes(MiB + MiB / 2)), { org: null })).json()).toMatchObject({ error: "quota_exceeded", scope: "instance" });
    } finally { await lim.app.close(); }
  });

  it("concurrent reservations of one person's private quota: only one gets through", async () => {
    const lim = await appWith({ userQuotaMb: 3 });
    try {
      const a = await createActiveUser(lim);
      const recs = await Promise.all([privateRecord(lim, a), privateRecord(lim, a), privateRecord(lim, a)]);
      const res = await Promise.all(recs.map(async (r) => create(lim, a, r.id, await prepare(r.id, r.recordKey, bytes(2 * MiB)), { org: null })));
      expect(res.map((r) => r.statusCode).sort()).toEqual([201, 409, 409]);
      expect(await userUsage(lim.prisma, a.id)).toBe(2 * MiB + 32);
    } finally { await lim.app.close(); }
  });

  it("the daily upload cap counts completed uploads (even removed ones) and reservations", async () => {
    const lim = await appWith({ dailyUploadMb: 2 });
    try {
      const a = await createActiveUser(lim);
      const rec = await privateRecord(lim, a);
      const p = await upload(lim, a, rec.id, rec.recordKey, bytes(MiB + MiB / 2), { org: null });
      ok(await call(lim, a, "DELETE", `/records/${rec.id}/attachments/${p.id}`, undefined, null), 204);
      const r = await create(lim, a, rec.id, await prepare(rec.id, rec.recordKey, bytes(MiB)), { org: null });
      expect(r.statusCode).toBe(429);
      expect(err(r)).toBe("daily_upload_limit");
      ok(await create(lim, a, rec.id, await prepare(rec.id, rec.recordKey, bytes(100)), { org: null }), 201);
    } finally { await lim.app.close(); }
  });

  it("moving a record into a team folder re-charges its files to the org, refused (and nothing changed) when the org is full", async () => {
    const lim = await appWith({ orgQuotaMb: 2 });
    try {
      const a = await createActiveUser(lim, { role: "admin" });
      const f = await teamFolder(lim, a);
      const tr = await teamRecord(lim, a, f);
      ok(await create(lim, a, tr.id, await prepare(tr.id, tr.recordKey, bytes(MiB + MiB / 2))), 201);
      const priv = await privateRecord(lim, a);
      await upload(lim, a, priv.id, priv.recordKey, bytes(MiB), { org: null });
      const wrapped = await wrapKey(priv.recordKey, f.folderKey, `record-key:${priv.id}`);
      const refused = await call(lim, a, "PUT", `/records/${priv.id}/folder`, { folderId: f.id, folderWrappedRecordKey: wrapped });
      expect(refused.statusCode).toBe(409);
      expect(refused.json()).toMatchObject({ error: "quota_exceeded", scope: "org" });
      expect((await lim.prisma.record.findUniqueOrThrow({ where: { id: priv.id } })).folderId).toBeNull();
      expect(await userUsage(lim.prisma, a.id)).toBe(MiB + 16);
      // Room made: the move goes through and the bytes move from the person to the org.
      await lim.prisma.attachment.deleteMany({ where: { recordId: tr.id } });
      ok(await call(lim, a, "PUT", `/records/${priv.id}/folder`, { folderId: f.id, folderWrappedRecordKey: wrapped }), 200);
      expect(await userUsage(lim.prisma, a.id)).toBe(0);
      expect(await orgUsage(lim.prisma, a.orgId!)).toBe(MiB + 16);
    } finally { await lim.app.close(); }
  });
});

describe("attachments: rate limits and switches", () => {
  it("chunk downloads are limited per person, not per address", async () => {
    const rl = await appWith({ chunkRatePerMinute: 3 });
    try {
      const a = await createActiveUser(rl), b = await createActiveUser(rl);
      const rec = await privateRecord(rl, a);
      await share(rl, a, rec, b, "view");
      const p = await upload(rl, a, rec.id, rec.recordKey, bytes(10), { org: null });
      const sameIp = "10.9.9.9";
      for (let i = 0; i < 3; i++) ok(await getChunk(rl, a, rec.id, p.id, 0, { org: null, ip: `10.8.8.${i}` }), 200);
      expect((await getChunk(rl, a, rec.id, p.id, 0, { org: null, ip: "10.8.9.1" })).statusCode).toBe(429);
      // Someone else behind the same address is unaffected.
      ok(await getChunk(rl, b, rec.id, p.id, 0, { ip: sameIp }), 200);
    } finally { await rl.app.close(); }
  });

  it("ATTACHMENTS_ENABLED=false: every attachment route answers 404 attachments_disabled", async () => {
    const off = await appWith({ enabled: false });
    try {
      const a = await createActiveUser(off);
      const rec = await privateRecord(off, a);
      for (const [m, u] of [["GET", `/records/${rec.id}/attachments`], ["POST", `/records/${rec.id}/attachments`], ["GET", "/attachments/limits"]] as const) {
        const r = await call(off, a, m, u, m === "POST" ? {} : undefined, null);
        expect(r.statusCode).toBe(404);
        expect(err(r)).toBe("attachments_disabled");
      }
      expect((await call(off, a, "GET", "/sync", undefined, null)).json().records[0].attachments).toEqual([]);
    } finally { await off.app.close(); }
  });

  it("the global 2 MB JSON limit is unchanged; only the chunk route takes raw bytes", async () => {
    const a = await createActiveUser(t);
    const rec = await privateRecord(t, a);
    const r = await attReq(t, a, "PUT", `/records/${rec.id}`, Buffer.alloc(16), { org: null, raw: true });
    expect(r.statusCode).toBe(415);
    const huge = await attReq(t, a, "POST", "/records", JSON.stringify({ x: "a".repeat(2 * 1024 * 1024 + 10) }), { org: null, raw: true, contentType: "application/json" });
    expect(huge.statusCode).toBe(413);
    expect((await call(t, a, "GET", "/attachments/limits", undefined, null)).json()).toEqual({ enabled: true, chunkSize: MiB, maxFileMb: 100, maxPerRecord: 25, maxRecordMb: 250 });
  });
});

describe("admin storage", () => {
  it("org admins see usage, members and the largest records; members can't; instance admins see the instance", async () => {
    const a = await createActiveUser(t, { role: "admin" }), m = await createActiveUser(t);
    const f = await teamFolder(t, a);
    await addMember(t, a, f, m, "edit");
    const rec = await teamRecord(t, a, f);
    await upload(t, a, rec.id, rec.recordKey, bytes(1000));
    const mr = await teamRecord(t, m, f);
    await upload(t, m, mr.id, mr.recordKey, bytes(2000));
    const s = (await call(t, a, "GET", "/admin/storage")).json();
    expect(s).toMatchObject({ used: 1016 + 2016, quota: 2048 * MiB, files: 2, policy: { allowed: true, maxFileMb: null, previews: true, linksAllowAttachments: true } });
    expect(s.members.map((x: { userId: string; bytes: number }) => [x.userId, x.bytes])).toEqual([[m.id, 2016], [a.id, 1016]]);
    expect(s.largest[0]).toMatchObject({ recordId: mr.id, ownerId: m.id, folderId: f.id, files: 1, bytes: 2016 });
    expect((await call(t, m, "GET", "/admin/storage")).statusCode).toBe(403);
    const csvRes = await call(t, a, "GET", "/admin/storage/members.csv");
    expect(csvRes.body.split("\r\n")[0]).toBe("name,email,files,bytes");
    expect((await call(t, a, "GET", "/admin/instance/storage")).statusCode).toBe(403);
    await t.prisma.user.update({ where: { id: a.id }, data: { instanceAdmin: true } });
    const inst = (await call(t, a, "GET", "/admin/instance/storage")).json();
    expect(inst).toMatchObject({ backend: "db", used: 3032, quota: 10240 * MiB, warn: false, rows: { db: 2, s3: 0 }, perOrg: [{ orgId: a.orgId, bytes: 3032 }] });
    const swept = (await call(t, a, "POST", "/admin/instance/storage/sweep")).json();
    expect(swept.gc).toMatchObject({ abandoned: 0, failures: 0 });
  });
});
