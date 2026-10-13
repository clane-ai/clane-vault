import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { createTeamFolder, encryptNewRecord, sealFolderKeyFor, shareRecordKey, wrapKey } from "@clane-vault/crypto";
import { makeTestApp, resetDb, createActiveUser, createInvite, defaultOrgId, FAST_KDF } from "./helpers.js";
import { escrowKey, keyUp } from "./keys.js";
import { createAccount } from "@clane-vault/crypto";

// Multiple organisations: tenant isolation, invites, and the org lifecycle
// (docs/design/2026-10-07-multi-org-design.md).
const t = await makeTestApp();
afterAll(() => t.app.close());
beforeEach(() => resetDb(t.prisma));

type U = Awaited<ReturnType<typeof createActiveUser>>;
type M = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
const ipOf = (u: U) => `10.${parseInt(u.id.slice(-6, -4), 16)}.${parseInt(u.id.slice(-4, -2), 16)}.${parseInt(u.id.slice(-2), 16)}`;
/** As `u`, in org `org` (default: the org they were created in; null: no X-Org-Id header). */
const call = (u: U, method: M, url: string, payload?: unknown, org?: string | null) => {
  const o = org === undefined ? u.orgId : org;
  return t.app.inject({ method, url: `/api/v1${url}`, payload: payload as object, remoteAddress: ipOf(u),
    headers: { authorization: `Bearer ${u.accessToken}`, ...(o ? { "x-org-id": o } : {}) } });
};
const sync = async (u: U, org?: string | null) => {
  const r = await call(u, "GET", "/sync", undefined, org);
  expect(r.statusCode).toBe(200);
  return r.json() as { folders: { id: string; kind: string }[]; records: { id: string; folderId: string | null }[] };
};
const newOrg = (name: string) => t.prisma.organization.create({ data: { name, slug: `${name.toLowerCase()}-${crypto.randomUUID().slice(0, 8)}` } });
/** Adds an existing account to another org directly (setup shortcut; the invite flow has its own tests). */
const join = (u: U, orgId: string, role: "owner" | "admin" | "member" = "member") =>
  t.prisma.membership.create({ data: { orgId, userId: u.id, role, status: "active", joinedAt: new Date(), ...(role !== "member" ? { adminSince: new Date() } : {}) } });

type Folder = { id: string; folderKey: Uint8Array };
async function teamFolder(owner: U, org?: string): Promise<Folder> {
  const id = crypto.randomUUID();
  const f = await createTeamFolder(id, "Infra", owner.keys.publicKey);
  expect((await call(owner, "POST", "/folders", { id, kind: "team", encName: f.encName, wrappedFolderKey: f.wrappedFolderKey }, org)).statusCode).toBe(201);
  return { id, folderKey: f.folderKey };
}
async function addMember(owner: U, f: Folder, who: U, permission = "edit", org?: string) {
  const r = await call(owner, "POST", `/folders/${f.id}/members`, { userId: who.id, permission, wrappedFolderKey: await sealFolderKeyFor(f.folderKey, f.id, who.keys.publicKey) }, org);
  expect(r.statusCode).toBe(201);
}
async function teamRecord(u: U, f: Folder, org?: string) {
  const id = crypto.randomUUID();
  const enc = await encryptNewRecord(id, { type: "login", title: "Team", password: "team-pw" }, u.keys.userKey);
  const r = await call(u, "POST", "/records", { id, folderId: f.id, type: "login", encBody: enc.encBody,
    wrappedRecordKey: await wrapKey(enc.recordKey, f.folderKey, `record-key:${id}`), ownerWrappedRecordKey: enc.wrappedRecordKey }, org);
  expect(r.statusCode).toBe(201);
  return { id, recordKey: enc.recordKey };
}
async function privateRecord(u: U) {
  const id = crypto.randomUUID();
  const enc = await encryptNewRecord(id, { type: "login", title: "Mine", password: "pw" }, u.keys.userKey);
  expect((await call(u, "POST", "/records", { id, folderId: null, type: "login", encBody: enc.encBody, wrappedRecordKey: enc.wrappedRecordKey }, null)).statusCode).toBe(201);
  return { id, recordKey: enc.recordKey };
}
const linkBody = (recordId: string) => ({ id: crypto.randomUUID(), recordId, encPayload: "v1.AAAA", expiresInHours: 24, maxOpens: null });

/**
 * Two orgs: A (ownerA, memberA) and B (ownerB, memberB), and `dual`, a member of both. Each org has a team folder with a
 * record; dual is in both folders and owns a record in B's folder.
 */
async function world() {
  const A = await newOrg("Alpha"), B = await newOrg("Beta");
  const ownerA = await createActiveUser(t, { role: "owner", orgId: A.id }), memberA = await createActiveUser(t, { orgId: A.id });
  const ownerB = await createActiveUser(t, { role: "owner", orgId: B.id }), memberB = await createActiveUser(t, { orgId: B.id });
  const dual = await createActiveUser(t, { orgId: A.id });
  await join(dual, B.id);
  const FA = await teamFolder(ownerA), FB = await teamFolder(ownerB);
  await addMember(ownerA, FA, memberA); await addMember(ownerA, FA, dual);
  await addMember(ownerB, FB, memberB); await addMember(ownerB, FB, dual);
  const RA = await teamRecord(ownerA, FA), RB = await teamRecord(ownerB, FB);
  const RBdual = await teamRecord(dual, FB, B.id);
  return { A: A.id, B: B.id, ownerA, memberA, ownerB, memberB, dual, FA, FB, RA, RB, RBdual };
}

describe("X-Org-Id", () => {
  it("must name an org the caller is an active member of: anything else is 403, for every org-scoped route", async () => {
    const w = await world();
    const bogus = crypto.randomUUID();
    for (const org of [w.B, bogus, "not-a-uuid", w.B.toUpperCase()]) {
      for (const [method, url] of [["GET", "/sync"], ["GET", "/users"], ["GET", "/admin/people"], ["GET", "/pending-members"], ["GET", "/org"], ["GET", "/links"],
        ["GET", `/records/${w.RA.id}/activity`], ["POST", "/admin/invites"]] as const) {
        const r = await call(w.memberA, method, url, method === "POST" ? { email: "x@y.io" } : undefined, org);
        expect(r.statusCode, `${org} ${url}`).toBe(403);
        expect(r.json(), `${org} ${url}`).toEqual({ error: "org_forbidden" });
      }
    }
    // Required where the route only makes sense in an org.
    for (const url of ["/users", "/admin/people", "/pending-members", "/org"]) expect((await call(w.memberA, "GET", url, undefined, null)).json(), url).toEqual({ error: "org_required" });
    // Another user's org, an invited membership and a disabled one don't count either.
    await t.prisma.membership.create({ data: { orgId: w.B, userId: w.memberA.id, status: "invited" } });
    expect((await call(w.memberA, "GET", "/sync", undefined, w.B)).statusCode).toBe(403);
    await t.prisma.membership.update({ where: { orgId_userId: { orgId: w.B, userId: w.memberA.id } }, data: { status: "disabled" } });
    expect((await call(w.memberA, "GET", "/sync", undefined, w.B)).statusCode).toBe(403);
  });
});

describe("tenant isolation", () => {
  it("sync shows only the active org's team folders and records, plus private ones everywhere", async () => {
    const w = await world();
    const mine = await privateRecord(w.dual);
    const inA = await sync(w.dual, w.A), inB = await sync(w.dual, w.B), none = await sync(w.dual, null);
    expect(inA.folders.map((f) => f.id)).toEqual([w.FA.id]);
    expect(inA.records.map((r) => r.id).sort()).toEqual([w.RA.id, mine.id].sort());
    expect(inB.folders.map((f) => f.id)).toEqual([w.FB.id]);
    expect(inB.records.map((r) => r.id).sort()).toEqual([w.RB.id, w.RBdual.id, mine.id].sort());
    // No org: private only, even the record dual owns in B's folder stays out.
    expect(none.folders).toEqual([]);
    expect(none.records.map((r) => r.id)).toEqual([mine.id]);
    // Someone only in A never sees B's folder.
    expect((await sync(w.memberA)).folders.map((f) => f.id)).toEqual([w.FA.id]);
  });

  it("spaces: ?space=org gives the org only (no personal items), no header gives Personal only", async () => {
    const w = await world();
    const mine = await privateRecord(w.dual);
    const folder = crypto.randomUUID();
    expect((await call(w.dual, "POST", "/folders", { id: folder, encName: "v1.AAAA" }, null)).statusCode).toBe(201);
    // ownerA shares a private record with dual in A; dual shares one of theirs with memberA in A.
    const fromA = await privateRecord(w.ownerA);
    expect((await call(w.ownerA, "POST", `/records/${fromA.id}/shares`, { userId: w.dual.id, permission: "view", sealedRecordKey: await shareRecordKey(fromA.recordKey, fromA.id, w.dual.keys.publicKey) })).statusCode).toBe(201);
    const sharedByDual = await privateRecord(w.dual);
    expect((await call(w.dual, "POST", `/records/${sharedByDual.id}/shares`, { userId: w.memberA.id, permission: "view", sealedRecordKey: await shareRecordKey(sharedByDual.recordKey, sharedByDual.id, w.memberA.keys.publicKey) }, w.A)).statusCode).toBe(201);
    const space = async (org: string) => {
      const r = await call(w.dual, "GET", "/sync?space=org", undefined, org);
      expect(r.statusCode).toBe(200);
      return r.json() as { folders: { id: string; kind: string }[]; records: { id: string; sharedWith?: { userId: string }[] }[]; privateLocked?: boolean };
    };
    const inA = await space(w.A), inB = await space(w.B), personal = await sync(w.dual, null);
    expect(inA.folders.map((f) => f.id)).toEqual([w.FA.id]);
    expect(inA.records.map((r) => r.id).sort()).toEqual([w.RA.id, fromA.id, sharedByDual.id].sort());
    expect(inA.records.find((r) => r.id === sharedByDual.id)!.sharedWith!.map((x) => x.userId)).toEqual([w.memberA.id]);
    expect(inB.folders.map((f) => f.id)).toEqual([w.FB.id]);
    expect(inB.records.map((r) => r.id).sort()).toEqual([w.RB.id, w.RBdual.id].sort());
    // Personal: private folders and own records only (no team folders, no shares from others); shares are named by org.
    expect(personal.folders.map((f) => f.id)).toEqual([folder]);
    expect(personal.records.map((r) => r.id).sort()).toEqual([mine.id, sharedByDual.id].sort());
    expect((personal.records as { id: string; sharedIn?: string[] }[]).find((r) => r.id === sharedByDual.id)!.sharedIn).toEqual([w.A]);
    expect((personal.records as { id: string; sharedIn?: string[] }[]).find((r) => r.id === mine.id)!.sharedIn).toBeUndefined();
    // The org's space needs the org; another org's id is refused as always.
    expect((await call(w.dual, "GET", "/sync?space=org", undefined, null)).json()).toEqual({ error: "org_required" });
    expect((await call(w.memberA, "GET", "/sync?space=org", undefined, w.B)).json()).toEqual({ error: "org_forbidden" });
    expect((await call(w.dual, "GET", "/sync?space=all", undefined, w.A)).statusCode).toBe(400);
    // Links: the org's only with ?space=org; personal ones without a header.
    expect((await call(w.dual, "POST", "/links", linkBody(mine.id), null)).statusCode).toBe(201);
    expect((await call(w.dual, "POST", "/links", linkBody(w.RBdual.id), w.B)).statusCode).toBe(201);
    expect((await call(w.dual, "GET", "/links?space=org", undefined, w.B)).json().links.map((l: { recordId: string }) => l.recordId)).toEqual([w.RBdual.id]);
    expect((await call(w.dual, "GET", "/links?space=org", undefined, w.A)).json().links).toEqual([]);
    expect((await call(w.dual, "GET", "/links", undefined, null)).json().links.map((l: { recordId: string }) => l.recordId)).toEqual([mine.id]);
    expect((await call(w.dual, "GET", "/links?space=org", undefined, null)).json()).toEqual({ error: "org_required" });
  });

  it("a member of A can't read or change B's folders, records, members, links or activity through any route", async () => {
    const w = await world();
    const link = await call(w.ownerB, "POST", "/links", linkBody(w.RB.id));
    expect(link.statusCode).toBe(201);
    const linkId = link.json().id;
    const f = await createTeamFolder(w.FB.id, "x", w.memberA.keys.publicKey);
    const enc = await encryptNewRecord(crypto.randomUUID(), { type: "login", title: "x", password: "x" }, w.memberA.keys.userKey);
    const attempts: [M, string, unknown?][] = [
      ["PUT", `/records/${w.RB.id}`, { encBody: enc.encBody, revision: 1 }],
      ["DELETE", `/records/${w.RB.id}`], ["POST", `/records/${w.RB.id}/restore`], ["DELETE", `/records/${w.RB.id}/purge`],
      ["PUT", `/records/${w.RB.id}/folder`, { folderId: null, ownerWrappedRecordKey: enc.wrappedRecordKey }],
      ["POST", `/records/${w.RB.id}/shares`, { userId: w.memberA.id, permission: "view", sealedRecordKey: "s1.x" }],
      ["PATCH", `/records/${w.RB.id}/shares/${w.memberB.id}`, { permission: "view" }], ["DELETE", `/records/${w.RB.id}/shares/${w.memberB.id}`],
      ["GET", `/records/${w.RB.id}/activity`], ["GET", `/records/${w.RB.id}/links`], ["POST", "/links", linkBody(w.RB.id)], ["DELETE", `/links/${linkId}`],
      ["PATCH", `/folders/${w.FB.id}`, { encName: f.encName }], ["DELETE", `/folders/${w.FB.id}`],
      ["POST", `/folders/${w.FB.id}/members`, { userId: w.memberA.id, permission: "edit", wrappedFolderKey: f.wrappedFolderKey }],
      ["PATCH", `/folders/${w.FB.id}/members/${w.memberB.id}`, { permission: "use" }], ["DELETE", `/folders/${w.FB.id}/members/${w.memberB.id}`],
      ["POST", `/folders/${w.FB.id}/pending-members`, { email: "p@x.io", permission: "view" }],
    ];
    for (const [method, url, body] of attempts) {
      const r = await call(w.memberA, method, url, body);
      expect([403, 404], `${method} ${url}: ${r.statusCode}`).toContain(r.statusCode);
    }
    // Writing into B's folder from A fails too, one record or a batch.
    expect((await call(w.memberA, "POST", "/records", { id: crypto.randomUUID(), folderId: w.FB.id, type: "login", encBody: enc.encBody, wrappedRecordKey: enc.wrappedRecordKey, ownerWrappedRecordKey: enc.wrappedRecordKey })).statusCode).toBe(404);
    expect((await call(w.memberA, "POST", "/records/batch", { records: [{ id: crypto.randomUUID(), folderId: w.FB.id, type: "login", encBody: enc.encBody, wrappedRecordKey: enc.wrappedRecordKey, ownerWrappedRecordKey: enc.wrappedRecordKey }] })).statusCode).toBe(404);
    // Nothing changed in B.
    expect(await t.prisma.folderMember.count({ where: { folderId: w.FB.id } })).toBe(3);
    expect((await t.prisma.shareLink.findUniqueOrThrow({ where: { id: linkId } })).revokedAt).toBeNull();
    expect((await t.prisma.record.findUniqueOrThrow({ where: { id: w.RB.id } })).deletedAt).toBeNull();
  });

  it("someone in both orgs reaches each org's records only from that org, even ones they own", async () => {
    const w = await world();
    // In A, B's folder and dual's own record in it are out of reach.
    for (const id of [w.RB.id, w.RBdual.id]) {
      expect((await call(w.dual, "GET", `/records/${id}/activity`, undefined, w.A)).statusCode).toBe(404);
      expect((await call(w.dual, "POST", "/links", linkBody(id), w.A)).statusCode).toBe(404);
    }
    expect((await call(w.dual, "DELETE", `/records/${w.RBdual.id}`, undefined, w.A)).statusCode).toBe(404);
    expect((await call(w.dual, "DELETE", `/folders/${w.FB.id}/members/${w.dual.id}`, undefined, w.A)).statusCode).toBe(404);
    // In B they work.
    expect((await call(w.dual, "GET", `/records/${w.RBdual.id}/activity`, undefined, w.B)).statusCode).toBe(200);
    expect((await call(w.dual, "POST", "/links", linkBody(w.RBdual.id), w.B)).statusCode).toBe(201);
    // Their B link is listed in B, not in A.
    expect((await call(w.dual, "GET", "/links", undefined, w.A)).json().links).toEqual([]);
    expect((await call(w.dual, "GET", "/links", undefined, w.B)).json().links).toHaveLength(1);
  });

  it("the share and member pickers list only active members of the active org; shares and folder members must be in it", async () => {
    const w = await world();
    const ids = (await call(w.ownerA, "GET", "/users")).json().users.map((u: { id: string }) => u.id).sort();
    expect(ids).toEqual([w.ownerA.id, w.memberA.id, w.dual.id].sort());
    const p = await privateRecord(w.ownerA);
    const shareTo = async (who: U, org?: string | null) => call(w.ownerA, "POST", `/records/${p.id}/shares`, { userId: who.id, permission: "view", sealedRecordKey: await shareRecordKey(p.recordKey, p.id, who.keys.publicKey) }, org);
    expect((await shareTo(w.memberB)).json()).toEqual({ error: "user_not_active" });
    expect((await shareTo(w.memberA, null)).json()).toEqual({ error: "org_required" });
    expect((await shareTo(w.dual)).statusCode).toBe(201);
    // The share lives in A: dual sees it there, not in B.
    expect((await sync(w.dual, w.A)).records.map((r) => r.id)).toContain(p.id);
    expect((await sync(w.dual, w.B)).records.map((r) => r.id)).not.toContain(p.id);
    expect((await call(w.dual, "GET", `/records/${p.id}/activity`, undefined, w.B)).statusCode).toBe(404);
    // Folder members too.
    const r = await call(w.ownerA, "POST", `/folders/${w.FA.id}/members`, { userId: w.memberB.id, permission: "view", wrappedFolderKey: await sealFolderKeyFor(w.FA.folderKey, w.FA.id, w.memberB.keys.publicKey) });
    expect(r.json()).toEqual({ error: "user_not_active" });
  });

  it("an admin of A has no admin power in B or over B's people", async () => {
    const w = await world();
    // Not a member of B: the header alone is refused.
    expect((await call(w.ownerA, "GET", "/admin/people", undefined, w.B)).statusCode).toBe(403);
    // A plain member of B: still no admin power there.
    await join(w.ownerA, w.B, "member");
    for (const [method, url] of [["GET", "/admin/people"], ["POST", `/admin/users/${w.memberB.id}/disable`], ["DELETE", `/admin/members/${w.memberB.id}`],
      ["GET", "/admin/settings"], ["GET", "/admin/recovery-requests"]] as const)
      expect((await call(w.ownerA, method, url, undefined, w.B)).json(), url).toEqual({ error: "forbidden" });
    // From A, B's people aren't targets.
    for (const [method, url] of [["POST", `/admin/users/${w.memberB.id}/disable`], ["POST", `/admin/users/${w.memberB.id}/reset-2fa`], ["DELETE", `/admin/members/${w.memberB.id}`], ["PATCH", `/admin/members/${w.memberB.id}`]] as const)
      expect((await call(w.ownerA, method, url, method === "PATCH" ? { role: "admin" } : undefined)).statusCode, url).toBe(404);
    // A's admin managing B's folder from A: not found.
    expect((await call(w.ownerA, "DELETE", `/folders/${w.FB.id}/members/${w.memberB.id}`)).statusCode).toBe(404);
    // People and invites: only A's.
    await call(w.ownerB, "POST", "/admin/invites", { email: "b-invitee@x.io" });
    const people = (await call(w.ownerA, "GET", "/admin/people")).json();
    expect(people.users.map((u: { id: string }) => u.id).sort()).toEqual([w.ownerA.id, w.memberA.id, w.dual.id].sort());
    expect(people.invites).toEqual([]);
    const bInvite = await t.prisma.invite.findFirstOrThrow({ where: { email: "b-invitee@x.io" } });
    expect((await call(w.ownerA, "DELETE", `/admin/invites/${bInvite.id}`)).statusCode).toBe(404);
    // A 2FA reset changes the whole account: A's admin can't reset someone who is also in B.
    expect((await call(w.ownerA, "POST", `/admin/users/${w.dual.id}/reset-2fa`)).json()).toEqual({ error: "other_orgs" });
    expect((await call(w.ownerA, "POST", `/admin/users/${w.memberA.id}/reset-2fa`)).statusCode).toBe(200);
  });

  it("disabled in A but active in B: A is closed to them, B works as before", async () => {
    const w = await world();
    expect((await call(w.ownerA, "POST", `/admin/users/${w.dual.id}/disable`)).statusCode).toBe(200);
    expect((await call(w.dual, "GET", "/sync", undefined, w.A)).statusCode).toBe(403);
    expect((await call(w.dual, "GET", `/records/${w.RA.id}/activity`, undefined, w.A)).statusCode).toBe(403);
    const inB = await sync(w.dual, w.B);
    expect(inB.folders.map((f) => f.id)).toEqual([w.FB.id]);
    expect((await call(w.dual, "GET", "/users", undefined, w.B)).statusCode).toBe(200);
    const orgs = (await call(w.dual, "GET", "/me/orgs", undefined, null)).json().orgs;
    expect(orgs.map((o: { id: string }) => o.id)).toEqual([w.B]);
    // A's people list shows them as disabled; enabling restores A with the folder membership intact.
    expect((await call(w.ownerA, "POST", `/admin/users/${w.dual.id}/enable`)).statusCode).toBe(200);
    expect((await sync(w.dual, w.A)).folders.map((f) => f.id)).toEqual([w.FA.id]);
  });

  it("escrows and recovery requests stay in their org; someone in two orgs is recoverable in each, separately", async () => {
    const w = await world();
    for (const o of [w.A, w.B]) await t.prisma.organization.update({ where: { id: o }, data: { adminRecoveryEnabled: true, adminRecoveryChangedAt: new Date(Date.now() - 1000) } });
    // A member of A can't reach B's keys or acknowledge B's policy.
    expect((await call(w.memberA, "GET", "/membership-key", undefined, w.B)).statusCode).toBe(403);
    expect((await call(w.memberA, "POST", "/me/admin-recovery-ack", { orgId: w.B }, null)).statusCode).toBe(403);
    // Every admin has unlocked once (membership keys); dual escrows in each org, to that org's admins only.
    await keyUp(t, w.ownerA, w.A); await keyUp(t, w.ownerB, w.B);
    expect(await escrowKey(t, w.dual, w.A)).toBe(1);
    expect(await escrowKey(t, w.dual, w.B)).toBe(1);
    const esc = await t.prisma.membershipEscrow.findMany({ where: { userId: w.dual.id }, orderBy: { orgId: "asc" } });
    expect(Object.fromEntries(esc.map((e) => [e.orgId, e.adminId]))).toEqual({ [w.A]: w.ownerA.id, [w.B]: w.ownerB.id });
    // Two different keys: A's admins hold nothing that opens B.
    expect(esc[0]!.memberPublicKey).not.toBe(esc[1]!.memberPublicKey);
    const sec = (await call(w.dual, "GET", "/me/security", undefined, null)).json();
    expect(sec.orgs.map((o: { orgId: string; recoverable: boolean }) => [o.orgId, o.recoverable]).sort()).toEqual([[w.A, true], [w.B, true]].sort());
    // "Ask an admin": one request per org.
    const ask = (email: string) => t.app.inject({ method: "POST", url: "/api/v1/auth/recovery/admin/request", payload: { email }, remoteAddress: `10.201.${Math.floor(Math.random() * 250)}.1` });
    expect((await ask(w.dual.email)).statusCode).toBe(202);
    const reqs = await t.prisma.recoveryRequest.findMany({ where: { userId: w.dual.id } });
    expect(reqs.map((r) => r.orgId).sort()).toEqual([w.A, w.B].sort());
    const inB = reqs.find((r) => r.orgId === w.B)!;
    expect((await call(w.ownerA, "GET", "/admin/recovery-requests")).json().requests.map((r: { id: string }) => r.id)).toEqual([reqs.find((r) => r.orgId === w.A)!.id]);
    for (const url of [`/admin/recovery-requests/${inB.id}/deny`, `/admin/recovery-requests/${inB.id}/escrow`])
      expect((await call(w.ownerA, "POST", url, { code: "000000" })).statusCode, url).toBeGreaterThanOrEqual(404);
    expect((await t.prisma.recoveryRequest.findUniqueOrThrow({ where: { id: inB.id } })).status).toBe("pending");
    // memberB is only in B and hasn't escrowed: no request.
    expect((await ask(w.memberB.email)).statusCode).toBe(202);
    expect(await t.prisma.recoveryRequest.count({ where: { userId: w.memberB.id } })).toBe(0);
  });

  it("activity events carry the org they happened in", async () => {
    const w = await world();
    const ev = await t.prisma.event.findFirstOrThrow({ where: { recordId: w.RB.id, action: "record.create" } });
    expect(ev.orgId).toBe(w.B);
    expect((await call(w.memberA, "GET", `/records/${w.RB.id}/activity`)).statusCode).toBe(404);
  });
});

describe("removal and leaving (offboarding)", () => {
  it("removing someone from A ends their A folder memberships, A shares and A links; records they owned pass to the folder owner; B is untouched", async () => {
    const w = await world();
    const RAdual = await teamRecord(w.dual, w.FA);
    const p = await privateRecord(w.ownerA);
    expect((await call(w.ownerA, "POST", `/records/${p.id}/shares`, { userId: w.dual.id, permission: "edit", sealedRecordKey: await shareRecordKey(p.recordKey, p.id, w.dual.keys.publicKey) })).statusCode).toBe(201);
    const l = (await call(w.dual, "POST", "/links", linkBody(RAdual.id))).json();
    expect((await call(w.ownerA, "DELETE", `/admin/members/${w.dual.id}`)).statusCode).toBe(204);
    expect(await t.prisma.membership.count({ where: { orgId: w.A, userId: w.dual.id } })).toBe(0);
    expect(await t.prisma.folderMember.count({ where: { folderId: w.FA.id, userId: w.dual.id } })).toBe(0);
    expect(await t.prisma.recordAccess.count({ where: { recordId: p.id, holderId: w.dual.id } })).toBe(0);
    expect((await t.prisma.shareLink.findUniqueOrThrow({ where: { id: l.id } })).revokedAt).not.toBeNull();
    expect((await t.prisma.record.findUniqueOrThrow({ where: { id: RAdual.id } })).ownerId).toBe(w.ownerA.id);
    expect((await call(w.dual, "GET", "/sync", undefined, w.A)).statusCode).toBe(403);
    expect((await sync(w.dual, w.B)).folders.map((f) => f.id)).toEqual([w.FB.id]);
  });

  it("a leaving folder owner hands the folder to an org admin in it, or trashes a folder nobody else can open", async () => {
    const w = await world();
    const mine = await teamFolder(w.dual, w.A);
    const r = await teamRecord(w.dual, mine, w.A);
    const shared = await teamFolder(w.dual, w.A);
    await addMember(w.dual, shared, w.memberA, "view", w.A);
    await addMember(w.dual, shared, w.ownerA, "view", w.A);
    expect((await call(w.dual, "POST", "/org/leave", undefined, w.A)).statusCode).toBe(204);
    expect((await t.prisma.folder.findUniqueOrThrow({ where: { id: mine.id } })).deletedAt).not.toBeNull();
    expect((await t.prisma.record.findUniqueOrThrow({ where: { id: r.id } })).deletedAt).not.toBeNull();
    const s = await t.prisma.folder.findUniqueOrThrow({ where: { id: shared.id }, include: { members: true } });
    expect(s.deletedAt).toBeNull();
    expect(s.ownerId).toBe(w.ownerA.id);
    expect(s.members.find((m) => m.userId === w.ownerA.id)?.permission).toBe("owner");
    expect(s.members.some((m) => m.userId === w.dual.id)).toBe(false);
  });
});

describe("invitations", () => {
  it("inviting an existing account creates an invitation they accept in the app (no new account); declining removes it", async () => {
    const w = await world();
    const res = await call(w.ownerB, "POST", "/admin/invites", { email: w.memberA.email.toUpperCase(), role: "admin" });
    expect(res.statusCode).toBe(201);
    // The same answer as for an address without an account (no account oracle), and no new account.
    const fresh = await call(w.ownerB, "POST", "/admin/invites", { email: "nobody-yet@x.io", role: "admin" });
    const shape = (r: { json: () => Record<string, unknown> }) => Object.keys(r.json()).sort();
    expect(shape(res)).toEqual(shape(fresh));
    expect(res.json()).toMatchObject({ invited: true, role: "admin" });
    expect(JSON.stringify(res.json())).not.toContain(w.memberA.id);
    expect(await t.prisma.user.count({ where: { email: w.memberA.email } })).toBe(1);
    // Inviting again, or inviting a member, answers the same way and changes nothing.
    for (const email of [w.memberA.email, w.memberB.email]) {
      const again = await call(w.ownerB, "POST", "/admin/invites", { email });
      expect(again.statusCode, email).toBe(201);
      expect(shape(again), email).toEqual(shape(fresh));
    }
    // People shows only the email until it's accepted (not the account's name).
    const people = (await call(w.ownerB, "GET", "/admin/people")).json();
    expect(people.invites.map((i: { email: string }) => i.email).sort()).toEqual([w.memberA.email, "nobody-yet@x.io"].sort());
    expect(JSON.stringify(people.invites)).not.toContain(w.memberA.id);
    expect(people.invitedMembers).toBeUndefined();
    // Before accepting: no access to B.
    expect((await call(w.memberA, "GET", "/sync", undefined, w.B)).statusCode).toBe(403);
    const mine = (await call(w.memberA, "GET", "/me/orgs", undefined, null)).json();
    expect(mine.invitations).toEqual([expect.objectContaining({ orgId: w.B, orgName: "Beta", role: "admin", invitedBy: expect.any(String) })]);
    const acc = await call(w.memberA, "POST", `/me/invitations/${w.B}/accept`, undefined, null);
    expect(acc.statusCode).toBe(200);
    expect(acc.json().orgs.map((o: { id: string; role: string }) => [o.id, o.role])).toEqual([[w.A, "member"], [w.B, "admin"]]);
    expect((await t.prisma.membership.findUniqueOrThrow({ where: { orgId_userId: { orgId: w.B, userId: w.memberA.id } } })).adminSince).not.toBeNull();
    expect((await call(w.memberA, "GET", "/admin/people", undefined, w.B)).statusCode).toBe(200);
    expect((await call(w.memberA, "POST", `/me/invitations/${w.B}/accept`, undefined, null)).statusCode).toBe(404);
    // Decline: gone, and the org can't invite that address again for a day.
    await call(w.ownerA, "POST", "/admin/invites", { email: w.memberB.email });
    expect((await call(w.memberB, "POST", `/me/invitations/${w.A}/decline`, undefined, null)).statusCode).toBe(204);
    expect(await t.prisma.membership.count({ where: { orgId: w.A, userId: w.memberB.id } })).toBe(0);
    expect((await call(w.ownerA, "POST", "/admin/invites", { email: w.memberB.email })).json()).toEqual({ error: "invite_cooldown" });
    // An admin can cancel an invitation before it's accepted (by the id People shows); the address cools down too.
    await call(w.ownerA, "POST", "/admin/invites", { email: w.ownerB.email });
    const inv = (await call(w.ownerA, "GET", "/admin/people")).json().invites.find((i: { email: string }) => i.email === w.ownerB.email);
    expect((await call(w.ownerA, "DELETE", `/admin/invites/${inv.id}`)).statusCode).toBe(204);
    expect((await call(w.ownerB, "GET", "/me/orgs", undefined, null)).json().invitations).toEqual([]);
    expect((await call(w.ownerA, "POST", "/admin/invites", { email: w.ownerB.email })).json()).toEqual({ error: "invite_cooldown" });
  });

  it("a new person invited by two orgs registers once and gets the second as an invitation", async () => {
    const A = await newOrg("Alpha"), B = await newOrg("Beta");
    const tokenA = await createInvite(t.prisma, "new@x.io", "member", A.id);
    await createInvite(t.prisma, "new@x.io", "admin", B.id);
    const acct = await createAccount("pw for new", FAST_KDF);
    const reg = await t.app.inject({ method: "POST", url: "/api/v1/auth/register", payload: { inviteToken: tokenA, name: "New", authKey: acct.authKey, material: acct.material } });
    expect(reg.statusCode).toBe(201);
    const u = await t.prisma.user.findUniqueOrThrow({ where: { email: "new@x.io" }, include: { memberships: true } });
    expect(u.memberships.map((m) => [m.orgId, m.status, m.role]).sort()).toEqual([[A.id, "active", "member"], [B.id, "invited", "admin"]].sort());
    expect(await t.prisma.invite.count({ where: { email: "new@x.io", acceptedAt: null } })).toBe(0);
  });
});

describe("org lifecycle", () => {
  it("anyone can create an org (unless disabled) and owns it", async () => {
    const u = await createActiveUser(t);
    const res = await call(u, "POST", "/orgs", { name: "  Side project " }, null);
    expect(res.statusCode).toBe(201);
    const org = res.json();
    expect(org).toMatchObject({ name: "Side project", role: "owner", isDefault: false });
    expect((await call(u, "GET", "/org", undefined, org.id)).json()).toMatchObject({ id: org.id, name: "Side project", myRole: "owner", memberCount: 1, teamFolderCount: 0, isDefault: false });
    expect((await call(u, "GET", "/me/orgs", undefined, null)).json().orgs.map((o: { id: string }) => o.id)).toEqual([u.orgId, org.id]);
    t.config.allowOrgCreation = false;
    try { expect((await call(u, "POST", "/orgs", { name: "Another" }, null)).json()).toEqual({ error: "org_creation_disabled" }); }
    finally { t.config.allowOrgCreation = true; }
  });

  it("owners and admins rename; only the owner transfers and deletes; the default org can't be deleted", async () => {
    const owner = await createActiveUser(t);
    const org = (await call(owner, "POST", "/orgs", { name: "Gamma" }, null)).json();
    const admin = await createActiveUser(t, { role: "admin", orgId: org.id }), member = await createActiveUser(t, { orgId: org.id });
    expect((await call(member, "PATCH", "/org", { name: "Mine now" })).statusCode).toBe(403);
    expect((await call(admin, "PATCH", "/org", { name: "Gamma A" })).json()).toEqual({ ok: true, name: "Gamma A" });
    expect((await call(owner, "PATCH", "/org", { name: "Gamma 2" }, org.id)).json()).toEqual({ ok: true, name: "Gamma 2" });
    expect((await t.prisma.event.findMany({ where: { orgId: org.id, action: "org.rename" }, orderBy: { at: "asc" }, select: { meta: true } })).map((e) => e.meta))
      .toEqual([{ from: "Gamma", to: "Gamma A" }, { from: "Gamma A", to: "Gamma 2" }]);
    expect((await call(admin, "POST", "/org/transfer", { userId: admin.id })).statusCode).toBe(403);
    expect((await call(owner, "POST", "/org/leave", undefined, org.id)).json()).toEqual({ error: "owner_must_transfer" });
    expect((await call(owner, "POST", "/org/transfer", { userId: member.id }, org.id)).statusCode).toBe(200);
    const roles = await t.prisma.membership.findMany({ where: { orgId: org.id }, select: { userId: true, role: true, adminSince: true } });
    expect(roles.find((m) => m.userId === member.id)).toMatchObject({ role: "owner", adminSince: expect.any(Date) });
    expect(roles.find((m) => m.userId === owner.id)?.role).toBe("admin");
    // The new owner deletes it: name check, then team folders need an explicit trash.
    const f = await teamFolder(member);
    const r = await teamRecord(member, f);
    expect((await call(member, "DELETE", "/org", { confirmName: "nope" })).json()).toEqual({ error: "confirm_name" });
    expect((await call(member, "DELETE", "/org", { confirmName: "Gamma 2" })).json()).toEqual({ error: "org_has_team_folders", teamFolders: 1 });
    expect((await call(member, "DELETE", "/org", { confirmName: "Gamma 2", trashTeamFolders: true })).statusCode).toBe(204);
    expect(await t.prisma.organization.count({ where: { id: org.id } })).toBe(0);
    expect(await t.prisma.membership.count({ where: { orgId: org.id } })).toBe(0);
    // Its team folders and their records are gone for good (nothing is left without an org).
    expect(await t.prisma.record.count({ where: { id: r.id } })).toBe(0);
    expect(await t.prisma.folder.count({ where: { id: f.id } })).toBe(0);
    expect(await t.prisma.folderMember.count({ where: { folderId: f.id } })).toBe(0);
    expect((await call(member, "GET", "/sync", undefined, org.id)).statusCode).toBe(403);
    // The owner of the default org can't delete it.
    const d = await createActiveUser(t, { role: "owner" });
    expect((await call(d, "DELETE", "/org", { confirmName: "Test org" })).json()).toEqual({ error: "default_org" });
    expect(await defaultOrgId(t.prisma)).toBe(d.orgId);
  });

  it("a member leaves: their membership and access go, their account stays", async () => {
    const w = await world();
    expect((await call(w.memberA, "POST", "/org/leave")).statusCode).toBe(204);
    expect((await call(w.memberA, "GET", "/sync")).statusCode).toBe(403);
    expect((await call(w.memberA, "GET", "/sync", undefined, null)).statusCode).toBe(200);
    expect(await t.prisma.folderMember.count({ where: { userId: w.memberA.id } })).toBe(0);
  });
});
