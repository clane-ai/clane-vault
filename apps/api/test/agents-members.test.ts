import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { createTeamFolder, encryptNewRecord } from "@clane-vault/crypto";
import { DEFAULT_ATTACHMENTS } from "../src/config.js";
import { makeTestApp, resetDb, createActiveUser, orgHeader } from "./helpers.js";
import { createTestAgent } from "./agentHelpers.js";
import { seatsUsed } from "../src/lib/seats.js";
import { attachmentConfig, checkQuota } from "../src/lib/attachments/quota.js";
import { recomputeFolder } from "../src/lib/groups.js";

// Agents are members with Use only, and never people: not seats, no pooled storage, not on People, risk or health.
const t = await makeTestApp();
afterAll(() => t.app.close());
beforeEach(() => resetDb(t.prisma));

type U = Awaited<ReturnType<typeof createActiveUser>>;
type App = { app: typeof t.app };
let ipSeq = 0;
const call = (u: U, method: "GET" | "POST" | "PATCH" | "DELETE", url: string, payload?: unknown, a: App = t) =>
  a.app.inject({ method, url: `/api/v1${url}`, payload: payload as object, remoteAddress: `10.241.${(++ipSeq >> 8) & 255}.${ipSeq & 255}`, headers: { authorization: `Bearer ${u.accessToken}`, ...orgHeader(u) } });

async function setup() {
  const owner = await createActiveUser(t, { role: "owner" }), member = await createActiveUser(t);
  const A = await createTestAgent(t, { orgId: owner.orgId, createdById: owner.id, verified: true, name: "Billing bot" });
  const B = await createTestAgent(t, { orgId: owner.orgId, createdById: owner.id, name: "Unverified bot" });
  return { owner, member, A, B };
}
async function teamFolder(owner: U) {
  const id = crypto.randomUUID();
  const f = await createTeamFolder(id, "Infra", owner.keys.publicKey);
  expect((await call(owner, "POST", "/folders", { id, kind: "team", encName: f.encName, wrappedFolderKey: f.wrappedFolderKey })).statusCode).toBe(201);
  return id;
}
const sealTo = (agent: { publicKey: string }) => ({ wrappedFolderKey: "s1.a.b.c", sealedTo: agent.publicKey });
async function privateRecord(u: U) {
  const id = crypto.randomUUID();
  const enc = await encryptNewRecord(id, { type: "login", title: "Stripe", password: "x" }, u.keys.userKey);
  expect((await call(u, "POST", "/records", { id, folderId: null, type: "login", encBody: enc.encBody, wrappedRecordKey: enc.wrappedRecordKey })).statusCode).toBe(201);
  return id;
}
const permOf = async (folderId: string, userId: string) => (await t.prisma.folderMember.findUnique({ where: { folderId_userId: { folderId, userId } } }))?.permission;

describe("agents in member lists", () => {
  it("GET /users lists a verified agent with kind agent, never an unverified one; pending group access marks it and caps it to use", async () => {
    const { owner, member, A, B } = await setup();
    const users = (await call(owner, "GET", "/users")).json().users as { id: string; kind: string }[];
    expect(users.find((u) => u.id === A.id)).toMatchObject({ kind: "agent" });
    expect(users.find((u) => u.id === member.id)).toMatchObject({ kind: "person" });
    expect(users.some((u) => u.id === B.id)).toBe(false);

    const f = await teamFolder(owner);
    const g = (await call(owner, "POST", "/admin/groups", { name: "Bots" })).json().id as string;
    expect((await call(owner, "POST", `/admin/groups/${g}/members`, { userIds: [A.id, member.id] })).statusCode).toBe(201);
    await t.prisma.groupMember.create({ data: { groupId: g, userId: B.id } }); // an invited agent can't be added through the route
    expect((await call(owner, "POST", `/folders/${f}/groups`, { groupId: g, permission: "edit", wraps: [] })).statusCode).toBe(201);
    const pending = (await call(owner, "GET", "/group-access/pending")).json().pending as { userId: string; kind: string; permission: string }[];
    expect(pending.find((p) => p.userId === A.id)).toMatchObject({ kind: "agent", permission: "use" });
    expect(pending.find((p) => p.userId === member.id)).toMatchObject({ kind: "person", permission: "edit" });
    expect(pending.some((p) => p.userId === B.id)).toBe(false);
  });

  it("GET /sync folder members carry kind", async () => {
    const { owner, A } = await setup();
    const f = await teamFolder(owner);
    expect((await call(owner, "POST", `/folders/${f}/members`, { userId: A.id, permission: "use", ...sealTo(A) })).statusCode).toBe(201);
    const folder = (await call(owner, "GET", "/sync")).json().folders.find((x: { id: string }) => x.id === f);
    expect(folder.members.map((m: { userId: string; kind: string }) => [m.userId, m.kind]).sort()).toEqual([[owner.id, "person"], [A.id, "agent"]].sort());
  });
});

describe("agents hold use only", () => {
  it("folder members: an unverified agent is not active; more than use is 400 agent_use_only", async () => {
    const { owner, A, B } = await setup();
    const f = await teamFolder(owner);
    const add = (who: { id: string; publicKey: string }, permission: string) => call(owner, "POST", `/folders/${f}/members`, { userId: who.id, permission, ...sealTo(who) });
    expect([(await add(B, "use")).statusCode, (await add(B, "use")).json().error]).toEqual([400, "user_not_active"]);
    for (const p of ["edit", "view"]) {
      const r = await add(A, p);
      expect([r.statusCode, r.json().error]).toEqual([400, "agent_use_only"]);
    }
    expect((await add(A, "use")).statusCode).toBe(201);
    const r = await call(owner, "PATCH", `/folders/${f}/members/${A.id}`, { permission: "view" });
    expect([r.statusCode, r.json().error]).toEqual([400, "agent_use_only"]);
    expect(await permOf(f, A.id)).toBe("use");
    expect((await call(owner, "PATCH", `/folders/${f}/members/${A.id}`, { permission: "use" })).statusCode).toBe(200);
  });

  it("record shares: more than use is 400 agent_use_only, use is 201; PATCH to view is refused", async () => {
    const { owner, A } = await setup();
    const id = await privateRecord(owner);
    const share = (permission: string) => call(owner, "POST", `/records/${id}/shares`, { userId: A.id, permission, sealedRecordKey: "s1.a.b.c", sealedTo: A.publicKey });
    const r = await share("view");
    expect([r.statusCode, r.json().error]).toEqual([400, "agent_use_only"]);
    expect((await share("use")).statusCode).toBe(201);
    const p = await call(owner, "PATCH", `/records/${id}/shares/${A.id}`, { permission: "view" });
    expect([p.statusCode, p.json().error]).toEqual([400, "agent_use_only"]);
    expect((await t.prisma.recordAccess.findFirstOrThrow({ where: { recordId: id, holderId: A.id } })).permission).toBe("use");
  });

  it("group grants are capped silently: approval gives use, and a recompute after raising the group keeps use", async () => {
    const { owner, A } = await setup();
    const f = await teamFolder(owner);
    const g = (await call(owner, "POST", "/admin/groups", { name: "Bots" })).json().id as string;
    expect((await call(owner, "POST", `/admin/groups/${g}/members`, { userIds: [A.id] })).statusCode).toBe(201);
    expect((await call(owner, "POST", `/folders/${f}/groups`, { groupId: g, permission: "edit", wraps: [] })).statusCode).toBe(201);
    const r = await call(owner, "POST", `/folders/${f}/group-access`, { wraps: [{ userId: A.id, ...sealTo(A) }] });
    expect(r.json()).toMatchObject({ added: [A.id] });
    expect(await permOf(f, A.id)).toBe("use");
    // Lowering then raising the group (each recomputes), and a recompute of a row someone set higher: still use.
    expect((await call(owner, "PATCH", `/folders/${f}/groups/${g}`, { permission: "view" })).statusCode).toBe(200);
    expect((await call(owner, "PATCH", `/folders/${f}/groups/${g}`, { permission: "edit" })).statusCode).toBe(200);
    expect(await permOf(f, A.id)).toBe("use");
    await t.prisma.folderMember.update({ where: { folderId_userId: { folderId: f, userId: A.id } }, data: { permission: "view" } });
    await t.prisma.$transaction((tx) => recomputeFolder(tx, f, [A.id]));
    expect(await permOf(f, A.id)).toBe("use");
  });
});

describe("agents are not people", () => {
  it("People, risk and password health list people only; GET /org memberCount counts people", async () => {
    const { owner, A, B } = await setup();
    const people = (await call(owner, "GET", "/admin/people")).json();
    expect(JSON.stringify(people)).not.toContain(A.id);
    expect(JSON.stringify(people)).not.toContain(B.id);
    expect(JSON.stringify(people)).not.toContain("agents.invalid");
    const risk = await call(owner, "GET", "/admin/risk/members");
    expect(risk.statusCode).toBe(200);
    expect(risk.body).not.toContain(A.id);
    expect(risk.body).not.toContain("agents.invalid");
    const health = await call(owner, "GET", "/admin/health");
    expect(health.statusCode).toBe(200);
    expect(health.json().members).toHaveLength(2);
    expect(health.body).not.toContain(A.id);
    expect((await call(owner, "GET", "/org")).json().memberCount).toBe(2);
  });

  it("People-page routes and ownership transfer refuse an agent with 409 is_agent; its membership is unchanged", async () => {
    const { owner, A } = await setup();
    const before = await t.prisma.membership.findUniqueOrThrow({ where: { orgId_userId: { orgId: owner.orgId, userId: A.id } } });
    const tries: [string, string, unknown?][] = [
      ["POST", `/admin/users/${A.id}/disable`], ["POST", `/admin/users/${A.id}/enable`], ["POST", `/admin/users/${A.id}/reset-2fa`],
      ["GET", `/admin/members/${A.id}`], ["DELETE", `/admin/members/${A.id}`], ["PATCH", `/admin/members/${A.id}`, { role: "admin" }],
      ["POST", "/org/transfer", { userId: A.id }],
    ];
    for (const [m, url, body] of tries) {
      const r = await call(owner, m as "GET", url, body);
      expect([url, r.statusCode, r.json().error]).toEqual([url, 409, "is_agent"]);
    }
    expect(await t.prisma.membership.findUniqueOrThrow({ where: { orgId_userId: { orgId: owner.orgId, userId: A.id } } })).toEqual(before);
    expect((await t.prisma.user.findUniqueOrThrow({ where: { id: A.id } })).status).toBe("active");
  });

  it("POST /auth/login with an agent's address is 401 invalid_credentials", async () => {
    const { A } = await setup();
    const email = (await t.prisma.user.findUniqueOrThrow({ where: { id: A.id } })).email;
    const r = await t.app.inject({ method: "POST", url: "/api/v1/auth/login", remoteAddress: "10.242.0.1", payload: { email, authKey: "x".repeat(44) } });
    expect([r.statusCode, r.json().error]).toEqual([401, "invalid_credentials"]);
  });
});

describe("agents take no seat and add no storage (hosted)", () => {
  it("seatsUsed and the pooled org quota are the same before and after creating agents", async () => {
    const h = await makeTestApp({ billingMode: "hosted", attachments: { ...DEFAULT_ATTACHMENTS, orgQuotaMb: 1_000_000, instanceQuotaMb: 10_000_000 } });
    try {
      const owner = await createActiveUser(h, { role: "owner" });
      const cfg = attachmentConfig(h.config), charge = { kind: "org" as const, orgId: owner.orgId };
      // 3 GiB is over one seat's 2 GiB: the refusal carries the pooled quota.
      const quota = async () => (await checkQuota(h.prisma, cfg, charge, 3 * 1024 ** 3))?.quota;
      const [seats0, quota0] = [await seatsUsed(h.prisma, owner.orgId), await quota()];
      expect([seats0, quota0]).toEqual([1, 2 * 1024 ** 3]);
      await createTestAgent(h, { orgId: owner.orgId, createdById: owner.id, verified: true });
      await createTestAgent(h, { orgId: owner.orgId, createdById: owner.id });
      expect([await seatsUsed(h.prisma, owner.orgId), await quota()]).toEqual([seats0, quota0]);
    } finally { await h.app.close(); }
  });
});
