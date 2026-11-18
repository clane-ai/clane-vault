import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import { createTeamFolder, encryptNewRecord } from "@clane-vault/crypto";
import { makeTestApp, resetDb, createActiveUser, orgHeader } from "./helpers.js";
import { createTestPersonalAgent } from "./agentHelpers.js";
import { startFakeGateway } from "./fakeGateway.js";
import { liveAgents, personalAttestationOk } from "../src/lib/agents.js";

const fake = await startFakeGateway();
const pem = generateKeyPairSync("ec", { namedCurve: "prime256v1" }).privateKey.export({ type: "pkcs8", format: "pem" }) as string;
const agents = (personalAgents: boolean) => ({ gatewayInternalUrl: fake.url, gatewayPublicUrl: "https://gw.test/mcp", gatewayApiToken: fake.token, tokenPrivateKeyPem: pem, acceptNewGatewayIdentity: false, personalAgents });
const t = await makeTestApp({ agents: agents(true) });
const hosted = await makeTestApp({ agents: agents(true), billingMode: "hosted" });
const off = await makeTestApp({ agents: agents(false) });
afterAll(async () => { await Promise.all([t.app.close(), hosted.app.close(), off.app.close()]); await fake.close(); });
beforeEach(async () => { await resetDb(t.prisma); fake.setDown(false); fake.setSignWrongAgent(false); fake.created.length = 0; });

type U = Awaited<ReturnType<typeof createActiveUser>>;
type App = typeof t;
let ipSeq = 0;
const call = (u: U, method: "GET" | "POST" | "PATCH" | "DELETE", url: string, payload?: unknown, a: App = t) =>
  a.app.inject({ method, url: `/api/v1${url}`, payload: payload as object, remoteAddress: `10.243.${(++ipSeq >> 8) & 255}.${ipSeq & 255}`, headers: { authorization: `Bearer ${u.accessToken}`, ...orgHeader(u) } });
const pk = async (u: U) => (await t.prisma.user.findUniqueOrThrow({ where: { id: u.id } })).publicKey;

describe("POST /me/agents", () => {
  it("a plain member enrols: rows, no membership, the owner's key sent to the gateway, attestation verifies", async () => {
    const m = await createActiveUser(t, { role: "member" });
    const r = await call(m, "POST", "/me/agents", { name: "My bot" });
    expect(r.statusCode).toBe(201);
    const b = r.json();
    expect(b.owner).toEqual({ userId: m.id, publicKey: await pk(m) });
    expect(personalAttestationOk(b.attestation, { ownerUserId: m.id, ownerPublicKey: await pk(m), agentId: b.id, publicKey: b.publicKey }, b.gateway)).toBe(true);
    expect(fake.created).toEqual([{ agentId: b.id, ownerUserId: m.id, ownerPublicKey: await pk(m) }]);
    expect(await t.prisma.user.findUniqueOrThrow({ where: { id: b.id } })).toMatchObject({ kind: "agent", name: "My bot" });
    expect(await t.prisma.agent.findUniqueOrThrow({ where: { userId: b.id } })).toMatchObject({ orgId: null, ownerUserId: m.id, createdById: m.id });
    expect(await t.prisma.membership.count({ where: { userId: b.id } })).toBe(0);
    expect(await t.prisma.membershipKey.count({ where: { userId: b.id } })).toBe(0);
  });

  it("spec 8: invisible to people lists and unusable as a member or a share target", async () => {
    const owner = await createActiveUser(t, { role: "owner" });
    const a = await createTestPersonalAgent(t, { ownerUserId: owner.id, verified: true });
    const has = (j: unknown) => JSON.stringify(j).includes(a.id);
    expect(has((await call(owner, "GET", "/users")).json())).toBe(false);
    expect(has((await call(owner, "GET", "/admin/people")).json())).toBe(false);
    expect(has((await call(owner, "GET", "/group-access/pending")).json())).toBe(false);
    const fid = crypto.randomUUID();
    const f = await createTeamFolder(fid, "Infra", owner.keys.publicKey);
    expect((await call(owner, "POST", "/folders", { id: fid, kind: "team", encName: f.encName, wrappedFolderKey: f.wrappedFolderKey })).statusCode).toBe(201);
    const rf = await call(owner, "POST", `/folders/${fid}/members`, { userId: a.id, permission: "view", wrappedFolderKey: "s1.a.b.c", sealedTo: a.publicKey });
    expect([rf.statusCode, rf.json()]).toEqual([400, { error: "user_not_active" }]);
    const rid = crypto.randomUUID();
    const enc = await encryptNewRecord(rid, { type: "login", title: "Stripe", password: "x" }, owner.keys.userKey);
    expect((await call(owner, "POST", "/records", { id: rid, folderId: null, type: "login", encBody: enc.encBody, wrappedRecordKey: enc.wrappedRecordKey })).statusCode).toBe(201);
    const rs = await call(owner, "POST", `/records/${rid}/shares`, { userId: a.id, permission: "view", sealedRecordKey: "s1.a.b.c", sealedTo: a.publicKey });
    expect([rs.statusCode, rs.json()]).toEqual([400, { error: "user_not_active" }]);
  });

  it("another person's agent is not listed; verify, PATCH and DELETE are 404", async () => {
    const [a, b] = [await createActiveUser(t), await createActiveUser(t)];
    const ag = await createTestPersonalAgent(t, { ownerUserId: a.id });
    expect((await call(b, "GET", "/me/agents")).json().agents).toEqual([]);
    expect((await call(a, "GET", "/me/agents")).json().agents.map((x: { id: string }) => x.id)).toEqual([ag.id]);
    expect((await call(b, "PATCH", `/me/agents/${ag.id}`, { name: "x" })).statusCode).toBe(404);
    expect((await call(b, "POST", `/me/agents/${ag.id}/verify`, { publicKey: ag.publicKey })).statusCode).toBe(404);
    expect((await call(b, "POST", `/me/agents/${ag.id}/tokens`, { label: "x" })).statusCode).toBe(404);
    expect((await call(b, "DELETE", `/me/agents/${ag.id}/tokens/${ag.id}`)).statusCode).toBe(404);
    expect((await call(b, "DELETE", `/me/agents/${ag.id}/grants/${ag.id}`)).statusCode).toBe(404);
  });

  it("Hosted Team: a third agent is 402 agent_limit and the organisation's agent count stays 0", async () => {
    const m = await createActiveUser(hosted);
    await hosted.prisma.organization.updateMany({ data: { plan: "team", billingStatus: "active", seatsPaid: 10 } });
    expect((await call(m, "POST", "/me/agents", { name: "one" }, hosted)).statusCode).toBe(201);
    expect((await call(m, "POST", "/me/agents", { name: "two" }, hosted)).statusCode).toBe(201);
    const r = await call(m, "POST", "/me/agents", { name: "three" }, hosted);
    expect([r.statusCode, r.json()]).toEqual([402, { error: "agent_limit", used: 2, allowed: 2 }]);
    expect(await liveAgents(hosted.prisma, m.orgId)).toBe(0);
    expect((await call(m, "GET", "/me/agents", undefined, hosted)).json().allowance).toEqual({ used: 2, allowed: 2 });
  });

  it("a policy block in one of two organisations: 403 personal_agents_disabled naming it", async () => {
    const m = await createActiveUser(t);
    const o2 = await t.prisma.organization.create({ data: { name: "B", slug: "b-org", policies: { personalAgents: { allowed: false } } } });
    await t.prisma.membership.create({ data: { orgId: o2.id, userId: m.id, role: "member", status: "active" } });
    const r = await call(m, "POST", "/me/agents", { name: "x" });
    expect([r.statusCode, r.json()]).toEqual([403, { error: "personal_agents_disabled", orgId: o2.id }]);
    expect(fake.created).toEqual([]);
    expect((await call(m, "GET", "/me/agents")).json().rules).toMatchObject({ allowed: false, blockedByOrgId: o2.id });
  });

  it("a policy switched off after the pre-check but before the transaction still refuses, and creates nothing", async () => {
    const m = await createActiveUser(t);
    const orig = t.app.gateway.createPersonalAgentKey.bind(t.app.gateway);
    t.app.gateway.createPersonalAgentKey = async (ids) => {
      await t.prisma.organization.updateMany({ data: { policies: { personalAgents: { allowed: false } } } });
      return orig(ids);
    };
    try {
      const r = await call(m, "POST", "/me/agents", { name: "x" });
      expect([r.statusCode, r.json()]).toEqual([403, { error: "personal_agents_disabled", orgId: m.orgId }]);
      expect(await t.prisma.agent.count()).toBe(0);
    } finally { t.app.gateway.createPersonalAgentKey = orig; }
  });

  it("a session confined to one organisation: 403 totp_step_up_required on every route", async () => {
    const m = await createActiveUser(t);
    await t.prisma.session.updateMany({ where: { userId: m.id }, data: { totpSkippedForOrg: m.orgId } });
    const id = "00000000-0000-4000-8000-000000000000";
    for (const [method, url, body] of [["POST", "/me/agents", { name: "x" }], ["GET", "/me/agents", undefined], ["GET", "/me/agents/gateway", undefined],
      ["POST", `/me/agents/${id}/verify`, { publicKey: "x" }], ["PATCH", `/me/agents/${id}`, {}], ["POST", `/me/agents/${id}/tokens`, { label: "x" }],
      ["DELETE", `/me/agents/${id}/tokens/${id}`, undefined], ["DELETE", `/me/agents/${id}/grants/${id}`, undefined]] as const) {
      const r = await call(m, method, url, body);
      expect([url, r.statusCode, r.json()]).toEqual([url, 403, { error: "totp_step_up_required" }]);
    }
  });

  it("the gateway attesting the wrong agent id: 503 and no rows", async () => {
    const m = await createActiveUser(t);
    fake.setSignWrongAgent(true);
    const r = await call(m, "POST", "/me/agents", { name: "x" });
    expect([r.statusCode, r.json()]).toEqual([503, { error: "gateway_unavailable" }]);
    expect(await t.prisma.agent.count()).toBe(0);
    expect(await t.prisma.user.count({ where: { kind: "agent" } })).toBe(0);
  });
});

describe("verify, rename, tokens, events", () => {
  it("verify needs the agent's key; lifecycle events go to every organisation with exactly the four keys", async () => {
    const m = await createActiveUser(t);
    const o2 = await t.prisma.organization.create({ data: { name: "B", slug: "b-org" } });
    await t.prisma.membership.create({ data: { orgId: o2.id, userId: m.id, role: "member", status: "active" } });
    const b = (await call(m, "POST", "/me/agents", { name: "x" })).json();
    const ev = await t.prisma.event.findMany({ where: { action: "personal_agent.create" } });
    expect(ev.map((e) => e.orgId).sort()).toEqual([m.orgId, o2.id].sort());
    for (const e of ev) expect(e).toMatchObject({ actorId: m.id, targetUserId: null, recordId: null, ip: null, meta: { agentId: b.id } });
    expect((await call(m, "POST", `/me/agents/${b.id}/verify`, { publicKey: await pk(m) })).json()).toEqual({ error: "stale_key" });
    expect((await call(m, "POST", `/me/agents/${b.id}/verify`, { publicKey: b.publicKey })).json()).toEqual({ ok: true });
    expect((await t.prisma.agent.findUniqueOrThrow({ where: { userId: b.id } })).verifiedById).toBe(m.id);
    expect(await t.prisma.event.count({ where: { action: "personal_agent.verify" } })).toBe(2);

    expect((await call(m, "PATCH", `/me/agents/${b.id}`, { name: "renamed" })).json()).toEqual({ ok: true });
    expect(await t.prisma.event.findFirstOrThrow({ where: { action: "agent.update" } })).toMatchObject({ orgId: null, actorId: m.id, targetUserId: b.id, meta: { fields: ["name"] } });
    const tk = await call(m, "POST", `/me/agents/${b.id}/tokens`, { label: "ci" });
    expect(tk.statusCode).toBe(201);
    expect(tk.json().token).toEqual(expect.any(String));
    expect(await t.prisma.event.count({ where: { action: "personal_agent.connect" } })).toBe(2);
    const l = (await call(m, "GET", "/me/agents")).json();
    expect(l.agents[0]).toMatchObject({ id: b.id, name: "renamed", status: "active", items: 0, owner: { userId: m.id, publicKey: await pk(m) }, attestation: b.attestation });
    expect(l.agents[0].tokens[0]).not.toHaveProperty("tokenHash");
    expect(l.revealEmail).toBe(true);
    expect((await call(m, "DELETE", `/me/agents/${b.id}/tokens/${tk.json().id}`)).statusCode).toBe(204);
    expect((await call(m, "GET", "/me/agents/gateway")).json()).toMatchObject({ url: "https://gw.test/mcp", identityKeyId: fake.identity.keyId });
  });
});

describe("GET /admin/agents/personal-count", () => {
  it("counts live personal agents of active members; non-admins get 403", async () => {
    const admin = await createActiveUser(t, { role: "admin" });
    const m = await createActiveUser(t, { role: "member" });
    await createTestPersonalAgent(t, { ownerUserId: admin.id });
    await createTestPersonalAgent(t, { ownerUserId: m.id });
    await createTestPersonalAgent(t, { ownerUserId: m.id });
    await createTestPersonalAgent(t, { ownerUserId: m.id, revoked: true });
    await createActiveUser(t, { role: "member" }); // a member with no agent is not counted
    const r = (await call(admin, "GET", "/admin/agents/personal-count")).json();
    expect(r).toMatchObject({ agents: 3, members: 2 });
    expect(r.perMember.sort((a: { count: number }, b: { count: number }) => a.count - b.count)).toEqual([{ userId: admin.id, count: 1 }, { userId: m.id, count: 2 }]);
    expect((await call(m, "GET", "/admin/agents/personal-count")).statusCode).toBe(403);
  });
});

describe("PERSONAL_AGENTS=off", () => {
  it("/me/agents and personal-count are 404 while /admin/agents works", async () => {
    const o = await createActiveUser(off, { role: "owner" });
    expect((await call(o, "GET", "/me/agents", undefined, off)).statusCode).toBe(404);
    expect((await call(o, "GET", "/admin/agents/personal-count", undefined, off)).statusCode).toBe(404);
    expect((await call(o, "GET", "/admin/agents", undefined, off)).statusCode).toBe(200);
  });
});
