import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { randomBytes, randomUUID } from "node:crypto";
import { exportPKCS8, generateKeyPair as joseKeyPair } from "jose";
import { b64url, encryptNewRecord, sealPersonalAgentRecordKey } from "@clane-vault/crypto";
import { makeTestApp, resetDb, createActiveUser, orgHeader } from "./helpers.js";
import { createTestPersonalAgent } from "./agentHelpers.js";
import { startFakeGateway } from "./fakeGateway.js";
import { hashToken, signAgentAccess } from "../src/lib/tokens.js";
import { lockUser } from "../src/lib/orgs.js";
import { sweepExpiredDemos } from "../src/lib/demo.js";

const fake = await startFakeGateway();
const tokenPrivateKeyPem = await exportPKCS8((await joseKeyPair("ES256", { extractable: true })).privateKey);
const agents = { gatewayInternalUrl: fake.url, gatewayPublicUrl: "https://gw.test/mcp", gatewayApiToken: fake.token, tokenPrivateKeyPem, acceptNewGatewayIdentity: false, personalAgents: true };
const t = await makeTestApp({ agents });
const hosted = await makeTestApp({ agents, billingMode: "hosted" });
afterAll(async () => { await Promise.all([t.app.close(), hosted.app.close()]); await fake.close(); });
beforeEach(async () => { await resetDb(t.prisma); fake.setDown(false); fake.dropped.length = 0; });

type U = Awaited<ReturnType<typeof createActiveUser>>;
type PA = Awaited<ReturnType<typeof createTestPersonalAgent>>;
type App = typeof t;
let ipSeq = 0;
const ip = () => `10.245.${(++ipSeq >> 8) & 255}.${ipSeq & 255}`;
const call = (u: U, method: "GET" | "POST" | "DELETE", url: string, payload?: unknown, a: App = t) =>
  a.app.inject({ method, url: `/api/v1${url}`, payload: payload as object, remoteAddress: ip(), headers: { authorization: `Bearer ${u.accessToken}`, ...orgHeader(u) } });
const agentCall = (token: string, method: "GET" | "POST", url: string, payload?: unknown) =>
  t.app.inject({ method, url: `/api/v1${url}`, payload: payload as object, remoteAddress: ip(), headers: { authorization: `Bearer ${token}`, "x-gateway-token": fake.token } });

async function setup() {
  const owner = await createActiveUser(t, { role: "owner" });
  const agent = await createTestPersonalAgent(t, { ownerUserId: owner.id, verified: true });
  const token = (await t.prisma.agentToken.create({ data: { agentId: agent.id, label: "ci", tokenHash: hashToken(randomBytes(16).toString("hex")), createdById: owner.id } })).id;
  const grant = (await t.prisma.agentGrant.create({ data: { agentId: agent.id, clientId: randomUUID(), grantedById: owner.id, refreshHash: "h", expiresAt: new Date(Date.now() + 864e5) } })).id;
  const access = (await signAgentAccess(t.config, { agentId: agent.id, orgId: null, ownerUserId: owner.id, grant: token })).token;
  return { owner, agent, token, grant, access };
}
async function grantedRecord(owner: U, a: PA) {
  const id = randomUUID();
  const enc = await encryptNewRecord(id, { type: "login", title: "Stripe", password: "x" }, owner.keys.userKey);
  expect((await call(owner, "POST", "/records", { id, folderId: null, type: "login", encBody: enc.encBody, wrappedRecordKey: enc.wrappedRecordKey })).statusCode).toBe(201);
  const wrappedRecordKey = await sealPersonalAgentRecordKey(enc.recordKey, { ownerUserId: owner.id, agentId: a.id, recordId: id }, b64url.decode(a.publicKey));
  expect((await call(owner, "POST", `/records/${id}/agent-grants`, { agentId: a.id, wrappedRecordKey })).statusCode).toBe(201);
  return id;
}

describe("DELETE /me/agents/:id", () => {
  it("answers the records to rotate and ends everything; one personal_agent.revoke per organisation; a second call is 409", async () => {
    const { owner, agent, token, grant, access } = await setup();
    const org2 = await t.prisma.organization.create({ data: { name: "Other", slug: `other-${randomUUID().slice(0, 8)}` } });
    await t.prisma.membership.create({ data: { orgId: org2.id, userId: owner.id, role: "member", status: "active", joinedAt: new Date() } });
    const ids = [await grantedRecord(owner, agent), await grantedRecord(owner, agent)];
    expect((await agentCall(access, "GET", "/agent/sync")).statusCode).toBe(200);

    const r = await call(owner, "DELETE", `/me/agents/${agent.id}`);
    expect(r.statusCode).toBe(200);
    const rotate = r.json().rotate;
    expect(rotate.records.map((x: { id: string }) => x.id).sort()).toEqual([...ids].sort());
    expect(rotate.revealed).toEqual([]);
    expect(await t.prisma.recordAccess.count({ where: { holderId: agent.id } })).toBe(0);
    expect((await t.prisma.agentToken.findUniqueOrThrow({ where: { id: token } })).revokedAt).not.toBeNull();
    expect((await t.prisma.agentGrant.findUniqueOrThrow({ where: { id: grant } })).revokedAt).not.toBeNull();
    expect(await t.prisma.agent.findUniqueOrThrow({ where: { userId: agent.id } })).toMatchObject({ wrappedPrivateKey: null, revokedById: owner.id });
    expect((await t.prisma.user.findUniqueOrThrow({ where: { id: agent.id } })).status).toBe("disabled");
    expect(fake.dropped).toContain(agent.id);
    expect((await agentCall(access, "GET", "/agent/sync")).statusCode).toBe(401);
    const lifecycle = await t.prisma.event.findMany({ where: { action: "personal_agent.revoke" }, select: { orgId: true, actorId: true, meta: true, targetUserId: true, recordId: true } });
    expect(lifecycle.map((e) => e.orgId).sort()).toEqual([owner.orgId, org2.id].sort());
    expect(lifecycle.every((e) => e.actorId === owner.id && e.targetUserId === null && e.recordId === null && JSON.stringify(e.meta) === JSON.stringify({ agentId: agent.id }))).toBe(true);

    const again = await call(owner, "DELETE", `/me/agents/${agent.id}`);
    expect([again.statusCode, again.json()]).toEqual([409, { error: "agent_revoked" }]);
    expect(await t.prisma.event.count({ where: { action: "personal_agent.revoke" } })).toBe(2);
  });

  it("succeeds with the gateway down; another person's agent is 404", async () => {
    const { owner, agent } = await setup();
    const other = await createActiveUser(t);
    expect((await call(other, "DELETE", `/me/agents/${agent.id}`)).statusCode).toBe(404);
    fake.setDown(true);
    expect((await call(owner, "DELETE", `/me/agents/${agent.id}`)).statusCode).toBe(200);
  });

  it("waits for the agent's lock, the one a grant takes", async () => {
    const { owner, agent } = await setup();
    let locked!: () => void, release!: () => void;
    const isLocked = new Promise<void>((r) => (locked = r)), held = new Promise<void>((r) => (release = r));
    const holder = t.prisma.$transaction(async (tx) => { await lockUser(tx, agent.id); locked(); await held; }, { timeout: 15_000 });
    await isLocked;
    const revoke = call(owner, "DELETE", `/me/agents/${agent.id}`);
    await new Promise((r) => setTimeout(r, 400));
    expect((await t.prisma.agent.findUniqueOrThrow({ where: { userId: agent.id } })).revokedAt).toBeNull();
    release();
    await holder;
    expect((await revoke).statusCode).toBe(200);
  });

  it("at the allowance, a revoke frees the slot for the next create", async () => {
    const m = await createActiveUser(hosted);
    await hosted.prisma.organization.updateMany({ data: { plan: "team", billingStatus: "active", seatsPaid: 10 } });
    const first = (await call(m, "POST", "/me/agents", { name: "one" }, hosted)).json().id as string;
    expect((await call(m, "POST", "/me/agents", { name: "two" }, hosted)).statusCode).toBe(201);
    expect((await call(m, "POST", "/me/agents", { name: "three" }, hosted)).statusCode).toBe(402);
    expect((await call(m, "DELETE", `/me/agents/${first}`, undefined, hosted)).statusCode).toBe(200);
    expect((await call(m, "POST", "/me/agents", { name: "three" }, hosted)).statusCode).toBe(201);
  });
});

describe("GET /me/agents/:id/activity", () => {
  it("lists the agent's owner-visible events newest first, pages with before; another's agent is 404", async () => {
    const { owner, agent, access } = await setup();
    const rid = await grantedRecord(owner, agent);
    const used = await agentCall(access, "POST", "/agent/events", { events: [{ at: new Date().toISOString(), recordId: rid, action: "use", host: "api.stripe.com", method: "GET" }] });
    expect(used.statusCode).toBe(200);
    // Another agent's rows and an organisation's row naming the agent are not listed.
    const otherAgent = await createTestPersonalAgent(t, { ownerUserId: owner.id, verified: true });
    await t.prisma.event.create({ data: { actorId: otherAgent.id, action: "agent.use" } });
    await t.prisma.event.create({ data: { orgId: owner.orgId, actorId: agent.id, action: "agent.use" } });

    const r = await call(owner, "GET", `/me/agents/${agent.id}/activity`);
    expect(r.statusCode).toBe(200);
    const b = r.json();
    expect(b.events.map((e: { action: string }) => e.action)).toEqual(["agent.use", "agent.item_grant"]);
    expect(b.events[0]).toMatchObject({ recordId: rid, meta: { host: "api.stripe.com", method: "GET" } });
    expect(typeof b.events[0].id).toBe("string");
    expect(typeof b.events[0].at).toBe("string");
    expect(b.nextBefore).toBeNull();

    const p1 = (await call(owner, "GET", `/me/agents/${agent.id}/activity?limit=1`)).json();
    expect(p1.events.map((e: { action: string }) => e.action)).toEqual(["agent.use"]);
    expect(p1.nextBefore).toBe(p1.events[0].id);
    const p2 = (await call(owner, "GET", `/me/agents/${agent.id}/activity?limit=1&before=${p1.nextBefore}`)).json();
    expect([p2.events.map((e: { action: string }) => e.action), p2.nextBefore]).toEqual([["agent.item_grant"], null]);
    expect((await call(owner, "GET", `/me/agents/${agent.id}/activity?limit=101`)).statusCode).toBe(400);

    const other = await createActiveUser(t);
    expect((await call(other, "GET", `/me/agents/${agent.id}/activity`)).statusCode).toBe(404);
  });
});

describe("demo sweep", () => {
  it("an expired demo account's personal agents go with it, and no event names them", async () => {
    const { owner, agent } = await setup();
    await grantedRecord(owner, agent);
    const revoked = await createTestPersonalAgent(t, { ownerUserId: owner.id, revoked: true });
    await t.prisma.event.create({ data: { actorId: agent.id, action: "agent.use" } });
    await t.prisma.user.update({ where: { id: owner.id }, data: { demoExpiresAt: new Date(Date.now() - 1000) } });
    await sweepExpiredDemos(t.prisma);
    const ids = [agent.id, revoked.id];
    expect(await t.prisma.agent.count({ where: { userId: { in: ids } } })).toBe(0);
    expect(await t.prisma.user.count({ where: { id: { in: [...ids, owner.id] } } })).toBe(0);
    expect(await t.prisma.event.count({ where: { OR: [{ actorId: { in: ids } }, { targetUserId: { in: ids } }] } })).toBe(0);
  });
});
