import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { randomBytes, randomUUID } from "node:crypto";
import { SignJWT, decodeJwt, exportPKCS8, generateKeyPair as joseKeyPair } from "jose";
import { b64url, createTeamFolder, encryptNewRecord, openPersonalAgentRecordKey, sealPersonalAgentRecordKey, wrapKey } from "@clane-vault/crypto";
import { makeTestApp, resetDb, createActiveUser, orgHeader } from "./helpers.js";
import { createTestAgent, createTestPersonalAgent } from "./agentHelpers.js";
import { startFakeGateway } from "./fakeGateway.js";
import { agentSigningKey, hashToken, signAgentAccess } from "../src/lib/tokens.js";
import { offboard } from "../src/lib/orgs.js";

const fake = await startFakeGateway();
const tokenPrivateKeyPem = await exportPKCS8((await joseKeyPair("ES256", { extractable: true })).privateKey);
const agents = { gatewayInternalUrl: fake.url, gatewayPublicUrl: "https://gw.test/mcp", gatewayApiToken: fake.token, tokenPrivateKeyPem, acceptNewGatewayIdentity: false, personalAgents: true };
const t = await makeTestApp({ agents });
afterAll(async () => { await t.app.close(); await fake.close(); });
beforeEach(async () => { await resetDb(t.prisma); fake.dropped.length = 0; });

type U = Awaited<ReturnType<typeof createActiveUser>>;
type PA = Awaited<ReturnType<typeof createTestPersonalAgent>>;
let ipSeq = 0;
const ip = () => `10.244.${(++ipSeq >> 8) & 255}.${ipSeq & 255}`;
/** As a person; `org: false` leaves X-Org-Id out (the Personal space). */
const call = (u: U, method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE", url: string, payload?: unknown, o: { org?: boolean } = {}) =>
  t.app.inject({ method, url: `/api/v1${url}`, payload: payload as object, remoteAddress: ip(), headers: { authorization: `Bearer ${u.accessToken}`, ...(o.org === false ? {} : orgHeader(u)) } });
/** As the gateway calls the API for an agent. */
const agentCall = (token: string, method: "GET" | "POST", url: string, payload?: unknown) =>
  t.app.inject({ method, url: `/api/v1${url}`, payload: payload as object, remoteAddress: ip(), headers: { authorization: `Bearer ${token}`, "x-gateway-token": fake.token } });
const exchange = (token: string) => t.app.inject({ method: "POST", url: "/api/v1/oauth/token", remoteAddress: ip(),
  payload: new URLSearchParams({ grant_type: "urn:clane:agent-token", token }).toString(), headers: { "content-type": "application/x-www-form-urlencoded", "x-gateway-token": fake.token } });

async function tokenRow(agentId: string, createdById: string) {
  return (await t.prisma.agentToken.create({ data: { agentId, label: "ci", tokenHash: hashToken(randomBytes(16).toString("hex")), createdById } })).id;
}
/** An owner, their verified personal agent and an access token for it. */
async function setup(o: { verified?: boolean } = {}) {
  const owner = await createActiveUser(t, { role: "owner" });
  const agent = await createTestPersonalAgent(t, { ownerUserId: owner.id, verified: o.verified ?? true });
  const grant = await tokenRow(agent.id, owner.id);
  const access = (await signAgentAccess(t.config, { agentId: agent.id, orgId: null, ownerUserId: owner.id, grant })).token;
  return { owner, agent, grant, access };
}
async function record(owner: U, folder?: { id: string; folderKey: Uint8Array }) {
  const id = randomUUID();
  const enc = await encryptNewRecord(id, { type: "login", title: "Stripe", password: "x" }, owner.keys.userKey);
  const body = folder
    ? { id, folderId: folder.id, type: "login", encBody: enc.encBody, wrappedRecordKey: await wrapKey(enc.recordKey, folder.folderKey, `record-key:${id}`), ownerWrappedRecordKey: enc.wrappedRecordKey }
    : { id, folderId: null, type: "login", encBody: enc.encBody, wrappedRecordKey: enc.wrappedRecordKey };
  expect((await call(owner, "POST", "/records", body)).statusCode).toBe(201);
  return { id, recordKey: enc.recordKey, encBody: enc.encBody };
}
async function teamFolder(owner: U) {
  const id = randomUUID();
  const f = await createTeamFolder(id, "Infra", owner.keys.publicKey);
  expect((await call(owner, "POST", "/folders", { id, kind: "team", encName: f.encName, wrappedFolderKey: f.wrappedFolderKey })).statusCode).toBe(201);
  return { id, folderKey: f.folderKey };
}
const seal = (r: { id: string; recordKey: Uint8Array }, ownerUserId: string, a: PA) =>
  sealPersonalAgentRecordKey(r.recordKey, { ownerUserId, agentId: a.id, recordId: r.id }, b64url.decode(a.publicKey));
const grantItem = (owner: U, r: { id: string; recordKey: Uint8Array }, a: PA, o: { wrapped?: string } = {}) =>
  seal(r, owner.id, a).then((wrappedRecordKey) => call(owner, "POST", `/records/${r.id}/agent-grants`, { agentId: a.id, wrappedRecordKey: o.wrapped ?? wrappedRecordKey }));
const sync = async (access: string) => { const r = await agentCall(access, "GET", "/agent/sync"); expect(r.statusCode).toBe(200); return r.json(); };

describe("owner-scoped access tokens", () => {
  it("a personal agent's exchanged token carries owner and no org; an organisation agent's is unchanged", async () => {
    const owner = await createActiveUser(t, { role: "owner" });
    const pa = await createTestPersonalAgent(t, { ownerUserId: owner.id, verified: true });
    const mine = await call(owner, "POST", `/me/agents/${pa.id}/tokens`, { label: "CI" });
    expect(mine.statusCode).toBe(201);
    const p = decodeJwt((await exchange(mine.json().token)).json().access_token);
    expect(p).toMatchObject({ scope: "agent", sub: pa.id, owner: owner.id });
    expect(p).not.toHaveProperty("org");

    const oa = await createTestAgent(t, { orgId: owner.orgId!, createdById: owner.id, verified: true });
    const theirs = await call(owner, "POST", `/admin/agents/${oa.id}/tokens`, { label: "CI" });
    const o = decodeJwt((await exchange(theirs.json().token)).json().access_token);
    expect(o).toMatchObject({ scope: "agent", sub: oa.id, org: owner.orgId });
    expect(o).not.toHaveProperty("owner");
  });

  it("a hand-signed token with both claims, or neither, is 401; an owner token can't act as an org agent and vice versa", async () => {
    const { owner, agent, grant, access } = await setup();
    expect((await agentCall(access, "GET", "/agent/sync")).statusCode).toBe(200);
    const { priv, jwk } = await agentSigningKey(t.config.agents!);
    const hand = (sub: string, claims: object, g = grant) => new SignJWT({ scope: "agent", grant: g, ...claims }).setProtectedHeader({ alg: "ES256", kid: jwk.kid })
      .setSubject(sub).setAudience(agents.gatewayPublicUrl).setIssuer(t.config.publicUrl).setJti(randomUUID()).setIssuedAt().setExpirationTime("15m").sign(priv);
    expect((await agentCall(await hand(agent.id, { org: owner.orgId, owner: owner.id }), "GET", "/agent/sync")).statusCode).toBe(401);
    expect((await agentCall(await hand(agent.id, {}), "GET", "/agent/sync")).statusCode).toBe(401);
    // An org claim naming the personal agent: no organisation agent matches.
    expect((await agentCall(await hand(agent.id, { org: owner.orgId }), "GET", "/agent/sync")).statusCode).toBe(401);
    const oa = await createTestAgent(t, { orgId: owner.orgId!, createdById: owner.id, verified: true });
    const og = await tokenRow(oa.id, owner.id);
    expect((await agentCall(await hand(oa.id, { org: owner.orgId }, og), "GET", "/agent/sync")).statusCode).toBe(200);
    expect((await agentCall(await hand(oa.id, { owner: owner.id }, og), "GET", "/agent/sync")).statusCode).toBe(401);
  });
});

describe("POST /records/:id/agent-grants", () => {
  it("201 with a real sealed box; the row is the agent's, sealed to its key, and logged", async () => {
    const { owner, agent } = await setup();
    const r = await record(owner);
    const res = await grantItem(owner, r, agent);
    expect([res.statusCode, res.json()]).toEqual([201, { ok: true }]);
    const row = await t.prisma.recordAccess.findUniqueOrThrow({ where: { recordId_holderType_holderId: { recordId: r.id, holderType: "user", holderId: agent.id } } });
    expect(row).toMatchObject({ permission: "use", orgId: null, sealedTo: agent.publicKey });
    expect(await openPersonalAgentRecordKey(row.wrappedRecordKey!, { ownerUserId: owner.id, agentId: agent.id, recordId: r.id }, { publicKey: b64url.decode(agent.publicKey), privateKey: agent.privateKey })).toEqual(r.recordKey);
    expect(await t.prisma.event.findFirst({ where: { action: "agent.item_grant" } })).toMatchObject({ orgId: null, actorId: owner.id, recordId: r.id, targetUserId: agent.id });
  });

  it("refusals: team record, shared to the caller, another's agent, unverified, trashed, twice, the 201st", async () => {
    const { owner, agent } = await setup();
    const f = await teamFolder(owner);
    expect((await grantItem(owner, await record(owner, f), agent)).json()).toEqual({ error: "team_record" });

    // A record someone else shared to the caller: not the caller's to grant.
    const other = await createActiveUser(t);
    const theirs = await record(other);
    await t.prisma.recordAccess.create({ data: { recordId: theirs.id, holderType: "user", holderId: owner.id, permission: "edit", wrappedRecordKey: "s1.a.b.c", orgId: owner.orgId } });
    expect((await grantItem(owner, theirs, agent)).statusCode).toBe(404);

    const r = await record(owner);
    const stranger = await createTestPersonalAgent(t, { ownerUserId: other.id, verified: true });
    const s = await grantItem(owner, r, stranger);
    expect([s.statusCode, s.json()]).toEqual([400, { error: "user_not_active" }]);
    const unverified = await createTestPersonalAgent(t, { ownerUserId: owner.id });
    expect((await grantItem(owner, r, unverified)).statusCode).toBe(400);

    const trashed = await record(owner);
    expect((await call(owner, "DELETE", `/records/${trashed.id}`)).statusCode).toBe(204);
    const tr = await grantItem(owner, trashed, agent);
    expect([tr.statusCode, tr.json()]).toEqual([409, { error: "in_trash" }]);

    expect((await grantItem(owner, r, agent)).statusCode).toBe(201);
    const again = await grantItem(owner, r, agent);
    expect([again.statusCode, again.json()]).toEqual([409, { error: "already_shared" }]);

    // 199 more rows inserted directly: 200 in all, the next is refused.
    const ids = Array.from({ length: 199 }, () => randomUUID());
    await t.prisma.record.createMany({ data: ids.map((id) => ({ id, folderId: null, ownerId: owner.id, type: "login", encBody: "v1.x" })) });
    await t.prisma.recordAccess.createMany({ data: ids.map((recordId) => ({ recordId, holderType: "user" as const, holderId: agent.id, permission: "use" as const, wrappedRecordKey: "s1.x" })) });
    const lim = await grantItem(owner, await record(owner), agent);
    expect([lim.statusCode, lim.json()]).toEqual([409, { error: "agent_item_limit" }]);
  });

  it("DELETE: 204, logged, the gateway told; 404 when there is no row of the caller's", async () => {
    const { owner, agent } = await setup();
    const r = await record(owner);
    expect((await grantItem(owner, r, agent)).statusCode).toBe(201);
    const other = await createActiveUser(t);
    expect((await call(other, "DELETE", `/records/${r.id}/agent-grants/${agent.id}`)).statusCode).toBe(404);
    expect((await call(owner, "DELETE", `/records/${r.id}/agent-grants/${agent.id}`)).statusCode).toBe(204);
    expect(await t.prisma.recordAccess.count({ where: { holderId: agent.id } })).toBe(0);
    expect(await t.prisma.event.findFirst({ where: { action: "agent.item_revoke" } })).toMatchObject({ orgId: null, actorId: owner.id, recordId: r.id, targetUserId: agent.id });
    await expect.poll(() => fake.dropped).toContain(agent.id);
    expect((await call(owner, "DELETE", `/records/${r.id}/agent-grants/${agent.id}`)).statusCode).toBe(404);
  });

  it("Review Focus 5: PATCH /records/:id/shares/<agentId> above use from the Personal space is 400 agent_use_only", async () => {
    const { owner, agent } = await setup();
    const r = await record(owner);
    expect((await grantItem(owner, r, agent)).statusCode).toBe(201);
    const p = await call(owner, "PATCH", `/records/${r.id}/shares/${agent.id}`, { permission: "edit" }, { org: false });
    expect([p.statusCode, p.json()]).toEqual([400, { error: "agent_use_only" }]);
  });
});

describe("GET /agent/sync for a personal agent", () => {
  it("exactly the granted record, the owner's current key, a k2 key and no folders", async () => {
    const { owner, agent, access } = await setup();
    const r = await record(owner);
    await record(owner); // not granted
    expect((await grantItem(owner, r, agent)).statusCode).toBe(201);
    const stored = (await t.prisma.recordAccess.findFirstOrThrow({ where: { holderId: agent.id } })).wrappedRecordKey;
    const b = await sync(access);
    expect(b).not.toHaveProperty("folders");
    expect(b).not.toHaveProperty("members");
    expect(b).toMatchObject({ owner: { userId: owner.id, publicKey: (await t.prisma.user.findUniqueOrThrow({ where: { id: owner.id } })).publicKey },
      agentId: agent.id, publicKey: agent.publicKey, kekId: "test-kek", expiresAt: null, reveal: [], deposits: [], policy: { write: true, reveal: "approval" } }); // the default organisation policy
    expect(b.wrappedPrivateKey).toMatch(/^k2\./);
    expect(b.records).toEqual([{ id: r.id, encBody: r.encBody, revision: 1, wrappedRecordKey: stored, write: false, deletedAt: null }]);
    expect(await t.prisma.event.findFirst({ where: { action: "agent.sync", actorId: agent.id } })).toMatchObject({ orgId: null });

    const next = b64url.encode(randomBytes(32));
    await t.prisma.user.update({ where: { id: owner.id }, data: { publicKey: next } });
    expect((await sync(access)).owner.publicKey).toBe(next);
  });

  it("Review Focus 2: moved into a team folder the grant goes; trashed it is listed with deletedAt; purged it is gone", async () => {
    const { owner, agent, access } = await setup();
    const f = await teamFolder(owner);
    const moved = await record(owner);
    expect((await grantItem(owner, moved, agent)).statusCode).toBe(201);
    const mv = await call(owner, "PUT", `/records/${moved.id}/folder`, { folderId: f.id, folderWrappedRecordKey: await wrapKey(moved.recordKey, f.folderKey, `record-key:${moved.id}`) });
    expect(mv.statusCode).toBe(200);
    expect(await t.prisma.recordAccess.count({ where: { recordId: moved.id, holderId: agent.id } })).toBe(0);
    expect((await sync(access)).records).toEqual([]);
    await expect.poll(() => fake.dropped).toContain(agent.id);

    fake.dropped.length = 0;
    const r = await record(owner);
    expect((await grantItem(owner, r, agent)).statusCode).toBe(201);
    expect((await call(owner, "DELETE", `/records/${r.id}`)).statusCode).toBe(204);
    await expect.poll(() => fake.dropped).toContain(agent.id);
    const listed = (await sync(access)).records;
    expect(listed.map((x: { id: string }) => x.id)).toEqual([r.id]);
    expect(listed[0].deletedAt).toEqual(expect.any(String));

    fake.dropped.length = 0;
    expect((await call(owner, "DELETE", `/records/${r.id}/purge`)).statusCode).toBe(204);
    await expect.poll(() => fake.dropped).toContain(agent.id);
    expect((await sync(access)).records).toEqual([]);
  });
});

describe("requireAgent for a personal agent", () => {
  it("unverified → 403 agent_unverified", async () => {
    const { access } = await setup({ verified: false });
    expect((await agentCall(access, "GET", "/agent/sync")).json()).toEqual({ error: "agent_unverified" });
  });

  it("owner disabled → 403 owner_inactive, re-enabled → 200", async () => {
    const { owner, access } = await setup();
    await t.prisma.user.update({ where: { id: owner.id }, data: { status: "disabled" } });
    const r = await agentCall(access, "GET", "/agent/sync");
    expect([r.statusCode, r.json()]).toEqual([403, { error: "owner_inactive" }]);
    await t.prisma.user.update({ where: { id: owner.id }, data: { status: "active" } });
    expect((await agentCall(access, "GET", "/agent/sync")).statusCode).toBe(200);
  });

  it("an organisation that disallows → 403 personal_agents_disabled with its id; leaving it → 200; the grant rows stay", async () => {
    const { owner, agent, access } = await setup();
    const r = await record(owner);
    expect((await grantItem(owner, r, agent)).statusCode).toBe(201);
    const o2 = await t.prisma.organization.create({ data: { name: "B", slug: "b-org", policies: { personalAgents: { allowed: false } } } });
    await t.prisma.membership.create({ data: { orgId: o2.id, userId: owner.id, role: "member", status: "active", joinedAt: new Date() } });
    const d = await agentCall(access, "GET", "/agent/sync");
    expect([d.statusCode, d.json()]).toEqual([403, { error: "personal_agents_disabled", orgId: o2.id }]);
    await t.prisma.$transaction((tx) => offboard(tx, o2.id, owner.id, "remove"));
    expect((await sync(access)).records.map((x: { id: string }) => x.id)).toEqual([r.id]);
    expect(await t.prisma.recordAccess.count({ where: { holderId: agent.id } })).toBe(1);
  });

  it("the agent's token reaches no person route", async () => {
    const { access } = await setup();
    for (const url of ["/sync", "/me/agents", "/users"]) {
      const r = await t.app.inject({ method: "GET", url: `/api/v1${url}`, remoteAddress: ip(), headers: { authorization: `Bearer ${access}`, "x-gateway-token": fake.token } });
      expect([url, r.statusCode]).toEqual([url, 401]);
    }
  });
});

describe("/agent/events for a personal agent", () => {
  it("rows have orgId null, link only a granted record, and no organisation's log shows them", async () => {
    const { owner, agent, access } = await setup();
    const r = await record(owner), other = await record(owner);
    expect((await grantItem(owner, r, agent)).statusCode).toBe(201);
    const at = new Date().toISOString();
    const res = await agentCall(access, "POST", "/agent/events", { events: [
      { at, recordId: r.id, action: "use", host: "api.stripe.com", method: "GET" },
      { at, recordId: other.id, action: "refused", host: "api.stripe.com", method: "GET", reason: "owner_key_changed" },
    ] });
    expect(res.statusCode).toBe(200);
    const rows = await t.prisma.event.findMany({ where: { actorId: agent.id, action: { in: ["agent.use", "agent.refused"] } }, orderBy: { id: "asc" } });
    expect(rows.map((e) => [e.action, e.orgId, e.recordId])).toEqual([["agent.use", null, r.id], ["agent.refused", null, null]]);
    const log = (await call(owner, "GET", "/admin/events")).json();
    expect(JSON.stringify(log)).not.toContain(agent.id);
  });
});

describe("GET /sync (Personal space) for the owner", () => {
  it("an owned record lists its agent grants and not the agent in sharedWith", async () => {
    const { owner, agent } = await setup();
    const r = await record(owner);
    expect((await grantItem(owner, r, agent)).statusCode).toBe(201);
    const s = await call(owner, "GET", "/sync", undefined, { org: false });
    expect(s.statusCode).toBe(200);
    const rec = s.json().records.find((x: { id: string }) => x.id === r.id);
    expect(rec.agentGrants).toEqual([{ agentId: agent.id, use: true, write: false }]);
    expect(rec.sharedWith).toEqual([]);
  });
});
