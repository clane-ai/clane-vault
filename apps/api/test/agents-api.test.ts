import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";
import { decodeJwt, decodeProtectedHeader, exportPKCS8, generateKeyPair as joseKeyPair } from "jose";
import { b64url, createTeamFolder, encryptNewRecord, openOrgFolderKey, sealOrgFolderKey, wrapKey } from "@clane-vault/crypto";
import { makeTestApp, resetDb, createActiveUser, orgHeader } from "./helpers.js";
import { createTestAgent } from "./agentHelpers.js";
import { startFakeGateway } from "./fakeGateway.js";
import { hashToken, signAgentAccess, verifyAgentAccess } from "../src/lib/tokens.js";

const fake = await startFakeGateway();
const tokenPrivateKeyPem = await exportPKCS8((await joseKeyPair("ES256", { extractable: true })).privateKey);
const agents = { gatewayInternalUrl: fake.url, gatewayPublicUrl: "https://gw.test/mcp", gatewayApiToken: fake.token, tokenPrivateKeyPem, acceptNewGatewayIdentity: false };
const t = await makeTestApp({ agents });
const limited = await makeTestApp({ agents, rateLimitPerMinute: 3 });
const off = await makeTestApp({});
afterAll(async () => { await Promise.all([t.app.close(), limited.app.close(), off.app.close()]); await fake.close(); });
beforeEach(async () => { await resetDb(t.prisma); fake.dropped.length = 0; });

type U = Awaited<ReturnType<typeof createActiveUser>>;
type A = Awaited<ReturnType<typeof createTestAgent>>;
let ipSeq = 0;
const ip = () => `10.243.${(++ipSeq >> 8) & 255}.${ipSeq & 255}`;
const call = (u: U, method: "GET" | "POST" | "PATCH" | "DELETE", url: string, payload?: unknown) =>
  t.app.inject({ method, url: `/api/v1${url}`, payload: payload as object, remoteAddress: ip(), headers: { authorization: `Bearer ${u.accessToken}`, ...orgHeader(u) } });
/** As the gateway calls the API for an agent. */
const agentCall = (token: string, method: "GET" | "POST", url: string, payload?: unknown, o: { gw?: string | null; app?: typeof t.app; remoteAddress?: string } = {}) =>
  (o.app ?? t.app).inject({ method, url: `/api/v1${url}`, payload: payload as object, remoteAddress: o.remoteAddress ?? ip(),
    headers: { authorization: `Bearer ${token}`, ...(o.gw === null ? {} : { "x-gateway-token": o.gw ?? fake.token }) } });

/** A static-token row (the cvat_ route is Task 5b) and an access token for it. */
async function tokenFor(agent: A, orgId: string, createdById: string, o: { expiresAt?: Date; app?: typeof t } = {}) {
  const row = await (o.app ?? t).prisma.agentToken.create({ data: { agentId: agent.id, label: "ci", tokenHash: hashToken(randomBytes(16).toString("hex")), createdById, expiresAt: o.expiresAt ?? null } });
  return { tokenId: row.id, access: (await signAgentAccess((o.app ?? t).config, { agentId: agent.id, orgId, grant: row.id })).token };
}
async function setup(o: { verified?: boolean } = {}) {
  const owner = await createActiveUser(t, { role: "owner" });
  const agent = await createTestAgent(t, { orgId: owner.orgId, createdById: owner.id, verified: o.verified ?? true, name: "Billing bot" });
  return { owner, agent, ...(await tokenFor(agent, owner.orgId, owner.id)) };
}
async function sharedFolder(owner: U, agent: A) {
  const id = crypto.randomUUID();
  const f = await createTeamFolder(id, "Infra", owner.keys.publicKey);
  expect((await call(owner, "POST", "/folders", { id, kind: "team", encName: f.encName, wrappedFolderKey: f.wrappedFolderKey })).statusCode).toBe(201);
  const wrappedFolderKey = await sealOrgFolderKey(f.folderKey, { orgId: owner.orgId!, folderId: id }, b64url.decode(agent.publicKey));
  expect((await call(owner, "POST", `/folders/${id}/members`, { userId: agent.id, permission: "use", wrappedFolderKey, sealedTo: agent.publicKey })).statusCode).toBe(201);
  return { id, folderKey: f.folderKey, wrappedFolderKey };
}
async function record(owner: U, folder?: { id: string; folderKey: Uint8Array }) {
  const id = crypto.randomUUID();
  const enc = await encryptNewRecord(id, { type: "login", title: "Stripe", password: "x" }, owner.keys.userKey);
  const body = folder
    ? { id, folderId: folder.id, type: "login", encBody: enc.encBody, wrappedRecordKey: await wrapKey(enc.recordKey, folder.folderKey, `record-key:${id}`), ownerWrappedRecordKey: enc.wrappedRecordKey }
    : { id, folderId: null, type: "login", encBody: enc.encBody, wrappedRecordKey: enc.wrappedRecordKey };
  expect((await call(owner, "POST", "/records", body)).statusCode).toBe(201);
  return id;
}

describe("agent access tokens", () => {
  it("ES256 with the agent claims; a person's HS256 token doesn't verify as one", async () => {
    const { owner, agent, tokenId, access } = await setup();
    expect(decodeProtectedHeader(access)).toMatchObject({ alg: "ES256", kid: expect.any(String) });
    const c = decodeJwt(access);
    expect(c).toMatchObject({ scope: "agent", aud: "https://gw.test/mcp", iss: t.config.publicUrl, sub: agent.id, org: owner.orgId, grant: tokenId });
    expect(c.exp! - c.iat!).toBe(900);
    expect(await verifyAgentAccess(t.config, access)).toMatchObject({ sub: agent.id, org: owner.orgId, grant: tokenId, jti: c.jti });
    await expect(verifyAgentAccess(t.config, owner.accessToken)).rejects.toThrow();
    // Another audience (a gateway elsewhere) is refused.
    const other = { ...t.config, agents: { ...agents, gatewayPublicUrl: "https://other.test/mcp" } };
    await expect(verifyAgentAccess(t.config, (await signAgentAccess(other, { agentId: agent.id, orgId: owner.orgId!, grant: tokenId })).token)).rejects.toThrow();
  });
});

describe("route walls", () => {
  it("GET /agent/sync: the org space, the agent's wrapped key and a folder sealed to it", async () => {
    const { owner, agent, access } = await setup();
    const f = await sharedFolder(owner, agent);
    const r = await agentCall(access, "GET", "/agent/sync");
    expect(r.statusCode).toBe(200);
    const body = r.json();
    expect(body).toMatchObject({ orgId: owner.orgId, kekId: "test-kek", expiresAt: null, entitlements: { approvals: true } });
    expect(body.wrappedPrivateKey).toMatch(/^k1\./);
    const folder = body.folders.find((x: { id: string }) => x.id === f.id);
    expect(folder).toMatchObject({ wrappedFolderKey: f.wrappedFolderKey, myPermission: "use" });
    expect(await openOrgFolderKey(folder.wrappedFolderKey, { orgId: owner.orgId!, folderId: f.id }, { orgId: owner.orgId!, publicKey: b64url.decode(agent.publicKey), privateKey: agent.privateKey })).toEqual(f.folderKey);
  });

  it("401 without X-Gateway-Token, with a wrong one, and with a person's token", async () => {
    const { owner, access } = await setup();
    expect((await agentCall(access, "GET", "/agent/sync", undefined, { gw: null })).json()).toEqual({ error: "unauthorized" });
    expect((await agentCall(access, "GET", "/agent/sync", undefined, { gw: "x".repeat(40) })).statusCode).toBe(401);
    expect((await agentCall(owner.accessToken, "GET", "/agent/sync")).statusCode).toBe(401);
  });

  it("the agent token reaches no person route (spec §10)", async () => {
    const { owner, access } = await setup();
    for (const url of ["/sync", "/users", "/me/orgs", "/admin/people"]) {
      const r = await t.app.inject({ method: "GET", url: `/api/v1${url}`, remoteAddress: ip(), headers: { authorization: `Bearer ${access}`, "x-gateway-token": fake.token, ...orgHeader(owner) } });
      expect([url, r.statusCode]).toEqual([url, 401]);
    }
  });

  it("agents off: /agent/* is 404", async () => {
    const r = await off.app.inject({ method: "GET", url: "/api/v1/agent/sync", remoteAddress: ip() });
    expect(r.statusCode).toBe(404);
    expect((await off.app.inject({ method: "POST", url: "/api/v1/agent/events", payload: { events: [] }, remoteAddress: ip() })).statusCode).toBe(404);
  });
});

describe("expiry and state", () => {
  it("past expiresAt: 403 agent_expired on every call, agent.expired logged once, the gateway told to drop it", async () => {
    const { agent, access } = await setup();
    await t.prisma.agent.update({ where: { userId: agent.id }, data: { expiresAt: new Date(Date.now() - 1000) } });
    for (let i = 0; i < 2; i++) expect((await agentCall(access, "GET", "/agent/sync")).json()).toEqual({ error: "agent_expired" });
    expect(await t.prisma.event.count({ where: { action: "agent.expired", actorId: agent.id } })).toBe(1);
    await expect.poll(() => fake.dropped).toContain(agent.id);
  });

  it("an unverified agent: 403 agent_unverified", async () => {
    const { access } = await setup({ verified: false });
    expect((await agentCall(access, "GET", "/agent/sync")).json()).toEqual({ error: "agent_unverified" });
  });

  it("a revoked or expired token, a revoked agent or a disabled user: 401", async () => {
    const { owner, agent, tokenId, access } = await setup();
    const expired = await tokenFor(agent, owner.orgId!, owner.id, { expiresAt: new Date(Date.now() - 1000) });
    expect((await agentCall(expired.access, "GET", "/agent/sync")).statusCode).toBe(401);
    // A grant id that names neither a token nor an OAuth grant of this agent.
    const stray = (await signAgentAccess(t.config, { agentId: agent.id, orgId: owner.orgId!, grant: crypto.randomUUID() })).token;
    expect((await agentCall(stray, "GET", "/agent/sync")).statusCode).toBe(401);
    expect((await agentCall(access, "GET", "/agent/sync")).statusCode).toBe(200);
    await t.prisma.agentToken.update({ where: { id: tokenId }, data: { revokedAt: new Date() } });
    expect((await agentCall(access, "GET", "/agent/sync")).statusCode).toBe(401);

    const b = await setup();
    await t.prisma.user.update({ where: { id: b.agent.id }, data: { status: "disabled" } });
    expect((await agentCall(b.access, "GET", "/agent/sync")).statusCode).toBe(401);
    const c = await setup();
    await t.prisma.agent.update({ where: { userId: c.agent.id }, data: { revokedAt: new Date() } });
    expect((await agentCall(c.access, "GET", "/agent/sync")).statusCode).toBe(401);
  });
});

describe("agent.sync", () => {
  it("logged once across two syncs within the hour, again after it", async () => {
    const { owner, agent, access } = await setup();
    await sharedFolder(owner, agent);
    for (let i = 0; i < 2; i++) expect((await agentCall(access, "GET", "/agent/sync")).statusCode).toBe(200);
    const ev = await t.prisma.event.findMany({ where: { action: "agent.sync" } });
    expect(ev).toHaveLength(1);
    expect(ev[0]).toMatchObject({ actorId: agent.id, orgId: owner.orgId, meta: { records: 0 } });
    await t.prisma.agent.update({ where: { userId: agent.id }, data: { lastSyncLoggedAt: new Date(Date.now() - 2 * 3600e3) } });
    await agentCall(access, "GET", "/agent/sync");
    expect(await t.prisma.event.count({ where: { action: "agent.sync" } })).toBe(2);
  });
});

describe("POST /agent/events", () => {
  const ev = (o: object = {}) => ({ at: new Date().toISOString(), action: "use", host: "api.stripe.com", method: "POST", ...o });

  it("stores agent.<action> rows; a record the agent can't open is unlinked; meta holds only host, method, reason, truncated", async () => {
    const { owner, agent, access } = await setup();
    const f = await sharedFolder(owner, agent);
    const mine = await record(owner, f), notMine = await record(owner);
    const r = await agentCall(access, "POST", "/agent/events", { events: [
      ev({ recordId: mine, truncated: true, path: "/v1/charges", value: "sk_live_x" }),
      ev({ recordId: notMine, action: "refused", reason: "host_not_allowed" }),
      ev({ action: "reflected", host: "" }),
    ] });
    expect([r.statusCode, r.json()]).toEqual([200, { ok: true }]);
    const rows = await t.prisma.event.findMany({ where: { actorId: agent.id, action: { startsWith: "agent." } }, orderBy: { id: "asc" } });
    expect(rows.map((x) => [x.action, x.recordId, x.orgId])).toEqual([["agent.use", mine, owner.orgId], ["agent.refused", null, owner.orgId], ["agent.reflected", null, owner.orgId]]);
    expect(rows.map((x) => x.meta)).toEqual([{ host: "api.stripe.com", method: "POST", truncated: true }, { host: "api.stripe.com", method: "POST", reason: "host_not_allowed" }, { host: "", method: "POST" }]);
    expect((await t.prisma.agent.findUniqueOrThrow({ where: { userId: agent.id } })).lastUsedAt).not.toBeNull();
  });

  it("refuses 0 or 201 events, an unknown method and a long host; lastUsedAt stays unset without a use", async () => {
    const { agent, access } = await setup();
    expect((await agentCall(access, "POST", "/agent/events", { events: Array.from({ length: 201 }, () => ev()) })).statusCode).toBe(400);
    expect((await agentCall(access, "POST", "/agent/events", { events: [] })).statusCode).toBe(400);
    expect((await agentCall(access, "POST", "/agent/events", { events: [ev({ method: "TRACE" })] })).statusCode).toBe(400);
    expect((await agentCall(access, "POST", "/agent/events", { events: [ev({ host: "h".repeat(256) })] })).statusCode).toBe(400);
    expect((await agentCall(access, "POST", "/agent/events", { events: [ev({ action: "refused" })] })).statusCode).toBe(200);
    expect((await t.prisma.agent.findUniqueOrThrow({ where: { userId: agent.id } })).lastUsedAt).toBeNull();
  });
});

describe("rate limits (preflight #12)", () => {
  it("gateway calls are counted per agent, not per the gateway's one address", async () => {
    await resetDb(limited.prisma);
    const owner = await createActiveUser(limited, { role: "owner" });
    const tokens = await Promise.all([0, 1].map(async () => {
      const a = await createTestAgent(limited, { orgId: owner.orgId, createdById: owner.id, verified: true });
      return (await tokenFor(a, owner.orgId!, owner.id, { app: limited })).access;
    }));
    const gw = "10.250.0.1";
    const codes = async (token: string, n: number, gwToken?: string | null) => {
      const out: number[] = [];
      for (let i = 0; i < n; i++) out.push((await agentCall(token, "GET", "/agent/sync", undefined, { app: limited.app, remoteAddress: gw, gw: gwToken })).statusCode);
      return out;
    };
    expect(await codes(tokens[0]!, 4)).toEqual([200, 200, 200, 429]);
    expect(await codes(tokens[1]!, 3)).toEqual([200, 200, 200]);
    // Without the gateway token the key is the address, which agent 0's calls didn't use up.
    expect(await codes(tokens[0]!, 1, null)).toEqual([401]);
  });
});
