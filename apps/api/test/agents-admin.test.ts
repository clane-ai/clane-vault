import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import { b64url, generateKeyPair, keyFingerprint, verifyAgentAttestation } from "@clane-vault/crypto";
import { makeTestApp, resetDb, createActiveUser, orgHeader } from "./helpers.js";
import { createTestAgent } from "./agentHelpers.js";
import { startFakeGateway } from "./fakeGateway.js";
import { checkGatewayAtStart, GatewayIdentityChanged, gatewayClient, GatewayUnavailable, pinGatewayIdentity, type GatewayClient } from "../src/lib/gateway.js";

const fake = await startFakeGateway();
const tokenPrivateKeyPem = generateKeyPairSync("ec", { namedCurve: "prime256v1" }).privateKey.export({ type: "pkcs8", format: "pem" }) as string;
const agents = { gatewayInternalUrl: fake.url, gatewayPublicUrl: "https://gw.test/mcp", gatewayApiToken: fake.token, tokenPrivateKeyPem, acceptNewGatewayIdentity: false };
const t = await makeTestApp({ agents });
const hosted = await makeTestApp({ agents, billingMode: "hosted" });
const off = await makeTestApp({});
afterAll(async () => { await Promise.all([t.app.close(), hosted.app.close(), off.app.close()]); await fake.close(); });
beforeEach(async () => { await resetDb(t.prisma); fake.setDown(false); fake.setSignWrongAgent(false); });

type U = Awaited<ReturnType<typeof createActiveUser>>;
type App = typeof t;
let ipSeq = 0;
const call = (u: U, method: "GET" | "POST" | "PATCH", url: string, payload?: unknown, a: App = t) =>
  a.app.inject({ method, url: `/api/v1${url}`, payload: payload as object, remoteAddress: `10.242.${(++ipSeq >> 8) & 255}.${ipSeq & 255}`, headers: { authorization: `Bearer ${u.accessToken}`, ...orgHeader(u) } });
const counts = async () => [await t.prisma.agent.count(), await t.prisma.user.count({ where: { kind: "agent" } }), await t.prisma.membership.count()];

describe("enrolment through the gateway", () => {
  it("gateway down: 503 gateway_unavailable and nothing is created", async () => {
    const owner = await createActiveUser(t, { role: "owner" });
    fake.setDown(true);
    const before = await counts();
    const r = await call(owner, "POST", "/admin/agents", { name: "Billing bot" });
    expect([r.statusCode, r.json()]).toEqual([503, { error: "gateway_unavailable" }]);
    expect(await counts()).toEqual(before);
    expect((await call(owner, "GET", "/org/agents/gateway")).json()).toEqual({ error: "gateway_unavailable" });
  });

  it("gateway up: 201 with an attestation that verifies; the rows enrolment makes; agent.create logged", async () => {
    const owner = await createActiveUser(t, { role: "owner" });
    const r = await call(owner, "POST", "/admin/agents", { name: "Billing bot", expiresAt: new Date(Date.now() + 864e5).toISOString() });
    expect(r.statusCode).toBe(201);
    const body = r.json();
    expect(body.gateway).toMatchObject(fake.identity);
    expect(fake.created).toContainEqual({ agentId: body.id, orgId: owner.orgId });
    expect(await verifyAgentAttestation(body.attestation, { orgId: owner.orgId, agentId: body.id, publicKey: body.publicKey }, body.gateway)).toBe(true);
    expect(body.fingerprint).toBe(await keyFingerprint(b64url.decode(body.publicKey)));
    expect(body.gateway.fingerprint).toBe(await keyFingerprint(b64url.decode(fake.identity.publicKey)));

    const agent = await t.prisma.agent.findUniqueOrThrow({ where: { userId: body.id } });
    expect(agent.wrappedPrivateKey).toMatch(/^k1\./);
    expect(agent.attestation).toMatch(/^g1\./);
    expect([agent.kekId, agent.orgId, agent.createdById, agent.publicKey]).toEqual(["file-test", owner.orgId, owner.id, body.publicKey]);
    const user = await t.prisma.user.findUniqueOrThrow({ where: { id: body.id } });
    expect(user).toMatchObject({ kind: "agent", email: `agent+${body.id}@agents.invalid`, name: "Billing bot", status: "active", authHash: "", wrappedPrivateKey: "", publicKey: body.publicKey });
    expect(await t.prisma.membership.findFirstOrThrow({ where: { userId: body.id } })).toMatchObject({ orgId: owner.orgId, role: "member", status: "invited" });
    expect(await t.prisma.membershipKey.findFirstOrThrow({ where: { userId: body.id } })).toMatchObject({ publicKey: body.publicKey, wrappedPrivateKey: "", userKeyGen: 1, state: "current" });
    const ev = await t.prisma.event.findMany({ where: { action: "agent.create" } });
    expect(ev).toHaveLength(1);
    expect(ev[0]).toMatchObject({ actorId: owner.id, targetUserId: body.id, meta: { gatewayKeyId: fake.identity.keyId } });
    expect(await t.prisma.gatewayIdentity.findUniqueOrThrow({ where: { id: "gateway" } })).toMatchObject(fake.identity);

    const gw = (await call(owner, "GET", "/org/agents/gateway")).json();
    expect(gw).toEqual({ url: "https://gw.test/mcp", identityKeyId: fake.identity.keyId, identityPublicKey: fake.identity.publicKey });
  });

  it("an attestation that doesn't verify (signed for another agent id): 503 gateway_unavailable and nothing is created", async () => {
    const owner = await createActiveUser(t, { role: "owner" });
    fake.setSignWrongAgent(true);
    const before = await counts();
    const r = await call(owner, "POST", "/admin/agents", { name: "Bot" });
    expect([r.statusCode, r.json()]).toEqual([503, { error: "gateway_unavailable" }]);
    expect(await counts()).toEqual(before);
    expect(await t.prisma.event.count({ where: { action: "agent.create" } })).toBe(0);
  });

  it("refuses an expiry in the past and a member", async () => {
    const owner = await createActiveUser(t, { role: "owner" }), member = await createActiveUser(t);
    expect((await call(owner, "POST", "/admin/agents", { name: "Bot", expiresAt: new Date(Date.now() - 1000).toISOString() })).statusCode).toBe(400);
    expect((await call(member, "POST", "/admin/agents", { name: "Bot" })).statusCode).toBe(403);
    expect((await call(member, "GET", "/admin/agents")).statusCode).toBe(403);
    expect(await t.prisma.agent.count()).toBe(0);
  });

  it("verify: another key is 409 stale_key and changes nothing; the right key activates it", async () => {
    const owner = await createActiveUser(t, { role: "owner" });
    const a = (await call(owner, "POST", "/admin/agents", { name: "Bot" })).json();
    const other = b64url.encode((await generateKeyPair()).publicKey);
    const bad = await call(owner, "POST", `/admin/agents/${a.id}/verify`, { publicKey: other });
    expect([bad.statusCode, bad.json()]).toEqual([409, { error: "stale_key" }]);
    expect((await t.prisma.membership.findFirstOrThrow({ where: { userId: a.id } })).status).toBe("invited");
    expect((await t.prisma.agent.findUniqueOrThrow({ where: { userId: a.id } })).verifiedAt).toBeNull();
    expect((await call(owner, "POST", `/admin/agents/${a.id}/verify`, { publicKey: a.publicKey })).statusCode).toBe(200);
    expect((await t.prisma.membership.findFirstOrThrow({ where: { userId: a.id } })).status).toBe("active");
    expect(await t.prisma.agent.findUniqueOrThrow({ where: { userId: a.id } })).toMatchObject({ verifiedById: owner.id });
    expect(await t.prisma.event.count({ where: { action: "agent.verify", targetUserId: a.id } })).toBe(1);
  });

  it("verifying a revoked agent is 409 agent_revoked", async () => {
    const owner = await createActiveUser(t, { role: "owner" });
    const a = await createTestAgent(t, { orgId: owner.orgId, createdById: owner.id });
    await t.prisma.agent.update({ where: { userId: a.id }, data: { revokedAt: new Date() } });
    const r = await call(owner, "POST", `/admin/agents/${a.id}/verify`, { publicKey: a.publicKey });
    expect([r.statusCode, r.json()]).toEqual([409, { error: "agent_revoked" }]);
    expect((await t.prisma.membership.findFirstOrThrow({ where: { userId: a.id } })).status).toBe("invited");
    expect(await t.prisma.event.count({ where: { action: "agent.verify" } })).toBe(0);
  });

  it("identity changed: creation is 503 gateway_identity_changed; accept pins the new one", async () => {
    const owner = await createActiveUser(t, { role: "owner" });
    expect((await call(owner, "POST", "/admin/agents", { name: "Bot" })).statusCode).toBe(201);
    const pinned = { ...fake.identity };
    await fake.rotateIdentity();
    try {
      const before = await counts();
      const r = await call(owner, "POST", "/admin/agents", { name: "Bot 2" });
      expect([r.statusCode, r.json()]).toEqual([503, { error: "gateway_identity_changed" }]);
      expect(await counts()).toEqual(before);
      const seen = { ...fake.identity };
      await expect(pinGatewayIdentity(t.prisma, seen, { accept: false })).rejects.toBeInstanceOf(GatewayIdentityChanged);
      expect(await pinGatewayIdentity(t.prisma, seen, { accept: true })).toBe("accepted");
      expect(await t.prisma.gatewayIdentity.findUniqueOrThrow({ where: { id: "gateway" } })).toMatchObject(seen);
      expect(seen.keyId).not.toBe(pinned.keyId);
      expect((await call(owner, "POST", "/admin/agents", { name: "Bot 2" })).statusCode).toBe(201);
    } finally { await t.prisma.gatewayIdentity.deleteMany(); }
  });

  it("GATEWAY_ACCEPT_NEW_IDENTITY at runtime: a re-pin logs a warning with the old and new keyId only", async () => {
    const owner = await createActiveUser(t, { role: "owner" });
    expect((await call(owner, "POST", "/admin/agents", { name: "Bot" })).statusCode).toBe(201);
    const pinned = fake.identity.keyId;
    await fake.rotateIdentity();
    const warn = vi.spyOn(t.app.log, "warn");
    t.config.agents!.acceptNewGatewayIdentity = true;
    try {
      expect((await call(owner, "POST", "/admin/agents", { name: "Bot 2" })).statusCode).toBe(201);
      const calls = warn.mock.calls.filter(([o]) => (o as { event?: string }).event === "gateway_identity_repinned");
      expect(calls.map(([o]) => o)).toEqual([{ event: "gateway_identity_repinned", oldKeyId: pinned, newKeyId: fake.identity.keyId }]);
    } finally { t.config.agents!.acceptNewGatewayIdentity = false; warn.mockRestore(); await t.prisma.gatewayIdentity.deleteMany(); }
  });

  it("an agent of another org is 404", async () => {
    const owner = await createActiveUser(t, { role: "owner" });
    const org2 = await t.prisma.organization.create({ data: { name: "Other", slug: "other-agents" } });
    const owner2 = await createActiveUser(t, { role: "owner", orgId: org2.id });
    const a = await createTestAgent(t, { orgId: org2.id, createdById: owner2.id });
    for (const r of [await call(owner, "POST", `/admin/agents/${a.id}/verify`, { publicKey: a.publicKey }), await call(owner, "PATCH", `/admin/agents/${a.id}`, { name: "Mine" })])
      expect([r.statusCode, r.json()]).toEqual([404, { error: "not_found" }]);
  });
});

describe("listing and editing", () => {
  it("GET /admin/agents shows each agent's status, folders and groups; PATCH changes name and expiry", async () => {
    const owner = await createActiveUser(t, { role: "owner" });
    const waiting = await createTestAgent(t, { orgId: owner.orgId, createdById: owner.id, name: "Waiting" });
    const live = await createTestAgent(t, { orgId: owner.orgId, createdById: owner.id, verified: true, name: "Live" });
    const old = await createTestAgent(t, { orgId: owner.orgId, createdById: owner.id, verified: true, expiresAt: new Date(Date.now() - 1000), name: "Old" });
    const gone = await createTestAgent(t, { orgId: owner.orgId, createdById: owner.id, verified: true, name: "Gone" });
    await t.prisma.agent.update({ where: { userId: gone.id }, data: { revokedAt: new Date() } });
    const g = await t.prisma.group.create({ data: { orgId: owner.orgId, name: "Bots" } });
    await t.prisma.groupMember.create({ data: { groupId: g.id, userId: live.id } });

    const list = (await call(owner, "GET", "/admin/agents")).json().agents as { id: string; status: string; name: string; groups: unknown[]; folders: unknown[]; tokens: unknown[]; grants: unknown[] }[];
    const status = Object.fromEntries(list.map((a) => [a.name, a.status]));
    expect(status).toEqual({ Waiting: "awaiting_verification", Live: "active", Old: "expired", Gone: "revoked" });
    expect(list.find((a) => a.id === live.id)).toMatchObject({ groups: [{ id: g.id, name: "Bots" }], folders: [], tokens: [], grants: [], publicKey: live.publicKey, attestation: "g1.test.sig" });
    expect(list.some((a) => a.id === waiting.id)).toBe(true);

    const exp = new Date(Date.now() + 3600e3).toISOString();
    expect((await call(owner, "PATCH", `/admin/agents/${old.id}`, { name: "Renewed", expiresAt: exp })).statusCode).toBe(200);
    expect((await call(owner, "PATCH", `/admin/agents/${live.id}`, { expiresAt: null })).statusCode).toBe(200);
    const after = (await call(owner, "GET", "/admin/agents")).json().agents as { id: string; status: string; name: string; expiresAt: string | null }[];
    expect(after.find((a) => a.id === old.id)).toMatchObject({ name: "Renewed", status: "active", expiresAt: exp });
    expect(await t.prisma.event.count({ where: { action: "agent.update" } })).toBe(2);
  });

  it("R41: /users, /groups, pending group access and /sync folder members carry a verified agent's attestation and gateway key id", async () => {
    const owner = await createActiveUser(t, { role: "owner" }), member = await createActiveUser(t);
    const a = (await call(owner, "POST", "/admin/agents", { name: "Bot" })).json();
    expect((await call(owner, "POST", `/admin/agents/${a.id}/verify`, { publicKey: a.publicKey })).statusCode).toBe(200);
    const gw = (await call(member, "GET", "/org/agents/gateway")).json();
    const identity = { keyId: gw.identityKeyId, publicKey: gw.identityPublicKey };
    const check = async (row: { attestation: string; gatewayKeyId: string; membershipKey: string }) => {
      expect(row.gatewayKeyId).toBe(fake.identity.keyId);
      expect(await verifyAgentAttestation(row.attestation, { orgId: owner.orgId, agentId: a.id, publicKey: row.membershipKey }, identity)).toBe(true);
    };
    const users = (await call(member, "GET", "/users")).json().users as { id: string; attestation?: string }[];
    await check(users.find((u) => u.id === a.id) as never);
    expect(users.find((u) => u.id === member.id)).not.toHaveProperty("attestation");

    const g = (await call(owner, "POST", "/admin/groups", { name: "Bots" })).json().id as string;
    expect((await call(owner, "POST", `/admin/groups/${g}/members`, { userIds: [a.id] })).statusCode).toBe(201);
    const groups = (await call(member, "GET", "/groups")).json().groups as { id: string; members: { id: string }[] }[];
    await check(groups.find((x) => x.id === g)!.members.find((m) => m.id === a.id) as never);

    const fid = crypto.randomUUID();
    const { createTeamFolder } = await import("@clane-vault/crypto");
    const f = await createTeamFolder(fid, "Infra", owner.keys.publicKey);
    expect((await call(owner, "POST", "/folders", { id: fid, kind: "team", encName: f.encName, wrappedFolderKey: f.wrappedFolderKey })).statusCode).toBe(201);
    expect((await call(owner, "POST", `/folders/${fid}/groups`, { groupId: g, permission: "use", wraps: [] })).statusCode).toBe(201);
    const pending = (await call(owner, "GET", "/group-access/pending")).json().pending as { userId: string }[];
    await check(pending.find((p) => p.userId === a.id) as never);

    // /sync folder members: what re-granting access seals to.
    expect((await call(owner, "POST", `/folders/${fid}/members`, { userId: a.id, permission: "use", wrappedFolderKey: "s1.a.b.c", sealedTo: a.publicKey })).statusCode).toBe(201);
    const folder = (await call(owner, "GET", "/sync")).json().folders.find((x: { id: string }) => x.id === fid);
    const members = folder.members as { userId: string; attestation?: string; gatewayKeyId: string; membershipKey: string }[];
    await check(members.find((m) => m.userId === a.id) as never);
    expect(members.find((m) => m.userId === owner.id)).not.toHaveProperty("attestation");
  });
});

describe("hosted agent limits", () => {
  it("Team allows 3 live agents: the 4th is 402 agent_limit; /org/plan reports agents", async () => {
    await resetDb(hosted.prisma);
    const owner = await createActiveUser(hosted, { role: "owner" });
    for (let i = 0; i < 3; i++) expect((await call(owner, "POST", "/admin/agents", { name: `Bot ${i}` }, hosted)).statusCode).toBe(201);
    const r = await call(owner, "POST", "/admin/agents", { name: "Bot 4" }, hosted);
    expect([r.statusCode, r.json()]).toEqual([402, { error: "agent_limit", used: 3, allowed: 3 }]);
    expect(await hosted.prisma.agent.count()).toBe(3);
    expect((await call(owner, "GET", "/org/plan", undefined, hosted)).json().agents).toEqual({ used: 3, allowed: 3 });
    // A revoked agent frees its slot.
    await hosted.prisma.agent.updateMany({ where: { orgId: owner.orgId }, data: { revokedAt: new Date() } });
    expect((await call(owner, "POST", "/admin/agents", { name: "Bot 5" }, hosted)).statusCode).toBe(201);
  });

  it("billing off: no limit", async () => {
    const owner = await createActiveUser(t, { role: "owner" });
    for (let i = 0; i < 12; i++) expect((await call(owner, "POST", "/admin/agents", { name: `Bot ${i}` })).statusCode).toBe(201);
  });
});

describe("agents off", () => {
  it("the agent routes don't exist", async () => {
    await resetDb(off.prisma);
    const owner = await createActiveUser(off, { role: "owner" });
    expect((await call(owner, "GET", "/admin/agents", undefined, off)).statusCode).toBe(404);
    expect((await call(owner, "POST", "/admin/agents", { name: "Bot" }, off)).statusCode).toBe(404);
    expect((await call(owner, "GET", "/org/agents/gateway", undefined, off)).statusCode).toBe(404);
  });
});

describe("gateway client and the start-up check", () => {
  const warns: string[] = [];
  const log = { warn: (m: string) => { warns.push(m); } };
  const stub = (h: () => Promise<{ keyId: string; publicKey: string }>): GatewayClient => ({ health: h, createAgentKey: () => Promise.reject(new Error("unused")), dropAgent: () => Promise.resolve() });

  it("created on first sight, ok after, unreachable warns and starts, changed throws unless accepted", async () => {
    const id = { keyId: "kid-1", publicKey: "pub-1" };
    expect(await checkGatewayAtStart(t.prisma, stub(async () => id), { accept: false, log })).toBe("created");
    expect(await checkGatewayAtStart(t.prisma, stub(async () => id), { accept: false, log })).toBe("ok");
    expect(await checkGatewayAtStart(t.prisma, stub(() => Promise.reject(new GatewayUnavailable("down"))), { accept: false, log })).toBe("unreachable");
    expect(warns.some((m) => /gateway/i.test(m))).toBe(true);
    const changed = { keyId: "kid-2", publicKey: "pub-2" };
    await expect(checkGatewayAtStart(t.prisma, stub(async () => changed), { accept: false, log })).rejects.toBeInstanceOf(GatewayIdentityChanged);
    expect(await t.prisma.gatewayIdentity.findUniqueOrThrow({ where: { id: "gateway" } })).toMatchObject(id);
    expect(await checkGatewayAtStart(t.prisma, stub(async () => changed), { accept: true, log })).toBe("accepted");
    expect(await t.prisma.gatewayIdentity.findUniqueOrThrow({ where: { id: "gateway" } })).toMatchObject(changed);
  });

  it("the client sends the token, reads health's identity, and maps refusals and network errors to GatewayUnavailable", async () => {
    expect(await gatewayClient(agents).health()).toEqual(fake.identity);
    await expect(gatewayClient({ ...agents, gatewayApiToken: "x".repeat(32) }).health()).rejects.toBeInstanceOf(GatewayUnavailable);
    await expect(gatewayClient({ ...agents, gatewayInternalUrl: "http://127.0.0.1:1" }).health()).rejects.toBeInstanceOf(GatewayUnavailable);
    await gatewayClient(agents).dropAgent("a1b2");
    expect(fake.dropped).toContain("a1b2");
  });

  it("buildApp resolves with agents on and the gateway down", async () => {
    fake.setDown(true);
    const a = await makeTestApp({ agents });
    await a.app.close();
  });
});
