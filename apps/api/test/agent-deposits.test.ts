import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { randomBytes, randomUUID } from "node:crypto";
import { exportPKCS8, generateKeyPair as joseKeyPair } from "jose";
import {
  agentDepositMessage, aeadEncrypt, b64url, encryptNewRecord, gatewayKeyId, generateIdentityKeyPair, openDepositKey, openPersonalAgentRecordKey,
  sealDepositKeyToOwner, sealPersonalAgentRecordKey, sha256B64, signGatewayMessage, utf8, wrapKey,
} from "@clane-vault/crypto";
import { makeTestApp, resetDb, createActiveUser, orgHeader } from "./helpers.js";
import { createTestAgent, createTestPersonalAgent } from "./agentHelpers.js";
import { startFakeGateway } from "./fakeGateway.js";
import { hashToken, signAgentAccess } from "../src/lib/tokens.js";
import { depositMessage, sha256B64 as apiSha256B64 } from "../src/lib/agents.js";
import { sweepAgentWrites } from "../src/lib/personalAgents.js";

const fake = await startFakeGateway();
const tokenPrivateKeyPem = await exportPKCS8((await joseKeyPair("ES256", { extractable: true })).privateKey);
const agents = { gatewayInternalUrl: fake.url, gatewayPublicUrl: "https://gw.test/mcp", gatewayApiToken: fake.token, tokenPrivateKeyPem, acceptNewGatewayIdentity: false, personalAgents: true };
const t = await makeTestApp({ agents });
afterAll(async () => { await t.app.close(); await fake.close(); });
beforeEach(async () => { await resetDb(t.prisma); });

type U = Awaited<ReturnType<typeof createActiveUser>>;
type PA = Awaited<ReturnType<typeof createTestPersonalAgent>>;
let ipSeq = 0;
const ip = () => `10.245.${(++ipSeq >> 8) & 255}.${ipSeq & 255}`;
const call = (u: U, method: "GET" | "POST" | "PUT" | "DELETE", url: string, payload?: unknown, o: { org?: boolean } = {}) =>
  t.app.inject({ method, url: `/api/v1${url}`, payload: payload as object, remoteAddress: ip(), headers: { authorization: `Bearer ${u.accessToken}`, ...(o.org ? orgHeader(u) : {}) } });
const agentCall = (token: string, method: "GET" | "POST" | "PUT", url: string, payload?: unknown) =>
  t.app.inject({ method, url: `/api/v1${url}`, payload: payload as object, remoteAddress: ip(), headers: { authorization: `Bearer ${token}`, "x-gateway-token": fake.token } });

async function token(agentId: string, createdById: string, o: { orgId?: string; ownerUserId?: string }) {
  const grant = (await t.prisma.agentToken.create({ data: { agentId, label: "Laptop CLI", tokenHash: hashToken(randomBytes(16).toString("hex")), createdById } })).id;
  return (await signAgentAccess(t.config, { agentId, orgId: o.orgId ?? null, ownerUserId: o.ownerUserId ?? null, grant })).token;
}
async function setup(owner?: U) {
  owner ??= await createActiveUser(t, { role: "owner" });
  const agent = await createTestPersonalAgent(t, { ownerUserId: owner.id, verified: true });
  return { owner, agent, access: await token(agent.id, owner.id, { ownerUserId: owner.id }) };
}
const ownerPk = async (u: U) => (await t.prisma.user.findUniqueOrThrow({ where: { id: u.id }, select: { publicKey: true } })).publicKey;
type Signer = (message: string) => Promise<string>;
const gw: Signer = (m) => fake.sign("d1", m);

/** What the gateway sends for save_secret: a real body under a fresh record key, sealed to the owner and to the agent, signed at revision 1. */
async function build(owner: U, agent: PA, o: { title?: string; signWith?: Signer; signedBody?: string } = {}) {
  const id = randomUUID();
  const enc = await encryptNewRecord(id, { type: "login", title: o.title ?? "GitHub deploy token", password: "ghp_x" }, owner.keys.userKey);
  const sig = await (o.signWith ?? gw)(agentDepositMessage({ ownerUserId: owner.id, ownerPublicKey: await ownerPk(owner), agentId: agent.id, id, revision: 1,
    encBodyHash: await sha256B64(o.signedBody ?? enc.encBody) }));
  return {
    recordKey: enc.recordKey,
    body: { id, type: "login", encBody: enc.encBody, signature: sig,
      ownerSealedKey: await sealDepositKeyToOwner(enc.recordKey, { ownerUserId: owner.id, id }, owner.keys.publicKey),
      agentSealedKey: await sealPersonalAgentRecordKey(enc.recordKey, { ownerUserId: owner.id, agentId: agent.id, recordId: id }, b64url.decode(agent.publicKey)) },
  };
}
async function deposit(owner: U, agent: PA, access: string, o: Parameters<typeof build>[2] = {}) {
  const d = await build(owner, agent, o);
  const r = await agentCall(access, "POST", "/agent/deposits", d.body);
  expect([r.statusCode, r.json()]).toEqual([201, { id: d.body.id, revision: 1 }]);
  return d;
}
/** The agent's update_secret on its deposit: a new body under the same key, signed at revision + 1. */
async function update(owner: U, agent: PA, d: Awaited<ReturnType<typeof build>>, revision: number, signer: Signer = gw) {
  const encBody = await aeadEncrypt(d.recordKey, utf8.encode(JSON.stringify({ type: "login", title: "Rotated", password: "ghp_y" })), `record-body:${d.body.id}`);
  const signature = await signer(agentDepositMessage({ ownerUserId: owner.id, ownerPublicKey: await ownerPk(owner), agentId: agent.id, id: d.body.id, revision: revision + 1, encBodyHash: await sha256B64(encBody) }));
  return { encBody, revision, signature };
}
const keepBody = async (d: Awaited<ReturnType<typeof build>>, revision: number, o: { agent?: PA; owner?: U; folderId?: string | null } = {}) => ({
  revision, folderId: o.folderId ?? null, wrappedRecordKey: await wrapKey(d.recordKey, o.owner!.keys.userKey, `record-key:${d.body.id}`),
  ...(o.agent ? { agentWrappedRecordKey: await sealPersonalAgentRecordKey(d.recordKey, { ownerUserId: o.owner!.id, agentId: o.agent.id, recordId: d.body.id }, b64url.decode(o.agent.publicKey)) } : {}),
});

describe("the API's deposit message", () => {
  it("is byte-identical to the crypto package's", () => {
    const m = { ownerUserId: "u", ownerPublicKey: "opk", agentId: "a", id: "d", revision: 2, encBodyHash: "h" };
    expect(depositMessage(m)).toBe(agentDepositMessage(m));
  });
  it("hashes the body as the crypto package does", async () => {
    for (const s of ["", "v1.abc", "ünïcødé"]) expect(apiSha256B64(s)).toBe(await sha256B64(s));
  });
});

describe("POST /agent/deposits", () => {
  it("201: stored, listed for the owner with the agent's name and the token's label, counted in /sync but never listed there", async () => {
    const { owner, agent, access } = await setup();
    const d = await deposit(owner, agent, access);
    const row = await t.prisma.agentDeposit.findUniqueOrThrow({ where: { id: d.body.id } });
    expect(row).toMatchObject({ ownerUserId: owner.id, agentId: agent.id, type: "login", encBody: d.body.encBody, revision: 1, connectedApp: "Laptop CLI" });
    expect(await t.prisma.event.findFirst({ where: { action: "agent.deposit" } })).toMatchObject({ orgId: null, actorId: agent.id, recordId: d.body.id, meta: { app: "Laptop CLI" } });

    const list = (await call(owner, "GET", "/me/agent-deposits")).json().deposits;
    expect(list).toHaveLength(1);
    expect(list[0]).toMatchObject({ id: d.body.id, agentId: agent.id, agentName: "Personal agent", app: "Laptop CLI", type: "login", encBody: d.body.encBody, revision: 1,
      ownerSealedKey: d.body.ownerSealedKey, signature: d.body.signature });
    expect(Date.parse(list[0].expiresAt) - Date.parse(list[0].createdAt)).toBe(90 * 86400e3);
    // The owner's browser opens it with the account key.
    expect(await openDepositKey(list[0].ownerSealedKey, { ownerUserId: owner.id, id: d.body.id }, owner.keys)).toEqual(d.recordKey);

    const personal = (await call(owner, "GET", "/sync")).json();
    expect(personal.agentInbox).toBe(1);
    expect(personal.records.find((r: { id: string }) => r.id === d.body.id)).toBeUndefined();
    const org = (await call(owner, "GET", "/sync?space=org", undefined, { org: true })).json();
    expect(org).not.toHaveProperty("agentInbox");
    expect(org.records.find((r: { id: string }) => r.id === d.body.id)).toBeUndefined();

    const s = (await agentCall(access, "GET", "/agent/sync")).json();
    expect(s.deposits).toEqual([{ id: d.body.id, encBody: d.body.encBody, revision: 1, agentSealedKey: d.body.agentSealedKey }]);
    expect(s.inboxFree).toBe(99);
  });

  it("409 conflict on a signature over another body or by another identity key, and on a taken id; nothing stored", async () => {
    const { owner, agent, access } = await setup();
    const other = await build(owner, agent, { signedBody: "v1.something-else" });
    const r1 = await agentCall(access, "POST", "/agent/deposits", other.body);
    expect([r1.statusCode, r1.json()]).toEqual([409, { error: "conflict" }]);
    const stranger = await generateIdentityKeyPair();
    const keyId = fake.identity.keyId;
    const forged = await build(owner, agent, { signWith: (m) => signGatewayMessage(stranger.privateKey, keyId, "d1", m) });
    const r2 = await agentCall(access, "POST", "/agent/deposits", forged.body);
    expect([r2.statusCode, r2.json()]).toEqual([409, { error: "conflict" }]);
    const forged2 = await build(owner, agent, { signWith: async (m) => signGatewayMessage(stranger.privateKey, await gatewayKeyId(stranger.publicKey), "d1", m) });
    expect((await agentCall(access, "POST", "/agent/deposits", forged2.body)).json()).toEqual({ error: "conflict" });
    expect(await t.prisma.agentDeposit.count()).toBe(0);

    const d = await deposit(owner, agent, access);
    const again = await agentCall(access, "POST", "/agent/deposits", d.body);
    expect([again.statusCode, again.json()]).toEqual([409, { error: "conflict" }]);
    // An id that is already a record.
    const taken = await build(owner, agent);
    await t.prisma.record.create({ data: { id: taken.body.id, folderId: null, ownerId: owner.id, type: "login", encBody: "v1.x" } });
    expect((await agentCall(access, "POST", "/agent/deposits", taken.body)).json()).toEqual({ error: "conflict" });
    expect(await t.prisma.agentDeposit.count()).toBe(1);
  });

  it("409 not_writable under a write: false policy and for an organisation agent; 409 inbox_full at 100 for the owner, across agents", async () => {
    const { owner, agent, access } = await setup();
    await t.prisma.organization.update({ where: { id: owner.orgId! }, data: { policies: { personalAgents: { write: false } } } });
    const r = await agentCall(access, "POST", "/agent/deposits", (await build(owner, agent)).body);
    expect([r.statusCode, r.json()]).toEqual([409, { error: "not_writable" }]);
    await t.prisma.organization.update({ where: { id: owner.orgId! }, data: { policies: {} } });

    const oa = await createTestAgent(t, { orgId: owner.orgId!, createdById: owner.id, verified: true });
    const orgAccess = await token(oa.id, owner.id, { orgId: owner.orgId! });
    const o = await agentCall(orgAccess, "POST", "/agent/deposits", (await build(owner, agent)).body);
    expect([o.statusCode, o.json()]).toEqual([409, { error: "not_writable" }]);

    // The owner's second agent fills the inbox (F2: the limit is per owner).
    const second = await setup(owner);
    await t.prisma.agentDeposit.createMany({ data: Array.from({ length: 100 }, () => ({ id: randomUUID(), ownerUserId: owner.id, agentId: second.agent.id, type: "item",
      encBody: "v1.x", ownerSealedKey: "s1.x", agentSealedKey: "s1.x", signature: "d1.x.y", connectedApp: "x" })) });
    expect((await agentCall(access, "GET", "/agent/sync")).json()).toMatchObject({ inboxFree: 0, deposits: [] });
    const full = await agentCall(access, "POST", "/agent/deposits", (await build(owner, agent)).body);
    expect([full.statusCode, full.json()]).toEqual([409, { error: "inbox_full" }]);
  });
});

describe("PUT /agent/deposits/:id", () => {
  it("the same agent bumps the revision; the owner's second agent is not_writable; a stale revision or a bad signature is a conflict", async () => {
    const { owner, agent, access } = await setup();
    const d = await deposit(owner, agent, access);
    const u = await update(owner, agent, d, 1);
    const r = await agentCall(access, "PUT", `/agent/deposits/${d.body.id}`, u);
    expect([r.statusCode, r.json()]).toEqual([200, { id: d.body.id, revision: 2 }]);
    expect(await t.prisma.agentDeposit.findUniqueOrThrow({ where: { id: d.body.id } })).toMatchObject({ revision: 2, encBody: u.encBody, signature: u.signature });

    const second = await setup(owner);
    const s = await agentCall(second.access, "PUT", `/agent/deposits/${d.body.id}`, await update(owner, second.agent, d, 2));
    expect([s.statusCode, s.json()]).toEqual([409, { error: "not_writable" }]);
    const stale = await agentCall(access, "PUT", `/agent/deposits/${d.body.id}`, await update(owner, agent, d, 1));
    expect([stale.statusCode, stale.json()]).toEqual([409, { error: "conflict" }]);
    const badSig = { ...(await update(owner, agent, d, 2)), encBody: u.encBody };
    expect((await agentCall(access, "PUT", `/agent/deposits/${d.body.id}`, badSig)).json()).toEqual({ error: "conflict" });
    expect((await t.prisma.agentDeposit.findUniqueOrThrow({ where: { id: d.body.id } })).revision).toBe(2);
  });
});

describe("the owner's inbox", () => {
  it("keep: a stale revision is a conflict; the current one makes the record, the owner row and (asked) the agent's use row; the deposit is gone", async () => {
    const { owner, agent, access } = await setup();
    const d = await deposit(owner, agent, access);
    expect((await agentCall(access, "PUT", `/agent/deposits/${d.body.id}`, await update(owner, agent, d, 1))).statusCode).toBe(200);
    const stale = await call(owner, "POST", `/me/agent-deposits/${d.body.id}/keep`, await keepBody(d, 1, { owner }));
    expect([stale.statusCode, stale.json()]).toEqual([409, { error: "conflict" }]);
    const nofolder = await call(owner, "POST", `/me/agent-deposits/${d.body.id}/keep`, await keepBody(d, 2, { owner, folderId: randomUUID() }));
    expect([nofolder.statusCode, nofolder.json()]).toEqual([404, { error: "folder_not_found" }]);

    const body = await keepBody(d, 2, { owner, agent });
    const k = await call(owner, "POST", `/me/agent-deposits/${d.body.id}/keep`, body);
    expect([k.statusCode, k.json()]).toEqual([201, { id: d.body.id, revision: 1 }]);
    const stored = await t.prisma.agentDeposit.findUnique({ where: { id: d.body.id } });
    expect(stored).toBeNull();
    const rec = await t.prisma.record.findUniqueOrThrow({ where: { id: d.body.id }, include: { access: true } });
    const encBody = (await t.prisma.event.findFirst({ where: { action: "agent.deposit_keep" } }))!;
    expect(encBody).toMatchObject({ orgId: null, actorId: owner.id, recordId: d.body.id });
    expect(rec).toMatchObject({ ownerId: owner.id, folderId: null, type: "login", revision: 1, createdByAgentId: agent.id });
    expect(rec.access.find((a) => a.holderId === owner.id)).toMatchObject({ permission: "owner", wrappedRecordKey: body.wrappedRecordKey });
    const ag = rec.access.find((a) => a.holderId === agent.id)!;
    expect(ag).toMatchObject({ permission: "use", orgId: null, sealedTo: agent.publicKey, wrappedRecordKey: body.agentWrappedRecordKey });
    expect(await openPersonalAgentRecordKey(ag.wrappedRecordKey!, { ownerUserId: owner.id, agentId: agent.id, recordId: d.body.id }, { publicKey: b64url.decode(agent.publicKey), privateKey: agent.privateKey })).toEqual(d.recordKey);

    const s = (await call(owner, "GET", "/sync")).json();
    expect(s.agentInbox).toBe(0);
    expect(s.records.find((r: { id: string }) => r.id === d.body.id)).toMatchObject({ createdByAgent: { id: agent.id, name: "Personal agent" }, encBody: rec.encBody });
    expect((await agentCall(access, "GET", "/agent/sync")).json()).toMatchObject({ deposits: [], records: [{ id: d.body.id }] });
  });

  it("keep without agentWrappedRecordKey makes no agent row; at the 200-item limit it keeps without one (agentRow false)", async () => {
    const { owner, agent, access } = await setup();
    const d = await deposit(owner, agent, access);
    expect((await call(owner, "POST", `/me/agent-deposits/${d.body.id}/keep`, await keepBody(d, 1, { owner }))).statusCode).toBe(201);
    expect(await t.prisma.recordAccess.count({ where: { recordId: d.body.id, holderId: agent.id } })).toBe(0);

    const ids = Array.from({ length: 200 }, () => randomUUID());
    await t.prisma.record.createMany({ data: ids.map((id) => ({ id, folderId: null, ownerId: owner.id, type: "login", encBody: "v1.x" })) });
    await t.prisma.recordAccess.createMany({ data: ids.map((recordId) => ({ recordId, holderType: "user" as const, holderId: agent.id, permission: "use" as const, wrappedRecordKey: "s1.x" })) });
    const e = await deposit(owner, agent, access);
    const k = await call(owner, "POST", `/me/agent-deposits/${e.body.id}/keep`, await keepBody(e, 1, { owner, agent }));
    expect([k.statusCode, k.json()]).toEqual([201, { id: e.body.id, revision: 1, agentRow: false }]);
    expect(await t.prisma.record.count({ where: { id: e.body.id } })).toBe(1);
    expect(await t.prisma.recordAccess.count({ where: { recordId: e.body.id, holderId: agent.id } })).toBe(0);
  });

  it("keep into the owner's private folder; another user can't see, keep or delete it (404); delete is 204", async () => {
    const { owner, agent, access } = await setup();
    const d = await deposit(owner, agent, access);
    const other = await createActiveUser(t);
    expect((await call(other, "GET", "/me/agent-deposits")).json()).toEqual({ deposits: [] });
    const k = await call(other, "POST", `/me/agent-deposits/${d.body.id}/keep`, await keepBody(d, 1, { owner: other }));
    expect([k.statusCode, k.json()]).toEqual([404, { error: "not_found" }]);
    expect((await call(other, "DELETE", `/me/agent-deposits/${d.body.id}`)).statusCode).toBe(404);

    const folderId = randomUUID();
    await t.prisma.folder.create({ data: { id: folderId, kind: "private", ownerId: owner.id, encName: "v1.x" } });
    expect((await call(owner, "POST", `/me/agent-deposits/${d.body.id}/keep`, await keepBody(d, 1, { owner, folderId }))).statusCode).toBe(201);
    expect((await t.prisma.record.findUniqueOrThrow({ where: { id: d.body.id } })).folderId).toBe(folderId);

    const e = await deposit(owner, agent, access);
    expect((await call(owner, "DELETE", `/me/agent-deposits/${e.body.id}`)).statusCode).toBe(204);
    expect(await t.prisma.agentDeposit.count()).toBe(0);
    expect(await t.prisma.event.findFirst({ where: { action: "agent.deposit_delete" } })).toMatchObject({ orgId: null, actorId: owner.id, recordId: e.body.id });
  });
});

describe("lifetime", () => {
  it("sweepAgentWrites deletes a deposit 90 days on, not before", async () => {
    const { owner, agent, access } = await setup();
    const d = await deposit(owner, agent, access);
    const created = (await t.prisma.agentDeposit.findUniqueOrThrow({ where: { id: d.body.id } })).createdAt.getTime();
    expect(await sweepAgentWrites(t.prisma, new Date(created + 89 * 86400e3))).toBe(0);
    expect(await t.prisma.agentDeposit.count()).toBe(1);
    expect(await sweepAgentWrites(t.prisma, new Date(created + 91 * 86400e3))).toBe(1);
    expect(await t.prisma.agentDeposit.count()).toBe(0);
  });

  it("revoking the agent deletes its unkept deposits and leaves a kept record", async () => {
    const { owner, agent, access } = await setup();
    const kept = await deposit(owner, agent, access);
    expect((await call(owner, "POST", `/me/agent-deposits/${kept.body.id}/keep`, await keepBody(kept, 1, { owner }))).statusCode).toBe(201);
    await deposit(owner, agent, access);
    expect((await call(owner, "DELETE", `/me/agents/${agent.id}`)).statusCode).toBe(200);
    expect(await t.prisma.agentDeposit.count()).toBe(0);
    expect(await t.prisma.record.findUniqueOrThrow({ where: { id: kept.body.id } })).toMatchObject({ createdByAgentId: agent.id });
  });
});
