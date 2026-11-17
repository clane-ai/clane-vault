import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { randomBytes, randomUUID } from "node:crypto";
import { exportPKCS8, generateKeyPair as joseKeyPair } from "jose";
import {
  aeadDecrypt, aeadEncrypt, agentDepositMessage, agentUpdateMessage, b64url, createTeamFolder, encryptNewRecord, sealDepositKeyToOwner,
  sealPersonalAgentRecordKey, sha256B64, utf8, wrapKey,
} from "@clane-vault/crypto";
import { makeTestApp, resetDb, createActiveUser, orgHeader } from "./helpers.js";
import { createTestPersonalAgent } from "./agentHelpers.js";
import { startFakeGateway } from "./fakeGateway.js";
import { hashToken, signAgentAccess } from "../src/lib/tokens.js";
import { updateMessage } from "../src/lib/agents.js";
import { sweepAgentWrites } from "../src/lib/personalAgents.js";

const fake = await startFakeGateway();
const tokenPrivateKeyPem = await exportPKCS8((await joseKeyPair("ES256", { extractable: true })).privateKey);
const agents = { gatewayInternalUrl: fake.url, gatewayPublicUrl: "https://gw.test/mcp", gatewayApiToken: fake.token, tokenPrivateKeyPem, acceptNewGatewayIdentity: false, personalAgents: true };
const t = await makeTestApp({ agents });
afterAll(async () => { await t.app.close(); await fake.close(); });
beforeEach(async () => { await resetDb(t.prisma); fake.dropped.length = 0; });

type U = Awaited<ReturnType<typeof createActiveUser>>;
type PA = Awaited<ReturnType<typeof createTestPersonalAgent>>;
type Rec = { id: string; recordKey: Uint8Array; encBody: string };
let ipSeq = 0;
const ip = () => `10.246.${(++ipSeq >> 8) & 255}.${ipSeq & 255}`;
const call = (u: U, method: "GET" | "POST" | "PUT" | "PATCH", url: string, payload?: unknown, o: { org?: boolean } = {}) =>
  t.app.inject({ method, url: `/api/v1${url}`, payload: payload as object, remoteAddress: ip(), headers: { authorization: `Bearer ${u.accessToken}`, ...(o.org ? orgHeader(u) : {}) } });
const agentCall = (token: string, method: "GET" | "POST" | "PUT", url: string, payload?: unknown) =>
  t.app.inject({ method, url: `/api/v1${url}`, payload: payload as object, remoteAddress: ip(), headers: { authorization: `Bearer ${token}`, "x-gateway-token": fake.token } });

async function setup(owner?: U) {
  owner ??= await createActiveUser(t, { role: "owner" });
  const agent = await createTestPersonalAgent(t, { ownerUserId: owner.id, verified: true });
  const grant = (await t.prisma.agentToken.create({ data: { agentId: agent.id, label: "CLI", tokenHash: hashToken(randomBytes(16).toString("hex")), createdById: owner.id } })).id;
  return { owner, agent, access: (await signAgentAccess(t.config, { agentId: agent.id, orgId: null, ownerUserId: owner.id, grant })).token };
}
async function record(owner: U): Promise<Rec> {
  const id = randomUUID();
  const enc = await encryptNewRecord(id, { type: "login", title: "Stripe", password: "old" }, owner.keys.userKey);
  expect((await call(owner, "POST", "/records", { id, folderId: null, type: "login", encBody: enc.encBody, wrappedRecordKey: enc.wrappedRecordKey })).statusCode).toBe(201);
  return { id, recordKey: enc.recordKey, encBody: enc.encBody };
}
const seal = (r: Rec, owner: U, a: PA) => sealPersonalAgentRecordKey(r.recordKey, { ownerUserId: owner.id, agentId: a.id, recordId: r.id }, b64url.decode(a.publicKey));
async function granted(owner: U, a: PA, o: { write?: boolean } = {}) {
  const r = await record(owner);
  expect((await call(owner, "POST", `/records/${r.id}/agent-grants`, { agentId: a.id, wrappedRecordKey: await seal(r, owner, a) })).statusCode).toBe(201);
  if (o.write) expect((await call(owner, "PATCH", `/records/${r.id}/agent-grants/${a.id}`, { write: true })).statusCode).toBe(200);
  return r;
}
/** What the gateway sends for update_secret on a record: a new body under the record key, signed u1. at revision + 1. */
async function update(owner: U, a: PA, r: Rec, revision: number, o: { password?: string; signedBody?: string } = {}) {
  const encBody = await aeadEncrypt(r.recordKey, utf8.encode(JSON.stringify({ type: "login", title: "Stripe", password: o.password ?? "new" })), `record-body:${r.id}`);
  const signature = await fake.sign("u1", agentUpdateMessage({ ownerUserId: owner.id, agentId: a.id, id: r.id, revision: revision + 1, encBodyHash: await sha256B64(o.signedBody ?? encBody) }));
  return { encBody, revision, signature };
}
const put = (access: string, r: Rec, b: unknown) => agentCall(access, "PUT", `/agent/records/${r.id}`, b);
const refused = async (res: Awaited<ReturnType<typeof put>>, error: string) => expect([res.statusCode, res.json()]).toEqual([409, { error }]);
const personalRecord = async (owner: U, id: string) => (await call(owner, "GET", "/sync")).json().records.find((x: { id: string }) => x.id === id);

describe("the API's update message", () => {
  it("is byte-identical to the crypto package's", () => {
    const m = { ownerUserId: "u", agentId: "a", id: "r", revision: 3, encBodyHash: "h" };
    expect(updateMessage(m)).toBe(agentUpdateMessage(m));
  });
});

describe("PUT /agent/records/:id", () => {
  it("not_writable until the owner allows writes; then revision 2, and the previous body is kept and still opens with the record key", async () => {
    const { owner, agent, access } = await setup();
    const r = await granted(owner, agent);
    await refused(await put(access, r, await update(owner, agent, r, 1)), "not_writable");
    expect((await agentCall(access, "GET", "/agent/sync")).json().records[0].write).toBe(false);

    const p = await call(owner, "PATCH", `/records/${r.id}/agent-grants/${agent.id}`, { write: true });
    expect([p.statusCode, p.json()]).toEqual([200, { ok: true }]);
    expect(await t.prisma.event.findFirst({ where: { action: "agent.item_write" } })).toMatchObject({ orgId: null, actorId: owner.id, recordId: r.id, meta: { write: true } });
    expect((await agentCall(access, "GET", "/agent/sync")).json().records[0].write).toBe(true);
    expect((await personalRecord(owner, r.id)).agentGrants).toEqual([{ agentId: agent.id, use: true, write: true }]);

    const u = await update(owner, agent, r, 1);
    const res = await put(access, r, u);
    expect([res.statusCode, res.json()]).toEqual([200, { id: r.id, revision: 2 }]);
    expect(await t.prisma.record.findUniqueOrThrow({ where: { id: r.id } })).toMatchObject({ encBody: u.encBody, revision: 2, type: "login" });
    expect(await t.prisma.event.findFirst({ where: { action: "agent.update" } })).toMatchObject({ orgId: null, actorId: agent.id, recordId: r.id });

    const list = (await call(owner, "GET", `/records/${r.id}/agent-overwrites`)).json().overwrites;
    expect(list).toHaveLength(1);
    expect(list[0]).toMatchObject({ agentId: agent.id, agentName: "Personal agent", prevEncBody: r.encBody, newRevision: 2, signature: u.signature });
    const prev = JSON.parse(utf8.decode(await aeadDecrypt(r.recordKey, list[0].prevEncBody, `record-body:${r.id}`)));
    expect(prev.password).toBe("old");
  });

  it("a stale revision is a conflict and leaves no overwrite row; so is a signature over another body", async () => {
    const { owner, agent, access } = await setup();
    const r = await granted(owner, agent, { write: true });
    // A person saved in between: the agent's revision is stale.
    const mine = await aeadEncrypt(r.recordKey, utf8.encode(JSON.stringify({ type: "login", title: "Stripe", password: "mine" })), `record-body:${r.id}`);
    expect((await call(owner, "PUT", `/records/${r.id}`, { encBody: mine, revision: 1 })).statusCode).toBe(200);
    await refused(await put(access, r, await update(owner, agent, r, 1)), "conflict");
    expect(await t.prisma.recordAgentOverwrite.count()).toBe(0);
    await refused(await put(access, r, await update(owner, agent, r, 2, { signedBody: "v1.another" })), "conflict");
    expect(await t.prisma.recordAgentOverwrite.count()).toBe(0);
    expect((await t.prisma.record.findUniqueOrThrow({ where: { id: r.id } })).encBody).toBe(mine);
  });

  it("six updates keep five overwrites; /sync shows agentChange until a person saves, or until ack", async () => {
    const { owner, agent, access } = await setup();
    const r = await granted(owner, agent, { write: true });
    for (let rev = 1; rev <= 6; rev++) expect((await put(access, r, await update(owner, agent, r, rev, { password: `p${rev}` }))).statusCode).toBe(200);
    const list = (await call(owner, "GET", `/records/${r.id}/agent-overwrites`)).json().overwrites;
    expect(list.map((o: { newRevision: number }) => o.newRevision)).toEqual([7, 6, 5, 4, 3]);
    const s = await personalRecord(owner, r.id);
    expect(s).toMatchObject({ revision: 7, agentChange: { agentId: agent.id, agentName: "Personal agent", signature: list[0].signature } });
    expect(Date.parse(s.agentChange.at)).not.toBeNaN();

    // The owner's save (e.g. a restore of a previous body) hides it.
    expect((await call(owner, "PUT", `/records/${r.id}`, { encBody: list[0].prevEncBody, revision: 7 })).statusCode).toBe(200);
    expect(await personalRecord(owner, r.id)).not.toHaveProperty("agentChange");

    expect((await put(access, r, await update(owner, agent, r, 8))).statusCode).toBe(200);
    expect(await personalRecord(owner, r.id)).toHaveProperty("agentChange");
    expect((await call(owner, "POST", `/records/${r.id}/agent-overwrites/ack`)).statusCode).toBe(200);
    expect(await personalRecord(owner, r.id)).not.toHaveProperty("agentChange");
    expect(await t.prisma.recordAgentOverwrite.count({ where: { ackedAt: null } })).toBe(0);
  });

  it("only PATCH agent-grants sets agentWrite: not keep, not the shares route; write: false drops the agent's cache", async () => {
    const { owner, agent, access } = await setup();
    const id = randomUUID();
    const enc = await encryptNewRecord(id, { type: "login", title: "Dep", password: "x" }, owner.keys.userKey);
    const ownerPublicKey = (await t.prisma.user.findUniqueOrThrow({ where: { id: owner.id } })).publicKey;
    const d = { id, type: "login", encBody: enc.encBody,
      signature: await fake.sign("d1", agentDepositMessage({ ownerUserId: owner.id, ownerPublicKey, agentId: agent.id, id, revision: 1, encBodyHash: await sha256B64(enc.encBody) })),
      ownerSealedKey: await sealDepositKeyToOwner(enc.recordKey, { ownerUserId: owner.id, id }, owner.keys.publicKey),
      agentSealedKey: await seal({ id, recordKey: enc.recordKey, encBody: enc.encBody }, owner, agent) };
    expect((await agentCall(access, "POST", "/agent/deposits", d)).statusCode).toBe(201);
    const keep = await call(owner, "POST", `/me/agent-deposits/${id}/keep`, { revision: 1, folderId: null, wrappedRecordKey: await wrapKey(enc.recordKey, owner.keys.userKey, `record-key:${id}`),
      agentWrappedRecordKey: d.agentSealedKey });
    expect(keep.statusCode).toBe(201);
    const row = () => t.prisma.recordAccess.findFirstOrThrow({ where: { recordId: id, holderId: agent.id } });
    expect((await row()).agentWrite).toBe(false);
    await call(owner, "PATCH", `/records/${id}/shares/${agent.id}`, { permission: "use", agentWrite: true, write: true });
    expect((await row()).agentWrite).toBe(false);

    expect((await call(owner, "PATCH", `/records/${id}/agent-grants/${agent.id}`, { write: true })).statusCode).toBe(200);
    expect((await row()).agentWrite).toBe(true);
    expect((await call(owner, "PATCH", `/records/${id}/agent-grants/${agent.id}`, { write: false })).statusCode).toBe(200);
    expect((await row()).agentWrite).toBe(false);
    await expect.poll(() => fake.dropped).toContain(agent.id);
    // No row, or another person's record: 404.
    const other = await createActiveUser(t);
    expect((await call(other, "PATCH", `/records/${id}/agent-grants/${agent.id}`, { write: true })).statusCode).toBe(404);
    expect((await call(owner, "PATCH", `/records/${randomUUID()}/agent-grants/${agent.id}`, { write: true })).statusCode).toBe(404);
  });

  it("not_writable under a write: false policy (and the sync's write is false), and after a move into a team folder", async () => {
    const { owner, agent, access } = await setup();
    const r = await granted(owner, agent, { write: true });
    await t.prisma.organization.update({ where: { id: owner.orgId! }, data: { policies: { personalAgents: { write: false } } } });
    await refused(await put(access, r, await update(owner, agent, r, 1)), "not_writable");
    expect((await agentCall(access, "GET", "/agent/sync")).json().records[0].write).toBe(false);
    await t.prisma.organization.update({ where: { id: owner.orgId! }, data: { policies: {} } });

    const fid = randomUUID();
    const f = await createTeamFolder(fid, "Infra", owner.keys.publicKey);
    expect((await call(owner, "POST", "/folders", { id: fid, kind: "team", encName: f.encName, wrappedFolderKey: f.wrappedFolderKey }, { org: true })).statusCode).toBe(201);
    const mv = await call(owner, "PUT", `/records/${r.id}/folder`, { folderId: fid, folderWrappedRecordKey: await wrapKey(r.recordKey, f.folderKey, `record-key:${r.id}`) }, { org: true });
    expect(mv.statusCode).toBe(200);
    await refused(await put(access, r, await update(owner, agent, r, 1)), "not_writable");
    expect(await t.prisma.record.findUniqueOrThrow({ where: { id: r.id }, select: { revision: true } })).toEqual({ revision: 1 });
  });

  it("not_writable for another owner's agent and on another user's record; trashed records too", async () => {
    const a = await setup();
    const b = await setup();
    const r = await granted(a.owner, a.agent, { write: true });
    // b's agent holds a (forged) write row on a's record: still not the agent owner's record.
    await t.prisma.recordAccess.create({ data: { recordId: r.id, holderType: "user", holderId: b.agent.id, permission: "use", wrappedRecordKey: "s1.x", agentWrite: true } });
    await refused(await put(b.access, r, await update(b.owner, b.agent, r, 1)), "not_writable");
    const theirs = await granted(b.owner, b.agent, { write: true });
    await refused(await put(a.access, theirs, await update(a.owner, a.agent, theirs, 1)), "not_writable");

    await t.prisma.record.update({ where: { id: r.id }, data: { deletedAt: new Date() } });
    await refused(await put(a.access, r, await update(a.owner, a.agent, r, 1)), "not_writable");
    expect(await t.prisma.recordAgentOverwrite.count()).toBe(0);
  });
});

describe("lifetime", () => {
  it("sweepAgentWrites deletes overwrites 30 days on, not before", async () => {
    const { owner, agent, access } = await setup();
    const r = await granted(owner, agent, { write: true });
    expect((await put(access, r, await update(owner, agent, r, 1))).statusCode).toBe(200);
    const at = (await t.prisma.recordAgentOverwrite.findFirstOrThrow()).createdAt.getTime();
    expect(await sweepAgentWrites(t.prisma, new Date(at + 29 * 86400e3))).toBe(0);
    expect(await sweepAgentWrites(t.prisma, new Date(at + 31 * 86400e3))).toBe(1);
    expect(await t.prisma.recordAgentOverwrite.count()).toBe(0);
  });
});
