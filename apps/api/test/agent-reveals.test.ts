import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { randomBytes, randomUUID } from "node:crypto";
import { exportPKCS8, generateKeyPair as joseKeyPair } from "jose";
import { b64url, createTeamFolder, encryptNewRecord, openRevealStub, REVEAL_REF, sealPersonalAgentRecordKey, sealRevealStub, wrapKey } from "@clane-vault/crypto";
import { makeTestApp, resetDb, createActiveUser, orgHeader } from "./helpers.js";
import { createTestPersonalAgent } from "./agentHelpers.js";
import { startFakeGateway } from "./fakeGateway.js";
import { hashToken, signAgentAccess } from "../src/lib/tokens.js";
import { REVEAL_FIELD } from "../src/routes/agentReveals.js";

const fake = await startFakeGateway();
const tokenPrivateKeyPem = await exportPKCS8((await joseKeyPair("ES256", { extractable: true })).privateKey);
const agents = { gatewayInternalUrl: fake.url, gatewayPublicUrl: "https://gw.test/mcp", gatewayApiToken: fake.token, tokenPrivateKeyPem, acceptNewGatewayIdentity: false, personalAgents: true };
const t = await makeTestApp({ agents });
afterAll(async () => { await t.app.close(); await fake.close(); });
beforeEach(async () => { await resetDb(t.prisma); fake.dropped.length = 0; });

type U = Awaited<ReturnType<typeof createActiveUser>>;
type PA = Awaited<ReturnType<typeof createTestPersonalAgent>>;
let ipSeq = 0;
const ip = () => `10.245.${(++ipSeq >> 8) & 255}.${ipSeq & 255}`;
const call = (u: U, method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE", url: string, payload?: unknown, o: { org?: boolean } = {}) =>
  t.app.inject({ method, url: `/api/v1${url}`, payload: payload as object, remoteAddress: ip(), headers: { authorization: `Bearer ${u.accessToken}`, ...(o.org === false ? {} : orgHeader(u)) } });
const agentCall = (token: string, method: "GET" | "POST", url: string, payload?: unknown) =>
  t.app.inject({ method, url: `/api/v1${url}`, payload: payload as object, remoteAddress: ip(), headers: { authorization: `Bearer ${token}`, "x-gateway-token": fake.token } });

async function setup() {
  const owner = await createActiveUser(t, { role: "owner" });
  const agent = await createTestPersonalAgent(t, { ownerUserId: owner.id, verified: true });
  const grant = (await t.prisma.agentToken.create({ data: { agentId: agent.id, label: "ci", tokenHash: hashToken(randomBytes(16).toString("hex")), createdById: owner.id } })).id;
  const access = (await signAgentAccess(t.config, { agentId: agent.id, orgId: null, ownerUserId: owner.id, grant })).token;
  return { owner, agent, access };
}
async function record(owner: U) {
  const id = randomUUID();
  const enc = await encryptNewRecord(id, { type: "login", title: "Stripe", username: "u", password: "x" }, owner.keys.userKey);
  expect((await call(owner, "POST", "/records", { id, folderId: null, type: "login", encBody: enc.encBody, wrappedRecordKey: enc.wrappedRecordKey })).statusCode).toBe(201);
  return { id, recordKey: enc.recordKey };
}
async function teamFolder(owner: U) {
  const id = randomUUID();
  const f = await createTeamFolder(id, "Infra", owner.keys.publicKey);
  expect((await call(owner, "POST", "/folders", { id, kind: "team", encName: f.encName, wrappedFolderKey: f.wrappedFolderKey })).statusCode).toBe(201);
  return { id, folderKey: f.folderKey };
}
const stubFor = (owner: U, r: { id: string }, a: PA, fields = ["username"]) =>
  sealRevealStub({ title: "Stripe", type: "login", fields }, { ownerUserId: owner.id, agentId: a.id, recordId: r.id }, b64url.decode(a.publicKey));
const putStub = async (owner: U, r: { id: string }, a: PA, fields = ["username"]) =>
  call(owner, "PUT", `/records/${r.id}/agent-reveal/${a.id}`, { sealedStub: await stubFor(owner, r, a, fields), fields });
const sync = async (access: string) => { const r = await agentCall(access, "GET", "/agent/sync"); expect(r.statusCode).toBe(200); return r.json(); };
const personalRecord = async (owner: U, id: string) => (await call(owner, "GET", "/sync", undefined, { org: false })).json().records.find((x: { id: string }) => x.id === id);
const setReveal = (owner: U, reveal: "off" | "approval" | "standing") =>
  t.prisma.organization.update({ where: { id: owner.orgId! }, data: { policies: { personalAgents: { allowed: true, maxPerMember: null, write: true, reveal } } } });

describe("reveal stubs", () => {
  it("the API's field pattern is the crypto package's", () => {
    expect(REVEAL_FIELD.source).toBe(REVEAL_REF.source);
  });

  it("PUT stores a stub, gives the agent no record key, and the agent's sync lists it", async () => {
    const { owner, agent, access } = await setup();
    const r = await record(owner);
    const p = await putStub(owner, r, agent);
    expect([p.statusCode, p.json()]).toEqual([200, { ok: true }]);
    expect(await t.prisma.recordAccess.count({ where: { holderId: agent.id } })).toBe(0);
    const s = await sync(access);
    expect(s.records).toEqual([]);
    expect(s.reveal).toEqual([{ recordId: r.id, sealedStub: expect.stringMatching(/^s1\./) }]);
    expect(await openRevealStub(s.reveal[0].sealedStub, { ownerUserId: owner.id, agentId: agent.id, recordId: r.id }, { privateKey: agent.privateKey, publicKey: b64url.decode(agent.publicKey) }))
      .toEqual({ title: "Stripe", type: "login", fields: ["username"] });
    expect((await personalRecord(owner, r.id)).agentGrants).toEqual([{ agentId: agent.id, use: false, write: false, reveal: ["username"] }]);
    expect(await t.prisma.event.findFirst({ where: { action: "agent.item_reveal_on" } })).toMatchObject({ orgId: null, recordId: r.id, meta: { fields: ["username"] } });

    // With a use grant too, one entry.
    const wrapped = await sealPersonalAgentRecordKey(r.recordKey, { ownerUserId: owner.id, agentId: agent.id, recordId: r.id }, b64url.decode(agent.publicKey));
    expect((await call(owner, "POST", `/records/${r.id}/agent-grants`, { agentId: agent.id, wrappedRecordKey: wrapped })).statusCode).toBe(201);
    expect((await personalRecord(owner, r.id)).agentGrants).toEqual([{ agentId: agent.id, use: true, write: false, reveal: ["username"] }]);

    const d = await call(owner, "DELETE", `/records/${r.id}/agent-reveal/${agent.id}`);
    expect(d.statusCode).toBe(204);
    await expect.poll(() => fake.dropped).toContain(agent.id);
    expect((await sync(access)).reveal).toEqual([]);
    expect(await t.prisma.event.count({ where: { action: "agent.item_reveal_off", recordId: r.id } })).toBe(1);
    expect((await call(owner, "DELETE", `/records/${r.id}/agent-reveal/${agent.id}`)).statusCode).toBe(404);
  });

  it("refuses as grants do, and on fields and policy", async () => {
    const { owner, agent, access } = await setup();
    const f = await teamFolder(owner);
    const r = await record(owner);
    const mv = await record(owner);
    await call(owner, "PUT", `/records/${mv.id}/folder`, { folderId: f.id, folderWrappedRecordKey: await wrapKey(mv.recordKey, f.folderKey, `record-key:${mv.id}`) });
    expect((await putStub(owner, mv, agent)).json()).toEqual({ error: "team_record" });
    const other = await createActiveUser(t, { role: "member", orgId: owner.orgId! });
    const theirs = await createTestPersonalAgent(t, { ownerUserId: other.id, verified: true });
    const p = await putStub(owner, r, theirs);
    expect([p.statusCode, p.json()]).toEqual([400, { error: "user_not_active" }]);
    expect((await putStub(other, r, theirs)).statusCode).toBe(404);
    for (const fields of [["totpSecret"], [], ["username", "username"], ["a,b"]])
      expect((await call(owner, "PUT", `/records/${r.id}/agent-reveal/${agent.id}`, { sealedStub: await stubFor(owner, r, agent), fields })).statusCode).toBe(400);

    expect((await putStub(owner, r, agent)).statusCode).toBe(200);
    await setReveal(owner, "off");
    const off = await putStub(owner, r, agent);
    expect([off.statusCode, off.json()]).toEqual([403, { error: "reveal_disabled" }]);
    expect((await sync(access)).reveal).toEqual([]);
  });

  it("Review Focus 2: a move into a team folder deletes the stub; a trashed record's stub is not synced; revoke deletes stubs", async () => {
    const { owner, agent, access } = await setup();
    const f = await teamFolder(owner);
    const moved = await record(owner);
    expect((await putStub(owner, moved, agent)).statusCode).toBe(200);
    const mv = await call(owner, "PUT", `/records/${moved.id}/folder`, { folderId: f.id, folderWrappedRecordKey: await wrapKey(moved.recordKey, f.folderKey, `record-key:${moved.id}`) });
    expect(mv.statusCode).toBe(200);
    expect(await t.prisma.agentRevealGrant.count({ where: { recordId: moved.id } })).toBe(0);
    await expect.poll(() => fake.dropped).toContain(agent.id);

    const r = await record(owner);
    expect((await putStub(owner, r, agent)).statusCode).toBe(200);
    expect((await call(owner, "DELETE", `/records/${r.id}`)).statusCode).toBe(204);
    expect((await sync(access)).reveal).toEqual([]);
    expect((await call(owner, "POST", `/records/${r.id}/restore`)).statusCode).toBeLessThan(300);
    expect((await sync(access)).reveal).toHaveLength(1);

    expect((await call(owner, "DELETE", `/me/agents/${agent.id}`, undefined, { org: false })).statusCode).toBe(200);
    expect(await t.prisma.agentRevealGrant.count({ where: { agentId: agent.id } })).toBe(0);
  });

  it("at 200 stubs the agent takes no more", async () => {
    const { owner, agent } = await setup();
    const ids = Array.from({ length: 200 }, () => randomUUID());
    await t.prisma.record.createMany({ data: ids.map((id) => ({ id, ownerId: owner.id, type: "item", encBody: "x" })) });
    await t.prisma.agentRevealGrant.createMany({ data: ids.map((recordId) => ({ recordId, agentId: agent.id, sealedStub: "s1.x", fields: ["username"] })) });
    const r = await record(owner);
    expect((await putStub(owner, r, agent)).json()).toEqual({ error: "agent_item_limit" });
    expect((await putStub(owner, { id: ids[0]! }, agent)).statusCode).not.toBe(409); // replacing one already held is not a new item
  });
});

describe("PATCH /records/:id/agent-grants/:agentId (carried)", () => {
  it("only on the caller's own live private record, for a live verified agent", async () => {
    const { owner, agent } = await setup();
    const r = await record(owner);
    const wrapped = await sealPersonalAgentRecordKey(r.recordKey, { ownerUserId: owner.id, agentId: agent.id, recordId: r.id }, b64url.decode(agent.publicKey));
    expect((await call(owner, "POST", `/records/${r.id}/agent-grants`, { agentId: agent.id, wrappedRecordKey: wrapped })).statusCode).toBe(201);
    const patch = () => call(owner, "PATCH", `/records/${r.id}/agent-grants/${agent.id}`, { write: true });
    expect((await patch()).statusCode).toBe(200);

    expect((await call(owner, "DELETE", `/records/${r.id}`)).statusCode).toBe(204);
    expect((await patch()).json()).toEqual({ error: "in_trash" });
    await t.prisma.record.update({ where: { id: r.id }, data: { deletedAt: null } });

    await t.prisma.recordAccess.updateMany({ where: { recordId: r.id, holderId: agent.id }, data: { state: "pending" } });
    expect((await patch()).statusCode).toBe(404);
    await t.prisma.recordAccess.updateMany({ where: { recordId: r.id, holderId: agent.id }, data: { state: "active" } });

    await t.prisma.agent.update({ where: { userId: agent.id }, data: { revokedAt: new Date() } });
    expect((await patch()).json()).toEqual({ error: "user_not_active" });
  });
});
