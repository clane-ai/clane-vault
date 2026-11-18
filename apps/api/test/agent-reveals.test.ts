import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { randomBytes, randomUUID } from "node:crypto";
import { exportPKCS8, generateKeyPair as joseKeyPair } from "jose";
import { agentRevealRequestMessage, b64url, createTeamFolder, encryptNewRecord, generateKeyPair, openReveal, openRevealStub, REVEAL_REF, sealPersonalAgentRecordKey, sealReveal, sealRevealStub, wrapKey } from "@clane-vault/crypto";
import { makeTestApp, resetDb, createActiveUser, orgHeader } from "./helpers.js";
import { createTestPersonalAgent } from "./agentHelpers.js";
import { startFakeGateway } from "./fakeGateway.js";
import { hashToken, signAgentAccess } from "../src/lib/tokens.js";
import { REVEAL_FIELD } from "../src/routes/agentReveals.js";
import { revealRequestMessage } from "../src/lib/agents.js";
import { sweepAgentWrites } from "../src/lib/personalAgents.js";

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

/** Plays the gateway: a one-time X25519 pair and a q1 signature by the fake gateway's identity key. */
async function ask(owner: U, agent: PA, access: string, recordId: string, o: { fields?: string[]; expiresAt?: string; signedKey?: string; reason?: string } = {}) {
  const kp = await generateKeyPair();
  const id = randomUUID(), fields = o.fields ?? ["username"], requestPublicKey = b64url.encode(kp.publicKey);
  const expiresAt = o.expiresAt ?? new Date(Date.now() + 5 * 60e3).toISOString();
  const signature = await fake.sign("q1", agentRevealRequestMessage({ requestId: id, ownerUserId: owner.id, agentId: agent.id, recordId, fields, requestPublicKey: o.signedKey ?? requestPublicKey, expiresAt }));
  const res = await agentCall(access, "POST", "/agent/reveals", { id, recordId, fields, reason: o.reason ?? "to log in", requestPublicKey, signature, expiresAt });
  return { id, kp, res };
}
const poll = (access: string, id: string) => agentCall(access, "GET", `/agent/reveals/${id}`);
const rids = (id: string, recordId: string, agentId: string) => ({ requestId: id, recordId, agentId });
const approve = async (owner: U, q: { id: string; kp: { publicKey: Uint8Array } }, recordId: string, agentId: string) =>
  call(owner, "POST", `/me/agent-reveals/${q.id}/approve`, { sealed: await sealReveal({ username: "u" }, rids(q.id, recordId, agentId), q.kp.publicKey) }, { org: false });

describe("reveal requests", () => {
  afterEach(() => { vi.restoreAllMocks(); });

  it("the API's request message is the crypto package's", () => {
    const m = { requestId: "q", ownerUserId: "u", agentId: "a", recordId: "r", fields: ["username", "password"], requestPublicKey: "k", expiresAt: "2026-11-15T10:00:00.000Z" };
    expect(revealRequestMessage(m)).toBe(agentRevealRequestMessage(m));
  });

  it("the happy path: ask, list, approve, deliver once", async () => {
    const { owner, agent, access } = await setup();
    const r = await record(owner);
    expect((await putStub(owner, r, agent)).statusCode).toBe(200);
    const q = await ask(owner, agent, access, r.id, { reason: "to check the account" });
    expect(q.res.statusCode).toBe(201);
    expect(q.res.json()).toEqual({ id: q.id, expiresAt: expect.any(String) });
    expect((await poll(access, q.id)).json()).toEqual({ status: "pending" });
    const list = (await call(owner, "GET", "/me/agent-reveals", undefined, { org: false })).json();
    expect(list.requests).toEqual([expect.objectContaining({ id: q.id, agentId: agent.id, agentName: "Personal agent", app: "ci", recordId: r.id, fields: ["username"], reason: "to check the account" })]);
    expect(list.paused).toEqual([]);
    const sealed = await sealReveal({ username: "u" }, rids(q.id, r.id, agent.id), q.kp.publicKey);
    expect((await call(owner, "POST", `/me/agent-reveals/${q.id}/approve`, { sealed }, { org: false })).json()).toEqual({ ok: true });
    const got = (await poll(access, q.id)).json();
    expect(got).toEqual({ status: "approved", sealed });
    expect(await openReveal(got.sealed, rids(q.id, r.id, agent.id), q.kp)).toEqual({ username: "u" });
    expect((await poll(access, q.id)).json()).toEqual({ status: "expired" });
    expect(await t.prisma.agentRevealRequest.findUnique({ where: { id: q.id } })).toMatchObject({ status: "delivered", sealed: null });
    const ev = await t.prisma.event.findMany({ where: { action: { startsWith: "agent.reveal" } }, orderBy: { id: "asc" } });
    expect(ev.map((e) => e.action)).toEqual(["agent.reveal_request", "agent.reveal"]);
    for (const e of ev) { expect(e).toMatchObject({ orgId: null, recordId: r.id, meta: { requestId: q.id, fields: ["username"], app: "ci" } }); expect(JSON.stringify(e.meta)).not.toContain("\"u\""); }
    const orgLog = (await call(owner, "GET", "/admin/events")).json();
    expect(JSON.stringify(orgLog)).not.toContain("agent.reveal");
  });

  it("refusals: no stub, a field outside it, a swapped key, a far expiry, busy", async () => {
    const { owner, agent, access } = await setup();
    const r = await record(owner);
    expect((await ask(owner, agent, access, r.id)).res.json()).toEqual({ error: "reveal_off" });
    expect((await putStub(owner, r, agent)).statusCode).toBe(200);
    expect((await ask(owner, agent, access, r.id, { fields: ["password"] })).res.json()).toEqual({ error: "reveal_off" });
    expect((await ask(owner, agent, access, r.id, { signedKey: b64url.encode((await generateKeyPair()).publicKey) })).res.json()).toEqual({ error: "reveal_off" });
    expect((await ask(owner, agent, access, r.id, { expiresAt: new Date(Date.now() + 3600e3).toISOString() })).res.json()).toEqual({ error: "reveal_off" });
    expect((await ask(owner, agent, access, r.id)).res.statusCode).toBe(201);
    const busy = await ask(owner, agent, access, r.id);
    expect([busy.res.statusCode, busy.res.json()]).toEqual([409, { error: "busy" }]);
  });

  it("Review Focus 1: expiry with nobody answering, and an approved-but-unfetched request", async () => {
    const { owner, agent, access } = await setup();
    const r = await record(owner);
    await putStub(owner, r, agent);
    const q = await ask(owner, agent, access, r.id);
    await t.prisma.agentRevealRequest.update({ where: { id: q.id }, data: { expiresAt: new Date(Date.now() - 1000) } });
    expect((await poll(access, q.id)).json()).toEqual({ status: "expired" });
    expect((await poll(access, q.id)).json()).toEqual({ status: "expired" });
    expect(await t.prisma.event.count({ where: { action: "agent.reveal_expired" } })).toBe(1);
    const late = await approve(owner, q, r.id, agent.id);
    expect([late.statusCode, late.json()]).toEqual([409, { error: "expired" }]);

    const q2 = await ask(owner, agent, access, r.id);
    expect(q2.res.statusCode).toBe(201);
    await approve(owner, q2, r.id, agent.id);
    await t.prisma.agentRevealRequest.update({ where: { id: q2.id }, data: { expiresAt: new Date(Date.now() - 1000) } });
    expect((await poll(access, q2.id)).json()).toEqual({ status: "expired" });
    expect(await t.prisma.agentRevealRequest.findUnique({ where: { id: q2.id } })).toMatchObject({ status: "expired", sealed: null });

    // The sweep does the same for rows nobody polls.
    const q3 = await ask(owner, agent, access, r.id);
    await approve(owner, q3, r.id, agent.id);
    await t.prisma.agentRevealRequest.update({ where: { id: q3.id }, data: { expiresAt: new Date(Date.now() - 1000) } });
    await sweepAgentWrites(t.prisma);
    expect(await t.prisma.agentRevealRequest.findUnique({ where: { id: q3.id } })).toMatchObject({ status: "expired", sealed: null });
  });

  it("three denials in ten minutes pause the agent's requests for an hour", async () => {
    const { owner, agent, access } = await setup();
    const r = await record(owner);
    await putStub(owner, r, agent);
    for (let i = 0; i < 3; i++) {
      const q = await ask(owner, agent, access, r.id);
      expect(q.res.statusCode).toBe(201);
      expect((await call(owner, "POST", `/me/agent-reveals/${q.id}/deny`, undefined, { org: false })).json()).toEqual({ ok: true });
      expect((await poll(access, q.id)).json()).toEqual({ status: "denied" });
    }
    expect((await ask(owner, agent, access, r.id)).res.json()).toEqual({ error: "denied" });
    const list = (await call(owner, "GET", "/me/agent-reveals", undefined, { org: false })).json();
    expect(list.paused).toEqual([{ agentId: agent.id, agentName: "Personal agent", until: expect.any(String) }]);
    expect(await t.prisma.event.count({ where: { action: "agent.reveal_denied", orgId: null } })).toBe(3);
    await t.prisma.agent.update({ where: { userId: agent.id }, data: { revealPausedUntil: new Date(Date.now() - 1000) } });
    expect((await ask(owner, agent, access, r.id)).res.statusCode).toBe(201);
  });

  it("policy off after the request: approve is 403 reveal_disabled", async () => {
    const { owner, agent, access } = await setup();
    const r = await record(owner);
    await putStub(owner, r, agent);
    const q = await ask(owner, agent, access, r.id);
    await setReveal(owner, "off");
    const a = await approve(owner, q, r.id, agent.id);
    expect([a.statusCode, a.json()]).toEqual([403, { error: "reveal_disabled" }]);
  });

  it("another user sees nothing; a private-locked session is refused", async () => {
    const { owner, agent, access } = await setup();
    const r = await record(owner);
    await putStub(owner, r, agent);
    const q = await ask(owner, agent, access, r.id);
    const other = await createActiveUser(t, { role: "member", orgId: owner.orgId! });
    expect((await call(other, "GET", "/me/agent-reveals", undefined, { org: false })).json().requests).toEqual([]);
    expect((await call(other, "POST", `/me/agent-reveals/${q.id}/approve`, { sealed: "s1.a.b.c" }, { org: false })).statusCode).toBe(404);
    expect((await call(other, "POST", `/me/agent-reveals/${q.id}/deny`, undefined, { org: false })).statusCode).toBe(404);
    await t.prisma.session.updateMany({ where: { userId: owner.id }, data: { totpSkippedForOrg: owner.orgId } });
    const locked = await call(owner, "GET", "/me/agent-reveals");
    expect([locked.statusCode, locked.json()]).toEqual([403, { error: "totp_step_up_required" }]);
  });

  it("email: one per ten minutes, nothing that names the request, and none when switched off", async () => {
    const { owner, agent, access } = await setup();
    const send = vi.spyOn(t.app.mail, "send").mockResolvedValue(true);
    const r = await record(owner);
    await putStub(owner, r, agent);
    const q = await ask(owner, agent, access, r.id, { reason: "a very particular reason" });
    await expect.poll(() => send.mock.calls.length).toBe(1);
    const [to, msg] = send.mock.calls[0]! as unknown as [string, { subject: string; text: string }];
    expect(to).toBe(owner.email);
    expect(msg.subject).toBe("An agent is asking for a secret");
    expect(msg.text).toMatch(/^An agent is asking for a secret\. Open .+ to answer: /);
    for (const bad of [r.id, q.id, "a very particular reason", "/agent-reveals"]) expect(msg.text).not.toContain(bad);
    await call(owner, "POST", `/me/agent-reveals/${q.id}/deny`, undefined, { org: false });
    await t.prisma.user.update({ where: { id: owner.id }, data: { agentRevealEmailedAt: new Date(Date.now() - 2 * 60e3) } });
    const q2 = await ask(owner, agent, access, r.id);
    expect(q2.res.statusCode).toBe(201);
    await call(owner, "POST", `/me/agent-reveals/${q2.id}/deny`, undefined, { org: false });
    await t.prisma.agent.update({ where: { userId: agent.id }, data: { revealPausedUntil: null } });
    expect((await call(owner, "PATCH", "/me/agents/settings", { revealEmail: false }, { org: false })).json()).toEqual({ ok: true });
    expect((await call(owner, "GET", "/me/agents", undefined, { org: false })).json().revealEmail).toBe(false);
    await t.prisma.user.update({ where: { id: owner.id }, data: { agentRevealEmailedAt: new Date(Date.now() - 3600e3) } });
    expect((await ask(owner, agent, access, r.id)).res.statusCode).toBe(201);
    await new Promise((res) => setTimeout(res, 300));
    expect(send.mock.calls.length).toBe(1);
  });

  it("GET /me/agents reports the gateway's reveal mode", async () => {
    const { owner } = await setup();
    expect((await call(owner, "GET", "/me/agents", undefined, { org: false })).json().gateway.reveal).toBe("off");
    fake.setReveal("approval");
    try { expect((await call(owner, "GET", "/me/agents", undefined, { org: false })).json().gateway.reveal).toBe("approval"); } finally { fake.setReveal(undefined); }
  });

  it("revoke lists what was revealed and expires open requests", async () => {
    const { owner, agent, access } = await setup();
    const r = await record(owner);
    await putStub(owner, r, agent);
    const q = await ask(owner, agent, access, r.id);
    await approve(owner, q, r.id, agent.id);
    expect((await poll(access, q.id)).json().status).toBe("approved");
    const open = await ask(owner, agent, access, r.id);
    expect(open.res.statusCode).toBe(201);
    const rv = await call(owner, "DELETE", `/me/agents/${agent.id}`, undefined, { org: false });
    expect(rv.json().rotate.revealed).toEqual([{ id: r.id, fields: ["username"] }]);
    expect(await t.prisma.agentRevealRequest.findUnique({ where: { id: open.id } })).toMatchObject({ status: "expired" });
  });
});

describe("standing reveal (Phase D)", () => {
  const standing = (access: string, recordId: string, fields = ["username"]) => agentCall(access, "POST", "/agent/reveals/standing", { recordId, fields });

  it("needs policy standing and a use grant; logs agent.reveal with standing: true", async () => {
    const { owner, agent, access } = await setup();
    const r = await record(owner);
    await setReveal(owner, "standing");
    expect((await standing(access, r.id)).json()).toEqual({ error: "reveal_off" }); // no grant row
    const wrapped = await sealPersonalAgentRecordKey(r.recordKey, { ownerUserId: owner.id, agentId: agent.id, recordId: r.id }, b64url.decode(agent.publicKey));
    expect((await call(owner, "POST", `/records/${r.id}/agent-grants`, { agentId: agent.id, wrappedRecordKey: wrapped })).statusCode).toBe(201);
    const ok = await standing(access, r.id);
    expect([ok.statusCode, ok.json()]).toEqual([201, { ok: true }]);
    const ev = await t.prisma.event.findMany({ where: { action: "agent.reveal" } });
    expect(ev).toHaveLength(1);
    expect(ev[0]).toMatchObject({ orgId: null, actorId: agent.id, recordId: r.id, meta: { fields: ["username"], app: "ci", standing: true } });
    await setReveal(owner, "approval");
    const off = await standing(access, r.id);
    expect([off.statusCode, off.json()]).toEqual([409, { error: "reveal_off" }]);
    expect((await standing(access, r.id, ["totpSecret"])).statusCode).toBe(400);
  });
});
