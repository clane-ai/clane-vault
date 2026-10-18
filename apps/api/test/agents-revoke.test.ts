import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";
import { exportPKCS8, generateKeyPair as joseKeyPair } from "jose";
import { b64url, createTeamFolder, encryptNewRecord, sealOrgFolderKey, wrapKey } from "@clane-vault/crypto";
import { makeTestApp, resetDb, createActiveUser, orgHeader } from "./helpers.js";
import { createTestAgent } from "./agentHelpers.js";
import { startFakeGateway } from "./fakeGateway.js";
import { hashToken, signAgentAccess } from "../src/lib/tokens.js";

const fake = await startFakeGateway();
const tokenPrivateKeyPem = await exportPKCS8((await joseKeyPair("ES256", { extractable: true })).privateKey);
const agents = { gatewayInternalUrl: fake.url, gatewayPublicUrl: "https://gw.test/mcp", gatewayApiToken: fake.token, tokenPrivateKeyPem, acceptNewGatewayIdentity: false };
const t = await makeTestApp({ agents });
const hosted = await makeTestApp({ agents, billingMode: "hosted" });
afterAll(async () => { await Promise.all([t.app.close(), hosted.app.close()]); await fake.close(); });
beforeEach(async () => { await resetDb(t.prisma); fake.dropped.length = 0; fake.setDown(false); });

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


describe("DELETE /admin/agents/:id", () => {
  it("removes access, lists what to rotate, kills tokens and grants, drops at the gateway", async () => {
    const { owner, agent, tokenId, access } = await setup();
    const f1 = await sharedFolder(owner, agent), f2 = await sharedFolder(owner, agent);
    await record(owner, f1); await record(owner, f2);
    const r3 = await record(owner);
    await t.prisma.recordAccess.create({ data: { recordId: r3, holderType: "user", holderId: agent.id, permission: "use", wrappedRecordKey: "x", sealedTo: agent.publicKey, orgId: owner.orgId } });
    const grant = await t.prisma.agentGrant.create({ data: { agentId: agent.id, clientId: crypto.randomUUID(), grantedById: owner.id, refreshHash: "h", expiresAt: new Date(Date.now() + 864e5) } });
    expect((await agentCall(access, "GET", "/agent/sync")).statusCode).toBe(200);
    // A trashed folder still needs rotating: it can be restored with the key the gateway held.
    await t.prisma.folder.update({ where: { id: f2.id }, data: { deletedAt: new Date() } });

    const r = await call(owner, "DELETE", `/admin/agents/${agent.id}`, { reason: "leaked" });
    expect(r.statusCode).toBe(200);
    expect(r.json().rotate.records).toBe(3);
    expect(r.json().rotate.folders.map((f: { id: string }) => f.id).sort()).toEqual([f1.id, f2.id].sort());
    // offboard leaves trashed folders alone (as for people); the trashed one is in `rotate` above instead.
    expect(await t.prisma.folderMember.count({ where: { userId: agent.id, folder: { deletedAt: null } } })).toBe(0);
    expect(await t.prisma.recordAccess.count({ where: { holderType: "user", holderId: agent.id } })).toBe(0);
    expect(await t.prisma.membership.count({ where: { userId: agent.id } })).toBe(0);
    expect(await t.prisma.membershipKey.count({ where: { userId: agent.id } })).toBe(0);
    expect(await t.prisma.user.findUniqueOrThrow({ where: { id: agent.id } })).toMatchObject({ status: "disabled" });
    const a = await t.prisma.agent.findUniqueOrThrow({ where: { userId: agent.id } });
    expect([a.wrappedPrivateKey, a.revokedById, a.revokedAt !== null]).toEqual([null, owner.id, true]);
    expect((await t.prisma.agentToken.findUniqueOrThrow({ where: { id: tokenId } })).revokedAt).not.toBeNull();
    expect((await t.prisma.agentGrant.findUniqueOrThrow({ where: { id: grant.id } })).revokedAt).not.toBeNull();
    expect(fake.dropped).toContain(agent.id);
    expect((await agentCall(access, "GET", "/agent/sync")).statusCode).toBe(401);
    const ev = await t.prisma.event.findMany({ where: { action: "agent.revoke" } });
    expect(ev).toHaveLength(1);
    expect(ev[0]).toMatchObject({ targetUserId: agent.id, meta: { reason: "leaked", folders: 2, records: 3 } });
  });

  it("a double revoke is 409 agent_revoked and logs once", async () => {
    const { owner, agent } = await setup();
    expect((await call(owner, "DELETE", `/admin/agents/${agent.id}`)).statusCode).toBe(200);
    const r = await call(owner, "DELETE", `/admin/agents/${agent.id}`);
    expect([r.statusCode, r.json()]).toEqual([409, { error: "agent_revoked" }]);
    expect(await t.prisma.event.count({ where: { action: "agent.revoke" } })).toBe(1);
  });

  it("succeeds with the gateway down", async () => {
    const { owner, agent } = await setup();
    fake.setDown(true);
    expect((await call(owner, "DELETE", `/admin/agents/${agent.id}`)).statusCode).toBe(200);
  });

  it("Hosted Team: at 3 live agents, revoking one lets the next create succeed", async () => {
    await resetDb(hosted.prisma);
    const owner = await createActiveUser(hosted, { role: "owner" });
    const mk = (name: string) => hosted.app.inject({ method: "POST", url: "/api/v1/admin/agents", payload: { name }, remoteAddress: ip(), headers: { authorization: `Bearer ${owner.accessToken}`, ...orgHeader(owner) } });
    const ids: string[] = [];
    for (let i = 0; i < 3; i++) ids.push((await mk(`Bot ${i}`)).json().id);
    expect((await mk("Bot 4")).statusCode).toBe(402);
    const d = await hosted.app.inject({ method: "DELETE", url: `/api/v1/admin/agents/${ids[0]}`, remoteAddress: ip(), headers: { authorization: `Bearer ${owner.accessToken}`, ...orgHeader(owner) } });
    expect(d.statusCode).toBe(200);
    expect((await mk("Bot 5")).statusCode).toBe(201);
  });
});

describe("5b review follow-ups", () => {
  it("a second token DELETE is 204 and logs no second event", async () => {
    const { owner, agent, tokenId } = await setup();
    for (let i = 0; i < 2; i++) expect((await call(owner, "DELETE", `/admin/agents/${agent.id}/tokens/${tokenId}`)).statusCode).toBe(204);
    expect(await t.prisma.event.count({ where: { action: "agent.token_revoke" } })).toBe(1);
  });

  it("two /agent/events with the same recordId are both linked", async () => {
    const { owner, agent, access } = await setup();
    const rec = await record(owner, await sharedFolder(owner, agent));
    const ev = { action: "use", at: new Date().toISOString(), recordId: rec, host: "api.test", method: "GET" };
    const r = await agentCall(access, "POST", "/agent/events", { events: [ev, ev] });
    expect(r.statusCode).toBe(200);
    expect(await t.prisma.event.count({ where: { action: "agent.use", recordId: rec } })).toBe(2);
  });
});
