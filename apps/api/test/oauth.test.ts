import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { createHash, randomBytes } from "node:crypto";
import { decodeJwt, exportPKCS8, generateKeyPair as joseKeyPair } from "jose";
import { makeTestApp, resetDb, createActiveUser, orgHeader } from "./helpers.js";
import { createTestAgent } from "./agentHelpers.js";
import { startFakeGateway } from "./fakeGateway.js";
import { sweepOAuthClients } from "../src/routes/oauth.js";

const fake = await startFakeGateway();
const tokenPrivateKeyPem = await exportPKCS8((await joseKeyPair("ES256", { extractable: true })).privateKey);
const GW = "https://gw.test/mcp";
const agents = { gatewayInternalUrl: fake.url, gatewayPublicUrl: GW, gatewayApiToken: fake.token, tokenPrivateKeyPem, acceptNewGatewayIdentity: false };
const t = await makeTestApp({ agents });
const based = await makeTestApp({ agents, publicUrl: "https://vault.test/app", basePath: "/app" });
const off = await makeTestApp({});
afterAll(async () => { await Promise.all([t.app.close(), based.app.close(), off.app.close()]); await fake.close(); });
beforeEach(async () => { await resetDb(t.prisma); fake.dropped.length = 0; });

type U = Awaited<ReturnType<typeof createActiveUser>>;
let ipSeq = 0;
const ip = () => `10.244.${(++ipSeq >> 8) & 255}.${ipSeq & 255}`;
const call = (u: U, method: "GET" | "POST" | "DELETE", url: string, payload?: unknown, headers: Record<string, string> = orgHeader(u)) =>
  t.app.inject({ method, url: `/api/v1${url}`, payload: payload as object, remoteAddress: ip(), headers: { authorization: `Bearer ${u.accessToken}`, ...headers } });
const form = (url: string, body: string | Record<string, string>, remoteAddress = ip()) =>
  t.app.inject({ method: "POST", url: `/api/v1${url}`, remoteAddress, headers: { "content-type": "application/x-www-form-urlencoded" },
    payload: typeof body === "string" ? body : new URLSearchParams(body).toString() });
const sync = (access: string) => t.app.inject({ method: "GET", url: "/api/v1/agent/sync", remoteAddress: ip(), headers: { authorization: `Bearer ${access}`, "x-gateway-token": fake.token } });

const CB = "https://claude.ai/api/mcp/auth_callback";
function pkce() {
  const verifier = randomBytes(32).toString("base64url");
  return { verifier, challenge: createHash("sha256").update(verifier).digest("base64url") };
}
async function register(redirect_uris = [CB]) {
  const r = await t.app.inject({ method: "POST", url: "/api/v1/oauth/register", remoteAddress: ip(), payload: { client_name: "Claude", redirect_uris } });
  expect(r.statusCode).toBe(201);
  return r.json().client_id as string;
}
async function setup() {
  const owner = await createActiveUser(t, { role: "owner" });
  const agent = await createTestAgent(t, { orgId: owner.orgId, createdById: owner.id, verified: true, name: "Billing bot" });
  return { owner, agent, clientId: await register() };
}
const infoQuery = (p: Record<string, string>) => new URLSearchParams({ response_type: "code", code_challenge_method: "S256", redirect_uri: CB, ...p }).toString();
/** Consent as `u`, then the code from the redirect. */
async function consent(u: U, clientId: string, agentId: string, extra: Record<string, string> = {}) {
  const p = pkce();
  const r = await call(u, "POST", "/oauth/authorize", { clientId, redirectUri: CB, codeChallenge: p.challenge, codeChallengeMethod: "S256", state: "st1", agentId, ...extra });
  expect(r.statusCode).toBe(200);
  const to = new URL(r.json().redirectTo);
  return { ...p, to, code: to.searchParams.get("code")! };
}
const exchange = (clientId: string, code: string, verifier: string, extra: Record<string, string> = {}) =>
  form("/oauth/token", { grant_type: "authorization_code", code, code_verifier: verifier, client_id: clientId, redirect_uri: CB, ...extra });
async function granted() {
  const s = await setup();
  const c = await consent(s.owner, s.clientId, s.agent.id);
  const r = await exchange(s.clientId, c.code, c.verifier, { resource: GW });
  expect(r.statusCode).toBe(200);
  const body = r.json() as { access_token: string; refresh_token: string };
  return { ...s, ...body, grantId: decodeJwt(body.access_token).grant as string };
}
const refresh = (clientId: string, token: string) => form("/oauth/token", { grant_type: "refresh_token", refresh_token: token, client_id: clientId });

describe("metadata and registration", () => {
  it("serves the AS metadata at the root; with a base path at both RFC 8414 forms; 404 with agents off", async () => {
    const r = await t.app.inject({ method: "GET", url: "/.well-known/oauth-authorization-server" });
    expect(r.statusCode).toBe(200);
    expect(r.json()).toMatchObject({ issuer: t.config.publicUrl, code_challenge_methods_supported: ["S256"], token_endpoint: `${t.config.publicUrl}/api/v1/oauth/token`,
      authorization_endpoint: `${t.config.publicUrl}/oauth/authorize`, token_endpoint_auth_methods_supported: ["none"] });
    for (const url of ["/.well-known/oauth-authorization-server/app", "/app/.well-known/oauth-authorization-server"]) {
      const b = await based.app.inject({ method: "GET", url });
      expect([url, b.statusCode, b.json().issuer, b.json().registration_endpoint]).toEqual([url, 200, "https://vault.test/app", "https://vault.test/app/api/v1/oauth/register"]);
    }
    expect((await off.app.inject({ method: "GET", url: "/.well-known/oauth-authorization-server" })).statusCode).toBe(404);
  });

  it("the agent token's iss is byte-identical to the metadata issuer", async () => {
    const g = await granted();
    const meta = (await t.app.inject({ method: "GET", url: "/.well-known/oauth-authorization-server" })).json();
    expect(decodeJwt(g.access_token).iss).toBe(meta.issuer);
  });

  it("registers https or loopback http redirect URIs only", async () => {
    const reg = (redirect_uris: string[]) => t.app.inject({ method: "POST", url: "/api/v1/oauth/register", remoteAddress: ip(), payload: { client_name: "X", redirect_uris } });
    expect((await reg(["http://evil.test/cb"])).statusCode).toBe(400);
    expect((await reg(["https://claude.ai/cb#frag"])).statusCode).toBe(400);
    expect((await reg(["javascript:alert(1)"])).statusCode).toBe(400);
    const ok = await reg([CB, "http://127.0.0.1:33418/cb", "http://localhost/cb", "http://[::1]:9/cb"]);
    expect(ok.statusCode).toBe(201);
    expect(ok.json()).toMatchObject({ client_name: "X", redirect_uris: [CB, "http://127.0.0.1:33418/cb", "http://localhost/cb", "http://[::1]:9/cb"],
      token_endpoint_auth_method: "none", response_types: ["code"], grant_types: ["authorization_code", "refresh_token"] });
  });

  it("caps registrations per address", async () => {
    const codes: number[] = [];
    for (let i = 0; i < 11; i++)
      codes.push((await t.app.inject({ method: "POST", url: "/api/v1/oauth/register", remoteAddress: "10.245.0.1", payload: { client_name: "X", redirect_uris: [CB] } })).statusCode);
    expect(codes.slice(0, 10).every((c) => c === 201)).toBe(true);
    expect(codes[10]).toBe(429);
  });
});

describe("authorize", () => {
  it("info refuses plain PKCE, an inexact redirect URI, repeated parameters, an unknown client and a foreign resource", async () => {
    const { owner, clientId } = await setup();
    const info = async (q: string) => { const r = await call(owner, "GET", `/oauth/authorize/info?${q}`, undefined, {}); return [r.statusCode, r.json().error]; };
    const ch = pkce().challenge;
    expect(await info(infoQuery({ client_id: clientId, code_challenge: ch, code_challenge_method: "plain" }))).toEqual([400, "invalid_request"]);
    expect(await info(infoQuery({ client_id: clientId, code_challenge: ch, response_type: "token" }))).toEqual([400, "invalid_request"]);
    expect(await info(infoQuery({ client_id: clientId, code_challenge: ch, redirect_uri: "https://claude.ai/api/mcp/other" }))).toEqual([400, "invalid_redirect_uri"]);
    expect(await info(infoQuery({ client_id: clientId, code_challenge: ch, redirect_uri: `${CB}/` }))).toEqual([400, "invalid_redirect_uri"]);
    expect(await info(infoQuery({ client_id: clientId, code_challenge: ch, redirect_uri: `${CB}?x=1` }))).toEqual([400, "invalid_redirect_uri"]);
    expect(await info(`${infoQuery({ client_id: clientId, code_challenge: ch })}&redirect_uri=${encodeURIComponent("https://evil.test/cb")}`)).toEqual([400, "invalid_request"]);
    expect(await info(`${infoQuery({ client_id: clientId, code_challenge: ch })}&state=a&state=b`)).toEqual([400, "invalid_request"]);
    expect(await info(infoQuery({ client_id: crypto.randomUUID(), code_challenge: ch }))).toEqual([400, "invalid_client"]);
    expect(await info(infoQuery({ client_id: clientId, code_challenge: ch, resource: "https://other.test/mcp" }))).toEqual([400, "invalid_target"]);
  });

  it("info lists the live verified agents an admin can grant, with the issuer", async () => {
    const { owner, agent, clientId } = await setup();
    await createTestAgent(t, { orgId: owner.orgId, createdById: owner.id, verified: false });
    await createTestAgent(t, { orgId: owner.orgId, createdById: owner.id, verified: true, expiresAt: new Date(Date.now() - 1000) });
    const revoked = await createTestAgent(t, { orgId: owner.orgId, createdById: owner.id, verified: true });
    await t.prisma.agent.update({ where: { userId: revoked.id }, data: { revokedAt: new Date() } });
    const r = await call(owner, "GET", `/oauth/authorize/info?${infoQuery({ client_id: clientId, code_challenge: pkce().challenge, state: "s", resource: GW })}`, undefined, {});
    expect(r.statusCode).toBe(200);
    expect(r.json()).toEqual({ client: { name: "Claude" }, issuer: t.config.publicUrl, agents: [{ id: agent.id, name: "Billing bot", orgId: owner.orgId, orgName: "Test org" }] });
  });

  it("a member sees no agents and may not consent (403)", async () => {
    const { agent, clientId } = await setup();
    const member = await createActiveUser(t, { role: "member" });
    const r = await call(member, "GET", `/oauth/authorize/info?${infoQuery({ client_id: clientId, code_challenge: pkce().challenge })}`, undefined, {});
    expect([r.statusCode, r.json().agents]).toEqual([200, []]);
    const p = await call(member, "POST", "/oauth/authorize", { clientId, redirectUri: CB, codeChallenge: pkce().challenge, codeChallengeMethod: "S256", agentId: agent.id });
    expect(p.statusCode).toBe(403);
    expect(await t.prisma.agentOAuthCode.count()).toBe(0);
  });

  it("consent refuses an unverified agent, plain PKCE and an unregistered redirect URI", async () => {
    const { owner, clientId } = await setup();
    const unverified = await createTestAgent(t, { orgId: owner.orgId, createdById: owner.id, verified: false });
    const base = { clientId, redirectUri: CB, codeChallenge: pkce().challenge, codeChallengeMethod: "S256", agentId: unverified.id };
    const r = await call(owner, "POST", "/oauth/authorize", base);
    expect([r.statusCode, r.json().error]).toEqual([403, "agent_unverified"]);
    const { agent } = { agent: await createTestAgent(t, { orgId: owner.orgId, createdById: owner.id, verified: true }) };
    expect((await call(owner, "POST", "/oauth/authorize", { ...base, agentId: agent.id, codeChallengeMethod: "plain" })).json().error).toBe("invalid_request");
    expect((await call(owner, "POST", "/oauth/authorize", { ...base, agentId: agent.id, redirectUri: "https://evil.test/cb" })).json().error).toBe("invalid_redirect_uri");
    expect(await t.prisma.agentOAuthCode.count()).toBe(0);
  });

  it("admin consent redirects with code, state and iss", async () => {
    const { owner, agent, clientId } = await setup();
    const c = await consent(owner, clientId, agent.id);
    expect(`${c.to.origin}${c.to.pathname}`).toBe(CB);
    expect([c.to.searchParams.get("state"), c.to.searchParams.get("iss"), c.code.length >= 43]).toEqual(["st1", t.config.publicUrl, true]);
  });
});

describe("code exchange", () => {
  it("issues an agent token for the grant, logs agent.grant once; the code is single-use", async () => {
    const { owner, agent, clientId } = await setup();
    const c = await consent(owner, clientId, agent.id);
    const r = await exchange(clientId, c.code, c.verifier);
    expect(r.statusCode).toBe(200);
    const body = r.json();
    expect([body.token_type, body.expires_in, typeof body.refresh_token]).toEqual(["Bearer", 900, "string"]);
    const claims = decodeJwt(body.access_token);
    const grant = await t.prisma.agentGrant.findFirstOrThrow({ where: { agentId: agent.id } });
    expect([claims.aud, claims.sub, claims.grant, claims.org]).toEqual([GW, agent.id, grant.id, owner.orgId]);
    const ev = await t.prisma.event.findMany({ where: { action: "agent.grant" } });
    expect(ev).toHaveLength(1);
    expect(ev[0]).toMatchObject({ actorId: owner.id, targetUserId: agent.id, meta: { clientName: "Claude" } });
    expect((await sync(body.access_token)).statusCode).toBe(200);
    const again = await exchange(clientId, c.code, c.verifier);
    expect([again.statusCode, again.json().error]).toEqual([400, "invalid_grant"]);
  });

  it("refuses a wrong verifier, another client, another redirect URI and a foreign resource", async () => {
    const { owner, agent, clientId } = await setup();
    const c = await consent(owner, clientId, agent.id);
    expect((await exchange(clientId, c.code, pkce().verifier)).json().error).toBe("invalid_grant");
    expect((await exchange(await register(), c.code, c.verifier)).json().error).toBe("invalid_grant");
    expect((await exchange(clientId, c.code, c.verifier, { redirect_uri: `${CB}/` })).json().error).toBe("invalid_grant");
    expect((await exchange(clientId, c.code, c.verifier, { resource: "https://other.test/mcp" })).json().error).toBe("invalid_target");
    expect((await exchange(clientId, c.code, c.verifier)).statusCode).toBe(200); // none of the failures used the code up
  });

  it("refuses repeated form parameters", async () => {
    const { owner, agent, clientId } = await setup();
    const c = await consent(owner, clientId, agent.id);
    const body = `${new URLSearchParams({ grant_type: "authorization_code", code: c.code, code_verifier: c.verifier, client_id: clientId, redirect_uri: CB })}&redirect_uri=${encodeURIComponent("https://evil.test/cb")}`;
    const r = await form("/oauth/token", body);
    expect([r.statusCode, r.json().error]).toEqual([400, "invalid_request"]);
  });

  it("refuses a code whose agent was revoked after consent", async () => {
    const { owner, agent, clientId } = await setup();
    const c = await consent(owner, clientId, agent.id);
    expect((await call(owner, "DELETE", `/admin/agents/${agent.id}`)).statusCode).toBe(200);
    expect((await exchange(clientId, c.code, c.verifier)).json().error).toBe("invalid_grant");
  });

  it("refuses an expired code", async () => {
    const { owner, agent, clientId } = await setup();
    const c = await consent(owner, clientId, agent.id);
    await t.prisma.agentOAuthCode.updateMany({ data: { expiresAt: new Date(Date.now() - 1000) } });
    expect((await exchange(clientId, c.code, c.verifier)).json().error).toBe("invalid_grant");
  });
});

describe("refresh", () => {
  it("rotates; a reused old refresh token revokes the grant and ends access", async () => {
    const g = await granted();
    const r = await refresh(g.clientId, g.refresh_token);
    expect(r.statusCode).toBe(200);
    const next = r.json();
    expect(next.refresh_token).not.toBe(g.refresh_token);
    expect((await sync(next.access_token)).statusCode).toBe(200);
    // Past the grace window, the old token is a replay.
    await t.prisma.agentGrant.update({ where: { id: g.grantId }, data: { rotatedAt: new Date(Date.now() - 60_000) } });
    const reuse = await refresh(g.clientId, g.refresh_token);
    expect([reuse.statusCode, reuse.json().error]).toEqual([400, "invalid_grant"]);
    expect((await t.prisma.agentGrant.findUniqueOrThrow({ where: { id: g.grantId } })).revokedAt).not.toBeNull();
    expect((await sync(next.access_token)).statusCode).toBe(401);
    expect((await refresh(g.clientId, next.refresh_token)).json().error).toBe("invalid_grant");
    expect(await t.prisma.event.findFirst({ where: { action: "agent.grant_revoke" } })).toMatchObject({ targetUserId: g.agent.id, meta: { reason: "refresh_reuse" } });
    expect(fake.dropped).toContain(g.agent.id);
  });

  it("two concurrent refreshes within the grace window both succeed and keep the grant", async () => {
    const g = await granted();
    const rs = await Promise.all([refresh(g.clientId, g.refresh_token), refresh(g.clientId, g.refresh_token)]);
    expect(rs.map((r) => r.statusCode)).toEqual([200, 200]);
    expect(rs.some((r) => typeof r.json().refresh_token === "string")).toBe(true);
    expect((await t.prisma.agentGrant.findUniqueOrThrow({ where: { id: g.grantId } })).revokedAt).toBeNull();
    for (const r of rs) expect((await sync(r.json().access_token)).statusCode).toBe(200);
  });

  it("refuses another client's refresh and garbage", async () => {
    const g = await granted();
    expect((await refresh(crypto.randomUUID(), g.refresh_token)).json().error).toBe("invalid_grant");
    expect((await refresh(g.clientId, `${g.grantId}.nope`)).json().error).toBe("invalid_grant");
    expect((await refresh(g.clientId, "garbage")).json().error).toBe("invalid_grant");
    expect((await t.prisma.agentGrant.findUniqueOrThrow({ where: { id: g.grantId } })).revokedAt).toBeNull();
  });

  it("a revoked agent's grant is refused", async () => {
    const g = await granted();
    expect((await call(g.owner, "DELETE", `/admin/agents/${g.agent.id}`)).statusCode).toBe(200);
    expect((await refresh(g.clientId, g.refresh_token)).json().error).toBe("invalid_grant");
  });
});

describe("revoking grants", () => {
  it("/oauth/revoke ends the grant (always 200)", async () => {
    const g = await granted();
    expect((await form("/oauth/revoke", { token: g.refresh_token })).statusCode).toBe(200);
    expect((await sync(g.access_token)).statusCode).toBe(401);
    expect(fake.dropped).toContain(g.agent.id);
    expect((await form("/oauth/revoke", { token: g.refresh_token })).statusCode).toBe(200);
    expect((await form("/oauth/revoke", { token: "garbage" })).statusCode).toBe(200);
    expect(await t.prisma.event.count({ where: { action: "agent.grant_revoke" } })).toBe(1);
  });

  it("the Agents page lists live grants; DELETE /admin/agents/:id/grants/:grantId ends one", async () => {
    const g = await granted();
    const list = (await call(g.owner, "GET", "/admin/agents")).json().agents[0];
    expect(list.grants).toEqual([{ id: g.grantId, clientName: "Claude", grantedBy: { id: g.owner.id, name: expect.any(String) }, createdAt: expect.any(String) }]);
    const d = await call(g.owner, "DELETE", `/admin/agents/${g.agent.id}/grants/${g.grantId}`);
    expect(d.statusCode).toBe(204);
    expect((await call(g.owner, "DELETE", `/admin/agents/${g.agent.id}/grants/${g.grantId}`)).statusCode).toBe(204);
    expect((await sync(g.access_token)).statusCode).toBe(401);
    expect(fake.dropped).toContain(g.agent.id);
    expect(await t.prisma.event.findMany({ where: { action: "agent.grant_revoke" } })).toMatchObject([{ actorId: g.owner.id, targetUserId: g.agent.id, meta: { grantId: g.grantId } }]);
    expect((await call(g.owner, "GET", "/admin/agents")).json().agents[0].grants).toEqual([]);
    expect((await call(g.owner, "DELETE", `/admin/agents/${g.agent.id}/grants/${crypto.randomUUID()}`)).statusCode).toBe(404);
  });
});

describe("review round 1", () => {
  it("a refresh with a client_id that isn't a uuid is invalid_grant, not a 500", async () => {
    const g = await granted();
    const r = await refresh("not-a-uuid", g.refresh_token);
    expect([r.statusCode, r.json().error]).toEqual([400, "invalid_grant"]);
  });

  it("a used code replayed with the right verifier revokes its grant; with a wrong verifier it doesn't", async () => {
    const { owner, agent, clientId } = await setup();
    const c = await consent(owner, clientId, agent.id);
    const first = (await exchange(clientId, c.code, c.verifier)).json();
    expect((await exchange(clientId, c.code, pkce().verifier)).json().error).toBe("invalid_grant");
    expect((await sync(first.access_token)).statusCode).toBe(200);
    expect(await t.prisma.event.count({ where: { action: "agent.grant_revoke" } })).toBe(0);
    expect((await exchange(clientId, c.code, c.verifier)).json().error).toBe("invalid_grant");
    expect((await sync(first.access_token)).statusCode).toBe(401);
    expect(await t.prisma.event.findFirst({ where: { action: "agent.grant_revoke" } })).toMatchObject({ targetUserId: agent.id, meta: { reason: "code_reuse" } });
  });

  it("refresh refuses a foreign resource", async () => {
    const g = await granted();
    const r = await form("/oauth/token", { grant_type: "refresh_token", refresh_token: g.refresh_token, client_id: g.clientId, resource: "https://other.test/mcp" });
    expect([r.statusCode, r.json().error]).toEqual([400, "invalid_target"]);
  });

  it("DCR refuses control and bidi characters in client_name", async () => {
    for (const client_name of ["Claude‮evil", "Claude\u0007", "a​b"])
      expect((await t.app.inject({ method: "POST", url: "/api/v1/oauth/register", remoteAddress: ip(), payload: { client_name, redirect_uris: [CB] } })).statusCode).toBe(400);
  });

  it("info caps state at 1000 characters", async () => {
    const { owner, clientId } = await setup();
    const q = (state: string) => call(owner, "GET", `/oauth/authorize/info?${infoQuery({ client_id: clientId, code_challenge: pkce().challenge, state })}`, undefined, {});
    expect((await q("s".repeat(1000))).statusCode).toBe(200);
    expect((await q("s".repeat(1001))).json().error).toBe("invalid_request");
  });

  it("grant events carry the request metadata; a refresh replay logs no actor", async () => {
    const g = await granted();
    expect(await t.prisma.event.findFirst({ where: { action: "agent.grant" } })).toMatchObject({ ip: expect.any(String), userAgent: expect.any(String) });
    expect((await refresh(g.clientId, g.refresh_token)).statusCode).toBe(200);
    await t.prisma.agentGrant.update({ where: { id: g.grantId }, data: { rotatedAt: new Date(Date.now() - 60_000) } });
    await refresh(g.clientId, g.refresh_token);
    expect(await t.prisma.event.findFirst({ where: { action: "agent.grant_revoke" } })).toMatchObject({ actorId: null, ip: expect.any(String), meta: { reason: "refresh_reuse" } });
  });

  it("metadata names the revocation auth method", async () => {
    expect((await t.app.inject({ method: "GET", url: "/.well-known/oauth-authorization-server" })).json().revocation_endpoint_auth_methods_supported).toEqual(["none"]);
  });

  it("consent refuses a foreign resource; an exchange without code_verifier is invalid_request", async () => {
    const { owner, agent, clientId } = await setup();
    const r = await call(owner, "POST", "/oauth/authorize", { clientId, redirectUri: CB, codeChallenge: pkce().challenge, codeChallengeMethod: "S256", agentId: agent.id, resource: "https://other.test/mcp" });
    expect([r.statusCode, r.json().error]).toEqual([400, "invalid_target"]);
    const c = await consent(owner, clientId, agent.id);
    const x = await form("/oauth/token", { grant_type: "authorization_code", code: c.code, client_id: clientId, redirect_uri: CB });
    expect([x.statusCode, x.json().error]).toEqual([400, "invalid_request"]);
  });

  it("the sweep deletes clients over 30 days old with no codes and no grants", async () => {
    const { owner, agent } = await setup();
    const old = new Date(Date.now() - 31 * 864e5);
    const mk = (createdAt: Date) => t.prisma.agentOAuthClient.create({ data: { name: "c", redirectUris: [CB], createdAt } });
    const [stale, fresh, withCode, withGrant] = await Promise.all([mk(old), mk(new Date()), mk(old), mk(old)]);
    await t.prisma.agentOAuthCode.create({ data: { codeHash: "x", clientId: withCode.id, agentId: agent.id, grantedById: owner.id, codeChallenge: "c", redirectUri: CB, expiresAt: new Date() } });
    await t.prisma.agentGrant.create({ data: { agentId: agent.id, clientId: withGrant.id, grantedById: owner.id, refreshHash: "rh", expiresAt: new Date() } });
    expect(await sweepOAuthClients(t.prisma)).toBe(1);
    const left = (await t.prisma.agentOAuthClient.findMany({ select: { id: true } })).map((c) => c.id);
    expect(left).not.toContain(stale.id);
    expect(left).toEqual(expect.arrayContaining([fresh.id, withCode.id, withGrant.id]));
  });
});
