import http from "node:http";
import net from "node:net";
import type { AddressInfo } from "node:net";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { RecordBody } from "@clane-vault/crypto";
import { SignJWT } from "jose";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { createGateway, type GatewayDeps } from "../src/app.js";
import { ApiRefused, apiClient, type ApiClient, type UseEvent } from "../src/apiClient.js";
import { bearerAuth, type AgentPrincipal } from "../src/auth.js";
import type { GatewayConfig } from "../src/config.js";
import { EventQueue } from "../src/events.js";
import { loadOrCreateIdentity } from "../src/identity.js";
import { AgentKeyCache, SyncCache } from "../src/keys.js";
import { createLogger, HeldSecrets, type Logger } from "../src/log.js";
import { agentTools, clientAddress } from "../src/mcp.js";
import type { Resolver } from "../src/outbound/ssrf.js";
import { RateLimiter } from "../src/rateLimit.js";
import { startFakeApi } from "./fakeApi.js";
import { fileKek, tempDir } from "./helpers.js";

const AUD = "http://localhost:3002/mcp";
const SECRET = "sk_live_PLAINTEXT_CANARY_42";
const closers: (() => Promise<void>)[] = [];
afterEach(async () => { await Promise.all(closers.splice(0).map((c) => c())); });

const cfgFor = (apiUrl: string, apiToken: string, over: Partial<GatewayConfig> = {}): GatewayConfig => ({
  apiUrl, apiToken, publicUrl: AUD, kek: "file:x", identityKeyFile: "x", cacheTtlSeconds: 60, agentRatePerMinute: 60, maxResponseBytes: 4194304,
  upstreamTimeoutMs: 5000, allowPrivateCidrs: ["127.0.0.0/8"], port: 0, internalPort: 0, internalHost: "127.0.0.1", trustProxy: 0, ...over,
});
const resolve: Resolver = async (h) => (h === "api.test" ? [{ address: "127.0.0.1", family: 4 }] : Promise.reject(new Error("ENOTFOUND")));
const quiet: Logger = { info: () => {}, error: () => {} };

async function fake() {
  const kek = await fileKek();
  const api = await startFakeApi({ kek, aud: AUD });
  closers.push(api.close);
  return { kek, api };
}

async function upstream() {
  const seen: http.IncomingHttpHeaders[] = [];
  const s = http.createServer((req, res) => { seen.push(req.headers); req.resume(); req.on("end", () => res.end("ok")); });
  await new Promise<void>((r) => s.listen(0, "127.0.0.1", r));
  closers.push(() => new Promise((r) => { s.closeAllConnections(); s.close(() => r()); }));
  return { port: (s.address() as AddressInfo).port, seen };
}

const apiKey = (title: string, hosts: string[] | null): RecordBody => ({
  v: 2, type: "apiKey", title, data: { secret: SECRET, keyId: "kid" },
  ...(hosts ? { agentPolicy: { v: 1, hosts, inject: { kind: "bearer" }, methods: ["GET"] } } : {}),
});

describe("bearerAuth", () => {
  it("refuses a missing, malformed or garbage bearer", async () => {
    const { api } = await fake();
    const auth = bearerAuth(cfgFor(api.url, api.token), apiClient({ apiUrl: api.url, apiToken: api.token }));
    for (const h of [undefined, "", "Basic abc", "Bearer", "Bearer not.a.jwt", "Bearer cvat_nope"]) expect(await auth(h)).toBeNull();
  });

  it("exchanges a static token once, and the principal is the token's agent", async () => {
    const { api } = await fake();
    const auth = bearerAuth(cfgFor(api.url, api.token), apiClient({ apiUrl: api.url, apiToken: api.token }));
    const h = `Bearer ${api.staticToken}`;
    const [a, b] = await Promise.all([auth(h), auth(h)]);
    const c = await auth(h);
    expect(api.tokenCalls).toBe(1);
    expect(a).toMatchObject({ agentId: api.agent.id, orgId: api.agent.orgId });
    expect(b).toEqual(a);
    expect(c).toEqual(a);
    expect(a!.exp * 1000).toBeGreaterThan(Date.now());
  });

  it("re-exchanges once the cached token is within 30 s of expiry", async () => {
    const { api } = await fake();
    let t = Date.now();
    const auth = bearerAuth(cfgFor(api.url, api.token), apiClient({ apiUrl: api.url, apiToken: api.token }), () => t);
    const h = `Bearer ${api.staticToken}`;
    const a = await auth(h);
    t = a!.exp * 1000 - 29_000;
    await auth(h);
    expect(api.tokenCalls).toBe(2);
  });

  it("does not cache a refused exchange", async () => {
    const { api } = await fake();
    const auth = bearerAuth(cfgFor(api.url, api.token), apiClient({ apiUrl: api.url, apiToken: api.token }));
    api.revoke();
    expect(await auth(`Bearer ${api.staticToken}`)).toBeNull();
    expect(await auth(`Bearer ${api.staticToken}`)).toBeNull();
    expect(api.tokenCalls).toBe(2);
  });

  it("verifies an access token against the JWKS and the audience", async () => {
    const { api } = await fake();
    const { api: other } = await fake();
    const client = apiClient({ apiUrl: api.url, apiToken: api.token });
    const jwt = await api.issueToken();
    expect(await bearerAuth(cfgFor(api.url, api.token), client)(`Bearer ${jwt}`)).toEqual(expect.objectContaining({ agentId: api.agent.id, accessToken: jwt }));
    // Another audience, and a token signed by a key not in this JWKS.
    expect(await bearerAuth(cfgFor(api.url, api.token, { publicUrl: "https://other.test/mcp" }), client)(`Bearer ${jwt}`)).toBeNull();
    expect(await bearerAuth(cfgFor(api.url, api.token), client)(`Bearer ${await other.issueToken()}`)).toBeNull();
  });

  it("refuses a JWT with scope other than agent, no org, no or a non-string sub, an expired exp or a non-ES256 alg", async () => {
    const { api } = await fake();
    const auth = bearerAuth(cfgFor(api.url, api.token), apiClient({ apiUrl: api.url, apiToken: api.token }));
    const hs = await new SignJWT({ scope: "agent", org: api.agent.orgId }).setProtectedHeader({ alg: "HS256", kid: api.kid }).setSubject(api.agent.id)
      .setAudience(AUD).setExpirationTime("15m").sign(new Uint8Array(32));
    for (const jwt of [await api.issueToken({ scope: "user" }), await api.issueToken({ org: undefined }), await api.issueToken({ sub: null }),
      await api.issueToken({ sub: 42 }), await api.issueToken({ exp: Math.floor(Date.now() / 1000) - 60 }), hs])
      expect(await auth(`Bearer ${jwt}`)).toBeNull();
  });

  it("refuses an exchanged JWT whose grant is not the static token's id", async () => {
    const { api } = await fake();
    const client = apiClient({ apiUrl: api.url, apiToken: api.token });
    const wrong: ApiClient = { ...client, exchangeStatic: async () => ({ accessToken: await api.issueToken({ grant: "another-token-id" }), expiresIn: 900 }) };
    expect(await bearerAuth(cfgFor(api.url, api.token), wrong)(`Bearer ${api.staticToken}`)).toBeNull();
    expect(await bearerAuth(cfgFor(api.url, api.token), client)(`Bearer ${api.staticToken}`)).toMatchObject({ agentId: api.agent.id });
  });

  it("drop(agentId) evicts the agent's cached exchange; onExchange runs on misses only", async () => {
    const { api } = await fake();
    const auth = bearerAuth(cfgFor(api.url, api.token), apiClient({ apiUrl: api.url, apiToken: api.token }));
    const h = `Bearer ${api.staticToken}`;
    let misses = 0;
    const miss = () => { misses++; };
    await auth(h, miss); await auth(h, miss);
    expect([misses, api.tokenCalls]).toEqual([1, 1]);
    auth.drop(api.agent2.id);
    await auth(h, miss);
    expect(api.tokenCalls).toBe(1);
    auth.drop(api.agent.id);
    api.revoke();
    expect(await auth(h, miss)).toBeNull();
    expect([misses, api.tokenCalls]).toEqual([2, 2]);
  });
});

describe("RateLimiter", () => {
  it("refuses past the limit with Retry-After, per key, until the window ends", () => {
    let t = 0;
    const l = new RateLimiter(() => t);
    for (let i = 0; i < 3; i++) expect(l.take("a", 3, 60_000)).toEqual({ ok: true });
    expect(l.take("a", 3, 60_000)).toEqual({ ok: false, retryAfterSeconds: 60 });
    expect(l.take("b", 3, 60_000)).toEqual({ ok: true });
    t = 59_500;
    expect(l.take("a", 3, 60_000)).toEqual({ ok: false, retryAfterSeconds: 1 });
    t = 60_000;
    expect(l.take("a", 3, 60_000)).toEqual({ ok: true });
  });

  it("sweeps finished windows past 10k keys at most once per window", () => {
    let t = 0;
    const l = new RateLimiter(() => t);
    const size = () => (l as unknown as { windows: Map<string, unknown> }).windows.size;
    for (let i = 0; i <= 10_000; i++) l.take(`a${i}`, 1, 1000);
    t = 1000;
    l.take("x", 1, 1000); // sweeps: every a* window has ended
    expect(size()).toBe(1);
    for (let i = 0; i <= 10_000; i++) l.take(`b${i}`, 1, 100);
    t = 1500; // the b* windows have ended, but a sweep ran 500 ms ago
    l.take("y", 1, 1000);
    expect(size()).toBe(10_003);
    t = 2000;
    l.take("z", 1, 1000);
    expect(size()).toBe(2); // y and z
  });
});

describe("EventQueue", () => {
  const p: AgentPrincipal = { agentId: "a1", orgId: "o", accessToken: "tok", exp: 0 };
  const ev = (n: number): UseEvent => ({ at: String(n), action: "use", host: "h", method: "GET" });
  it("keeps the newest 200 per agent and sends them with the agent's token", async () => {
    const sent: [string, UseEvent[]][] = [];
    const q = new EventQueue({ events: async (t: string, e: UseEvent[]) => { sent.push([t, e]); } } as unknown as ApiClient, quiet);
    for (let i = 0; i < 205; i++) q.push(p, ev(i));
    q.push({ ...p, agentId: "a2", accessToken: "tok2" }, ev(999));
    await q.flush(p);
    await q.flush(p);
    expect(sent).toHaveLength(1);
    expect(sent[0]![0]).toBe("tok");
    expect(sent[0]![1].map((e) => e.at)).toEqual(Array.from({ length: 200 }, (_, i) => String(i + 5)));
  });
  it("keeps a failed batch for the next flush, but not one the API refused", async () => {
    let fail: Error | null = new Error("down");
    const sent: UseEvent[][] = [];
    const q = new EventQueue({ events: async (_t: string, e: UseEvent[]) => { if (fail) throw fail; sent.push(e); } } as unknown as ApiClient, quiet);
    q.push(p, ev(1));
    await q.flush(p);
    fail = null;
    q.push(p, ev(2));
    await q.flush(p);
    expect(sent).toEqual([[ev(1), ev(2)]]);
    fail = new ApiRefused(401, "unauthorized");
    q.push(p, ev(3));
    await q.flush(p);
    fail = null;
    await q.flush(p);
    expect(sent).toHaveLength(1);
  });
});

describe("clientAddress", () => {
  const req = (xff?: string) => ({ headers: xff ? { "x-forwarded-for": xff } : {}, socket: { remoteAddress: "10.0.0.9" } }) as never;
  it("uses the socket unless proxies are trusted, then counts hops from the right", () => {
    expect(clientAddress(req("1.1.1.1, 2.2.2.2"), 0)).toBe("10.0.0.9");
    expect(clientAddress(req("1.1.1.1, 2.2.2.2"), 1)).toBe("2.2.2.2");
    expect(clientAddress(req("1.1.1.1, 2.2.2.2"), 2)).toBe("1.1.1.1");
    expect(clientAddress(req("1.1.1.1"), 5)).toBe("1.1.1.1");
    expect(clientAddress(req(), 1)).toBe("10.0.0.9");
  });
});

describe("agentTools", () => {
  async function setup(ttlSeconds = 60) {
    const { kek, api } = await fake();
    const client = apiClient({ apiUrl: api.url, apiToken: api.token });
    const cfg = cfgFor(api.url, api.token, { cacheTtlSeconds: ttlSeconds });
    const lines: string[] = [];
    const held = new HeldSecrets();
    const log = createLogger(held, (l) => lines.push(l));
    const keys = new AgentKeyCache({ ttlMs: ttlSeconds * 1000, kek });
    const syncs = new SyncCache({ ttlMs: ttlSeconds * 1000, api: client });
    const tools = agentTools({ cfg, keys, syncs, events: new EventQueue(client, log), log, held, resolve });
    const p = (await bearerAuth(cfg, client)(`Bearer ${api.staticToken}`))!;
    return { api, keys, syncs, tools, p, lines };
  }

  it("list_secrets gives handles and summary fields, never a secret or a record id", async () => {
    const { api, tools, p } = await setup();
    const id = await api.addFolderRecord("Payments", apiKey("Stripe", ["api.test:1"]));
    const items = await tools.listSecrets(p);
    expect(items).toEqual([{ handle: "payments/stripe", title: "Stripe", type: "apiKey", hosts: ["api.test:1"], inject: { kind: "bearer" }, approval: false, methods: ["GET"] }]);
    expect(JSON.stringify(items)).not.toContain(SECRET);
    expect(JSON.stringify(items)).not.toContain(id);
  });

  it("http_request injects the secret and records one use event with no url or path", async () => {
    const { api, tools, p, lines } = await setup();
    const up = await upstream();
    const id = await api.addFolderRecord("Payments", apiKey("Stripe", [`api.test:${up.port}`]));
    const r = await tools.httpRequest(p, { item: "payments/stripe", method: "GET", url: `http://api.test:${up.port}/v1/charges?limit=1` });
    expect(r).toMatchObject({ status: 200, body: "ok" });
    expect(up.seen[0]!.authorization).toBe(`Bearer ${SECRET}`);
    expect(api.events).toHaveLength(1);
    expect(api.events[0]).toEqual({ at: expect.any(String), action: "use", recordId: id, host: "api.test", method: "GET" });
    expect(JSON.stringify(lines)).not.toContain(SECRET);
  });

  it("a record with no policy is refused no_policy, with one refused event", async () => {
    const { api, tools, p } = await setup();
    await api.addFolderRecord("Ops", apiKey("Legacy", null));
    expect(await tools.httpRequest(p, { item: "ops/legacy", method: "GET", url: "https://api.test/x" })).toEqual({ error: "refused", reason: "no_policy" });
    expect(api.events).toEqual([{ at: expect.any(String), action: "refused", host: "api.test", method: "GET", reason: "no_policy" }]);
  });

  it("an unknown item is not_found, with host \"\" when the url doesn't parse", async () => {
    const { api, tools, p } = await setup();
    expect(await tools.httpRequest(p, { item: "nope/x", method: "GET", url: "::bad" })).toEqual({ error: "refused", reason: "not_found" });
    expect(api.events).toEqual([expect.objectContaining({ action: "refused", host: "", reason: "not_found" })]);
  });

  it("an item that won't decrypt is not_found", async () => {
    const { api, keys, p } = await setup();
    const id = await api.addFolderRecord("Payments", apiKey("Stripe", ["api.test"]));
    const client = apiClient({ apiUrl: api.url, apiToken: api.token });
    const good = await client.sync(p.accessToken);
    const bad = { ...good, records: good.records.map((r) => ({ ...r, encBody: r.encBody.slice(0, -8) + "AAAAAAAA" })) };
    const syncs = { get: async () => bad, drop: () => {} } as unknown as SyncCache;
    const tools = agentTools({ cfg: cfgFor(api.url, api.token), keys, syncs, events: new EventQueue(client, quiet), log: quiet, held: new HeldSecrets(), resolve });
    expect(await tools.httpRequest(p, { item: id, method: "GET", url: "https://api.test/" })).toEqual({ error: "refused", reason: "not_found" });
  });

  it("an unexpected error before the item opens is upstream_error, logged by class only", async () => {
    const { api, keys, syncs, p, lines } = await setup();
    await api.addFolderRecord("Payments", apiKey("Stripe", ["api.test"]));
    const client = apiClient({ apiUrl: api.url, apiToken: api.token });
    const held = { hold: () => { throw new TypeError(`odd ${SECRET}`); }, redact: (s: string) => s } as unknown as HeldSecrets;
    const log = createLogger(new HeldSecrets(), (l) => lines.push(l));
    const tools = agentTools({ cfg: cfgFor(api.url, api.token), keys, syncs, events: new EventQueue(client, quiet), log, held, resolve });
    expect(await tools.httpRequest(p, { item: "payments/stripe", method: "GET", url: "https://api.test/" })).toEqual({ error: "refused", reason: "upstream_error" });
    expect(lines.some((l) => l.includes('"class":"TypeError"'))).toBe(true);
    expect(lines.join("\n")).not.toContain(SECRET);
  });

  it("a host outside the policy is refused, with the event host taken from the outcome", async () => {
    const { api, tools, p } = await setup();
    const id = await api.addFolderRecord("Payments", apiKey("Stripe", ["*.stripe.com"]));
    expect(await tools.httpRequest(p, { item: id, method: "GET", url: "https://evil.test/" })).toEqual({ error: "refused", reason: "host" });
    expect(api.events).toEqual([{ at: expect.any(String), action: "refused", recordId: id, host: "evil.test", method: "GET", reason: "host" }]);
  });

  it("after a revoke (sync TTL 0) the next call is refused and the key is gone", async () => {
    const { api, keys, tools, p } = await setup(0);
    await api.addFolderRecord("Payments", apiKey("Stripe", ["api.test"]));
    await tools.listSecrets(p);
    api.revoke();
    await expect(tools.listSecrets(p)).rejects.toBeInstanceOf(ApiRefused);
    expect(keys.has(api.agent.id)).toBe(false);
  });

  it("after a revoke and the internal drop (cached sync) the next call is refused and both caches are dropped", async () => {
    const { api, keys, syncs, tools, p } = await setup(60);
    await api.addFolderRecord("Payments", apiKey("Stripe", ["api.test"]));
    await tools.listSecrets(p);
    expect(keys.has(api.agent.id)).toBe(true);
    api.revoke();
    keys.drop(api.agent.id); syncs.drop(api.agent.id); // what DELETE /internal/agents/:id does
    const drop = vi.spyOn(keys, "drop");
    await expect(tools.httpRequest(p, { item: "payments/stripe", method: "GET", url: "https://api.test/" })).rejects.toBeInstanceOf(ApiRefused);
    expect(keys.has(api.agent.id)).toBe(false);
    expect(drop).toHaveBeenCalledWith(api.agent.id);
  });
});

async function start(over: Partial<GatewayConfig> = {}, deps: Partial<GatewayDeps> = {}) {
  const { kek, api } = await fake();
  const dir = tempDir();
  const identity = await loadOrCreateIdentity(join(dir, "identity.json"), kek);
  const held = new HeldSecrets();
  const gw = await createGateway(cfgFor(api.url, api.token, over), { kek, identity, held, log: createLogger(held, () => {}), resolve, ...deps });
  closers.push(gw.close);
  await new Promise<void>((r) => gw.publicServer.listen(0, "127.0.0.1", r));
  await new Promise<void>((r) => gw.internalServer.listen(0, "127.0.0.1", r));
  const port = (s: net.Server) => (s.address() as AddressInfo).port;
  return { api, gw, url: `http://127.0.0.1:${port(gw.publicServer)}/mcp`, int: `http://127.0.0.1:${port(gw.internalServer)}` };
}

describe("MCP route gate", () => {
  const call = (name: string, id = 1) => JSON.stringify({ jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: {} } });
  const post = (url: string, body: string, token?: string) =>
    fetch(url, { method: "POST", body, headers: { "content-type": "application/json", accept: "application/json, text/event-stream", ...(token ? { authorization: `Bearer ${token}` } : {}) } });

  it("401 with WWW-Authenticate: Bearer without a valid bearer", async () => {
    const { url } = await start();
    for (const t of [undefined, "cvat_wrong", "x.y.z"]) {
      const r = await post(url, call("list_secrets"), t);
      expect(r.status).toBe(401);
      expect(r.headers.get("www-authenticate")).toBe("Bearer");
      expect(await r.json()).toEqual({ error: "unauthorized" });
    }
  });

  it("serves only the PUBLIC_URL path", async () => {
    const { url } = await start();
    expect((await post(url.replace("/mcp", "/other"), "{}")).status).toBe(404);
  });

  it("the 61st http_request in a minute is 429 with Retry-After; other tools are not counted", async () => {
    const { api, url } = await start({ agentRatePerMinute: 60 });
    for (let i = 0; i < 60; i++) expect((await post(url, call("http_request", i), api.staticToken)).status).not.toBe(429);
    const r = await post(url, call("http_request"), api.staticToken);
    expect(r.status).toBe(429);
    expect(Number(r.headers.get("retry-after"))).toBeGreaterThan(0);
    expect(await r.json()).toEqual({ error: "rate_limited" });
    expect((await post(url, call("list_secrets"), api.staticToken)).status).not.toBe(429);
    expect((await post(url, JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }), api.staticToken)).status).not.toBe(429);
  });

  it("the 21st list_secrets in a minute is 429, counted inside a batch too", async () => {
    const { api, url } = await start();
    const batch = JSON.stringify(Array.from({ length: 20 }, (_, i) => JSON.parse(call("list_secrets", i))));
    expect((await post(url, batch, api.staticToken)).status).not.toBe(429);
    expect((await post(url, call("list_secrets"), api.staticToken)).status).toBe(429);
  });

  it("DELETE /internal/agents/:id drops the agent's key and sync caches", async () => {
    const { api, gw, int } = await start();
    const k = vi.spyOn(gw.keys, "drop"), s = vi.spyOn(gw.syncs, "drop");
    const r = await fetch(`${int}/internal/agents/${api.agent.id}`, { method: "DELETE", headers: { "x-gateway-token": api.token } });
    expect(r.status).toBe(204);
    expect(k).toHaveBeenCalledWith(api.agent.id);
    expect(s).toHaveBeenCalledWith(api.agent.id);
  });
});

async function connect(url: string, token: string) {
  const client = new Client({ name: "test", version: "1" });
  const transport = new StreamableHTTPClientTransport(new URL(url), { requestInit: { headers: { Authorization: `Bearer ${token}` } } });
  await client.connect(transport);
  closers.unshift(() => client.close().catch(() => {}));
  return { client, transport };
}
const result = (r: unknown) => (r as { structuredContent: Record<string, unknown> }).structuredContent;

describe("MCP endpoint", () => {
  it("a static token lists exactly list_secrets and http_request, and list_secrets holds handles but no secret", async () => {
    const { api, url } = await start();
    await api.addFolderRecord("Payments", apiKey("Stripe", ["api.test"]));
    const { client } = await connect(url, api.staticToken);
    expect((await client.listTools()).tools.map((t) => t.name).sort()).toEqual(["http_request", "list_secrets"]);
    expect(client.getInstructions()).toContain("You will never see a credential");
    const r = await client.callTool({ name: "list_secrets", arguments: {} });
    expect(result(r)).toEqual({ secrets: [expect.objectContaining({ handle: "payments/stripe", hosts: ["api.test"] })] });
    expect(JSON.stringify(r)).not.toContain(SECRET);
  });

  it("two connects with one static token make one exchange", async () => {
    const { api, url } = await start();
    await connect(url, api.staticToken);
    await connect(url, api.staticToken);
    expect(api.tokenCalls).toBe(1);
  });

  it("http_request injects the secret and records one use event with no url or path", async () => {
    const { api, url } = await start();
    const up = await upstream();
    const id = await api.addFolderRecord("Payments", apiKey("Stripe", [`api.test:${up.port}`]));
    const { client } = await connect(url, api.staticToken);
    const r = await client.callTool({ name: "http_request", arguments: { item: "payments/stripe", method: "GET", url: `http://api.test:${up.port}/v1/charges?limit=1` } });
    expect(result(r)).toMatchObject({ status: 200, body: "ok" });
    expect(JSON.parse((r.content as { text: string }[])[0]!.text)).toEqual(result(r));
    expect(up.seen[0]!.authorization).toBe(`Bearer ${SECRET}`);
    expect(api.events).toEqual([{ at: expect.any(String), action: "use", recordId: id, host: "api.test", method: "GET" }]);
  });

  it("a record with no policy is refused no_policy, with one refused event", async () => {
    const { api, url } = await start();
    await api.addFolderRecord("Ops", apiKey("Legacy", null));
    const { client } = await connect(url, api.staticToken);
    expect(result(await client.callTool({ name: "http_request", arguments: { item: "ops/legacy", method: "GET", url: "https://api.test/x" } })))
      .toEqual({ error: "refused", reason: "no_policy" });
    expect(api.events).toEqual([expect.objectContaining({ action: "refused", reason: "no_policy" })]);
  });

  it("enforces the input limits", async () => {
    const { api, url } = await start();
    const { client } = await connect(url, api.staticToken);
    const bad = [{ item: "x".repeat(201), method: "GET", url: "https://api.test/" }, { item: "a/b", method: "TRACE", url: "https://api.test/" },
      { item: "a/b", method: "GET", url: `https://api.test/${"x".repeat(4096)}` },
      { item: "a/b", method: "GET", url: "https://api.test/", headers: Object.fromEntries(Array.from({ length: 51 }, (_, i) => [`h${i}`, "v"])) },
      { item: "a/b", method: "GET", url: "https://api.test/", headers: { h: "v".repeat(4097) } },
      { item: "a/b", method: "GET", url: "https://api.test/", headers: { "bad name": "v" } },
      { item: "a/b", method: "GET", url: "https://api.test/", headers: { "": "v" } },
      { item: "a/b", method: "GET", url: "https://api.test/", headers: { ["h".repeat(65)]: "v" } },
      { item: "a/b", method: "GET", url: "https://api.test/", headers: { h: "v\r\nx-injected: 1" } },
      { item: "a/b", method: "GET", url: "https://api.test/", headers: { h: "v\u0000" } }];
    for (const args of bad) expect((await client.callTool({ name: "http_request", arguments: args })).isError).toBe(true);
    expect(api.events).toEqual([]);
  });

  it("after a revoke the next MCP call is 401 and the key is gone; the static token is refused at once", async () => {
    const { api, gw, url, int } = await start();
    await api.addFolderRecord("Payments", apiKey("Stripe", ["api.test"]));
    const { client } = await connect(url, api.staticToken);
    await client.callTool({ name: "list_secrets", arguments: {} });
    expect(gw.keys.has(api.agent.id)).toBe(true);
    api.revoke();
    await fetch(`${int}/internal/agents/${api.agent.id}`, { method: "DELETE", headers: { "x-gateway-token": api.token } });
    await expect(connect(url, api.staticToken)).rejects.toMatchObject({ code: 401 }); // the cached exchange went with the DELETE
    await expect(client.callTool({ name: "list_secrets", arguments: {} })).rejects.toMatchObject({ code: 401 });
    expect(gw.keys.has(api.agent.id)).toBe(false);
  });

  it("an API refusal during a tool call (no internal drop) is HTTP 401 and evicts the exchange", async () => {
    const { api, gw, url } = await start({ cacheTtlSeconds: 0 });
    const { client } = await connect(url, api.staticToken);
    api.revoke();
    const calls = api.tokenCalls;
    await expect(client.callTool({ name: "list_secrets", arguments: {} })).rejects.toMatchObject({ code: 401 });
    expect(gw.keys.has(api.agent.id)).toBe(false);
    await expect(connect(url, api.staticToken)).rejects.toMatchObject({ code: 401 });
    expect(api.tokenCalls).toBe(calls + 1);
  });

  it("a second call on a busy session is refused busy", async () => {
    const { api, url } = await start();
    const s = http.createServer((req, res) => { req.resume(); setTimeout(() => res.end("slow"), 200); });
    await new Promise<void>((r) => s.listen(0, "127.0.0.1", r));
    closers.push(() => new Promise((r) => { s.closeAllConnections(); s.close(() => r()); }));
    const port = (s.address() as AddressInfo).port;
    await api.addFolderRecord("Payments", apiKey("Stripe", [`api.test:${port}`]));
    const { client } = await connect(url, api.staticToken);
    const args = { item: "payments/stripe", method: "GET", url: `http://api.test:${port}/` };
    const rs = (await Promise.all([client.callTool({ name: "http_request", arguments: args }), client.callTool({ name: "http_request", arguments: args })])).map(result);
    expect(rs).toEqual(expect.arrayContaining([expect.objectContaining({ status: 200, body: "slow" }), { error: "refused", reason: "busy" }]));
    expect(api.events).toEqual(expect.arrayContaining([{ at: expect.any(String), action: "refused", host: "api.test", method: "GET", reason: "busy" },
      expect.objectContaining({ action: "use" })]));
    expect(api.events).toHaveLength(2);
  });

  it("an agent holds at most 20 sessions; the least recently touched makes room", async () => {
    const { api, url } = await start();
    const cs = [];
    for (let i = 0; i < 20; i++) cs.push((await connect(url, api.staticToken)).client);
    await cs[0]!.listTools(); // the first is now the most recently touched; the second the least
    await connect(url, api.staticToken);
    await expect(cs[1]!.listTools()).rejects.toMatchObject({ code: 404 });
    for (const c of [cs[0]!, ...cs.slice(2)]) await c.listTools();
  });

  it("the internal DELETE closes every session of the agent's", async () => {
    const { api, url, int } = await start();
    const jwt = await api.issueToken(); // verifies without the API, so only a closed session can refuse it
    const a = (await connect(url, jwt)).client, b = (await connect(url, jwt)).client;
    await fetch(`${int}/internal/agents/${api.agent.id}`, { method: "DELETE", headers: { "x-gateway-token": api.token } });
    for (const c of [a, b]) await expect(c.listTools()).rejects.toMatchObject({ code: 404 });
  });

  it("a session belongs to one agent: another agent's token on it is 403", async () => {
    const { api, url } = await start();
    const { transport } = await connect(url, api.staticToken);
    const other = await api.issueToken({ sub: api.agent2.id });
    const r = await fetch(url, { method: "POST", body: JSON.stringify({ jsonrpc: "2.0", id: 9, method: "tools/list" }), headers: {
      "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${other}`,
      "mcp-session-id": transport.sessionId!, "mcp-protocol-version": transport.protocolVersion ?? "2025-06-18" } });
    expect(r.status).toBe(403);
    expect(await r.json()).toEqual({ error: "forbidden" });
  });

  it("an idle session is closed", async () => {
    const { api, url } = await start({}, { sessionIdleMs: 50 });
    const { client } = await connect(url, api.staticToken);
    await new Promise((r) => setTimeout(r, 150));
    await expect(client.listTools()).rejects.toMatchObject({ code: 404 });
  });

  it("limits exchange misses per address to 10 a minute; cached tokens are not counted", async () => {
    const { api, url } = await start();
    await connect(url, api.staticToken); // one miss
    const post = (t: string) => fetch(url, { method: "POST", body: "{}", headers: { "content-type": "application/json", authorization: `Bearer ${t}` } });
    for (let i = 0; i < 9; i++) expect((await post(`cvat_${i}_unknown`)).status).toBe(401);
    const r = await post("cvat_10_unknown");
    expect(r.status).toBe(429);
    expect(Number(r.headers.get("retry-after"))).toBeGreaterThan(0);
    expect(await r.json()).toEqual({ error: "rate_limited" });
    await connect(url, api.staticToken); // a cache hit still works
  });
});
