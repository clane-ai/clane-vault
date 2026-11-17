import http from "node:http";
import type { AddressInfo } from "node:net";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { b64url, generateKeyPair as generateX25519, type RecordBody } from "@clane-vault/crypto";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { createGateway } from "../src/app.js";
import type { GatewayConfig } from "../src/config.js";
import { pointerValue } from "../src/deposits.js";
import { loadOrCreateIdentity } from "../src/identity.js";
import { createLogger, HeldSecrets } from "../src/log.js";
import type { Resolver } from "../src/outbound/ssrf.js";
import { startFakeApi } from "./fakeApi.js";
import { fileKek, tempDir } from "./helpers.js";

const AUD = "http://localhost:3002/mcp";
const CANARY = "ghp_CAPTURED_CANARY";
const FORMS = [CANARY, Buffer.from(CANARY).toString("base64"), encodeURIComponent(CANARY)];
const closers: (() => Promise<void>)[] = [];
afterEach(async () => { await Promise.all(closers.splice(0).map((c) => c())); });

const resolve: Resolver = async (h) => (h === "api.test" ? [{ address: "127.0.0.1", family: 4 }] : Promise.reject(new Error("ENOTFOUND")));
const cfgFor = (apiUrl: string, apiToken: string, over: Partial<GatewayConfig>): GatewayConfig => ({
  apiUrl, apiToken, publicUrl: AUD, kek: "file:x", identityKeyFile: "x", cacheTtlSeconds: 60, agentRatePerMinute: 60, maxResponseBytes: 4194304,
  upstreamTimeoutMs: 5000, allowPrivateCidrs: ["127.0.0.0/8"], port: 0, internalPort: 0, internalHost: "127.0.0.1", trustProxy: 0, writePerHour: 20, ...over,
});

/** The upstream creates a credential on /create; /fail answers 500 with one; /big has one past the response cap. */
async function upstream() {
  const seen: string[] = [];
  const s = http.createServer((req, res) => {
    seen.push(`${req.method} ${req.url}`);
    req.resume();
    req.on("end", () => {
      const created = JSON.stringify({ id: 7, token: CANARY });
      if (req.url === "/fail") res.writeHead(500).end(created);
      else if (req.url === "/echo") res.writeHead(201).end(JSON.stringify({ headers: { Authorization: req.headers.authorization } }));
      else if (req.url === "/short") res.writeHead(201).end(JSON.stringify({ token: "ghp_123" }));
      else if (req.url === "/big") res.writeHead(201).end(JSON.stringify({ token: CANARY, pad: "x".repeat(4096) }));
      else res.writeHead(201, { "content-type": "application/json" }).end(created);
    });
  });
  await new Promise<void>((r) => s.listen(0, "127.0.0.1", r));
  closers.push(() => new Promise((r) => { s.closeAllConnections(); s.close(() => r()); }));
  return { port: (s.address() as AddressInfo).port, seen };
}

async function setup(over: Partial<GatewayConfig> = {}) {
  const kek = await fileKek();
  const api = await startFakeApi({ kek, aud: AUD });
  closers.push(api.close);
  const identity = await loadOrCreateIdentity(join(tempDir(), "identity.json"), kek);
  const held = new HeldSecrets();
  const gw = await createGateway(cfgFor(api.url, api.token, over), { kek, identity, held, log: createLogger(held, () => {}), resolve });
  closers.push(gw.close);
  await new Promise<void>((r) => gw.publicServer.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${(gw.publicServer.address() as AddressInfo).port}/mcp`;
  const up = await upstream();
  const admin: RecordBody = { v: 2, type: "apiKey", title: "GitHub admin", data: { secret: "ghp_ADMIN_TOKEN_1" },
    agentPolicy: { v: 1, hosts: [`api.test:${up.port}`], inject: { kind: "bearer" } } };
  await api.personal.addRecord(admin);
  await api.addFolderRecord("Ops", admin);
  const connect = async (token: string) => {
    const client = new Client({ name: "test", version: "1" });
    await client.connect(new StreamableHTTPClientTransport(new URL(url), { requestInit: { headers: { Authorization: `Bearer ${token}` } } }));
    closers.unshift(() => client.close().catch(() => {}));
    return Object.assign(async (name: string, args: Record<string, unknown>) => {
      const r = await client.callTool({ name, arguments: args });
      return { r, out: (r as { structuredContent?: Record<string, unknown> }).structuredContent, text: JSON.stringify(r) };
    }, { client });
  };
  const tool = await connect(await api.personal.token());
  const capture = { from: "/token", title: "GitHub deploy token", type: "apiKey", agent_use: { hosts: ["api.github.test"], inject: { kind: "bearer" } } };
  const req = (path = "/create", c: Record<string, unknown> = capture) => ({ item: "personal/github-admin", method: "POST", url: `http://api.test:${up.port}${path}`, body: "{}", capture: c });
  return { api, gw, url, up, tool, connect, capture, req };
}

describe("http_request capture", () => {
  it("saves the created credential as a deposit; the model sees only the redacted response and the new handle", async () => {
    const { api, up, tool, req } = await setup();
    const { out, text } = await tool("http_request", req());
    expect(out).toMatchObject({ status: 201, saved: { item: "personal/github-deploy-token" } });
    expect(out!.body).toContain("[clane:redacted]");
    expect(out!.body).toContain('"id":7');
    for (const f of FORMS) expect(text).not.toContain(f);
    expect(up.seen).toEqual(["POST /create"]);
    const [d] = api.personal.deposits;
    expect(await api.personal.open(d!.id)).toMatchObject({ type: "apiKey", title: "GitHub deploy token", data: { secret: CANARY },
      agentPolicy: { hosts: ["api.github.test"], inject: { kind: "bearer" } } });
    for (const b of api.bodies) for (const f of FORMS) expect(b).not.toContain(f);
    expect((await tool("list_secrets", {})).out).toEqual({ secrets: expect.arrayContaining([expect.objectContaining({ handle: "personal/github-deploy-token", deposit: true })]) });
  });

  it("an inbox another agent of the owner filled is inbox_full, checked on a fresh sync, with nothing sent", async () => {
    const { api, up, tool, req } = await setup();
    await tool("list_secrets", {}); // the sync is cached with room
    api.personal.setInboxFree(0);
    expect((await tool("http_request", req())).out).toEqual({ error: "refused", reason: "inbox_full" });
    expect(up.seen).toEqual([]);
    expect(api.personal.writes).toEqual([]);
  });

  it("policy write off is not_writable, a swapped owner key is owner_key_changed; nothing sent, nothing deposited", async () => {
    const { api, gw, up, tool, req } = await setup();
    api.personal.setPolicyWrite(false);
    expect((await tool("http_request", req())).out).toEqual({ error: "refused", reason: "not_writable" });
    api.personal.setPolicyWrite(true);
    api.personal.setOwnerPublicKey(b64url.encode((await generateX25519()).publicKey));
    gw.keys.drop(api.personal.agentId);
    expect((await tool("http_request", req())).out).toEqual({ error: "refused", reason: "owner_key_changed" });
    expect(up.seen).toEqual([]);
    expect(api.personal.writes).toEqual([]);
  });

  it("the write limit used up is 429 before the transport: no request sent; http_request without capture is not counted", async () => {
    const { api, up, req, url } = await setup({ writePerHour: 1 });
    const t = await api.personal.token();
    const post = (args: Record<string, unknown>) => fetch(url, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${t}` },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "http_request", arguments: args } }) });
    const { capture: _c, ...plain } = req();
    expect((await post(plain)).status).not.toBe(429);
    expect((await post(req())).status).not.toBe(429); // takes the one write (no session: refused after the limit)
    const r = await post(req());
    expect(r.status).toBe(429);
    expect(await r.json()).toEqual({ error: "rate_limited" });
    expect(up.seen).toEqual([]);
  });

  it("a deposit refused after the call: the response still scrubbed, capture.refused names the reason, no saved", async () => {
    const { api, up, tool, req } = await setup();
    api.personal.refuseWrites("conflict");
    const { out, text } = await tool("http_request", req());
    expect(out).toMatchObject({ status: 201, capture: { refused: "conflict" } });
    expect(out).not.toHaveProperty("saved");
    for (const f of FORMS) expect(text).not.toContain(f);
    expect(up.seen).toEqual(["POST /create"]);
  });

  it("no value at the pointer is not_found; a non-2xx is not_found and still scrubbed of the value; a truncated body is withheld", async () => {
    const { api, tool, req, capture } = await setup({ maxResponseBytes: 1024 });
    expect((await tool("http_request", req("/create", { ...capture, from: "/missing" }))).out).toMatchObject({ status: 201, capture: { refused: "not_found" } });
    const fail = await tool("http_request", req("/fail"));
    expect(fail.out).toMatchObject({ status: 500, capture: { refused: "not_found" } });
    expect(fail.out!.body).toContain("[clane:redacted]");
    for (const f of FORMS) expect(fail.text).not.toContain(f);
    const big = await tool("http_request", req("/big"));
    expect(big.out).toMatchObject({ status: 201, truncated: true, body: "", capture: { refused: "invalid" } });
    for (const f of FORMS) expect(big.text).not.toContain(f);
    expect(api.personal.writes).toEqual([]);
  });

  it("the injected credential echoed back is never saved: invalid, scrubbed, reflected; a value under 8 characters is invalid", async () => {
    const { api, tool, req, capture } = await setup();
    const echo = await tool("http_request", req("/echo", { ...capture, from: "/headers/Authorization", agent_use: { hosts: ["evil.test"], inject: { kind: "bearer" } } }));
    expect(echo.out).toMatchObject({ status: 201, capture: { refused: "invalid" } });
    expect(echo.out).not.toHaveProperty("saved");
    for (const f of ["ghp_ADMIN_TOKEN_1", Buffer.from("ghp_ADMIN_TOKEN_1").toString("base64")]) expect(echo.text).not.toContain(f);
    expect(api.events).toEqual(expect.arrayContaining([expect.objectContaining({ action: "reflected" })]));
    const short = await tool("http_request", req("/short"));
    expect(short.out).toMatchObject({ status: 201, capture: { refused: "invalid" } });
    expect(short.text).not.toContain("ghp_123");
    expect(api.personal.writes).toEqual([]);
  });

  it("is an input error in an organisation session, and for a type with no default secret field", async () => {
    const { api, up, tool, connect, req, capture } = await setup();
    const org = await connect(api.staticToken);
    // Its listed schema is the shipped one: no capture, nothing about additional properties.
    const schema = (await org.client.listTools()).tools.find((t) => t.name === "http_request")!.inputSchema;
    expect(Object.keys(schema.properties ?? {}).sort()).toEqual(["body", "headers", "item", "method", "url"]);
    expect(schema).not.toHaveProperty("additionalProperties");
    expect((await org("http_request", { ...req(), item: "ops/github-admin" })).r.isError).toBe(true);
    expect((await tool("http_request", req("/create", { ...capture, type: "note" }))).r.isError).toBe(true);
    expect((await tool("http_request", req("/create", { ...capture, from: `/${"x".repeat(256)}` }))).r.isError).toBe(true);
    expect(up.seen).toEqual([]);
    // Without capture an organisation agent's http_request is unchanged.
    const { capture: _c, ...plain } = req();
    expect((await org("http_request", { ...plain, item: "ops/github-admin" })).out).toMatchObject({ status: 201 });
  });
});

describe("pointerValue", () => {
  it("follows RFC 6901 and returns only a non-empty string", () => {
    expect(pointerValue('{"a/b":{"c":["x","y"]}}', "/a~1b/c/1")).toBe("y");
    expect(pointerValue('{"m~n":"v"}', "/m~0n")).toBe("v");
    for (const [j, p] of [['{"a":1}', "/a"], ['{"a":{}}', "/a"], ['{"a":""}', "/a"], ['{"a":"v"}', "/b"], ["not json", "/a"], ['["v"]', "/01"], ['"v"', "a"]])
      expect(pointerValue(j!, p!), `${j} ${p}`).toBeNull();
    expect(pointerValue('"v"', "")).toBe("v");
    expect(pointerValue(JSON.stringify({ a: "x".repeat(64 * 1024 + 1) }), "/a")).toBeNull();
  });
});
