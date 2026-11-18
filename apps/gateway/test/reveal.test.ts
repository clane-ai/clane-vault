import type { AddressInfo } from "node:net";
import { randomUUID } from "node:crypto";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { agentRevealRequestMessage, verifyGatewayMessage, type RecordBody } from "@clane-vault/crypto";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { createGateway } from "../src/app.js";
import type { GatewayConfig } from "../src/config.js";
import { loadOrCreateIdentity } from "../src/identity.js";
import { createLogger, HeldSecrets } from "../src/log.js";
import { PendingReveals } from "../src/reveal.js";
import { startFakeApi } from "./fakeApi.js";
import { fileKek, tempDir } from "./helpers.js";

const AUD = "http://localhost:3002/mcp";
const closers: (() => Promise<void>)[] = [];
afterEach(async () => { await Promise.all(closers.splice(0).map((c) => c())); });

const cfgFor = (apiUrl: string, apiToken: string, over: Partial<GatewayConfig>): GatewayConfig => ({
  apiUrl, apiToken, publicUrl: AUD, kek: "file:x", identityKeyFile: "x", cacheTtlSeconds: 0, agentRatePerMinute: 60, maxResponseBytes: 4194304,
  upstreamTimeoutMs: 5000, allowPrivateCidrs: ["127.0.0.0/8"], port: 0, internalPort: 0, internalHost: "127.0.0.1", trustProxy: 0, writePerHour: 20,
  reveal: "approval", revealPerHour: 10, ...over,
});
const login: RecordBody = { v: 2, type: "login", title: "Echo", username: "u", password: "p", agentPolicy: { v: 1, hosts: ["api.test"], inject: { kind: "bearer" } } };

async function setup(over: Partial<GatewayConfig> = {}) {
  const kek = await fileKek();
  const api = await startFakeApi({ kek, aud: AUD });
  closers.push(api.close);
  const identity = await loadOrCreateIdentity(join(tempDir(), "identity.json"), kek);
  const held = new HeldSecrets();
  const gw = await createGateway(cfgFor(api.url, api.token, over), { kek, identity, held, log: createLogger(held, () => {}), revealPollMs: 5, revealWaitMs: 60 });
  closers.push(gw.close);
  await new Promise<void>((r) => gw.publicServer.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${(gw.publicServer.address() as AddressInfo).port}/mcp`;
  const connect = async (token: string) => {
    const client = new Client({ name: "test", version: "1" });
    await client.connect(new StreamableHTTPClientTransport(new URL(url), { requestInit: { headers: { Authorization: `Bearer ${token}` } } }));
    closers.unshift(() => client.close().catch(() => {}));
    return Object.assign(async (name: string, args: Record<string, unknown> = {}) =>
      (await client.callTool({ name, arguments: args }) as { structuredContent?: Record<string, unknown> }).structuredContent, { client });
  };
  api.personal.setPolicyReveal("approval");
  const echo = await api.personal.addRecord(login);
  await api.personal.addStub(["username"], { recordId: echo, title: "Echo" });
  const tool = await connect(await api.personal.token());
  const ask = { item: "personal/echo", fields: ["username"], reason: "to log in" };
  const asked = () => api.personal.writes.filter((w) => w.path === "/agent/reveals");
  return { api, gw, identity, url, tool, connect, ask, asked, echo };
}

describe("get_secret", () => {
  it("GATEWAY_REVEAL off: reveal_off and no request reaches the API (spec §8)", async () => {
    const { tool, ask, asked } = await setup({ reveal: "off" });
    expect(await tool("get_secret", ask)).toEqual({ error: "refused", reason: "reveal_off" });
    expect(asked()).toEqual([]);
  });

  it("the owner's policy off: reveal_off with no API call", async () => {
    const { api, tool, ask, asked } = await setup();
    api.personal.setPolicyReveal("off");
    expect(await tool("get_secret", ask)).toEqual({ error: "refused", reason: "reveal_off" });
    expect(asked()).toEqual([]);
  });

  it("approval: the owner allows, the value comes back once; the request is signed by the gateway over its own key", async () => {
    const { api, identity, tool, ask, asked } = await setup();
    api.personal.onReveal((r) => api.personal.approveReveal(r.id, { username: "u" }));
    expect(await tool("get_secret", ask)).toEqual({ fields: { username: "u" } });
    const [w] = asked();
    const b = w!.body as { id: string; recordId: string; fields: string[]; requestPublicKey: string; signature: string; expiresAt: string; reason: string };
    expect(b.reason).toBe("to log in");
    expect(Date.parse(b.expiresAt) - Date.now()).toBeLessThanOrEqual(5 * 60e3);
    const msg = agentRevealRequestMessage({ requestId: b.id, ownerUserId: api.personal.ownerId, agentId: api.personal.agentId, recordId: b.recordId, fields: b.fields,
      requestPublicKey: b.requestPublicKey, expiresAt: b.expiresAt });
    expect(await verifyGatewayMessage(b.signature, "q1", msg, identity)).toBe(true);
  });

  it("a field outside the stub is `field`, an item without a stub `reveal_off`, an unknown item `not_found`: no API call", async () => {
    const { api, tool, ask, asked } = await setup();
    await api.personal.addRecord({ ...login, title: "Plain" });
    expect(await tool("get_secret", { ...ask, fields: ["password"] })).toEqual({ error: "refused", reason: "field" });
    expect(await tool("get_secret", { ...ask, item: "personal/plain" })).toEqual({ error: "refused", reason: "reveal_off" });
    expect(await tool("get_secret", { ...ask, item: "personal/nope" })).toEqual({ error: "refused", reason: "not_found" });
    expect(asked()).toEqual([]);
  });

  it("denied, pending then resumed, expired; another agent's request id; the session is free afterwards (Review Focus 1)", async () => {
    const { api, tool, ask } = await setup();
    api.personal.onReveal((r) => { r.status = "denied"; });
    expect(await tool("get_secret", ask)).toEqual({ error: "refused", reason: "denied" });

    api.personal.onReveal(null);
    const p = await tool("get_secret", ask) as { status: string; request_id: string };
    expect(p).toEqual({ status: "pending", request_id: expect.any(String) });
    expect(await tool("list_secrets")).toHaveProperty("secrets"); // not busy any more
    await api.personal.approveReveal(p.request_id, { username: "u" });
    expect(await tool("get_secret", { request_id: p.request_id })).toEqual({ fields: { username: "u" } });
    expect(await tool("get_secret", { request_id: p.request_id })).toEqual({ error: "refused", reason: "expired" });

    const q = await tool("get_secret", ask) as { request_id: string };
    api.personal.reveals.find((x) => x.id === q.request_id)!.status = "expired";
    expect(await tool("get_secret", { request_id: q.request_id })).toEqual({ error: "refused", reason: "expired" });
    expect(await tool("get_secret", { request_id: randomUUID() })).toEqual({ error: "refused", reason: "expired" });
    expect(await tool("get_secret", { request_id: q.request_id, item: "personal/echo" })).toEqual({ error: "refused", reason: "invalid" });
  });

  it("the API's busy is `busy`; the 11th new request in an hour is HTTP 429 before the transport", async () => {
    const { api, tool, ask, url } = await setup();
    api.personal.refuseReveal("busy");
    for (let i = 0; i < 10; i++) expect(await tool("get_secret", ask)).toEqual({ error: "refused", reason: "busy" });
    const r = await fetch(url, { method: "POST", body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "get_secret", arguments: ask } }),
      headers: { authorization: `Bearer ${await api.personal.token()}`, "content-type": "application/json", accept: "application/json, text/event-stream" } });
    expect(r.status).toBe(429);
    expect(await tool("get_secret", { request_id: randomUUID() })).toEqual({ error: "refused", reason: "expired" }); // resuming costs nothing
  });

  it("list_secrets: modes and reveal; a reveal-only item is listed and http_request on it is not_found", async () => {
    const { api, tool } = await setup();
    await api.personal.addStub(["password", "username"], { title: "Wifi" });
    const { secrets } = await tool("list_secrets") as { secrets: Record<string, unknown>[] };
    expect(secrets.find((s) => s.handle === "personal/echo")).toMatchObject({ modes: ["use", "reveal"], reveal: { fields: ["username"], approval: true } });
    expect(secrets.find((s) => s.handle === "personal/wifi")).toMatchObject({ title: "Wifi", type: "login", hosts: [], modes: ["reveal"], reveal: { fields: ["password", "username"], approval: true } });
    expect(await tool("http_request", { item: "personal/wifi", method: "GET", url: "http://api.test/" })).toEqual({ error: "refused", reason: "not_found" });
    api.personal.onReveal((r) => api.personal.approveReveal(r.id, { password: "pw" }));
    expect(await tool("get_secret", { item: "personal/wifi", fields: ["password"], reason: "join the network" })).toEqual({ fields: { password: "pw" } });
  });

  it("tools: five for a personal session, two for an organisation's; /internal/health reports the mode", async () => {
    const { api, connect, gw, tool } = await setup();
    expect((await tool.client.listTools()).tools.map((t) => t.name).sort()).toEqual(["get_secret", "http_request", "list_secrets", "save_secret", "update_secret"]);
    expect(tool.client.getInstructions()).toBe("`http_request` uses a credential without showing it; prefer it. `get_secret` shows you a value only where the owner allowed it, and they may be asked to approve.");
    const org = await connect(api.staticToken);
    expect((await org.client.listTools()).tools.map((t) => t.name).sort()).toEqual(["http_request", "list_secrets"]);
    expect(org.client.getInstructions()).toContain("You will never see a credential");
    await new Promise<void>((r) => gw.internalServer.listen(0, "127.0.0.1", r));
    const h = await fetch(`http://127.0.0.1:${(gw.internalServer.address() as AddressInfo).port}/internal/health`, { headers: { "x-gateway-token": api.token } });
    expect(await h.json()).toMatchObject({ reveal: "approval" });
  });
});

describe("PendingReveals", () => {
  it("zeroes a key when it is taken or swept, and gives a request only to its own agent", () => {
    const p = new PendingReveals();
    const k = { privateKey: new Uint8Array([1, 2, 3]), publicKey: new Uint8Array(32) };
    p.add({ id: "q", agentId: "a", recordId: "r", keys: k, expiresAt: 1000 });
    expect(p.get("q", "b")).toBeUndefined();
    expect(p.get("q", "a")?.recordId).toBe("r");
    p.take("q");
    expect([...k.privateKey]).toEqual([0, 0, 0]);
    const k2 = { privateKey: new Uint8Array([4]), publicKey: new Uint8Array(32) };
    p.add({ id: "q2", agentId: "a", recordId: "r", keys: k2, expiresAt: 1000 });
    p.sweep(1001);
    expect(p.get("q2", "a")).toBeUndefined();
    expect([...k2.privateKey]).toEqual([0]);
  });
});
