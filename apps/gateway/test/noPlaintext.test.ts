import http from "node:http";
import type { AddressInfo } from "node:net";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { RecordBody } from "@clane-vault/crypto";
import { createGateway } from "../src/app.js";
import type { GatewayConfig } from "../src/config.js";
import { loadOrCreateIdentity } from "../src/identity.js";
import type { Kek } from "../src/kek.js";
import { createLogger, HeldSecrets, installCrashHandlers } from "../src/log.js";
import type { Resolver } from "../src/outbound/ssrf.js";
import { startFakeApi } from "./fakeApi.js";
import { fileKek, tempDir } from "./helpers.js";

const SECRET = "sk_live_PLAINTEXT_CANARY_42";
// Values the agent writes with save_secret and update_secret (spec §8).
const WRITTEN = ["sk_live_SAVE_CANARY_43", "sk_live_UPDATE_CANARY_44", "pw_RECORD_CANARY_45", "cf_FIELD_CANARY_46"];
// A credential the upstream creates and http_request's capture saves.
const CAPTURED = "ghp_CAPTURED_CANARY_47";
// Env-file entry values the agent saves and sets (spec §10).
const ENV = ["sk_live_ENVCANARY1", "sk_live_ENVCANARY2"];
// A value the owner lets get_secret show: in that tool's response only (spec §8).
const REVEALED = "acct_REVEALED_CANARY_48";
// One read on standing reveal (Phase D): the same rule.
const STANDING = "wifi_STANDING_CANARY_49";
const FORMS = [SECRET, ...WRITTEN, CAPTURED, ...ENV, REVEALED, STANDING].flatMap((v) => [v, Buffer.from(v).toString("base64"), Buffer.from(v).toString("base64url")]);
const AUD = "http://localhost:3002/mcp";

// performRequest as is, unless a test makes the tool throw (an Error carrying the secret) or raise a real uncaught throw.
const boom = vi.hoisted(() => ({ mode: "" as "" | "throw" | "uncaught" }));
vi.mock("../src/outbound/request.js", async (orig) => {
  const m = await orig<typeof import("../src/outbound/request.js")>();
  return {
    ...m,
    performRequest: async (...a: Parameters<typeof m.performRequest>) => {
      if (boom.mode === "throw") throw new Error(`tool failed holding ${a[1].secret}`);
      if (boom.mode === "uncaught") {
        const s = a[1].secret;
        // After the call has ended, so the secret is no longer held for redaction: only the handler keeps it out.
        setTimeout(() => setImmediate(() => { throw new Error(`crashed holding ${s}`); }), 100);
      }
      return m.performRequest(...a);
    },
  };
});

const captured: string[] = [];
const closers: (() => Promise<void>)[] = [];
const resolve: Resolver = async (h) => (h === "api.test" ? [{ address: "127.0.0.1", family: 4 }] : Promise.reject(new Error("ENOTFOUND")));
const cfgFor = (apiUrl: string, apiToken: string): GatewayConfig => ({
  apiUrl, apiToken, publicUrl: AUD, kek: "file:x", identityKeyFile: "x", cacheTtlSeconds: 60, agentRatePerMinute: 600, maxResponseBytes: 4194304,
  upstreamTimeoutMs: 300, allowPrivateCidrs: ["127.0.0.0/8"], port: 0, internalPort: 0, internalHost: "127.0.0.1", trustProxy: 0, writePerHour: 20, reveal: "standing", revealPerHour: 10,
});
const apiKey = (port: number): RecordBody => ({ v: 2, type: "apiKey", title: "Stripe", data: { secret: SECRET, keyId: "kid" },
  agentPolicy: { v: 1, hosts: [`api.test:${port}`], inject: { kind: "bearer" } } });

let port = 0;
const apis: Awaited<ReturnType<typeof startFakeApi>>[] = [];
const held = new HeldSecrets();
const log = createLogger(held); // the real logger: lines reach process.stdout / process.stderr

/** A gateway whose KEK is `gwKek`, against a fake API whose agent key is wrapped under `apiKek`. */
async function gateway(apiKek: Kek, gwKek: Kek) {
  const api = await startFakeApi({ kek: apiKek, aud: AUD });
  closers.push(api.close);
  apis.push(api);
  await api.addFolderRecord("Payments", apiKey(port));
  const identity = await loadOrCreateIdentity(join(tempDir(), "identity.json"), gwKek);
  const gw = await createGateway(cfgFor(api.url, api.token), { kek: gwKek, identity, held, log, resolve });
  closers.push(gw.close);
  await new Promise<void>((r) => gw.publicServer.listen(0, "127.0.0.1", r));
  return Object.assign(await caller(gw.publicServer, api.staticToken), { api, server: gw.publicServer });
}

async function caller(server: http.Server, token: string) {
  const client = new Client({ name: "test", version: "1" });
  await client.connect(new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${(server.address() as AddressInfo).port}/mcp`),
    { requestInit: { headers: { Authorization: `Bearer ${token}` } } }));
  closers.unshift(() => client.close().catch(() => {}));
  // Every MCP response, including the errors the client throws.
  return async (name: string, args: Record<string, unknown> = {}) => {
    let out: string;
    try { out = JSON.stringify(await client.callTool({ name, arguments: args })); } catch (e) { out = `${String(e)} ${JSON.stringify(e)}`; }
    captured.push(out);
    return out;
  };
}

const call = (path: string) => ({ item: "payments/stripe", method: "GET", url: `http://api.test:${port}${path}` });

beforeAll(async () => {
  for (const s of [process.stdout, process.stderr]) vi.spyOn(s, "write").mockImplementation(((c: unknown) => { captured.push(String(c)); return true; }) as never);
  // /echo hands the credential back in a header and the body; /hang never answers.
  const up = http.createServer((req, res) => {
    req.resume();
    if (req.url === "/hang") return;
    if (req.url === "/create") return res.end(JSON.stringify({ id: 7, token: CAPTURED }));
    res.setHeader("x-echo", String(req.headers.authorization));
    res.end(`you sent ${req.headers.authorization} and ${Buffer.from(SECRET).toString("base64")}`);
  });
  await new Promise<void>((r) => up.listen(0, "127.0.0.1", r));
  closers.push(() => new Promise((r) => { up.closeAllConnections(); up.close(() => r()); }));
  port = (up.address() as AddressInfo).port;
});
afterAll(async () => {
  for (const c of closers.splice(0)) await c();
  vi.restoreAllMocks();
});

describe("no plaintext anywhere", () => {
  it("the canary and its base64 forms appear in no log line, output write, MCP response or API request body", async () => {
    const kek = await fileKek();
    const tool = await gateway(kek, kek);

    // A bad KEK: the wrapped key is under another file KEK.
    const badKek = await gateway(await fileKek(), kek);
    for (const r of [await badKek("list_secrets"), await badKek("http_request", call("/echo"))]) {
      expect(JSON.parse(r)).toMatchObject({ isError: true, structuredContent: { error: "internal_error" } });
    }

    // A personal agent writes known values: a deposit, its update, an update of a record it may write.
    await tool.api.personal.addRecord({ v: 2, type: "login", title: "Writable", username: "bot", password: "old_pw_value" }, undefined, true);
    const mine = await caller(tool.server, await tool.api.personal.token());
    expect(JSON.parse(await mine("save_secret", { title: "Saved", type: "apiKey", fields: { data: { secret: WRITTEN[0] } },
      custom_fields: [{ label: "Extra", kind: "secret", value: WRITTEN[3] }] }))).toMatchObject({ structuredContent: { item: "personal/saved" } });
    expect(JSON.parse(await mine("update_secret", { item: "personal/saved", set: { data: { secret: WRITTEN[1] } } }))).toMatchObject({ structuredContent: { revision: 2 } });
    expect(JSON.parse(await mine("update_secret", { item: "personal/writable", set: { password: WRITTEN[2] } }))).toMatchObject({ structuredContent: { revision: 2 } });
    expect(JSON.parse(await mine("save_secret", { title: "Too big", type: "note", fields: { notes: `${WRITTEN[0]}${"x".repeat(60 * 1024)}` } })))
      .toMatchObject({ structuredContent: { error: "refused", reason: "invalid" } });
    expect((await tool.api.personal.open(tool.api.personal.deposits[0]!.id)).data?.secret).toBe(WRITTEN[1]); // the writes did happen

    // An env file saved, then one entry set.
    expect(JSON.parse(await mine("save_secret", { type: "envFile", title: "Billing", fields: { data: { project: "billing", content: `STRIPE_KEY=${ENV[0]}\nPORT=3000\n` } } })))
      .toMatchObject({ structuredContent: { item: "personal/billing" } });
    expect(JSON.parse(await mine("update_secret", { item: "personal/billing", set: { env: { STRIPE_KEY: ENV[1] } } }))).toMatchObject({ structuredContent: { revision: 2 } });
    expect((await tool.api.personal.open(tool.api.personal.deposits[1]!.id)).data?.content).toBe(`STRIPE_KEY=${ENV[1]}\nPORT=3000\n`);

    // A capture: the upstream answers with a new credential, which is saved and scrubbed from the response.
    await tool.api.personal.addRecord({ ...apiKey(port), title: "Creator" });
    expect(JSON.parse(await mine("http_request", { item: "personal/creator", method: "POST", url: `http://api.test:${port}/create`, body: "{}",
      capture: { from: "/token", title: "Captured", type: "apiKey" } }))).toMatchObject({ structuredContent: { saved: { item: "personal/captured" } } });
    expect((await tool.api.personal.open(tool.api.personal.deposits[2]!.id)).data?.secret).toBe(CAPTURED);

    // A reveal the owner approves: the value is in get_secret's response, and in nothing else checked below.
    tool.api.personal.setPolicyReveal("approval");
    const shownId = await tool.api.personal.addRecord({ v: 2, type: "login", title: "Shown", username: REVEALED });
    await tool.api.personal.addStub(["username"], { recordId: shownId, title: "Shown" });
    tool.api.personal.onReveal((r) => tool.api.personal.approveReveal(r.id, { username: REVEALED }));
    expect(JSON.parse(await mine("get_secret", { item: "personal/shown", fields: ["username"], reason: "check the account" })))
      .toMatchObject({ structuredContent: { fields: { username: REVEALED } } });
    expect(captured.pop()).toContain(REVEALED); // that response, and only it, leaves the check
    tool.api.personal.setPolicyReveal("standing");
    await tool.api.personal.addRecord({ v: 2, type: "wifi", title: "Office wifi", password: STANDING,
      agentReveal: { v: 1, agents: [tool.api.personal.agentId], fields: ["password"] } }, undefined, false, false, "owner");
    expect(JSON.parse(await mine("get_secret", { item: "personal/office-wifi", fields: ["password"], reason: "join the network" })))
      .toMatchObject({ structuredContent: { fields: { password: STANDING } } });
    expect(captured.pop()).toContain(STANDING);

    await tool("http_request", call("/hang")); // an upstream timeout
    await tool("http_request", call("/echo")); // a scrub hit
    await tool("http_request", { ...call("/"), url: "https://evil.test/" }); // a refused host

    boom.mode = "throw"; // a tool throw: the SDK would put the message in the result
    expect(JSON.parse(await tool("http_request", call("/echo")))).toMatchObject({ isError: true, structuredContent: { error: "internal_error" } });

    // A real uncaught exception, through the crash handlers with a fake exit.
    boom.mode = "uncaught";
    const events = ["uncaughtException", "unhandledRejection"] as const;
    const saved = events.map((ev) => [ev, process.listeners(ev)] as const);
    for (const ev of events) process.removeAllListeners(ev);
    const proc = { on: (ev: string, f: (e: unknown) => void) => { process.on(ev as "uncaughtException", f); } } as Pick<NodeJS.Process, "on">;
    let exited!: (code: number) => void;
    const exit = new Promise<number>((r) => { exited = r; });
    installCrashHandlers(proc, log, exited);
    try {
      await tool("http_request", call("/echo"));
      expect(await exit).toBe(1);
    } finally {
      boom.mode = "";
      for (const [ev, ls] of saved) {
        process.removeAllListeners(ev);
        for (const l of ls) process.on(ev, l as never);
      }
    }

    const all = [...captured, ...apis.flatMap((a) => a.bodies)].join("\n");
    // The scenarios ran and were seen.
    for (const s of ['"reason":"timeout"', '"reflected"', '"reason":"host"', "[clane:redacted]", '"event":"tool_error"', '"event":"crash"'])
      expect(all).toContain(s);
    for (const f of FORMS) expect(all).not.toContain(f);
  });
});
