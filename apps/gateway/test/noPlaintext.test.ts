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
const FORMS = [SECRET, Buffer.from(SECRET).toString("base64"), Buffer.from(SECRET).toString("base64url")];
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
  upstreamTimeoutMs: 300, allowPrivateCidrs: ["127.0.0.0/8"], port: 0, internalPort: 0, internalHost: "127.0.0.1", trustProxy: 0,
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
  const client = new Client({ name: "test", version: "1" });
  await client.connect(new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${(gw.publicServer.address() as AddressInfo).port}/mcp`),
    { requestInit: { headers: { Authorization: `Bearer ${api.staticToken}` } } }));
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
