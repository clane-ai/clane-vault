import http from "node:http";
import https from "node:https";
import net from "node:net";
import tls from "node:tls";
import { readFileSync } from "node:fs";
import { gzipSync } from "node:zlib";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { AgentInject, AgentPolicy } from "@clane-vault/crypto";
import { performRequest, type OutboundCtx } from "../src/outbound/request.js";
import { REDACTED } from "../src/outbound/scrub.js";
import { parseCidrs, type Resolver } from "../src/outbound/ssrf.js";

const SECRET = "sk_test/Ab+9 x!*'z";
const allow = parseCidrs(["127.0.0.0/8"]);
const MiB = 1024 * 1024;
const cert = readFileSync(new URL("./fixtures/upstream-cert.pem", import.meta.url), "utf8");
const key = readFileSync(new URL("./fixtures/upstream-key.pem", import.meta.url), "utf8");

interface Seen { method: string; url: string; headers: http.IncomingHttpHeaders; body: string }
type Handler = (req: http.IncomingMessage, res: http.ServerResponse, body: string) => void;
const servers: (http.Server & { closeAllConnections(): void })[] = [];
afterEach(async () => {
  vi.restoreAllMocks();
  for (const s of servers.splice(0)) { s.closeAllConnections(); await new Promise((r) => s.close(r)); }
});

async function serve(handler: Handler = (_q, r) => r.end("ok"), secure = false) {
  const seen: Seen[] = [];
  const fn = (req: http.IncomingMessage, res: http.ServerResponse) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => { seen.push({ method: req.method!, url: req.url!, headers: req.headers, body }); handler(req, res, body); });
  };
  const s = (secure ? https.createServer({ key, cert }, fn) : http.createServer(fn)) as (typeof servers)[number];
  servers.push(s);
  await new Promise<void>((r) => s.listen(0, "127.0.0.1", r));
  return { port: (s.address() as net.AddressInfo).port, seen };
}

const stub = (map: Record<string, string[]>): Resolver & { calls: string[] } => {
  const calls: string[] = [];
  const f = async (h: string) => {
    calls.push(h);
    const a = map[h];
    if (!a) throw new Error("ENOTFOUND");
    return a.map((address) => ({ address, family: (net.isIP(address) as 4 | 6) }));
  };
  return Object.assign(f, { calls });
};
const local = () => stub({ "api.test": ["127.0.0.1"], "other.test": ["127.0.0.1"] });

function ctx(hosts: string[], over: Partial<OutboundCtx> & { inject?: AgentInject; pol?: Partial<AgentPolicy> } = {}): OutboundCtx {
  const { inject = { kind: "bearer" }, pol, ...rest } = over;
  return {
    policy: { v: 1, hosts, inject, ...pol }, secret: SECRET, username: "bob",
    cfg: { maxResponseBytes: 4 * MiB, upstreamTimeoutMs: 5000 }, allow, resolve: local(), ...rest,
  };
}

describe("performRequest: SSRF", () => {
  it.each(["127.0.0.1", "10.0.0.5", "169.254.169.254", "fd00::1", "::ffff:10.0.0.1"])("refuses a host resolving to %s with no socket opened", async (ip) => {
    const onConnect = vi.fn();
    const nc = vi.spyOn(net, "connect"), tc = vi.spyOn(tls, "connect");
    const out = await performRequest({ method: "GET", url: "https://evil.test/" }, ctx(["evil.test"], { allow: [], resolve: stub({ "evil.test": [ip] }), onConnect }));
    expect(out).toEqual({ ok: false, host: "evil.test", reason: "ssrf" });
    expect(onConnect).not.toHaveBeenCalled();
    expect(nc).not.toHaveBeenCalled();
    expect(tc).not.toHaveBeenCalled();
  });
  it("refuses metadata.google.internal by name without resolving it", async () => {
    const r = stub({ "metadata.google.internal": ["8.8.8.8"] });
    const out = await performRequest({ method: "GET", url: "https://metadata.google.internal/" }, ctx(["metadata.google.internal"], { allow: [], resolve: r }));
    expect(out).toMatchObject({ ok: false, reason: "ssrf" });
    expect(r.calls).toEqual([]);
  });
  it("refuses when any resolved address is private", async () => {
    const out = await performRequest({ method: "GET", url: "https://mixed.test/" }, ctx(["mixed.test"], { allow: [], resolve: stub({ "mixed.test": ["8.8.8.8", "10.0.0.1"] }) }));
    expect(out).toMatchObject({ ok: false, reason: "ssrf" });
  });
  it("refuses 169.254.169.254 even when 169.254.0.0/16 is allowed", async () => {
    const out = await performRequest({ method: "GET", url: "http://md.test/" },
      ctx(["md.test:80"], { allow: parseCidrs(["169.254.0.0/16"]), resolve: stub({ "md.test": ["169.254.169.254"] }) }));
    expect(out).toMatchObject({ ok: false, reason: "ssrf" });
  });
  it("connects to the checked address only (DNS rebinding)", async () => {
    const up = await serve();
    let n = 0;
    const r: Resolver = vi.fn(async () => [{ address: n++ === 0 ? "127.0.0.1" : "10.9.9.9", family: 4 as const }]);
    const onConnect = vi.fn();
    const out = await performRequest({ method: "GET", url: `http://api.test:${up.port}/x` }, ctx([`api.test:${up.port}`], { resolve: r, onConnect }));
    expect(out).toMatchObject({ ok: true, result: { status: 200, body: "ok" } });
    expect(up.seen).toHaveLength(1);
    expect(up.seen[0]!.headers.host).toBe(`api.test:${up.port}`);
    expect(onConnect.mock.calls).toEqual([["127.0.0.1"]]);
    expect(r).toHaveBeenCalledTimes(1);
  });
  it("refuses a host not in the policy, with no socket", async () => {
    const onConnect = vi.fn();
    const out = await performRequest({ method: "GET", url: "https://api.test/" }, ctx(["other.test"], { onConnect }));
    expect(out).toEqual({ ok: false, host: "api.test", reason: "host" });
    expect(onConnect).not.toHaveBeenCalled();
  });
  it("refuses http with no allow at once, and http to an address outside allow", async () => {
    const r = local();
    expect(await performRequest({ method: "GET", url: "http://api.test/" }, ctx(["api.test:80"], { allow: [], resolve: r }))).toMatchObject({ ok: false, reason: "scheme" });
    expect(r.calls).toEqual([]);
    const pub = await performRequest({ method: "GET", url: "http://api.test/" }, ctx(["api.test:80"], { resolve: stub({ "api.test": ["8.8.8.8"] }) }));
    expect(pub).toMatchObject({ ok: false, reason: "scheme" });
    expect(await performRequest({ method: "GET", url: "ftp://api.test/" }, ctx(["api.test"]))).toMatchObject({ ok: false, reason: "scheme" });
  });
  it("applies the policy's methods and paths", async () => {
    const c = ctx(["api.test"], { pol: { methods: ["GET"], paths: ["/v1"] } });
    expect(await performRequest({ method: "POST", url: "https://api.test/v1" }, c)).toMatchObject({ ok: false, reason: "method" });
    expect(await performRequest({ method: "GET", url: "https://api.test/v2" }, c)).toMatchObject({ ok: false, reason: "path" });
    expect(await performRequest({ method: "GET", url: "https://api.test/v1/..%252fadmin" }, c)).toMatchObject({ ok: false, reason: "path" });
  });
});

describe("performRequest: TLS", () => {
  it("talks https to a self-signed upstream with Host and SNI kept as the URL host", async () => {
    const up = await serve(undefined, true);
    const out = await performRequest({ method: "GET", url: `https://api.test:${up.port}/` }, ctx([`api.test:${up.port}`], { ca: cert }));
    expect(out).toMatchObject({ ok: true, result: { status: 200, body: "ok" } });
    expect(up.seen[0]!.headers.authorization).toBe(`Bearer ${SECRET}`);
    expect(up.seen[0]!.headers.host).toBe(`api.test:${up.port}`);
  });
  it("fails without the test CA (no trust downgrade)", async () => {
    const up = await serve(undefined, true);
    expect(await performRequest({ method: "GET", url: `https://api.test:${up.port}/` }, ctx([`api.test:${up.port}`]))).toMatchObject({ ok: false, reason: "upstream_error" });
    expect(up.seen).toHaveLength(0);
  });
});

describe("performRequest: redirects", () => {
  it("returns a 302 to a host outside the policy without following it", async () => {
    const b = await serve();
    const a = await serve((_q, r) => { r.writeHead(302, { location: `http://other.test:${b.port}/x` }).end(); });
    const out = await performRequest({ method: "GET", url: `http://api.test:${a.port}/` }, ctx([`api.test:${a.port}`]));
    expect(out).toMatchObject({ ok: true, result: { status: 302 } });
    expect(b.seen).toHaveLength(0);
  });
  it("follows a 302 to another policy host without the secret (different origin)", async () => {
    const b = await serve();
    const a = await serve((_q, r) => { r.writeHead(302, { location: `http://other.test:${b.port}/x` }).end(); });
    const out = await performRequest({ method: "GET", url: `http://api.test:${a.port}/`, headers: { "X-Trace": "1" } }, ctx([`api.test:${a.port}`, `other.test:${b.port}`]));
    expect(out).toMatchObject({ ok: true, result: { status: 200, body: "ok" } });
    expect(b.seen).toHaveLength(1);
    expect(b.seen[0]!.headers.authorization).toBeUndefined();
    expect(b.seen[0]!.headers["x-trace"]).toBe("1");
  });
  it("re-injects the secret on a same-origin redirect, and strips an agent query copy cross-origin", async () => {
    const b = await serve();
    const a = await serve((q, r) => {
      if (q.url!.startsWith("/start")) r.writeHead(302, { location: "/next?key=mine" }).end();
      else if (q.url!.startsWith("/next")) r.writeHead(307, { location: `http://other.test:${b.port}/far?key=mine&x=1` }).end();
      else r.end("?");
    });
    const out = await performRequest({ method: "GET", url: `http://api.test:${a.port}/start` },
      ctx([`api.test:${a.port}`, `other.test:${b.port}`], { inject: { kind: "query", name: "key" } }));
    expect(out).toMatchObject({ ok: true, result: { status: 200 } });
    expect(new URL(a.seen[1]!.url, "http://x").searchParams.getAll("key")).toEqual([SECRET]);
    expect(b.seen[0]!.url).toBe("/far?x=1");
  });
  it("stops at the 4th redirect and returns it", async () => {
    const a = await serve((q, r) => { const n = Number(q.url!.slice(1)); r.writeHead(302, { location: `/${n + 1}` }).end(); });
    const out = await performRequest({ method: "GET", url: `http://api.test:${a.port}/1` }, ctx([`api.test:${a.port}`]));
    expect(out).toMatchObject({ ok: true, result: { status: 302, headers: { location: "/5" } } });
    expect(a.seen.map((s) => s.url)).toEqual(["/1", "/2", "/3", "/4"]);
  });
  it("turns a 303 after POST into a GET with no body", async () => {
    const a = await serve((q, r) => { if (q.url === "/post") r.writeHead(303, { location: "/done" }).end(); else r.end("done"); });
    await performRequest({ method: "POST", url: `http://api.test:${a.port}/post`, body: "x=1", headers: { "content-type": "text/plain" } }, ctx([`api.test:${a.port}`]));
    expect(a.seen[1]).toMatchObject({ method: "GET", url: "/done", body: "" });
    expect(a.seen[1]!.headers["content-type"]).toBeUndefined();
  });
  it("does not follow a Location carrying the secret, and redacts it", async () => {
    const a = await serve((q, r) => {
      if (q.url === "/") r.writeHead(302, { location: `/leak?k=${encodeURIComponent(q.headers.authorization!.slice(7))}` }).end(); else r.end("followed");
    });
    const out = await performRequest({ method: "GET", url: `http://api.test:${a.port}/` }, ctx([`api.test:${a.port}`]));
    expect(out).toMatchObject({ ok: true, reflected: true, result: { status: 302, headers: { location: `/leak?k=${REDACTED}` } } });
    expect(a.seen).toHaveLength(1);
  });
});

describe("performRequest: strip, then inject", () => {
  it("strips agent credentials and injects the policy header", async () => {
    const a = await serve();
    await performRequest({ method: "GET", url: `http://api.test:${a.port}/`, headers: { Authorization: "Bearer fake", Cookie: "a=1", "X-Key": "mine", "x-api-key": "k", "Proxy-Authorization": "p" } },
      ctx([`api.test:${a.port}`], { inject: { kind: "header", name: "X-Key", prefix: "Key " } }));
    const h = a.seen[0]!.headers;
    expect(h["x-key"]).toBe(`Key ${SECRET}`);
    expect(h.cookie).toBeUndefined();
    expect(h.authorization).toBeUndefined();
    expect(h["x-api-key"]).toBeUndefined();
    expect(h["proxy-authorization"]).toBeUndefined();
  });
  it("replaces an agent-supplied query value with the secret", async () => {
    const a = await serve();
    await performRequest({ method: "GET", url: `http://api.test:${a.port}/q?key=mine&KEY=two&x=1` }, ctx([`api.test:${a.port}`], { inject: { kind: "query", name: "key" } }));
    const q = new URL(a.seen[0]!.url, "http://x").searchParams;
    expect([...q.keys()]).toEqual(["x", "key"]);
    expect(q.get("key")).toBe(SECRET);
  });
  it("injects basic auth over the agent's own Authorization", async () => {
    const a = await serve();
    await performRequest({ method: "GET", url: `http://api.test:${a.port}/`, headers: { authorization: "Basic Zm9vOmJhcg==" } }, ctx([`api.test:${a.port}`], { inject: { kind: "basic" } }));
    expect(a.seen[0]!.headers.authorization).toBe(`Basic ${Buffer.from(`bob:${SECRET}`).toString("base64")}`);
  });
});

describe("performRequest: scrubbing", () => {
  const b = Buffer.from(SECRET);
  const forms = [SECRET, b.toString("base64"), b.toString("base64url"), encodeURIComponent(SECRET), b.toString("hex"), b.toString("hex").toUpperCase(),
    Buffer.from(`bob:${SECRET}`).toString("base64")];
  const check = (out: Awaited<ReturnType<typeof performRequest>>) => {
    expect(out.ok).toBe(true);
    if (!out.ok) return;
    expect(out.reflected).toBe(true);
    expect(out.result.headers["x-echo"]).toContain(REDACTED);
    expect(out.result.body).toContain(REDACTED);
    const all = JSON.stringify(out.result);
    for (const f of [...forms, "sk_test"]) expect(all).not.toContain(f);
  };
  it("redacts every form of the secret in headers and body", async () => {
    const a = await serve((_q, r) => { r.setHeader("x-echo", forms.join(" | ")); r.end(JSON.stringify({ forms })); });
    check(await performRequest({ method: "GET", url: `http://api.test:${a.port}/` }, ctx([`api.test:${a.port}`], { inject: { kind: "basic" } })));
  });
  it("redacts a gzip-encoded echo and drops content-encoding and content-length", async () => {
    const a = await serve((_q, r) => {
      const z = gzipSync(JSON.stringify({ forms }));
      r.writeHead(200, { "x-echo": SECRET, "content-encoding": "gzip", "content-length": z.length }).end(z);
    });
    const out = await performRequest({ method: "GET", url: `http://api.test:${a.port}/` }, ctx([`api.test:${a.port}`], { inject: { kind: "basic" } }));
    check(out);
    if (out.ok) { expect(out.result.headers["content-encoding"]).toBeUndefined(); expect(out.result.headers["content-length"]).toBeUndefined(); }
  });
  it("redacts a secret split across two writes", async () => {
    const a = await serve((_q, r) => { r.setHeader("x-echo", SECRET); r.write(`{"s":"${SECRET.slice(0, 6)}`); setTimeout(() => r.end(`${SECRET.slice(6)}"}`), 30); });
    const out = await performRequest({ method: "GET", url: `http://api.test:${a.port}/` }, ctx([`api.test:${a.port}`]));
    check(out);
    expect(out.ok && out.result.body).toBe(`{"s":"${REDACTED}"}`);
  });
  it("does not leak a secret prefix where the cap cuts the body", async () => {
    const a = await serve((_q, r) => r.end("a".repeat(1000 - 9) + SECRET));
    const out = await performRequest({ method: "GET", url: `http://api.test:${a.port}/` }, ctx([`api.test:${a.port}`], { cfg: { maxResponseBytes: 1000, upstreamTimeoutMs: 5000 } }));
    expect(out).toMatchObject({ ok: true, reflected: true, result: { truncated: true, body: "a".repeat(991) + REDACTED } });
  });
});

describe("performRequest: limits", () => {
  it("caps a 5 MiB body at 4 MiB", async () => {
    const a = await serve((_q, r) => r.end(Buffer.alloc(5 * MiB, "a")));
    const out = await performRequest({ method: "GET", url: `http://api.test:${a.port}/` }, ctx([`api.test:${a.port}`]));
    expect(out.ok && out.result.truncated).toBe(true);
    expect(out.ok && out.result.body.length).toBe(4 * MiB);
  });
  it("cuts a gzip bomb at maxResponseBytes of decompressed bytes", async () => {
    const bomb = gzipSync(Buffer.alloc(10 * MiB));
    const a = await serve((_q, r) => r.writeHead(200, { "content-encoding": "gzip" }).end(bomb));
    const out = await performRequest({ method: "GET", url: `http://api.test:${a.port}/` }, ctx([`api.test:${a.port}`]));
    expect(out.ok && out.result.truncated).toBe(true);
    expect(out.ok && out.result.body.length).toBe(4 * MiB);
  });
  it("ends a slow drip at the total timeout with no body", async () => {
    const a = await serve((_q, r) => {
      r.writeHead(200);
      let i = 0;
      const t = setInterval(() => (r.destroyed ? clearInterval(t) : r.write(SECRET[i++ % SECRET.length]!)), 100);
    });
    const t0 = Date.now();
    const out = await performRequest({ method: "GET", url: `http://api.test:${a.port}/` }, ctx([`api.test:${a.port}`], { cfg: { maxResponseBytes: MiB, upstreamTimeoutMs: 300 } }));
    expect(out).toEqual({ ok: false, host: "api.test", reason: "timeout" });
    expect(Date.now() - t0).toBeLessThan(2000);
  });
  it("refuses a request body over 1 MiB before resolving", async () => {
    const r = local();
    expect(await performRequest({ method: "POST", url: "https://api.test/", body: "a".repeat(MiB + 1) }, ctx(["api.test"], { resolve: r })))
      .toEqual({ ok: false, host: "api.test", reason: "request_too_large" });
    expect(r.calls).toEqual([]);
  });
  it("reports an unreachable upstream as upstream_error, without the URL", async () => {
    const out = await performRequest({ method: "GET", url: "http://api.test:1/?key=x" }, ctx(["api.test:1"]));
    expect(out).toEqual({ ok: false, host: "api.test", reason: "upstream_error" });
  });
});

describe("performRequest: review round 1", () => {
  const slow = (ms: number, fastFirst = 0): Resolver => {
    let n = 0;
    return () => new Promise((r) => setTimeout(() => r([{ address: "127.0.0.1", family: 4 }]), n++ < fastFirst ? 0 : ms));
  };
  it("counts a slow first-hop DNS lookup inside the total timeout", async () => {
    const t0 = Date.now();
    const out = await performRequest({ method: "GET", url: "http://api.test:1/" }, ctx(["api.test:1"], { resolve: slow(3000), cfg: { maxResponseBytes: MiB, upstreamTimeoutMs: 300 } }));
    expect(out).toEqual({ ok: false, host: "api.test", reason: "timeout" });
    expect(Date.now() - t0).toBeLessThan(800);
  });
  it("counts a slow redirect-hop DNS lookup inside the total timeout", async () => {
    const a = await serve((q, r) => { if (q.url === "/") r.writeHead(302, { location: "/next" }).end(); else r.end("late"); });
    const t0 = Date.now();
    const out = await performRequest({ method: "GET", url: `http://api.test:${a.port}/` },
      ctx([`api.test:${a.port}`], { resolve: slow(3000, 1), cfg: { maxResponseBytes: MiB, upstreamTimeoutMs: 300 } }));
    expect(out).toEqual({ ok: false, host: "api.test", reason: "timeout" });
    expect(Date.now() - t0).toBeLessThan(800);
    expect(a.seen).toHaveLength(1);
  });
  it("drops a response header whose name carries the secret, and marks it reflected", async () => {
    const name = `x-${Buffer.from(SECRET).toString("base64url")}`;
    const a = await serve((_q, r) => { r.setHeader(name, "1"); r.end("ok"); });
    const out = await performRequest({ method: "GET", url: `http://api.test:${a.port}/` }, ctx([`api.test:${a.port}`]));
    expect(out).toMatchObject({ ok: true, reflected: true, result: { body: "ok" } });
    expect(JSON.stringify(out).toLowerCase()).not.toContain(name.toLowerCase());
  });
  it("refuses a body undici left encoded, and accepts identity", async () => {
    const a = await serve((q, r) => {
      if (q.url === "/x") r.writeHead(200, { "content-encoding": "gzip, x-custom" }).end(gzipSync(SECRET));
      else r.writeHead(200, { "content-encoding": "identity" }).end("plain");
    });
    expect(await performRequest({ method: "GET", url: `http://api.test:${a.port}/x` }, ctx([`api.test:${a.port}`]))).toEqual({ ok: false, host: "api.test", reason: "upstream_error" });
    expect(await performRequest({ method: "GET", url: `http://api.test:${a.port}/i` }, ctx([`api.test:${a.port}`]))).toMatchObject({ ok: true, result: { body: "plain" } });
  });
  it("strips the agent's Range and If-Range", async () => {
    const a = await serve();
    await performRequest({ method: "GET", url: `http://api.test:${a.port}/`, headers: { Range: "bytes=0-3", "If-Range": "x" } }, ctx([`api.test:${a.port}`]));
    expect(a.seen[0]!.headers.range).toBeUndefined();
    expect(a.seen[0]!.headers["if-range"]).toBeUndefined();
  });
  it("returns a redirect whose Location carries userinfo without following it", async () => {
    const a = await serve((q, r) => { if (q.url === "/") r.writeHead(302, { location: `http://u:p@api.test:${a.port}/x` }).end(); else r.end("followed"); });
    const out = await performRequest({ method: "GET", url: `http://api.test:${a.port}/` }, ctx([`api.test:${a.port}`]));
    expect(out).toMatchObject({ ok: true, result: { status: 302 } });
    expect(a.seen).toHaveLength(1);
  });
  it.each(["GET", "HEAD"] as const)("refuses a body on %s as method, before any lookup or connection", async (method) => {
    const r = local(), onConnect = vi.fn();
    expect(await performRequest({ method, url: "https://api.test/", body: "x" }, ctx(["api.test"], { resolve: r, onConnect })))
      .toEqual({ ok: false, host: "api.test", reason: "method" });
    expect(r.calls).toEqual([]);
    expect(onConnect).not.toHaveBeenCalled();
  });
});
