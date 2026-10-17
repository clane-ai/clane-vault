import zlib from "node:zlib";
import { Agent, fetch } from "undici";
import type { AgentMethod, AgentPolicy } from "@clane-vault/crypto";
import type { GatewayConfig } from "../config.js";
import { REDACTED, scrub, variantsOf } from "./scrub.js";
import { checkMethodPath, matchHost, Refused, resolveChecked, type Cidr, type RefuseReason, type Resolver } from "./ssrf.js";

export interface OutboundInput { method: AgentMethod; url: string; headers?: Record<string, string>; body?: string }
export type OutboundOutcome =
  | { ok: true; host: string; reflected: boolean; result: { status: number; headers: Record<string, string>; body: string; truncated?: true } }
  | { ok: false; host: string; reason: RefuseReason };
export interface OutboundCtx {
  policy: AgentPolicy; secret: string; username: string; cfg: Pick<GatewayConfig, "maxResponseBytes" | "upstreamTimeoutMs">;
  allow: Cidr[]; resolve: Resolver; onConnect?: (address: string) => void;
  /** Test only: trust this CA for a self-signed upstream. */
  ca?: string;
}

const MAX_REQUEST_BYTES = 1024 * 1024;
const MAX_REDIRECTS = 3;
// Agent-supplied credentials and hop headers never reach the upstream; the policy's own header name is added per call.
const STRIP = ["authorization", "proxy-authorization", "cookie", "x-api-key", "host", "content-length", "transfer-encoding", "connection",
  "range", "if-range"]; // Range would let an echoing upstream hand the secret back piece by piece
// The codings undici decodes (it decodes none if any other is listed); anything else would reach the agent unscrubbable.
const DECODED = new Set(["gzip", "x-gzip", "deflate", "br", ...("createZstdDecompress" in zlib ? ["zstd"] : [])]);

/** Rejects with the abort reason once `signal` fires, so a slow resolver can't outlast the total timeout. */
function raced<T>(p: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) return Promise.reject(signal.reason);
  return new Promise<T>((res, rej) => {
    const on = () => rej(signal.reason);
    signal.addEventListener("abort", on, { once: true });
    p.then(res, rej).finally(() => signal.removeEventListener("abort", on));
  });
}

/** Rules 1-4 for one hop: scheme, policy host, method and path, body size, then the SSRF-checked address to pin. */
async function checkHop(url: URL, method: AgentMethod, body: string | undefined, ctx: OutboundCtx, signal: AbortSignal) {
  if (url.protocol !== "https:" && !(url.protocol === "http:" && ctx.allow.length)) throw new Refused("scheme");
  if (!matchHost(ctx.policy.hosts, url)) throw new Refused("host");
  const mp = checkMethodPath(ctx.policy, method, url);
  if (mp) throw new Refused(mp);
  if (body !== undefined && Buffer.byteLength(body, "utf8") > MAX_REQUEST_BYTES) throw new Refused("request_too_large");
  const r = await raced(resolveChecked(url.hostname, ctx), signal);
  if (url.protocol === "http:" && !r.viaAllow) throw new Refused("scheme");
  return r;
}

/** Strips agent credentials (and any agent copy of the policy's query name), then injects the policy credential when `inject`. */
function prepare(url: URL, agentHeaders: Record<string, string>, ctx: OutboundCtx, inject: boolean) {
  const inj = ctx.policy.inject;
  const strip = new Set(inj.kind === "header" ? [...STRIP, inj.name.toLowerCase()] : STRIP);
  const headers: Record<string, string> = {};
  for (const [k, v] of Object.entries(agentHeaders)) if (!strip.has(k.toLowerCase())) headers[k] = v;
  if (inj.kind === "query") for (const k of [...url.searchParams.keys()]) if (k.toLowerCase() === inj.name.toLowerCase()) url.searchParams.delete(k);
  if (inject) {
    if (inj.kind === "bearer") headers.authorization = `Bearer ${ctx.secret}`;
    else if (inj.kind === "basic") headers.authorization = `Basic ${Buffer.from(`${ctx.username}:${ctx.secret}`, "utf8").toString("base64")}`;
    else if (inj.kind === "header") headers[inj.name] = `${inj.prefix ?? ""}${ctx.secret}`;
    else url.searchParams.set(inj.name, ctx.secret);
  }
  return headers;
}

/** Reads at most `max` decompressed bytes, then cancels the stream. */
async function readCapped(body: { getReader(): ReadableStreamDefaultReader<Uint8Array> } | null, max: number) {
  const chunks: Uint8Array[] = [];
  let n = 0;
  if (body) {
    const reader = body.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (n + value.length > max) {
        chunks.push(value.subarray(0, max - n));
        n = max;
        await reader.cancel().catch(() => {});
        return { buf: Buffer.concat(chunks), truncated: true };
      }
      chunks.push(value);
      n += value.length;
    }
  }
  return { buf: Buffer.concat(chunks), truncated: false };
}

/** A capped body can end part-way into a secret form; redact the longest trailing prefix of any variant. */
function cutTail(text: string, vs: string[]) {
  const t = text.replace(/�$/, "");
  let k = 0;
  for (const v of vs) for (let n = Math.min(v.length - 1, t.length); n > k; n--) if (t.endsWith(v.slice(0, n))) { k = n; break; }
  return k ? { text: t.slice(0, t.length - k) + REDACTED, hit: true } : { text, hit: false };
}

export async function performRequest(input: OutboundInput, ctx: OutboundCtx): Promise<OutboundOutcome> {
  let url: URL;
  try { url = new URL(input.url); } catch { return { ok: false, host: "", reason: "host" }; }
  const host = url.hostname;
  const signal = AbortSignal.timeout(ctx.cfg.upstreamTimeoutMs);
  const variants = variantsOf(ctx.secret, ctx.policy.inject.kind === "basic" ? ctx.username : undefined);
  const agents: Agent[] = [];
  let method = input.method, body = input.body, agentHeaders = input.headers ?? {};
  try {
    // A body on GET or HEAD is refused before any lookup or connection (fetch would throw on it).
    if (body !== undefined && (method === "GET" || method === "HEAD")) throw new Refused("method");
    let pin = await checkHop(url, method, body, ctx, signal);
    const origin = url.origin;
    for (let hop = 0; ; hop++) {
      const { address, family } = pin;
      const agent = new Agent({
        connect: {
          ...(ctx.ca ? { ca: ctx.ca } : {}),
          // Connect to the checked address only: no second DNS lookup (rebinding). Host and SNI stay the URL host.
          lookup: (_h: string, o: { all?: boolean }, cb: (...a: unknown[]) => void) => {
            ctx.onConnect?.(address);
            if (o?.all) cb(null, [{ address, family }]); else cb(null, address, family);
          },
        } as never,
      });
      agents.push(agent);
      // Never forward the secret to another origin (ruling e): a cross-origin hop goes without it.
      const headers = prepare(url, agentHeaders, ctx, url.origin === origin);
      const res = await fetch(url, { method, headers, body, redirect: "manual", signal, dispatcher: agent });
      const loc = res.headers.get("location");
      if ([301, 302, 303, 307, 308].includes(res.status) && loc && hop < MAX_REDIRECTS) {
        const next = await nextHop(url, loc, res.status, method, body, ctx, variants, signal);
        if (next) {
          await res.body?.cancel().catch(() => {});
          ({ url, method, body, pin } = next);
          if (next.dropBody) agentHeaders = Object.fromEntries(Object.entries(agentHeaders).filter(([k]) => k.toLowerCase() !== "content-type"));
          continue;
        }
      }
      const codings = res.headers.get("content-encoding");
      if (codings && method !== "HEAD" && codings.trim().toLowerCase() !== "identity" && !codings.toLowerCase().split(",").every((c) => DECODED.has(c.trim())))
        throw new Error("undecoded content-encoding");
      const capped = await readCapped(res.body, ctx.cfg.maxResponseBytes);
      const lowVariants = variants.map((v) => v.toLowerCase());
      let hits = 0;
      const outHeaders = new Map<string, string>();
      for (const [k, v] of res.headers) {
        if (k === "content-encoding" || k === "content-length") continue;
        if (lowVariants.some((v) => k.includes(v))) { hits++; continue; } // a header name can't be redacted, so it is dropped
        const s = scrub(v, variants);
        hits += s.hits;
        outHeaders.set(k, outHeaders.has(k) ? `${outHeaders.get(k)}, ${s.text}` : s.text); // set-cookie comes once per value
      }
      const s = scrub(capped.buf.toString("utf8"), variants);
      hits += s.hits;
      let text = s.text;
      if (capped.truncated) {
        const c = cutTail(text, variants);
        text = c.text;
        if (c.hit) hits++;
      }
      return { ok: true, host, reflected: hits > 0, result: { status: res.status, headers: Object.fromEntries(outHeaders), body: text, ...(capped.truncated ? { truncated: true as const } : {}) } };
    }
  } catch (e) {
    if (signal.aborted) return { ok: false, host, reason: "timeout" };
    return { ok: false, host, reason: e instanceof Refused ? e.reason : "upstream_error" };
  } finally {
    for (const a of agents) a.destroy().catch(() => {});
  }
}

/** The next hop when a redirect may be followed (it passes rules 1-4 against the same policy), else null. */
async function nextHop(from: URL, loc: string, status: number, method: AgentMethod, body: string | undefined, ctx: OutboundCtx, variants: string[], signal: AbortSignal) {
  let url: URL;
  try { url = new URL(loc, from); } catch { return null; }
  if (url.username || url.password) return null; // fetch refuses userinfo; return the 3xx as is
  // A Location carrying the secret (e.g. echoed in its query), as sent or as the URL parser re-encodes it, is never followed.
  if (scrub(`${loc} ${url.href}`, variants).hits) return null;
  const dropBody = status === 303 ? method !== "HEAD" : (status === 301 || status === 302) && method === "POST";
  const m: AgentMethod = dropBody ? "GET" : method;
  const b = dropBody ? undefined : body;
  try { return { url, method: m, body: b, dropBody, pin: await checkHop(url, m, b, ctx, signal) }; } catch (e) {
    if (e instanceof Refused) return null;
    throw e;
  }
}
