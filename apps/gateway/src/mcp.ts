import { randomUUID } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { AGENT_METHODS, CryptoError, type AgentMethod, type MembershipKeys } from "@clane-vault/crypto";
import { ApiRefused, type AgentSync, type ApiClient, type UseEvent } from "./apiClient.js";
import type { AgentPrincipal, BearerAuth } from "./auth.js";
import type { GatewayConfig } from "./config.js";
import type { EventQueue } from "./events.js";
import { HttpError, readJson, send } from "./http.js";
import { ItemUnopenable, listItems, withItem, type ItemSummary } from "./items.js";
import type { AgentKeyCache, SyncCache } from "./keys.js";
import type { HeldSecrets, Logger } from "./log.js";
import { performRequest, type OutboundInput } from "./outbound/request.js";
import { parseCidrs, type Resolver } from "./outbound/ssrf.js";
import type { RateLimiter } from "./rateLimit.js";

export interface McpDeps {
  cfg: GatewayConfig; api: ApiClient; auth: BearerAuth; keys: AgentKeyCache; syncs: SyncCache; events: EventQueue;
  limiter: RateLimiter; log: Logger; held: HeldSecrets; resolve: Resolver;
  /** Test hook: a session idle this long is closed (default 30 min). */
  sessionIdleMs?: number;
}

const MAX_BODY = 1024 * 1024 + 64 * 1024;
const MINUTE = 60_000;
export const ADDRESS_PER_MINUTE = 600, LIST_PER_MINUTE = 20, EXCHANGE_MISSES_PER_MINUTE = 10, SESSIONS_PER_AGENT = 20;
const IDLE_MS = 30 * MINUTE;
const INSTRUCTIONS = "Use `list_secrets` to see what you may call, then `http_request` with the item handle. You will never see a credential. No tool returns a secret.";

export type SecretListing = Pick<ItemSummary, "handle" | "title" | "type" | "hosts" | "inject" | "approval" | "methods" | "paths">;
export type HttpRequestInput = OutboundInput & { item: string };
export type Refusal = { error: "refused"; reason: string };
export type HttpRequestResult = { status: number; headers: Record<string, string>; body: string; truncated?: true } | Refusal;

/** The client address: `hops` trusted proxies from the right of X-Forwarded-For (the API's TRUST_PROXY semantics), else the socket. */
export function clientAddress(req: IncomingMessage, hops: number): string {
  const xff = [req.headers["x-forwarded-for"] ?? []].flat().join(",").split(",").map((s) => s.trim()).filter(Boolean);
  const chain = [req.socket.remoteAddress ?? "", ...xff.reverse()];
  return chain[Math.min(hops, chain.length - 1)]!;
}

const hostOf = (url: string) => { try { return new URL(url).hostname; } catch { return ""; } };
const classOf = (e: unknown) => (e instanceof Error ? e.name : typeof e);

/** The tools' work, outside MCP. Every call runs as the verified principal's agent only. */
export function agentTools(d: Pick<McpDeps, "cfg" | "keys" | "syncs" | "events" | "log" | "held" | "resolve">) {
  const allow = parseCidrs(d.cfg.allowPrivateCidrs);

  /** Sync and key for this agent; an API refusal (revoked, expired) drops both caches at once and is rethrown. */
  async function asAgent<T>(p: AgentPrincipal, f: (sync: AgentSync, keys: MembershipKeys) => Promise<T>): Promise<T> {
    try {
      const sync = await d.syncs.get(p.agentId, p.accessToken);
      return await d.keys.use(p.agentId, sync, (keys) => f(sync, keys));
    } catch (e) {
      if (e instanceof ApiRefused) { d.keys.drop(p.agentId); d.syncs.drop(p.agentId); }
      throw e;
    }
  }

  const event = (action: UseEvent["action"], method: AgentMethod, host: string, extra: Pick<UseEvent, "recordId" | "reason" | "truncated"> = {}): UseEvent =>
    ({ at: new Date().toISOString(), action, host, method, ...extra });

  return {
    async listSecrets(p: AgentPrincipal): Promise<SecretListing[]> {
      const items = await asAgent(p, (sync, keys) => listItems(sync, keys, p.agentId, d.log));
      return items.map((i) => ({ handle: i.handle, title: i.title, type: i.type, hosts: i.hosts, inject: i.inject, approval: i.approval,
        ...(i.methods ? { methods: i.methods } : {}), ...(i.paths ? { paths: i.paths } : {}) }));
    },

    async httpRequest(p: AgentPrincipal, input: HttpRequestInput): Promise<HttpRequestResult> {
      const { item, ...req } = input;
      let ran = false;
      const r = await asAgent(p, async (sync, keys) => {
        try {
          return await withItem(sync, keys, p.agentId, item, d.held, async (x) => {
            ran = true;
            const o = await performRequest(req, { policy: x.policy, secret: x.secret, username: x.username, cfg: d.cfg, allow, resolve: d.resolve });
            // The host comes from the outcome: the policy's may be a wildcard.
            if (!o.ok) {
              d.events.push(p, event("refused", req.method, o.host, { recordId: x.recordId, reason: o.reason }));
              return { error: "refused", reason: o.reason } as Refusal;
            }
            d.events.push(p, event("use", req.method, o.host, { recordId: x.recordId, ...(o.result.truncated ? { truncated: true } : {}) }));
            if (o.reflected) d.events.push(p, event("reflected", req.method, o.host, { recordId: x.recordId }));
            return o.result;
          }, d.log);
        } catch (e) {
          if (ran) throw e;
          // The item would not open (a decrypt failure): to the agent it does not exist. Anything else is our fault.
          const unopenable = e instanceof CryptoError || e instanceof ItemUnopenable;
          d.log.error({ event: unopenable ? "item_unopenable" : "item_error", class: classOf(e) });
          return { error: "refused", reason: unopenable ? "not_found" : "upstream_error" } as Refusal;
        }
      });
      if (!ran && "error" in r) d.events.push(p, event("refused", req.method, hostOf(req.url), { reason: r.reason }));
      await d.events.flush(p);
      return r;
    },

    /** A call refused because the session is running one: one refused event (busy calls are rate-counted, so these are bounded). */
    async busy(p: AgentPrincipal, input: HttpRequestInput): Promise<Refusal> {
      d.events.push(p, event("refused", input.method, hostOf(input.url), { reason: "busy" }));
      await d.events.flush(p);
      return { error: "refused", reason: "busy" };
    },
  };
}

const httpRequestInput = {
  item: z.string().max(200),
  method: z.enum(AGENT_METHODS),
  url: z.string().max(4096),
  // Names are RFC 7230 tokens; values carry no CR, LF or NUL.
  headers: z.record(z.string().regex(/^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}$/), z.string().max(4096).regex(/^[^\r\n\0]*$/))
    .refine((h) => Object.keys(h).length <= 50, "at most 50 headers").optional(),
  body: z.string().optional(),
};

interface Session { agentId: string; transport: WebStandardStreamableHTTPServerTransport; busy: boolean; timer?: NodeJS.Timeout }
/** One per HTTP request, handed to the tools through the transport's authInfo. */
interface Call { principal: AgentPrincipal; refused: boolean }

const asResult = (x: object) => ({ content: [{ type: "text" as const, text: JSON.stringify(x) }], structuredContent: x as Record<string, unknown> });

/** One McpServer per session with exactly the two tools; a session runs one tool call at a time. */
function sessionServer(s: Pick<Session, "busy">, tools: ReturnType<typeof agentTools>, log: Logger) {
  const server = new McpServer({ name: "clane-vault-gateway", version: "0.1.0" }, { instructions: INSTRUCTIONS });
  const run = async (extra: { authInfo?: { extra?: Record<string, unknown> } }, f: (p: AgentPrincipal) => Promise<object>,
    busy: (p: AgentPrincipal) => Promise<object> = async () => ({ error: "refused", reason: "busy" })) => {
    const call = extra.authInfo?.extra?.call as Call;
    if (s.busy) return asResult(await busy(call.principal));
    s.busy = true;
    try {
      return asResult(await f(call.principal));
    } catch (e) {
      if (e instanceof ApiRefused) call.refused = true; // the handler answers HTTP 401 instead of this result
      // Class only: a message could carry a secret that is no longer held for redaction.
      else log.error({ event: "tool_error", class: classOf(e) });
      return { ...asResult({ error: "internal_error" }), isError: true };
    } finally {
      s.busy = false;
    }
  };
  server.registerTool("list_secrets", { description: "The items you may use: handles, hosts and how the credential is injected. Never a secret." },
    (extra) => run(extra, async (p) => ({ secrets: await tools.listSecrets(p) })));
  server.registerTool("http_request", {
    description: "An HTTP request with an item's credential injected by the gateway. `item` is a handle from list_secrets (or a record id).",
    inputSchema: httpRequestInput,
  }, (input, extra) => run(extra, (p) => tools.httpRequest(p, input), (p) => tools.busy(p, input)));
  return server;
}

/**
 * The MCP route: per-address limit, bearer auth (exchange misses limited per address), the body, then per-agent tool limits,
 * all before the transport. Rate-limit keys and session binding use the verified agent id only.
 */
export function mcpHandler(deps: McpDeps): ((req: IncomingMessage, res: ServerResponse) => Promise<void>) & { dropAgent(agentId: string): void } {
  const { cfg, auth, limiter } = deps;
  const tools = agentTools(deps);
  const idleMs = deps.sessionIdleMs ?? IDLE_MS;
  const sessions = new Map<string, Session>();
  /** agentId → its live sessions, least recently touched first. */
  const byAgent = new Map<string, Set<Session>>();
  const close = (s: Session) => { s.transport.close().catch(() => {}); };
  const limited = (res: ServerResponse, key: string, limit: number) => {
    const r = limiter.take(key, limit, MINUTE);
    if (r.ok) return false;
    send(res, 429, { error: "rate_limited" }, { "retry-after": String(r.retryAfterSeconds) });
    return true;
  };
  const touch = (s: Session) => {
    const mine = byAgent.get(s.agentId);
    mine?.delete(s); mine?.add(s);
    clearTimeout(s.timer);
    s.timer = setTimeout(() => close(s), idleMs).unref();
  };
  /** Revoked or refused: the cached exchange and every session of the agent's go at once. */
  const dropAgent = (agentId: string) => {
    auth.drop(agentId);
    for (const s of [...(byAgent.get(agentId) ?? [])]) close(s);
  };

  async function open(agentId: string): Promise<Session> {
    const s = { agentId, busy: false } as Session;
    s.transport = new WebStandardStreamableHTTPServerTransport({
      sessionIdGenerator: randomUUID,
      enableJsonResponse: true, // the response is complete before it is written, so an API refusal can still become HTTP 401
      onsessioninitialized: (id) => {
        const mine = byAgent.get(agentId) ?? new Set<Session>();
        byAgent.set(agentId, mine);
        // At the cap, the agent's least recently touched session makes room.
        for (const old of mine) { if (mine.size < SESSIONS_PER_AGENT) break; mine.delete(old); close(old); }
        sessions.set(id, s); mine.add(s); touch(s);
      },
    });
    s.transport.onclose = () => {
      clearTimeout(s.timer);
      if (s.transport.sessionId) sessions.delete(s.transport.sessionId);
      const mine = byAgent.get(agentId);
      mine?.delete(s);
      if (mine?.size === 0) byAgent.delete(agentId);
    };
    await sessionServer(s, tools, deps.log).connect(s.transport);
    return s;
  }

  const handler = async (req: IncomingMessage, res: ServerResponse) => {
    const addr = clientAddress(req, cfg.trustProxy);
    if (limited(res, `addr:${addr}`, ADDRESS_PER_MINUTE)) return;
    const p = await auth(req.headers.authorization, () => {
      const r = limiter.take(`xchg:${addr}`, EXCHANGE_MISSES_PER_MINUTE, MINUTE);
      if (!r.ok) throw new HttpError(429, "rate_limited", { "retry-after": String(r.retryAfterSeconds) });
    });
    if (!p) return send(res, 401, { error: "unauthorized" }, { "www-authenticate": "Bearer" });
    // No server-to-client stream (GET) is offered.
    if (req.method !== "POST" && req.method !== "DELETE") return send(res, 405, { error: "method_not_allowed" }, { allow: "POST, DELETE" });
    const body = req.method === "POST" ? await readJson(req, MAX_BODY) : undefined;
    const msgs = Array.isArray(body) ? body : [body];
    for (const m of msgs) {
      const msg = m as { method?: unknown; params?: { name?: unknown } } | null;
      if (msg?.method !== "tools/call") continue;
      if (msg.params?.name === "http_request" && limited(res, `http:${p.agentId}`, cfg.agentRatePerMinute)) return;
      if (msg.params?.name === "list_secrets" && limited(res, `list:${p.agentId}`, LIST_PER_MINUTE)) return;
    }

    const sid = req.headers["mcp-session-id"];
    let s: Session | undefined;
    if (typeof sid === "string") {
      s = sessions.get(sid);
      if (!s) return send(res, 404, { error: "session_not_found" });
      if (s.agentId !== p.agentId) return send(res, 403, { error: "forbidden" });
      touch(s);
    } else if (req.method === "POST" && msgs.some((m) => isInitializeRequest(m))) {
      s = await open(p.agentId);
    } else {
      return send(res, 400, { error: "invalid_request" });
    }

    const call: Call = { principal: p, refused: false };
    const headers = new Headers();
    for (const [k, v] of Object.entries(req.headers)) for (const x of [v ?? []].flat()) headers.append(k, x);
    const r = await s.transport.handleRequest(new Request(new URL(req.url ?? "/", "http://gateway"), { method: req.method, headers }), {
      parsedBody: body,
      authInfo: { token: p.accessToken, clientId: p.agentId, scopes: ["agent"], expiresAt: p.exp, extra: { call } },
    });
    if (call.refused) {
      // Revoked or expired (the tool already dropped the key and sync caches): its static token is checked at the API again.
      dropAgent(p.agentId);
      return send(res, 401, { error: "unauthorized" }, { "www-authenticate": "Bearer" });
    }
    res.writeHead(r.status, Object.fromEntries(r.headers)).end(Buffer.from(await r.arrayBuffer()));
  };
  return Object.assign(handler, { dropAgent });
}
