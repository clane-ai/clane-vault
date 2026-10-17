import type { IncomingMessage, ServerResponse } from "node:http";
import type { AgentMethod, MembershipKeys } from "@clane-vault/crypto";
import { ApiRefused, type AgentSync, type ApiClient, type UseEvent } from "./apiClient.js";
import type { AgentPrincipal, bearerAuth } from "./auth.js";
import type { GatewayConfig } from "./config.js";
import type { EventQueue } from "./events.js";
import { readJson, send } from "./http.js";
import { listItems, withItem, type ItemSummary } from "./items.js";
import type { AgentKeyCache, SyncCache } from "./keys.js";
import type { HeldSecrets, Logger } from "./log.js";
import { performRequest, type OutboundInput } from "./outbound/request.js";
import { parseCidrs, type Resolver } from "./outbound/ssrf.js";
import type { RateLimiter } from "./rateLimit.js";

export interface McpDeps {
  cfg: GatewayConfig; api: ApiClient; auth: ReturnType<typeof bearerAuth>; keys: AgentKeyCache; syncs: SyncCache; events: EventQueue;
  limiter: RateLimiter; log: Logger; held: HeldSecrets; resolve: Resolver;
}

const MAX_BODY = 1024 * 1024 + 64 * 1024;
const MINUTE = 60_000;
export const ADDRESS_PER_MINUTE = 600, LIST_PER_MINUTE = 20;

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

/** The tools' work, outside MCP (Task 11b registers them on the transport). Every call runs as the verified principal's agent only. */
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
          // The item would not open (a decrypt failure): to the agent it does not exist.
          d.log.error({ event: "item_unopenable", class: e instanceof Error ? e.name : typeof e });
          return { error: "refused", reason: "not_found" } as Refusal;
        }
      });
      if (!ran && "error" in r) d.events.push(p, event("refused", req.method, hostOf(req.url), { reason: r.reason }));
      await d.events.flush(p);
      return r;
    },
  };
}

/**
 * The MCP route: per-address limit, bearer auth, the body, then per-agent tool limits, all before the transport.
 * Rate-limit keys use the verified agent id only.
 */
export function mcpHandler(deps: McpDeps): (req: IncomingMessage, res: ServerResponse) => Promise<void> {
  const { cfg, auth, limiter } = deps;
  const limited = (res: ServerResponse, key: string, limit: number) => {
    const r = limiter.take(key, limit, MINUTE);
    if (r.ok) return false;
    send(res, 429, { error: "rate_limited" }, { "retry-after": String(r.retryAfterSeconds) });
    return true;
  };
  return async (req, res) => {
    if (limited(res, `addr:${clientAddress(req, cfg.trustProxy)}`, ADDRESS_PER_MINUTE)) return;
    const p = await auth(req.headers.authorization);
    if (!p) return send(res, 401, { error: "unauthorized" }, { "www-authenticate": "Bearer" });
    const body = req.method === "POST" ? await readJson(req, MAX_BODY) : undefined;
    for (const m of Array.isArray(body) ? body : [body]) {
      const msg = m as { method?: unknown; params?: { name?: unknown } } | null;
      if (msg?.method !== "tools/call") continue;
      if (msg.params?.name === "http_request" && limited(res, `http:${p.agentId}`, cfg.agentRatePerMinute)) return;
      if (msg.params?.name === "list_secrets" && limited(res, `list:${p.agentId}`, LIST_PER_MINUTE)) return;
    }
    // Task 11b: the Streamable HTTP transport, sessions and the tools (agentTools) go here.
    send(res, 501, { error: "not_implemented" });
  };
}
