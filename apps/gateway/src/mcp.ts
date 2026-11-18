import { randomUUID } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { AGENT_METHODS, CryptoError, defaultSecretRef, ENV_KEY, FIELD_KINDS, MAX_ENV_BYTES, MAX_FIELD_VALUE, quoteEnvValue, RECORD_TYPES, type AgentMethod, type MembershipKeys, type RecordType } from "@clane-vault/crypto";
import { ApiRefused, isPersonal, type AgentSync, type ApiClient, type PersonalAgentSync, type UseEvent, type WriteRefused } from "./apiClient.js";
import { challenge, type AgentPrincipal, type BearerAuth } from "./auth.js";
import type { GatewayConfig } from "./config.js";
import type { EventQueue } from "./events.js";
import { HttpError, readJson, send } from "./http.js";
import { buildDeposit, buildUpdate, checkDeposit, InvalidInput, pointerValue, type SaveInput, type UpdateSet } from "./deposits.js";
import type { Identity } from "./identity.js";
import { findItem, handleOf, ItemUnopenable, listItems, withItem, type ItemSummary } from "./items.js";
import { OwnerKeyChanged, type AgentKeyCache, type SyncCache } from "./keys.js";
import type { HeldSecrets, Logger } from "./log.js";
import { performRequest, type OutboundInput } from "./outbound/request.js";
import { scrub, variantsOf } from "./outbound/scrub.js";
import { parseCidrs, type Resolver } from "./outbound/ssrf.js";
import type { RateLimiter } from "./rateLimit.js";

export interface McpDeps {
  cfg: GatewayConfig; api: ApiClient; auth: BearerAuth; keys: AgentKeyCache; syncs: SyncCache; events: EventQueue;
  limiter: RateLimiter; log: Logger; held: HeldSecrets; resolve: Resolver; identity: Identity;
  /** Test hook: a session idle this long is closed (default 30 min). */
  sessionIdleMs?: number;
}

const MAX_BODY = 1024 * 1024 + 64 * 1024;
const MINUTE = 60_000, HOUR = 60 * MINUTE;
export const ADDRESS_PER_MINUTE = 600, LIST_PER_MINUTE = 20, EXCHANGE_MISSES_PER_MINUTE = 10, SESSIONS_PER_AGENT = 20;
const IDLE_MS = 30 * MINUTE;
const INSTRUCTIONS = "Use `list_secrets` to see what you may call, then `http_request` with the item handle. You will never see a credential. No tool returns a secret.";

export type SecretListing = Pick<ItemSummary, "handle" | "title" | "type" | "hosts" | "inject" | "approval" | "methods" | "paths" | "deposit" | "can_update" | "env_keys" | "env_injects">;
/**
 * Personal sessions only: save the credential the upstream creates, at JSON pointer `from`, into `type`'s default secret field;
 * for an envFile, as the one entry `entry` of a new .env file.
 */
export type CaptureInput = { from: string; title: string; type: RecordType; entry?: string; agent_use?: SaveInput["agent_use"] };
export type HttpRequestInput = OutboundInput & { item: string; capture?: CaptureInput };
export type Refusal = { error: "refused"; reason: string };
export type HttpRequestResult = { status: number; headers: Record<string, string>; body: string; truncated?: true;
  saved?: { item: string }; capture?: { refused: string } } | Refusal;

/** The client address: `hops` trusted proxies from the right of X-Forwarded-For (the API's TRUST_PROXY semantics), else the socket. */
export function clientAddress(req: IncomingMessage, hops: number): string {
  const xff = [req.headers["x-forwarded-for"] ?? []].flat().join(",").split(",").map((s) => s.trim()).filter(Boolean);
  const chain = [req.socket.remoteAddress ?? "", ...xff.reverse()];
  return chain[Math.min(hops, chain.length - 1)]!;
}

const refused = (reason: string): Refusal => ({ error: "refused", reason });
const OWNER_KEY_CHANGED: Refusal = refused("owner_key_changed");
/** A personal agent whose owner key the API now reports differently: refused before anything is opened or sent. */
const ownerKeyChanged = (e: unknown): Refusal => { if (e instanceof OwnerKeyChanged) return OWNER_KEY_CHANGED; throw e; };

const hostOf = (url: string) => { try { return new URL(url).hostname; } catch { return ""; } };
const classOf = (e: unknown) => (e instanceof Error ? e.name : typeof e);

/** What a capture deposits. An env file's agent_use with no `secret` injects the captured entry. */
function capturedInput(c: CaptureInput, value: string): SaveInput {
  const ref = defaultSecretRef(c.type)!; // the input schema allows only types that have one, or envFile with an entry
  const fields = c.type === "envFile" ? { data: { content: `${c.entry}=${quoteEnvValue(value)}\n`, fileName: ".env" } }
    : ref === "password" ? { password: value } : { data: { [ref.slice(5)]: value } };
  const agentUse = c.agent_use && c.type === "envFile" && c.agent_use.secret === undefined ? { ...c.agent_use, secret: `env:${c.entry}` } : c.agent_use;
  return { title: c.title, type: c.type, fields, ...(agentUse ? { agent_use: agentUse } : {}) };
}

/** The tools' work, outside MCP. Every call runs as the verified principal's agent only. */
export function agentTools(d: Pick<McpDeps, "cfg" | "api" | "keys" | "syncs" | "events" | "log" | "held" | "resolve" | "identity">) {
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

  /** A write tool: personal agents only (organisation sessions never register one). The key opens before anything else (F1). */
  const asPersonal = <T>(p: AgentPrincipal, f: (sync: PersonalAgentSync, keys: MembershipKeys) => Promise<T>) =>
    asAgent(p, (sync, keys) => { if (!isPersonal(sync)) throw new Error("not a personal agent"); return f(sync, keys); });
  /** InvalidInput is `invalid`; anything else (a seal failure among it) is the gateway's fault: internal_error. */
  const invalid = (e: unknown): Refusal => { if (e instanceof InvalidInput) return refused("invalid"); throw e; };
  /** For an update also: an item that won't decrypt is `not_found`, as for http_request. */
  const updateRefusal = (e: unknown): Refusal => {
    if (e instanceof CryptoError || e instanceof ItemUnopenable) return refused("not_found");
    return invalid(e);
  };

  /** buildDeposit, the API's POST, then the new deposit's handle. The API's refusal is returned as is. */
  async function deposit(p: AgentPrincipal, sync: PersonalAgentSync, keys: MembershipKeys, input: SaveInput): Promise<{ item: string } | WriteRefused> {
    const built = await buildDeposit(sync, keys, d.identity, input, d.held);
    const r = await d.api.deposit(p.accessToken, built);
    d.syncs.drop(p.agentId);
    if ("refused" in r) return r;
    const deposits = [...sync.deposits, { id: built.id, encBody: built.encBody, revision: r.revision, agentSealedKey: built.agentSealedKey, signature: built.signature }];
    return { item: (await handleOf({ ...sync, deposits }, keys, built.id, d.log)) ?? built.id };
  }

  /** The upstream already made the credential: a failure from here is `capture.refused`, never a lost response. ApiRefused still ends the agent. */
  async function saveCaptured(p: AgentPrincipal, sync: PersonalAgentSync, keys: MembershipKeys, c: CaptureInput, value: string) {
    try {
      const r = await deposit(p, sync, keys, capturedInput(c, value));
      return "refused" in r ? { capture: { refused: r.refused } } : { saved: r };
    } catch (e) {
      if (e instanceof ApiRefused) throw e;
      if (e instanceof InvalidInput) return { capture: { refused: "invalid" } };
      d.log.error({ event: "capture_error", class: classOf(e) });
      return { capture: { refused: "internal_error" } };
    }
  }

  const event = (action: UseEvent["action"], method: AgentMethod, host: string, extra: Pick<UseEvent, "recordId" | "reason" | "truncated"> = {}): UseEvent =>
    ({ at: new Date().toISOString(), action, host, method, ...extra });

  return {
    async listSecrets(p: AgentPrincipal): Promise<SecretListing[] | Refusal> {
      const items = await asAgent(p, (sync, keys) => listItems(sync, keys, d.log)).catch(ownerKeyChanged);
      if (!Array.isArray(items)) return items;
      return items.map((i) => ({ handle: i.handle, title: i.title, type: i.type, hosts: i.hosts, inject: i.inject, approval: i.approval,
        ...(i.methods ? { methods: i.methods } : {}), ...(i.paths ? { paths: i.paths } : {}),
        ...(i.deposit ? { deposit: i.deposit } : {}), ...(i.can_update ? { can_update: i.can_update } : {}),
        ...(i.env_keys ? { env_keys: i.env_keys } : {}), ...(i.env_injects ? { env_injects: i.env_injects } : {}) }));
    },

    /** A deposit in the owner's inbox. Policy and inbox are checked on the sync before anything is built or sent. */
    async saveSecret(p: AgentPrincipal, input: SaveInput): Promise<{ item: string } | Refusal> {
      return asPersonal(p, async (sync, keys) => {
        if (!sync.policy.write) return refused("not_writable");
        if (sync.inboxFree <= 0) return refused("inbox_full");
        const r = await deposit(p, sync, keys, input).catch(invalid);
        if ("error" in r || !("refused" in r)) return r;
        // conflict on a new id means a broken API or a colliding id: not a reason save_secret has.
        if (r.refused === "conflict") throw new Error("deposit refused: conflict");
        return refused(r.refused);
      }).catch(ownerKeyChanged);
    },

    /** The agent's own unkept deposit, or a record with write. A given revision must be the current one. */
    async updateSecret(p: AgentPrincipal, input: { item: string; set: UpdateSet; revision?: number }): Promise<{ item: string; revision: number } | Refusal> {
      return asPersonal(p, async (sync, keys) => {
        // Nothing to set would write a no-op revision.
        if (Object.values(input.set).every((v) => v === undefined || (typeof v === "object" && Object.keys(v).length === 0))) return refused("invalid");
        const t = await findItem(sync, keys, input.item, d.log);
        if (!t) return refused("not_found");
        if (!t.write) return refused("not_writable");
        if (input.revision !== undefined && input.revision !== t.revision) return refused("conflict");
        const u = await buildUpdate(sync, keys, d.identity, { kind: t.deposit ? "deposit" : "record", id: t.id, revision: t.revision }, input.set, d.held).catch(updateRefusal);
        if ("error" in u) return u;
        const r = t.deposit ? await d.api.updateDeposit(p.accessToken, t.id, u) : await d.api.updateRecord(p.accessToken, t.id, u);
        d.syncs.drop(p.agentId);
        return "refused" in r ? refused(r.refused) : { item: input.item, revision: r.revision };
      }).catch(ownerKeyChanged);
    },

    async httpRequest(p: AgentPrincipal, input: HttpRequestInput): Promise<HttpRequestResult> {
      const { item, capture, ...req } = input;
      // A capture checks the owner-wide inbox on a fresh sync (F2); the key still opens first (F1).
      if (capture) d.syncs.drop(p.agentId);
      let ran = false;
      const r = await asAgent(p, async (sync, keys) => {
        if (capture) {
          if (!isPersonal(sync)) throw new Error("not a personal agent");
          // Before anything is sent: else the upstream makes a credential that can't be saved (Review Focus 3).
          if (!sync.policy.write) return refused("not_writable");
          if (sync.inboxFree <= 0) return refused("inbox_full");
          // The deposit's own checks on a placeholder value: an agent_use the vault refuses must not cost a minted credential.
          try { checkDeposit(capturedInput(capture, "x".repeat(8))); } catch (e) { return invalid(e); }
        }
        let value: string | null = null, release = () => {};
        try {
          return await withItem(sync, keys, item, d.held, async (x) => {
            ran = true;
            // Whatever the status, the value at the pointer is scrubbed (a 4xx/5xx or an unfollowed 3xx can carry a minted credential too).
            const grab = (body: string) => {
              value = pointerValue(body, capture!.from);
              if (value) release = d.held.hold(value);
              return value;
            };
            const o = await performRequest(req, { policy: x.policy, secret: x.secret, username: x.username, cfg: d.cfg, allow, resolve: d.resolve,
              ...(capture ? { capture: grab } : {}) });
            // The host comes from the outcome: the policy's may be a wildcard.
            if (!o.ok) {
              d.events.push(p, event("refused", req.method, o.host, { recordId: x.recordId, reason: o.reason }));
              return { error: "refused", reason: o.reason } as Refusal;
            }
            d.events.push(p, event("use", req.method, o.host, { recordId: x.recordId, ...(o.result.truncated ? { truncated: true } : {}) }));
            if (o.reflected) d.events.push(p, event("reflected", req.method, o.host, { recordId: x.recordId }));
            if (!capture) return o.result;
            // A cut body can't be parsed and may hold the minted credential unscrubbed (so may a header): both withheld.
            if (o.result.truncated) return { ...o.result, headers: {}, body: "", capture: { refused: "invalid" } };
            const v = value as string | null; // assigned in grab
            if (v === null || o.result.status < 200 || o.result.status >= 300) return { ...o.result, capture: { refused: "not_found" } };
            // Never launder the injected credential (an echoing upstream) into a new item; nor save a value too short to scrub reliably.
            if (v.length < 8 || x.secret.includes(v) || scrub(v, variantsOf(x.secret, x.policy.inject.kind === "basic" ? x.username : undefined)).hits)
              return { ...o.result, capture: { refused: "invalid" } };
            return { ...o.result, ...(await saveCaptured(p, sync as PersonalAgentSync, keys, capture, v)) };
          }, d.log);
        } catch (e) {
          if (ran) throw e;
          // The item would not open (a decrypt failure): to the agent it does not exist. Anything else is our fault.
          const unopenable = e instanceof CryptoError || e instanceof ItemUnopenable;
          d.log.error({ event: unopenable ? "item_unopenable" : "item_error", class: classOf(e) });
          return { error: "refused", reason: unopenable ? "not_found" : "upstream_error" } as Refusal;
        } finally {
          release();
        }
      }).catch(ownerKeyChanged);
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

const value = z.string().max(MAX_FIELD_VALUE);
const fieldsInput = z.strictObject({ username: value.optional(), password: value.optional(), url: value.optional(), notes: value.optional(),
  data: z.record(z.string().max(64), value).refine((x) => Object.keys(x).length <= 64, "at most 64 data keys").optional() });
// The record validator (normalizeRecordBody, validateAgentPolicy) has the last word; these bound the input's size.
const saveSecretInput = {
  title: z.string().min(1).max(200),
  type: z.enum(RECORD_TYPES),
  fields: fieldsInput.optional(),
  custom_fields: z.array(z.strictObject({ label: z.string().max(100), kind: z.enum(FIELD_KINDS), value })).max(64).optional(),
  agent_use: z.strictObject({
    hosts: z.array(z.string().max(255)).min(1).max(32),
    inject: z.strictObject({ kind: z.enum(["bearer", "basic", "header", "query"]), name: z.string().max(64).optional(), prefix: z.string().max(64).optional() }),
    secret: z.string().max(128).optional(),
  }).optional(),
};
const captureInput = z.strictObject({
  from: z.string().max(256),
  title: saveSecretInput.title,
  type: saveSecretInput.type.refine((t) => t === "envFile" || defaultSecretRef(t) !== null, "a type with a default secret field, or envFile"),
  entry: z.string().regex(ENV_KEY).optional(),
  agent_use: saveSecretInput.agent_use,
}).refine((c) => (c.type === "envFile") === (c.entry !== undefined), "entry is required for envFile and only for envFile");
const updateSecretInput = {
  item: z.string().max(200),
  set: z.strictObject({ ...fieldsInput.shape, env: z.record(z.string().regex(ENV_KEY), z.string().max(MAX_ENV_BYTES))
    .refine((x) => Object.keys(x).length >= 1 && Object.keys(x).length <= 50, "1 to 50 entries").optional() }),
  revision: z.number().int().min(1).optional(),
};

interface Session { agentId: string; transport: WebStandardStreamableHTTPServerTransport; busy: boolean; timer?: NodeJS.Timeout }
/** One per HTTP request, handed to the tools through the transport's authInfo. */
interface Call { principal: AgentPrincipal; refused: boolean; /** An http_request in it carries `capture`. */ capture: boolean }

const asResult = (x: object) => ({ content: [{ type: "text" as const, text: JSON.stringify(x) }], structuredContent: x as Record<string, unknown> });

/** One McpServer per session: the two tools, and for a personal agent the two write tools; a session runs one tool call at a time. */
function sessionServer(s: Pick<Session, "busy">, tools: ReturnType<typeof agentTools>, log: Logger, personal: boolean) {
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
    (extra) => run(extra, async (p) => { const r = await tools.listSecrets(p); return Array.isArray(r) ? { secrets: r } : r; }));
  const httpRequest = { description: "An HTTP request with an item's credential injected by the gateway. `item` is a handle from list_secrets (or a record id)." };
  const onHttpRequest = (input: object, extra: Parameters<typeof run>[0]) =>
    run(extra, (p) => tools.httpRequest(p, input as HttpRequestInput), (p) => tools.busy(p, input as HttpRequestInput));
  if (personal) server.registerTool("http_request", { ...httpRequest, inputSchema: { ...httpRequestInput, capture: captureInput.optional() } }, onHttpRequest);
  // An organisation session keeps its schema (zod strips `capture`), but refuses `capture` as an input error rather than dropping it.
  else server.registerTool("http_request", { ...httpRequest, inputSchema: httpRequestInput }, (input, extra) => (extra.authInfo?.extra?.call as Call).capture
    ? { content: [{ type: "text" as const, text: "Input validation error: capture is for personal agents only" }], isError: true }
    : onHttpRequest(input, extra));
  if (!personal) return server;
  server.registerTool("save_secret", {
    description: "Saves a credential already in the conversation as a new item in the owner's inbox (they keep or delete it). Returns its handle. "
      + "For a .env file use type envFile with fields.data.content; you have then seen its values, so prefer capture for a value an API returns.",
    inputSchema: saveSecretInput,
  }, (input, extra) => run(extra, (p) => tools.saveSecret(p, input as SaveInput)));
  server.registerTool("update_secret", {
    description: "Changes fields of your own unkept item, or of an item the owner lets you update. `revision`, if given, must be the current one.",
    inputSchema: updateSecretInput,
  }, (input, extra) => run(extra, (p) => tools.updateSecret(p, input)));
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
  const limited = (res: ServerResponse, key: string, limit: number, windowMs = MINUTE) => {
    const r = limiter.take(key, limit, windowMs);
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

  async function open(agentId: string, personal: boolean): Promise<Session> {
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
    await sessionServer(s, tools, deps.log, personal).connect(s.transport);
    return s;
  }

  const handler = async (req: IncomingMessage, res: ServerResponse) => {
    const addr = clientAddress(req, cfg.trustProxy);
    if (limited(res, `addr:${addr}`, ADDRESS_PER_MINUTE)) return;
    const p = await auth(req.headers.authorization, () => {
      const r = limiter.take(`xchg:${addr}`, EXCHANGE_MISSES_PER_MINUTE, MINUTE);
      if (!r.ok) throw new HttpError(429, "rate_limited", { "retry-after": String(r.retryAfterSeconds) });
    });
    if (!p) return send(res, 401, { error: "unauthorized" }, challenge(cfg, /^Bearer\s+\S/i.test(req.headers.authorization ?? "")));
    // No server-to-client stream (GET) is offered.
    if (req.method !== "POST" && req.method !== "DELETE") return send(res, 405, { error: "method_not_allowed" }, { allow: "POST, DELETE" });
    const body = req.method === "POST" ? await readJson(req, MAX_BODY) : undefined;
    const msgs = Array.isArray(body) ? body : [body];
    let capture = false;
    for (const m of msgs) {
      const msg = m as { method?: unknown; params?: { name?: unknown } } | null;
      if (msg?.method !== "tools/call") continue;
      if (msg.params?.name === "http_request" && limited(res, `http:${p.agentId}`, cfg.agentRatePerMinute)) return;
      const capturing = msg.params?.name === "http_request" && (msg.params as { arguments?: { capture?: unknown } }).arguments?.capture !== undefined;
      if (capturing && limited(res, `write:${p.agentId}`, cfg.writePerHour, HOUR)) return;
      capture ||= capturing;
      if (msg.params?.name === "list_secrets" && limited(res, `list:${p.agentId}`, LIST_PER_MINUTE)) return;
      if ((msg.params?.name === "save_secret" || msg.params?.name === "update_secret") && limited(res, `write:${p.agentId}`, cfg.writePerHour, HOUR)) return;
    }

    const sid = req.headers["mcp-session-id"];
    let s: Session | undefined;
    if (typeof sid === "string") {
      s = sessions.get(sid);
      if (!s) return send(res, 404, { error: "session_not_found" });
      if (s.agentId !== p.agentId) return send(res, 403, { error: "forbidden" });
      touch(s);
    } else if (req.method === "POST" && msgs.some((m) => isInitializeRequest(m))) {
      s = await open(p.agentId, p.ownerUserId !== null);
    } else {
      return send(res, 400, { error: "invalid_request" });
    }

    const call: Call = { principal: p, refused: false, capture };
    const headers = new Headers();
    for (const [k, v] of Object.entries(req.headers)) for (const x of [v ?? []].flat()) headers.append(k, x);
    const r = await s.transport.handleRequest(new Request(new URL(req.url ?? "/", "http://gateway"), { method: req.method, headers }), {
      parsedBody: body,
      authInfo: { token: p.accessToken, clientId: p.agentId, scopes: ["agent"], expiresAt: p.exp, extra: { call } },
    });
    if (call.refused) {
      // Revoked or expired (the tool already dropped the key and sync caches): its static token is checked at the API again.
      dropAgent(p.agentId);
      return send(res, 401, { error: "unauthorized" }, challenge(cfg, true));
    }
    res.writeHead(r.status, Object.fromEntries(r.headers)).end(Buffer.from(await r.arrayBuffer()));
  };
  return Object.assign(handler, { dropAgent });
}
