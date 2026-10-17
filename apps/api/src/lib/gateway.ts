import { z } from "zod";
import type { AgentConfig } from "../config.js";
import type { Db } from "./access.js";
import { isPublicKeyB64 } from "./membershipKeys.js";

/** The gateway's Ed25519 identity: keyId is the first 16 chars of base64url(SHA-256(raw key)). */
export interface GatewayIdentityInfo { keyId: string; publicKey: string }
export interface AgentKeyResult { publicKey: string; wrappedPrivateKey: string; kekId: string; attestation: string }

export class GatewayUnavailable extends Error {
  constructor(msg = "the agent gateway is unreachable") { super(msg); this.name = "GatewayUnavailable"; }
}

export class GatewayIdentityChanged extends Error {
  constructor(public pinned: GatewayIdentityInfo, public seen: GatewayIdentityInfo) {
    super(`The agent gateway's identity key changed (pinned ${pinned.keyId}, now ${seen.keyId}). Agent keys signed by the new key are not trusted. ` +
      "If the gateway was replaced on purpose, compare its fingerprint with the published one, then set GATEWAY_ACCEPT_NEW_IDENTITY=true for one start (docs/agents.md).");
    this.name = "GatewayIdentityChanged";
  }
}

export interface GatewayClient {
  health(): Promise<GatewayIdentityInfo>;
  createAgentKey(ids: { agentId: string; orgId: string }): Promise<AgentKeyResult>;
  dropAgent(agentId: string): Promise<void>;
}

const noDot = z.string().regex(/^[^.]+$/);
const healthBody = z.object({ identity: z.object({ keyId: noDot, publicKey: z.string().min(1) }) });
const keyBody = z.object({
  publicKey: z.string().refine(isPublicKeyB64), kekId: noDot,
  wrappedPrivateKey: z.string().regex(/^k1\.[^.]+\.[^.]+\.v1\./), attestation: z.string().regex(/^g1\.[^.]+\.[^.]+$/),
});

/** The gateway's internal port, over HTTP only (apps/api never imports apps/gateway). 5 s per call. */
export function gatewayClient(cfg: AgentConfig, fetchImpl: typeof fetch = fetch): GatewayClient {
  const base = cfg.gatewayInternalUrl.replace(/\/+$/, "");
  async function call(method: string, path: string, body?: unknown): Promise<unknown> {
    let res: Response;
    try {
      res = await fetchImpl(base + path, { method, signal: AbortSignal.timeout(5000), body: body === undefined ? undefined : JSON.stringify(body),
        headers: { "x-gateway-token": cfg.gatewayApiToken, ...(body === undefined ? {} : { "content-type": "application/json" }) } });
    } catch { throw new GatewayUnavailable(); }
    if (!res.ok) throw new GatewayUnavailable(`the agent gateway answered ${res.status}`);
    try { return res.status === 204 ? null : await res.json(); } catch { throw new GatewayUnavailable("the agent gateway sent an unreadable answer"); }
  }
  const parse = <T>(s: z.ZodType<T>, v: unknown): T => {
    const r = s.safeParse(v);
    if (!r.success) throw new GatewayUnavailable("the agent gateway sent an unexpected answer");
    return r.data;
  };
  return {
    health: async () => { const { identity } = parse(healthBody, await call("GET", "/internal/health")); return { keyId: identity.keyId, publicKey: identity.publicKey }; },
    createAgentKey: async (ids) => parse(keyBody, await call("POST", "/internal/agents", ids)),
    dropAgent: async (agentId) => { await call("DELETE", `/internal/agents/${encodeURIComponent(agentId)}`); },
  };
}

const SLOT = "gateway";

/** First sight creates the row; same → "ok"; different → throws GatewayIdentityChanged unless accept (then updates). */
export async function pinGatewayIdentity(db: Db, seen: GatewayIdentityInfo, opts: { accept: boolean }): Promise<"created" | "ok" | "accepted"> {
  let row = await db.gatewayIdentity.findUnique({ where: { id: SLOT } });
  if (!row) {
    // Two starts at once: the first row wins and the other compares against it.
    if ((await db.gatewayIdentity.createMany({ data: [{ id: SLOT, keyId: seen.keyId, publicKey: seen.publicKey }], skipDuplicates: true })).count) return "created";
    row = await db.gatewayIdentity.findUniqueOrThrow({ where: { id: SLOT } });
  }
  if (row.keyId === seen.keyId && row.publicKey === seen.publicKey) return "ok";
  if (!opts.accept) throw new GatewayIdentityChanged({ keyId: row.keyId, publicKey: row.publicKey }, seen);
  await db.gatewayIdentity.update({ where: { id: SLOT }, data: { keyId: seen.keyId, publicKey: seen.publicKey, firstSeenAt: new Date() } });
  return "accepted";
}

/**
 * Runs before the server listens (agents on). An unreachable gateway only warns: the identity is pinned on first
 * contact instead. A changed identity throws GatewayIdentityChanged (server.ts stops) unless `accept`.
 */
export async function checkGatewayAtStart(db: Db, client: GatewayClient, opts: { accept: boolean; log: { warn: (msg: string) => void } }): Promise<"created" | "ok" | "accepted" | "unreachable"> {
  let seen: GatewayIdentityInfo;
  try { seen = await client.health(); } catch (e) {
    if (!(e instanceof GatewayUnavailable)) throw e;
    opts.log.warn(`${e.message}: starting anyway; agent enrolment answers 503 gateway_unavailable until it is reachable, and its identity is pinned on first contact.`);
    return "unreachable";
  }
  const r = await pinGatewayIdentity(db, seen, { accept: opts.accept });
  if (r === "accepted") opts.log.warn(`GATEWAY_ACCEPT_NEW_IDENTITY=true: the gateway identity ${seen.keyId} is now pinned. Remove the setting.`);
  return r;
}
