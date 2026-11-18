import { randomUUID } from "node:crypto";
import { agentRevealRequestMessage, b64url, generateKeyPair, openReveal, revealFieldsOf, type MembershipKeys, type SealKeys } from "@clane-vault/crypto";
import type { ApiClient, PersonalAgentSync } from "./apiClient.js";
import type { AgentPrincipal } from "./auth.js";
import type { GatewayConfig } from "./config.js";
import type { Identity } from "./identity.js";
import { revealableItem, standingBody } from "./items.js";
import type { HeldSecrets, Logger } from "./log.js";

/** "unverified": the approval did not come from the owner's key (a forged or broken seal); nothing is released. */
export type RevealReason = "reveal_off" | "field" | "denied" | "expired" | "busy" | "not_found" | "unverified";
/** `release` (fields only): the values stay held in the log scrubber until the caller has written the result. */
export type RevealResult = { fields: Record<string, string>; release: () => void } | { status: "pending"; request_id: string } | { error: "refused"; reason: RevealReason };

/** A request lives 5 minutes (the API refuses a longer one). */
export const REVEAL_TTL_MS = 5 * 60e3;

/** `ownerPublicKey`: the owner key checked against the k2 attestation when the request was made; `fields`: what was asked. */
interface Pending { id: string; agentId: string; recordId: string; fields: string[]; ownerPublicKey: string; keys: SealKeys; expiresAt: number }

/**
 * In memory, per process: the one-time private key of each open request. A request can only be completed by the gateway
 * process that made it; a restart turns it into "expired". Keys are zeroed when they leave.
 */
export class PendingReveals {
  private open = new Map<string, Pending>();
  /** Abandoned requests too: their keys are zeroed within a minute of expiring, even if nothing touches them again. */
  constructor() { setInterval(() => this.sweep(Date.now()), 60e3).unref(); }
  add(p: Pending): void { this.sweep(Date.now()); this.open.set(p.id, p); }
  get(id: string, agentId: string): Pending | undefined { this.sweep(Date.now()); const p = this.open.get(id); return p && p.agentId === agentId ? p : undefined; }
  take(id: string): void { const p = this.open.get(id); if (p) { p.keys.privateKey.fill(0); this.open.delete(id); } }
  sweep(now: number): void { for (const p of [...this.open.values()]) if (p.expiresAt < now) this.take(p.id); }
}

export interface RevealDeps {
  cfg: GatewayConfig; api: ApiClient; identity: Identity; held: HeldSecrets; pending: PendingReveals; log?: Logger;
  pollMs?: number; waitMs?: number; now?: () => number;
}

const refused = (reason: RevealReason): RevealResult => ({ error: "refused", reason });
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** get_secret { item, fields, reason } with the owner's approval (spec §5.3). */
export async function requestReveal(d: RevealDeps, p: AgentPrincipal, sync: PersonalAgentSync, keys: MembershipKeys,
  input: { item: string; fields: string[]; reason: string }): Promise<RevealResult> {
  if (d.cfg.reveal === "off" || sync.policy.reveal === "off") return refused("reveal_off"); // no API call (spec §8)
  const fields = [...new Set(input.fields)].sort();
  // Standing reveal (spec §5.6): the operator, every policy and the item's own encrypted body all say so. Otherwise the
  // approval path below runs, so an item can have both.
  if (d.cfg.reveal === "standing" && sync.policy.reveal === "standing") {
    const s = await standingBody(sync, keys, input.item, fields, d.log);
    if (s) {
      if ("refused" in await d.api.standingReveal(p.accessToken, { recordId: s.recordId, fields })) return refused("reveal_off"); // only a 201 releases values
      const out = await revealFieldsOf(s.body, fields);
      const releases = Object.values(out).map((v) => d.held.hold(v));
      return { fields: out, release: () => { for (const r of releases) r(); } };
    }
  }
  const it = await revealableItem(sync, keys, input.item, d.log);
  if (it === undefined) return refused("not_found");
  if (it === "no_stub") return refused("reveal_off");
  if (fields.some((f) => !it.fields.includes(f))) return refused("field");
  const kp = await generateKeyPair();
  const id = randomUUID(), now = (d.now ?? Date.now)();
  const expiresAt = new Date(now + REVEAL_TTL_MS).toISOString(), requestPublicKey = b64url.encode(kp.publicKey);
  const signature = await d.identity.signMessage("q1", agentRevealRequestMessage({ requestId: id, ownerUserId: sync.owner.userId, agentId: sync.agentId,
    recordId: it.recordId, fields, requestPublicKey, expiresAt }));
  let r: Awaited<ReturnType<ApiClient["createReveal"]>>;
  try {
    r = await d.api.createReveal(p.accessToken, { id, recordId: it.recordId, fields, reason: input.reason, requestPublicKey, signature, expiresAt });
  } catch (e) { kp.privateKey.fill(0); throw e; }
  if ("refused" in r) { kp.privateKey.fill(0); return refused(r.refused); }
  d.pending.add({ id, agentId: sync.agentId, recordId: it.recordId, fields, ownerPublicKey: sync.owner.publicKey, keys: kp, expiresAt: Date.parse(expiresAt) });
  return wait(d, p, id);
}

/** get_secret { request_id }: an open request of this agent, made by this process; anything else is "expired". */
export async function resumeReveal(d: RevealDeps, p: AgentPrincipal, requestId: string): Promise<RevealResult> {
  if (!d.pending.get(requestId, p.agentId)) return refused("expired");
  return wait(d, p, requestId);
}

/** Polls the API every pollMs for up to waitMs; the one-time key is zeroed as soon as the request ends either way. */
async function wait(d: RevealDeps, p: AgentPrincipal, id: string): Promise<RevealResult> {
  const now = d.now ?? Date.now, until = now() + (d.waitMs ?? 50_000), pollMs = d.pollMs ?? 2000;
  for (;;) {
    const pr = d.pending.get(id, p.agentId);
    if (!pr || pr.expiresAt <= now()) { d.pending.take(id); return refused("expired"); }
    let s: Awaited<ReturnType<ApiClient["reveal"]>>;
    try { s = await d.api.reveal(p.accessToken, id); } catch (e) { d.pending.take(id); throw e; }
    if (s.status === "approved") {
      try {
        let fields: Record<string, string>;
        try { fields = await openReveal(s.sealed, { requestId: id, recordId: pr.recordId, agentId: p.agentId }, pr.keys, b64url.decode(pr.ownerPublicKey), pr.fields); }
        catch { d.log?.error({ event: "reveal_unverified", requestId: id }); return refused("unverified"); }
        const releases = Object.values(fields).map((v) => d.held.hold(v));
        return { fields, release: () => { for (const r of releases) r(); } };
      } finally { d.pending.take(id); }
    }
    if (s.status !== "pending") { d.pending.take(id); return refused(s.status); }
    if (now() + pollMs > until) return { status: "pending", request_id: id };
    await sleep(pollMs);
  }
}
