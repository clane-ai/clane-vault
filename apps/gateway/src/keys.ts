import { b64url, type MembershipKeys } from "@clane-vault/crypto";
import { ApiRefused, type AgentSync, type ApiClient } from "./apiClient.js";
import { unwrapAgentKey } from "./envelope.js";
import type { Kek } from "./kek.js";

export class AgentKeyCache {
  private entries = new Map<string, { keys: MembershipKeys; wrapped: string; until: number }>();
  private ttlMs: number; private kek: Kek; private now: () => number;

  constructor(o: { ttlMs: number; kek: Kek; now?: () => number }) {
    this.ttlMs = o.ttlMs; this.kek = o.kek; this.now = o.now ?? Date.now;
  }

  /**
   * The agent's opened X25519 keys; a KEK unwrap only on a miss. ttlMs 0: never stored.
   * A cached result belongs to the cache (drop zeroes it); with ttlMs 0 the caller owns it and zeroes it when done.
   */
  async open(agentId: string, sync: AgentSync): Promise<MembershipKeys> {
    this.sweep();
    const e = this.entries.get(agentId);
    if (e && e.wrapped === sync.wrappedPrivateKey && e.keys.orgId === sync.orgId) return e.keys;
    this.drop(agentId); // re-keyed or moved: the old key must not linger
    const publicKey = sync.membershipKeys[0]?.publicKey;
    if (!publicKey) throw new Error("the agent has no membership key");
    const privateKey = await unwrapAgentKey(this.kek, { orgId: sync.orgId, agentId, publicKey }, sync.wrappedPrivateKey);
    const keys: MembershipKeys = { orgId: sync.orgId, publicKey: b64url.decode(publicKey), privateKey };
    if (this.ttlMs > 0) {
      this.entries.set(agentId, { keys, wrapped: sync.wrappedPrivateKey, until: this.now() + this.ttlMs });
      setTimeout(() => this.sweep(), this.ttlMs + 1).unref(); // zero it on time even when the agent goes quiet
    }
    return keys;
  }

  drop(agentId: string): void {
    this.entries.get(agentId)?.keys.privateKey.fill(0);
    this.entries.delete(agentId);
  }

  /** Test hook. */
  has(agentId: string): boolean {
    this.sweep();
    return this.entries.has(agentId);
  }

  private sweep() {
    const t = this.now();
    for (const [id, e] of this.entries) if (t >= e.until) this.drop(id);
  }
}

export class SyncCache {
  private entries = new Map<string, { sync: AgentSync; token: string; until: number }>();
  private drops = new Map<string, number>();
  private ttlMs: number; private api: ApiClient; private now: () => number;

  constructor(o: { ttlMs: number; api: ApiClient; now?: () => number }) {
    this.ttlMs = o.ttlMs; this.api = o.api; this.now = o.now ?? Date.now;
  }

  /** Keyed by agent and token too, so a token the API would refuse never rides on a sync fetched with another. */
  async get(agentId: string, token: string): Promise<AgentSync> {
    const e = this.entries.get(agentId);
    if (e && e.token === token && this.now() < e.until) return e.sync;
    const gen = this.drops.get(agentId) ?? 0;
    try {
      const sync = await this.api.sync(token);
      // A drop (revoke) while the fetch was in flight wins: don't cache what it ended.
      if (this.ttlMs > 0 && (this.drops.get(agentId) ?? 0) === gen) this.entries.set(agentId, { sync, token, until: this.now() + this.ttlMs });
      return sync;
    } catch (x) {
      if (x instanceof ApiRefused) this.drop(agentId);
      throw x;
    }
  }

  drop(agentId: string): void {
    this.entries.delete(agentId);
    this.drops.set(agentId, (this.drops.get(agentId) ?? 0) + 1);
  }
}
