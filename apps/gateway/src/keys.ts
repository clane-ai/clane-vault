import { b64url, type MembershipKeys } from "@clane-vault/crypto";
import { ApiRefused, type AgentSync, type ApiClient } from "./apiClient.js";
import { unwrapAgentKey } from "./envelope.js";
import type { Kek } from "./kek.js";

/**
 * The agent's opened X25519 keys for a short TTL. Every `open` must be paired with `release` in `finally` (or use `use`):
 * a key is zeroed at its last release once it is no longer the live cached entry (TTL 0, replaced, dropped or expired).
 */
export class AgentKeyCache {
  private entries = new Map<string, { keys: MembershipKeys; wrapped: string; until: number }>();
  private refs = new Map<MembershipKeys, number>();
  private ttlMs: number; private kek: Kek; private now: () => number;

  constructor(o: { ttlMs: number; kek: Kek; now?: () => number }) {
    this.ttlMs = o.ttlMs; this.kek = o.kek; this.now = o.now ?? Date.now;
  }

  /** A KEK unwrap only on a miss. ttlMs 0: never stored. */
  async open(agentId: string, sync: AgentSync): Promise<MembershipKeys> {
    this.sweep();
    const e = this.entries.get(agentId);
    if (e && e.wrapped === sync.wrappedPrivateKey && e.keys.orgId === sync.orgId) return this.ref(e.keys);
    this.drop(agentId); // re-keyed or moved: the old key must not linger
    const publicKey = sync.membershipKeys[0]?.publicKey;
    if (!publicKey) throw new Error("the agent has no membership key");
    const privateKey = await unwrapAgentKey(this.kek, { orgId: sync.orgId, agentId, publicKey }, sync.wrappedPrivateKey);
    const keys = this.ref({ orgId: sync.orgId, publicKey: b64url.decode(publicKey), privateKey });
    if (this.ttlMs > 0) {
      this.drop(agentId); // a concurrent miss stored one meanwhile: it loses
      this.entries.set(agentId, { keys, wrapped: sync.wrappedPrivateKey, until: this.now() + this.ttlMs });
      setTimeout(() => this.sweep(), this.ttlMs + 1).unref(); // zero it on time even when the agent goes quiet
    }
    return keys;
  }

  release(agentId: string, keys: MembershipKeys): void {
    const n = (this.refs.get(keys) ?? 1) - 1;
    if (n > 0) { this.refs.set(keys, n); return; }
    this.refs.delete(keys);
    if (this.entries.get(agentId)?.keys !== keys) keys.privateKey.fill(0);
  }

  /** open, f, release. */
  async use<T>(agentId: string, sync: AgentSync, f: (keys: MembershipKeys) => Promise<T>): Promise<T> {
    const keys = await this.open(agentId, sync);
    try { return await f(keys); } finally { this.release(agentId, keys); }
  }

  /** Zeroes at once, or at the last release of a key still in use. */
  drop(agentId: string): void {
    const e = this.entries.get(agentId);
    if (!e) return;
    this.entries.delete(agentId);
    if (!this.refs.has(e.keys)) e.keys.privateKey.fill(0);
  }

  /** Test hook. */
  has(agentId: string): boolean {
    this.sweep();
    return this.entries.has(agentId);
  }

  private ref(keys: MembershipKeys) {
    this.refs.set(keys, (this.refs.get(keys) ?? 0) + 1);
    return keys;
  }

  private sweep() {
    const t = this.now();
    for (const [id, e] of this.entries) if (t >= e.until) this.drop(id);
  }
}

export class SyncCache {
  /** agentId → token → entry, so an agent's concurrent sessions don't evict each other. */
  private entries = new Map<string, Map<string, { sync: AgentSync; until: number }>>();
  private drops = new Map<string, number>();
  private ttlMs: number; private api: ApiClient; private now: () => number;

  constructor(o: { ttlMs: number; api: ApiClient; now?: () => number }) {
    this.ttlMs = o.ttlMs; this.api = o.api; this.now = o.now ?? Date.now;
  }

  /** Keyed by token too, so a token the API would refuse never rides on a sync fetched with another. */
  async get(agentId: string, token: string): Promise<AgentSync> {
    const mine = this.entries.get(agentId), t = this.now();
    if (mine) for (const [k, e] of mine) if (t >= e.until) mine.delete(k);
    const e = mine?.get(token);
    if (e) return e.sync;
    const gen = this.drops.get(agentId) ?? 0;
    try {
      const sync = await this.api.sync(token);
      // A drop (revoke) while the fetch was in flight wins: don't cache what it ended.
      if (this.ttlMs > 0 && (this.drops.get(agentId) ?? 0) === gen) {
        const m = this.entries.get(agentId) ?? new Map<string, { sync: AgentSync; until: number }>();
        m.set(token, { sync, until: this.now() + this.ttlMs });
        this.entries.set(agentId, m);
      }
      return sync;
    } catch (x) {
      if (x instanceof ApiRefused) this.drop(agentId);
      throw x;
    }
  }

  /** Every entry of the agent's, whatever the token. */
  drop(agentId: string): void {
    this.entries.delete(agentId);
    this.drops.set(agentId, (this.drops.get(agentId) ?? 0) + 1);
  }
}
