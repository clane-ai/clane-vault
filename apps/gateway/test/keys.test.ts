import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { apiClient, ApiRefused, type PersonalAgentSync } from "../src/apiClient.js";
import { b64url, generateKeyPair } from "@clane-vault/crypto";
import { AgentKeyCache, OwnerKeyChanged, SyncCache } from "../src/keys.js";
import type { Kek } from "../src/kek.js";
import { startFakeApi } from "./fakeApi.js";
import { fileKek } from "./helpers.js";

let kek: Kek & { unwraps: number };
let api: Awaited<ReturnType<typeof startFakeApi>>;
beforeEach(async () => {
  const real = await fileKek();
  const counting = { id: real.id, unwraps: 0, wrap: real.wrap, unwrap: (w: string, c: Record<string, string>) => { counting.unwraps++; return real.unwrap(w, c); } };
  kek = counting;
  api = await startFakeApi({ kek });
});
afterEach(() => api.close());

const client = () => apiClient({ apiUrl: api.url, apiToken: api.token });
const syncOf = async () => client().sync(await api.issueToken());

describe("AgentKeyCache", () => {
  it("unwraps once within the TTL", async () => {
    const sync = await syncOf();
    const cache = new AgentKeyCache({ ttlMs: 60_000, kek });
    const a = await cache.open(api.agent.id, sync);
    await cache.open(api.agent.id, sync);
    expect(kek.unwraps).toBe(1);
    expect(a.orgId).toBe(api.agent.orgId);
    expect(cache.has(api.agent.id)).toBe(true);
  });

  it("ttlMs 0 hits the KEK on every call and stores nothing", async () => {
    const sync = await syncOf();
    const cache = new AgentKeyCache({ ttlMs: 0, kek });
    await cache.open(api.agent.id, sync);
    await cache.open(api.agent.id, sync);
    expect(kek.unwraps).toBe(2);
    expect(cache.has(api.agent.id)).toBe(false);
  });

  it("zeroes the private key once the TTL passes", async () => {
    let t = 1_000;
    const cache = new AgentKeyCache({ ttlMs: 60_000, kek, now: () => t });
    const keys = await cache.open(api.agent.id, await syncOf());
    cache.release(api.agent.id, keys);
    expect(keys.privateKey.some((b) => b !== 0)).toBe(true);
    t += 60_001;
    expect(cache.has(api.agent.id)).toBe(false);
    expect(keys.privateKey.every((b) => b === 0)).toBe(true);
  });

  it("an expiry while the key is in use defers zeroing until release", async () => {
    let t = 1_000;
    const cache = new AgentKeyCache({ ttlMs: 60_000, kek, now: () => t });
    const keys = await cache.open(api.agent.id, await syncOf());
    t += 60_001;
    expect(cache.has(api.agent.id)).toBe(false);
    expect(keys.privateKey.some((b) => b !== 0)).toBe(true);
    cache.release(api.agent.id, keys);
    expect(keys.privateKey.every((b) => b === 0)).toBe(true);
  });

  it("drop zeroes at once", async () => {
    const cache = new AgentKeyCache({ ttlMs: 60_000, kek });
    const keys = await cache.open(api.agent.id, await syncOf());
    cache.release(api.agent.id, keys);
    cache.drop(api.agent.id);
    expect(cache.has(api.agent.id)).toBe(false);
    expect(keys.privateKey.every((b) => b === 0)).toBe(true);
  });

  it("ttlMs 0: release zeroes the key", async () => {
    const cache = new AgentKeyCache({ ttlMs: 0, kek });
    const keys = await cache.open(api.agent.id, await syncOf());
    cache.release(api.agent.id, keys);
    expect(keys.privateKey.every((b) => b === 0)).toBe(true);
  });

  it("ttlMs > 0: release leaves the cached key usable", async () => {
    const sync = await syncOf();
    const cache = new AgentKeyCache({ ttlMs: 60_000, kek });
    const a = await cache.open(api.agent.id, sync);
    cache.release(api.agent.id, a);
    expect(a.privateKey.some((b) => b !== 0)).toBe(true);
    const b = await cache.use(api.agent.id, sync, async (k) => k);
    expect(b).toBe(a);
    expect(a.privateKey.some((x) => x !== 0)).toBe(true);
    expect(kek.unwraps).toBe(1);
  });

  it("zeroes the key that loses a concurrent miss", async () => {
    const sync = await syncOf();
    const cache = new AgentKeyCache({ ttlMs: 60_000, kek });
    const [a, b] = await Promise.all([cache.open(api.agent.id, sync), cache.open(api.agent.id, sync)]);
    expect(kek.unwraps).toBe(2);
    cache.release(api.agent.id, a);
    cache.release(api.agent.id, b);
    const live = await cache.use(api.agent.id, sync, async (k) => k);
    const loser = live === a ? b : a;
    expect(loser.privateKey.every((x) => x === 0)).toBe(true);
    expect(live.privateKey.some((x) => x !== 0)).toBe(true);
    expect(kek.unwraps).toBe(2);
  });
});

describe("AgentKeyCache, personal agent", () => {
  const personalSync = async () => await client().sync(await api.personal.token()) as PersonalAgentSync;

  it("opens the k2 key with the owner key the API reports, with orgId \"\"", async () => {
    const cache = new AgentKeyCache({ ttlMs: 60_000, kek });
    const keys = await cache.open(api.personal.agentId, await personalSync());
    expect(keys.orgId).toBe("");
    expect(b64url.encode(keys.publicKey)).toBe(api.personal.publicKey);
    expect(cache.has(api.personal.agentId)).toBe(true);
  });

  it("after a hit, a sync with another owner.publicKey throws OwnerKeyChanged and drops the entry", async () => {
    const cache = new AgentKeyCache({ ttlMs: 60_000, kek });
    const sync = await personalSync();
    cache.release(api.personal.agentId, await cache.open(api.personal.agentId, sync));
    cache.release(api.personal.agentId, await cache.open(api.personal.agentId, sync));
    expect(kek.unwraps).toBe(1);
    const other = { ...sync, owner: { ...sync.owner, publicKey: b64url.encode((await generateKeyPair()).publicKey) } };
    await expect(cache.open(api.personal.agentId, other)).rejects.toBeInstanceOf(OwnerKeyChanged);
    expect(cache.has(api.personal.agentId)).toBe(false);
  });

  it("after a hit, a sync naming another owner userId is refused, never the cached key", async () => {
    const cache = new AgentKeyCache({ ttlMs: 60_000, kek });
    const sync = await personalSync();
    cache.release(api.personal.agentId, await cache.open(api.personal.agentId, sync));
    await expect(cache.open(api.personal.agentId, { ...sync, owner: { ...sync.owner, userId: crypto.randomUUID() } })).rejects.toBeInstanceOf(OwnerKeyChanged);
    expect(cache.has(api.personal.agentId)).toBe(false);
  });

  it("a personal sync for another agent id is ApiRefused(401), on a hit too", async () => {
    const cache = new AgentKeyCache({ ttlMs: 60_000, kek });
    const sync = await personalSync();
    cache.release(api.personal.agentId, await cache.open(api.personal.agentId, sync));
    const e = await cache.open(api.agent2.id, sync).catch((x: unknown) => x);
    expect(e).toBeInstanceOf(ApiRefused);
    expect((e as ApiRefused).status).toBe(401);
    await expect(cache.open(api.personal.agentId, { ...sync, agentId: api.agent2.id })).rejects.toBeInstanceOf(ApiRefused);
  });

  it("a null wrappedPrivateKey (revoked) is ApiRefused(401) and drops the entry", async () => {
    const cache = new AgentKeyCache({ ttlMs: 60_000, kek });
    const sync = await personalSync();
    cache.release(api.personal.agentId, await cache.open(api.personal.agentId, sync));
    const e = await cache.open(api.personal.agentId, { ...sync, wrappedPrivateKey: null }).catch((x: unknown) => x);
    expect(e).toBeInstanceOf(ApiRefused);
    expect((e as ApiRefused).status).toBe(401);
    expect(cache.has(api.personal.agentId)).toBe(false);
  });
});

describe("SyncCache", () => {
  it("serves the cached sync within the TTL", async () => {
    const syncs = new SyncCache({ ttlMs: 60_000, api: client() });
    const t = await api.issueToken();
    await syncs.get(api.agent.id, t);
    await syncs.get(api.agent.id, t);
    expect(api.syncCalls).toBe(1);
  });

  it("ttlMs 0 fetches every time", async () => {
    const syncs = new SyncCache({ ttlMs: 0, api: client() });
    const t = await api.issueToken();
    await syncs.get(api.agent.id, t);
    await syncs.get(api.agent.id, t);
    expect(api.syncCalls).toBe(2);
  });

  it("keeps one entry per token, and drop clears them all", async () => {
    const syncs = new SyncCache({ ttlMs: 60_000, api: client() });
    const t1 = await api.issueToken(), t2 = await api.issueToken();
    await syncs.get(api.agent.id, t1);
    await syncs.get(api.agent.id, t2);
    await syncs.get(api.agent.id, t1);
    await syncs.get(api.agent.id, t2);
    expect(api.syncCalls).toBe(2);
    syncs.drop(api.agent.id);
    await syncs.get(api.agent.id, t1);
    await syncs.get(api.agent.id, t2);
    expect(api.syncCalls).toBe(4);
  });

  it("throws ApiRefused(401) after revoke and drops the cache", async () => {
    const syncs = new SyncCache({ ttlMs: 60_000, api: client() });
    const t1 = await api.issueToken();
    await syncs.get(api.agent.id, t1);
    api.revoke();
    const e = await syncs.get(api.agent.id, await api.issueToken()).catch((x: unknown) => x);
    expect(e).toBeInstanceOf(ApiRefused);
    expect((e as ApiRefused).status).toBe(401);
    // Dropped: the first token's entry is gone too, so this goes back to the API.
    await expect(syncs.get(api.agent.id, t1)).rejects.toBeInstanceOf(ApiRefused);
    expect(api.syncCalls).toBe(1);
  });

  it("an expired agent is ApiRefused(403, agent_expired)", async () => {
    api.expire();
    const e = await client().sync(await api.issueToken()).catch((x: unknown) => x);
    expect(e).toMatchObject({ status: 403, code: "agent_expired" });
  });
});

describe("apiClient", () => {
  it("exchanges a static token and posts events", async () => {
    const c = client();
    const { accessToken, expiresIn } = await c.exchangeStatic(api.staticToken);
    expect(expiresIn).toBe(900);
    await c.events(accessToken, [{ at: new Date().toISOString(), action: "use", host: "api.stripe.com", method: "GET" }]);
    expect(api.events).toHaveLength(1);
    expect(c.jwksUrl.href).toBe(`${api.url}/api/v1/.well-known/jwks.json`);
  });

  it("a bad static token is ApiRefused(401) and the error never carries it", async () => {
    const bad = `${api.staticToken}x`;
    const e = await client().exchangeStatic(bad).catch((x: unknown) => x);
    expect(e).toMatchObject({ status: 401, code: "invalid_grant" });
    expect(String((e as Error).message)).not.toContain(bad);
  });
});
