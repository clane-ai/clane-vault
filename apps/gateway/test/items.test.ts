import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { MembershipKeys, RecordBody } from "@clane-vault/crypto";
import { apiClient, type AgentSync } from "../src/apiClient.js";
import { AgentKeyCache } from "../src/keys.js";
import { listItems, withItem } from "../src/items.js";
import { HeldSecrets, type Logger } from "../src/log.js";
import { startFakeApi } from "./fakeApi.js";
import { fileKek } from "./helpers.js";

const apiKey = (title: string, secret: string, withPolicy = true): RecordBody => ({
  v: 2, type: "apiKey", title, data: { secret, keyId: "kid" }, notes: `notes-${secret}`,
  ...(withPolicy ? { agentPolicy: { v: 1, hosts: ["api.stripe.com"], inject: { kind: "bearer" }, methods: ["GET"] } } : {}),
});

let api: Awaited<ReturnType<typeof startFakeApi>>;
let sync: AgentSync, keys: MembershipKeys, cache: AgentKeyCache;
const ids: Record<string, string> = {};
const SECRETS = ["sk_pay_1", "sk_ops_2", "ghp_3", "sk_pay_4", "sk_nopol_5"];

beforeAll(async () => {
  const kek = await fileKek();
  api = await startFakeApi({ kek });
  ids.pay = await api.addFolderRecord("Payments", apiKey("Stripe", "sk_pay_1"));
  ids.ops = await api.addFolderRecord("Ops", apiKey("Stripe", "sk_ops_2"));
  ids.gh = await api.addSharedRecord({ v: 2, type: "login", title: "GitHub", username: "bot", password: "ghp_3",
    agentPolicy: { v: 1, hosts: ["api.github.com"], inject: { kind: "basic" } } });
  ids.pay2 = await api.addFolderRecord("Payments", apiKey("Stripe", "sk_pay_4"));
  ids.nopol = await api.addFolderRecord("Ops", apiKey("Legacy", "sk_nopol_5", false));
  sync = await apiClient({ apiUrl: api.url, apiToken: api.token }).sync(await api.issueToken());
  cache = new AgentKeyCache({ ttlMs: 60_000, kek });
  keys = await cache.open(api.agent.id, sync);
});
afterAll(async () => { cache.release(api.agent.id, keys); await api.close(); });

describe("listItems", () => {
  it("names items by folder and title, and shared/ for direct shares", async () => {
    const items = await listItems(sync, keys);
    const byId = Object.fromEntries(items.map((i) => [i.recordId, i.handle]));
    expect(byId[ids.ops!]).toBe("ops/stripe");
    expect(byId[ids.gh!]).toBe("shared/github");
    expect(items.find((i) => i.recordId === ids.gh)).toMatchObject({ title: "GitHub", type: "login", hosts: ["api.github.com"], inject: { kind: "basic" }, approval: false });
  });

  it("numbers collisions in record-id order, the same on every call", async () => {
    const [lo, hi] = [ids.pay!, ids.pay2!].sort();
    const a = await listItems(sync, keys), b = await listItems(sync, keys);
    for (const items of [a, b]) {
      const byId = Object.fromEntries(items.map((i) => [i.recordId, i.handle]));
      expect(byId[lo!]).toBe("payments/stripe");
      expect(byId[hi!]).toBe("payments/stripe-2");
    }
    expect(a).toEqual(b);
  });

  it("lists a record without a policy with no hosts and inject none", async () => {
    const items = await listItems(sync, keys);
    expect(items.find((i) => i.recordId === ids.nopol)).toMatchObject({ handle: "ops/legacy", hosts: [], inject: { kind: "none" } });
  });

  it("contains no secret value", async () => {
    const json = JSON.stringify(await listItems(sync, keys));
    for (const s of SECRETS) expect(json).not.toContain(s);
    expect(json).not.toContain("notes-");
  });

  it("skips a record that won't open and logs only its id and reason", async () => {
    const lines: Record<string, unknown>[] = [];
    const log: Logger = { info: (f) => lines.push(f), error: (f) => lines.push(f) };
    const bad = { ...sync, records: sync.records.map((r) => (r.id === ids.ops ? { ...r, encBody: r.encBody.slice(0, -8) + "AAAAAAAA" } : r)) };
    const items = await listItems(bad, keys, log);
    expect(items.map((i) => i.recordId)).not.toContain(ids.ops);
    expect(items).toHaveLength(4);
    expect(lines).toEqual([{ event: "item_skipped", recordId: ids.ops, reason: expect.any(String) }]);
  });

  it("throws when no record opens at all (a dead key)", async () => {
    const dead = { ...keys, privateKey: new Uint8Array(keys.privateKey.length) };
    await expect(listItems(sync, dead)).rejects.toThrow("none of the agent's items could be opened");
  });

  it("leaves out trashed records", async () => {
    const trashed = { ...sync, records: sync.records.map((r) => (r.id === ids.ops ? { ...r, deletedAt: new Date().toISOString() } : r)) };
    const items = await listItems(trashed, keys);
    expect(items.map((i) => i.recordId)).not.toContain(ids.ops);
    const held = new HeldSecrets();
    expect(await withItem(trashed, keys, "ops/stripe", held, async () => "used")).toEqual({ error: "refused", reason: "not_found" });
    expect(await withItem(trashed, keys, ids.ops!, held, async () => "used")).toEqual({ error: "refused", reason: "not_found" });
  });
});

describe("withItem", () => {
  it("hands f the secret, held while f runs and released after", async () => {
    const held = new HeldSecrets();
    const [lo] = [ids.pay!, ids.pay2!].sort();
    const seen = await withItem(sync, keys, "payments/stripe", held, async (x) => {
      expect(held.redact(x.secret)).not.toBe(x.secret);
      return { secret: x.secret, recordId: x.recordId, username: x.username, hosts: x.policy.hosts };
    });
    expect(seen).toEqual({ secret: lo === ids.pay ? "sk_pay_1" : "sk_pay_4", recordId: lo, username: "kid", hosts: ["api.stripe.com"] });
    expect(held.redact("sk_pay_1 sk_pay_4")).toBe("sk_pay_1 sk_pay_4");
  });

  it("matches a record id too, and releases when f throws", async () => {
    const held = new HeldSecrets();
    await expect(withItem(sync, keys, ids.gh!, held, async (x) => { throw new Error(`boom ${x.username}`); })).rejects.toThrow("boom bot");
    expect(held.redact("ghp_3")).toBe("ghp_3");
  });

  it("refuses no_policy and not_found", async () => {
    const held = new HeldSecrets();
    let called = false;
    const f = async () => { called = true; return "used"; };
    expect(await withItem(sync, keys, "ops/legacy", held, f)).toEqual({ error: "refused", reason: "no_policy" });
    expect(await withItem(sync, keys, "ops/nope", held, f)).toEqual({ error: "refused", reason: "not_found" });
    expect(await withItem(sync, keys, "nope", held, f)).toEqual({ error: "refused", reason: "not_found" });
    expect(called).toBe(false);
  });
});
