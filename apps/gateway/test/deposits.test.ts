import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  agentDepositMessage, agentUpdateMessage, CryptoError, decryptRecordBody, openDepositKey, openPersonalAgentRecordKey, sha256B64, verifyGatewayMessage,
  type MembershipKeys, type RecordBody,
} from "@clane-vault/crypto";
import { apiClient, type PersonalAgentSync } from "../src/apiClient.js";
import { buildDeposit, buildUpdate, ENV_HOLD_MIN, InvalidInput } from "../src/deposits.js";
import { loadOrCreateIdentity, type Identity } from "../src/identity.js";
import { AgentKeyCache } from "../src/keys.js";
import { HeldSecrets } from "../src/log.js";
import { startFakeApi } from "./fakeApi.js";
import { fileKek, tempDir } from "./helpers.js";

let api: Awaited<ReturnType<typeof startFakeApi>>;
let identity: Identity, cache: AgentKeyCache, keys: MembershipKeys, sync: PersonalAgentSync;
const resync = async () => {
  sync = await apiClient({ apiUrl: api.url, apiToken: api.token }).sync(await api.personal.token()) as PersonalAgentSync;
  keys = await cache.open(api.personal.agentId, sync);
};
beforeEach(async () => {
  const kek = await fileKek();
  api = await startFakeApi({ kek });
  identity = await loadOrCreateIdentity(join(tempDir(), "identity.json"), kek);
  cache = new AgentKeyCache({ ttlMs: 0, kek });
  await resync();
});
afterEach(() => api.close());

const ids = () => ({ ownerUserId: api.personal.ownerId, agentId: api.personal.agentId });

describe("buildDeposit", () => {
  it("the owner opens it, the agent opens it, and the d1 signature at revision 1 verifies", async () => {
    const held = new HeldSecrets();
    const d = await buildDeposit(sync, keys, identity, { title: "Stripe", type: "apiKey", fields: { data: { secret: "sk_dep_1", keyId: "kid" } },
      custom_fields: [{ label: "Pin", kind: "secret", value: "4242" }], agent_use: { hosts: ["api.stripe.com"], inject: { kind: "bearer" } } }, held);
    expect(d.type).toBe("item");
    const owner = await openDepositKey(d.ownerSealedKey, { ownerUserId: api.personal.ownerId, id: d.id }, api.personal.ownerKeys);
    const body = await decryptRecordBody(d.id, d.encBody, owner);
    expect(body).toMatchObject({ title: "Stripe", type: "apiKey", data: { secret: "sk_dep_1", keyId: "kid" }, fields: [{ label: "Pin", kind: "secret", value: "4242" }],
      agentPolicy: { v: 1, hosts: ["api.stripe.com"], inject: { kind: "bearer" } } });
    const agent = await openPersonalAgentRecordKey(d.agentSealedKey, { ...ids(), recordId: d.id }, keys);
    expect(agent).toEqual(owner);
    expect(await verifyGatewayMessage(d.signature, "d1", agentDepositMessage({ ...ids(), ownerPublicKey: sync.owner.publicKey, id: d.id, revision: 1,
      encBodyHash: await sha256B64(d.encBody) }), identity)).toBe(true);
    expect(held.redact("sk_dep_1 4242")).toBe("sk_dep_1 4242"); // released on return
  });

  it("holds the values while it runs", async () => {
    const held = new HeldSecrets();
    const sign = identity.signMessage;
    let during = "";
    const spy: Identity = { ...identity, signMessage: (t, m) => { during = held.redact("pw_held_1 sec_held_2 cf_held_3"); return sign(t, m); } };
    await buildDeposit(sync, keys, spy, { title: "S", type: "server", fields: { password: "pw_held_1", data: { hostname: "sec_held_2" } },
      custom_fields: [{ label: "x", kind: "text", value: "cf_held_3" }] }, held);
    expect(during).not.toMatch(/pw_held_1|sec_held_2|cf_held_3/);
  });

  it("a body the vault would refuse throws InvalidInput", async () => {
    const held = new HeldSecrets();
    await expect(buildDeposit(sync, keys, identity, { title: "Big", type: "note", fields: { notes: "x".repeat(60 * 1024) } }, held)).rejects.toBeInstanceOf(InvalidInput);
    await expect(buildDeposit(sync, keys, identity, { title: "Bad", type: "note", fields: { password: "p" } }, held)).rejects.toBeInstanceOf(InvalidInput);
    await expect(buildDeposit(sync, keys, identity, { title: "Bad", type: "note", agent_use: { hosts: ["a.test"], inject: { kind: "bearer" } } }, held))
      .rejects.toBeInstanceOf(InvalidInput);
  });
});

describe("buildUpdate", () => {
  const before: RecordBody = { v: 2, type: "login", title: "GitHub", username: "bot", password: "old_pw", url: "https://github.com", notes: "n",
    agentPolicy: { v: 1, hosts: ["api.github.com"], inject: { kind: "basic" }, methods: ["GET", "POST"], paths: ["/repos"], approval: true } };

  it("on a record: only the set fields change, agentPolicy is byte for byte the same, signed u1 at revision + 1", async () => {
    const id = await api.personal.addRecord(before, undefined, true);
    await resync();
    const held = new HeldSecrets();
    const u = await buildUpdate(sync, keys, identity, { kind: "record", id, revision: 1 }, { password: "new_pw" }, held);
    expect(u.revision).toBe(1); // what the API is sent: the current revision; the signature names revision + 1
    const rec = sync.records.find((r) => r.id === id)!;
    const rk = await openPersonalAgentRecordKey(rec.wrappedRecordKey, { ...ids(), recordId: id }, keys);
    const was = await decryptRecordBody(id, rec.encBody, rk), after = await decryptRecordBody(id, u.encBody, rk);
    expect(JSON.stringify(after.agentPolicy)).toBe(JSON.stringify(was.agentPolicy));
    expect(after).toEqual({ ...was, password: "new_pw" });
    expect(await verifyGatewayMessage(u.signature, "u1", agentUpdateMessage({ ...ids(), id, revision: 2, encBodyHash: await sha256B64(u.encBody) }), identity)).toBe(true);
    expect(held.redact("old_pw new_pw")).toBe("old_pw new_pw");
  });

  it("on a deposit: data keys merge, signed d1 at revision + 1, and the owner still opens it", async () => {
    const held = new HeldSecrets();
    const d = await buildDeposit(sync, keys, identity, { title: "K", type: "apiKey", fields: { data: { secret: "s1", keyId: "k" } } }, held);
    const dep = { id: d.id, encBody: d.encBody, revision: 1, agentSealedKey: d.agentSealedKey, signature: d.signature };
    const s2 = { ...sync, deposits: [dep] };
    // Not this gateway's d1 for that revision: refused before anything is opened.
    await expect(buildUpdate({ ...sync, deposits: [{ ...dep, revision: 3 }] }, keys, identity, { kind: "deposit", id: d.id, revision: 3 }, { password: "x" }, held))
      .rejects.toBeInstanceOf(CryptoError);
    const u = await buildUpdate(s2, keys, identity, { kind: "deposit", id: d.id, revision: 1 }, { data: { secret: "s2" } }, held);
    const owner = await openDepositKey(d.ownerSealedKey, { ownerUserId: api.personal.ownerId, id: d.id }, api.personal.ownerKeys);
    expect((await decryptRecordBody(d.id, u.encBody, owner)).data).toEqual({ secret: "s2", keyId: "k" });
    expect(await verifyGatewayMessage(u.signature, "d1", agentDepositMessage({ ...ids(), ownerPublicKey: sync.owner.publicKey, id: d.id, revision: 2,
      encBodyHash: await sha256B64(u.encBody) }), identity)).toBe(true);
  });

  it("a set the vault would refuse throws InvalidInput", async () => {
    const id = await api.personal.addRecord(before, undefined, true);
    await resync();
    await expect(buildUpdate(sync, keys, identity, { kind: "record", id, revision: 1 }, { data: { secret: "x" } }, new HeldSecrets())).rejects.toBeInstanceOf(InvalidInput);
  });
});

describe("env files", () => {
  it("buildDeposit and buildUpdate hold the whole text and every entry value of ENV_HOLD_MIN or more, old and new", async () => {
    expect(ENV_HOLD_MIN).toBe(8);
    const held = new HeldSecrets();
    const sign = identity.signMessage;
    const seen: string[] = [];
    const content = "LONG=long_value_1\nSHORT=abc\n";
    const probe = `v1=long_value_1 short=abc v2=long_value_2 file=${content}`;
    const spy: Identity = { ...identity, signMessage: (t, m) => { seen.push(held.redact(probe)); return sign(t, m); } };
    const d = await buildDeposit(sync, keys, spy, { title: "E", type: "envFile", fields: { data: { content } } }, held);
    expect(seen[0]).not.toContain("long_value_1");
    expect(seen[0]).not.toContain(content);
    expect(seen[0]).toContain("short=abc"); // shorter than ENV_HOLD_MIN: not held
    const s2 = { ...sync, deposits: [{ id: d.id, encBody: d.encBody, revision: 1, agentSealedKey: d.agentSealedKey, signature: d.signature }] };
    await buildUpdate(s2, keys, spy, { kind: "deposit", id: d.id, revision: 1 }, { env: { NEW: "long_value_2" } }, held);
    expect(seen[1]).not.toMatch(/long_value_1|long_value_2/);
    expect(held.redact(probe)).toBe(probe);
  });
});
