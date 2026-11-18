import { describe, expect, it } from "vitest";
import {
  validateAgentPolicy, agentSecretOf, basicUsername, defaultSecretRef, agentKeyMessage, agentPrivateKeyAad,
  generateIdentityKeyPair, gatewayKeyId, signAgentKey, verifyAgentAttestation, b64url,
  personalAgentKeyMessage, personalAgentPrivateKeyAad, personalAgentRecordAad, signPersonalAgentKey, verifyPersonalAgentAttestation,
  verifyGatewayMessage, sealPersonalAgentRecordKey, openPersonalAgentRecordKey, generateKeyPair, randomBytes,
  normalizeRecordBody, encryptRecordBody, decryptRecordBody, aeadEncrypt, utf8, type RecordBody,
  sha256B64, agentDepositOwnerAad, agentDepositMessage, agentUpdateMessage, sealDepositKeyToOwner, openDepositKey,
} from "../src/index.js";

const ok = { v: 1, hosts: ["API.Stripe.com", "*.github.com:8443"], inject: { kind: "bearer" } };

describe("agent policy", () => {
  it("accepts and cleans a valid policy", () => {
    expect(validateAgentPolicy(ok, { type: "apiKey" }).hosts).toEqual(["api.stripe.com", "*.github.com:8443"]);
  });

  it("refuses bad policies", () => {
    for (const bad of [{ ...ok, extra: 1 }, { ...ok, hosts: [] }, { ...ok, hosts: ["10.0.0.5"] }, { ...ok, hosts: ["a.b:70000"] }, { ...ok, hosts: Array(33).fill("a.b") },
      { ...ok, inject: { kind: "header", name: "Host" } }, { ...ok, inject: { kind: "header", name: "X-Key", prefix: "a\r\n" } }, { ...ok, inject: { kind: "bearer", x: 1 } },
      { ...ok, paths: ["v1"] }, { ...ok, methods: ["TRACE"] }, { ...ok, secret: "data.nope" }, { ...ok, approval: "yes" },
      { ...ok, inject: { kind: "query", name: "a b" } }, null, "x"])
      expect(() => validateAgentPolicy(bad, { type: "apiKey" })).toThrow();
  });

  it("needs a secret ref", () => {
    expect(() => validateAgentPolicy(ok, { type: "note" })).toThrow(); // no default secret for a note
    expect(validateAgentPolicy({ ...ok, secret: "field:f1" }, { type: "note", fields: [{ id: "f1", label: "Key", kind: "secret", value: "x" }] }).secret).toBe("field:f1");
    expect(() => validateAgentPolicy({ ...ok, secret: "field:f2" }, { type: "note", fields: [{ id: "f1", label: "Key", kind: "secret", value: "x" }] })).toThrow();
    expect(defaultSecretRef("apiKey")).toBe("data.secret");
    expect(defaultSecretRef("login")).toBe("password");
    expect(defaultSecretRef("note")).toBeNull();
  });

  it("reads the secret and basic username", () => {
    const agentPolicy = validateAgentPolicy(ok, { type: "apiKey" });
    expect(agentSecretOf({ v: 2, type: "apiKey", title: "S", data: { secret: "sk_test_1" }, agentPolicy })).toBe("sk_test_1");
    expect(agentSecretOf({ v: 2, type: "apiKey", title: "S", agentPolicy })).toBeNull();
    expect(basicUsername({ v: 2, type: "apiKey", title: "S", data: { keyId: "kid" } })).toBe("kid");
    expect(basicUsername({ v: 2, type: "login", title: "S", username: "u" })).toBe("u");
  });
});

describe("env file references", () => {
  const body = { type: "envFile" as const, data: { content: "STRIPE_KEY=sk_live_1\nEMPTY=\n" } };
  const pol = (secret?: string) => ({ v: 1, hosts: ["api.stripe.com"], inject: { kind: "bearer" }, ...(secret ? { secret } : {}) });

  it("validates env:<KEY> against the file's keys; no default, no whole file", () => {
    expect(validateAgentPolicy(pol("env:STRIPE_KEY"), body).secret).toBe("env:STRIPE_KEY");
    for (const bad of [pol(), pol("env:NOPE"), pol("data.content"), pol("env:")]) expect(() => validateAgentPolicy(bad, body)).toThrow();
    expect(() => validateAgentPolicy(pol("env:STRIPE_KEY"), { type: "apiKey" })).toThrow();
    expect(defaultSecretRef("envFile")).toBeNull();
  });

  it("reads the entry's value; an empty one is null", () => {
    expect(agentSecretOf({ ...body, title: "T", agentPolicy: pol("env:STRIPE_KEY") as RecordBody["agentPolicy"] })).toBe("sk_live_1");
    expect(agentSecretOf({ ...body, title: "T", agentPolicy: pol("env:EMPTY") as RecordBody["agentPolicy"] })).toBeNull();
  });

  it("a write that drops the policy's key is refused; a stored one reads without the policy", async () => {
    const stale = { v: 2 as const, type: "envFile" as const, title: "T", data: { content: "OTHER=1" }, agentPolicy: pol("env:STRIPE_KEY") as RecordBody["agentPolicy"] };
    expect(() => normalizeRecordBody(stale)).toThrow();
    const ok = { ...stale, data: body.data };
    const id = "r1", rk = randomBytes(32);
    expect(await decryptRecordBody(id, await encryptRecordBody(id, ok, rk), rk)).toEqual({ ...ok, agentPolicy: pol("env:STRIPE_KEY") }); // normalize is a fixpoint
    const enc = await aeadEncrypt(rk, utf8.encode(JSON.stringify(stale)), `record-body:${id}`);
    const read = await decryptRecordBody(id, enc, rk);
    expect(read).toEqual({ v: 2, type: "envFile", title: "T", data: { content: "OTHER=1" } });
  });
});

describe("agent attestation", () => {
  it("signs and verifies, and refuses tampering", async () => {
    const id = await generateIdentityKeyPair(); const keyId = await gatewayKeyId(id.publicKey);
    expect(keyId).toHaveLength(16);
    const ids = { orgId: "o", agentId: "a", publicKey: "pub" };
    const att = await signAgentKey(id.privateKey, keyId, ids);
    expect(att.startsWith(`g1.${keyId}.`)).toBe(true);
    const identity = { keyId, publicKey: b64url.encode(id.publicKey) };
    expect(await verifyAgentAttestation(att, ids, identity)).toBe(true);
    expect(await verifyAgentAttestation(att, { ...ids, publicKey: "other" }, identity)).toBe(false);
    expect(await verifyAgentAttestation(att, { ...ids, orgId: "p" }, identity)).toBe(false);
    expect(await verifyAgentAttestation(att.replace(keyId, "x".repeat(16)), ids, identity)).toBe(false);
    expect(await verifyAgentAttestation("garbage", ids, identity)).toBe(false);
    const other = await generateIdentityKeyPair();
    expect(await verifyAgentAttestation(att, ids, { keyId, publicKey: b64url.encode(other.publicKey) })).toBe(false);
  });

  it("builds the messages", () => {
    expect(agentKeyMessage("o", "a", "p")).toBe("agent-key:o:a:p");
    expect(agentPrivateKeyAad("o", "a", "p")).toBe("agent-private-key:o:a:p");
  });
});

describe("personal agents", () => {
  it("binds the attestation to the owner and seals per item", async () => {
    const id = await generateIdentityKeyPair(); const keyId = await gatewayKeyId(id.publicKey);
    const identity = { keyId, publicKey: b64url.encode(id.publicKey) };
    const i = { ownerUserId: "u", ownerPublicKey: "opk", agentId: "a", publicKey: "pub" };
    expect(personalAgentKeyMessage(i)).toBe("personal-agent-key:u:opk:a:pub");
    expect(personalAgentPrivateKeyAad(i)).toBe("agent-private-key:personal:u:opk:a:pub");
    expect(personalAgentRecordAad("u", "a", "r")).toBe("personal-agent-record:u:a:r");
    const att = await signPersonalAgentKey(id.privateKey, keyId, i);
    expect(att.startsWith(`g1.${keyId}.`)).toBe(true);
    expect(await verifyPersonalAgentAttestation(att, i, identity)).toBe(true);
    expect(await verifyPersonalAgentAttestation(att, { ...i, ownerPublicKey: "other" }, identity)).toBe(false);
    expect(await verifyAgentAttestation(att, { orgId: "u", agentId: "a", publicKey: "pub" }, identity)).toBe(false);
    expect(await verifyGatewayMessage(att, "d1", personalAgentKeyMessage(i), identity)).toBe(false);
    expect(await verifyGatewayMessage("g1.x", "g1" as never, "m", { keyId, publicKey: "!!" })).toBe(false);
    const kp = await generateKeyPair(); const rk = randomBytes(32);
    const ids = { ownerUserId: "u", agentId: "a", recordId: "r" };
    const s = await sealPersonalAgentRecordKey(rk, ids, kp.publicKey);
    expect(await openPersonalAgentRecordKey(s, ids, kp)).toEqual(rk);
    await expect(openPersonalAgentRecordKey(s, { ...ids, recordId: "r2" }, kp)).rejects.toThrow();
  });
});

describe("agent deposits", () => {
  it("builds the messages and the hash", async () => {
    expect(agentDepositMessage({ ownerUserId: "u", ownerPublicKey: "opk", agentId: "a", id: "d", revision: 2, encBodyHash: "h" })).toBe("agent-deposit:u:opk:a:d:2:h");
    expect(agentUpdateMessage({ ownerUserId: "u", agentId: "a", id: "d", revision: 2, encBodyHash: "h" })).toBe("agent-update:u:a:d:2:h");
    expect(agentDepositOwnerAad("u", "d")).toBe("agent-deposit-owner:u:d");
    expect(await sha256B64("")).toBe("47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU");
  });

  it("seals the deposit key to the owner and opens it only for that id", async () => {
    const kp = await generateKeyPair(); const rk = randomBytes(32);
    const s = await sealDepositKeyToOwner(rk, { ownerUserId: "u", id: "d" }, kp.publicKey);
    expect(await openDepositKey(s, { ownerUserId: "u", id: "d" }, kp)).toEqual(rk);
    await expect(openDepositKey(s, { ownerUserId: "u", id: "d2" }, kp)).rejects.toThrow();
  });
});
