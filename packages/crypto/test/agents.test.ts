import { describe, expect, it } from "vitest";
import {
  validateAgentPolicy, agentSecretOf, basicUsername, defaultSecretRef, agentKeyMessage, agentPrivateKeyAad,
  generateIdentityKeyPair, gatewayKeyId, signAgentKey, verifyAgentAttestation, b64url,
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
