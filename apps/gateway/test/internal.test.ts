import { afterEach, describe, expect, it, vi } from "vitest";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { b64url, generateKeyPair, publicKeyFromPrivateKey, verifyAgentAttestation, verifyPersonalAgentAttestation } from "@clane-vault/crypto";
import { createGateway } from "../src/app.js";
import type { GatewayConfig } from "../src/config.js";
import { unwrapAgentKey, unwrapPersonalAgentKey } from "../src/envelope.js";
import { loadOrCreateIdentity } from "../src/identity.js";
import { createLogger, HeldSecrets } from "../src/log.js";
import { fileKek, tempDir } from "./helpers.js";

const TOKEN = "t".repeat(40);
const cfg: GatewayConfig = {
  apiUrl: "http://localhost:3001", apiToken: TOKEN, publicUrl: "http://localhost:3002/mcp", kek: "file:x", identityKeyFile: "x",
  cacheTtlSeconds: 60, agentRatePerMinute: 60, maxResponseBytes: 4194304, upstreamTimeoutMs: 30000, allowPrivateCidrs: [],
  port: 0, internalPort: 0, internalHost: "127.0.0.1", trustProxy: 0, writePerHour: 20,
};
const closers: (() => Promise<void>)[] = [];
afterEach(async () => { await Promise.all(closers.splice(0).map((c) => c())); });

const listen = (s: Server) => new Promise<string>((r) => s.listen(0, "127.0.0.1", () => r(`http://127.0.0.1:${(s.address() as AddressInfo).port}`)));

async function start() {
  const dir = tempDir();
  const kek = await fileKek(dir);
  const identity = await loadOrCreateIdentity(join(dir, "identity.json"), kek);
  const held = new HeldSecrets();
  const lines: string[] = [];
  const gw = await createGateway(cfg, { kek, identity, held, log: createLogger(held, (l) => lines.push(l)) });
  closers.push(gw.close);
  return { gw, kek, identity, lines, pub: await listen(gw.publicServer), int: await listen(gw.internalServer) };
}
const auth = { "x-gateway-token": TOKEN, "content-type": "application/json" };
const B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
/** The same 32 bytes with a nonzero padding bit in the last character: it decodes, but re-encodes to another string. */
const nonCanonical = (k: string) => k.slice(0, -1) + B64URL[B64URL.indexOf(k.at(-1)!) | 1];

describe("internal routes", () => {
  it("POST /internal/agents needs the token", async () => {
    const { int } = await start();
    const body = JSON.stringify({ agentId: randomUUID(), orgId: randomUUID() });
    const none = await fetch(`${int}/internal/agents`, { method: "POST", body, headers: { "content-type": "application/json" } });
    expect(none.status).toBe(401);
    expect(await none.json()).toEqual({ error: "unauthorized" });
    const wrong = await fetch(`${int}/internal/agents`, { method: "POST", body, headers: { ...auth, "x-gateway-token": "x" + TOKEN.slice(1) } });
    expect(wrong.status).toBe(401);
  });
  it("POST /internal/agents mints an attested, KEK-wrapped key", async () => {
    const { int, kek, identity } = await start();
    const ids = { agentId: randomUUID(), orgId: randomUUID() };
    const res = await fetch(`${int}/internal/agents`, { method: "POST", body: JSON.stringify(ids), headers: auth });
    expect(res.status).toBe(200);
    const r = await res.json() as { publicKey: string; wrappedPrivateKey: string; kekId: string; attestation: string };
    expect(r.kekId).toBe(kek.id);
    expect(r.wrappedPrivateKey).toMatch(/^k1\.[^.]+\.[^.]+\.v1\./);
    expect(await verifyAgentAttestation(r.attestation, { ...ids, publicKey: r.publicKey }, identity)).toBe(true);
    const priv = await unwrapAgentKey(kek, { ...ids, publicKey: r.publicKey }, r.wrappedPrivateKey);
    expect(b64url.encode(await publicKeyFromPrivateKey(priv))).toBe(r.publicKey);
  });
  it("POST /internal/agents mints a k2 key bound to the owner's key for a personal agent", async () => {
    const { int, kek, identity } = await start();
    const owner = { agentId: randomUUID(), ownerUserId: randomUUID(), ownerPublicKey: b64url.encode((await generateKeyPair()).publicKey) };
    const res = await fetch(`${int}/internal/agents`, { method: "POST", body: JSON.stringify(owner), headers: auth });
    expect(res.status).toBe(200);
    const r = await res.json() as { publicKey: string; wrappedPrivateKey: string; kekId: string; attestation: string };
    expect(r.kekId).toBe(kek.id);
    expect(r.wrappedPrivateKey).toMatch(/^k2\.[^.]+\.[^.]+\.v1\./);
    const ids = { ...owner, publicKey: r.publicKey };
    expect(await verifyPersonalAgentAttestation(r.attestation, ids, identity)).toBe(true);
    expect(await verifyAgentAttestation(r.attestation, { orgId: owner.ownerUserId, agentId: owner.agentId, publicKey: r.publicKey }, identity)).toBe(false);
    const priv = await unwrapPersonalAgentKey(kek, ids, r.wrappedPrivateKey);
    expect(b64url.encode(await publicKeyFromPrivateKey(priv))).toBe(r.publicKey);
  });
  it("POST /internal/agents refuses a body naming both an org and an owner, extra keys, or a bad owner key", async () => {
    const { int } = await start();
    const opk = b64url.encode((await generateKeyPair()).publicKey);
    const agentId = randomUUID(), ownerUserId = randomUUID();
    for (const body of [{ agentId, orgId: randomUUID(), ownerUserId, ownerPublicKey: opk }, { agentId, orgId: randomUUID(), ownerUserId },
      { agentId, ownerUserId, ownerPublicKey: opk, extra: 1 }, { agentId, ownerUserId }, { agentId, ownerUserId, ownerPublicKey: "short" },
      { agentId, ownerUserId, ownerPublicKey: `${opk}AAAA` }, { agentId, ownerUserId, ownerPublicKey: nonCanonical(opk) }]) {
      const res = await fetch(`${int}/internal/agents`, { method: "POST", body: JSON.stringify(body), headers: auth });
      expect(res.status, JSON.stringify(body)).toBe(400);
    }
  });
  it("POST /internal/agents refuses a bad body", async () => {
    const { int } = await start();
    const bad = await fetch(`${int}/internal/agents`, { method: "POST", body: JSON.stringify({ agentId: "nope", orgId: randomUUID() }), headers: auth });
    expect(bad.status).toBe(400);
    expect((await fetch(`${int}/internal/agents`, { method: "POST", body: "{", headers: auth })).status).toBe(400);
  });
  it("GET /internal/health returns the identity", async () => {
    const { int, identity } = await start();
    const res = await fetch(`${int}/internal/health`, { headers: auth });
    expect(await res.json()).toEqual({ ok: true, identity: { keyId: identity.keyId, publicKey: identity.publicKey } });
    expect((await fetch(`${int}/internal/health`)).status).toBe(401);
  });
  it("DELETE /internal/agents/:id drops the agent's cached key", async () => {
    const { int, gw } = await start();
    const drop = vi.spyOn(gw.keys, "drop");
    const id = randomUUID();
    const res = await fetch(`${int}/internal/agents/${id}`, { method: "DELETE", headers: auth });
    expect(res.status).toBe(204);
    expect(drop).toHaveBeenCalledWith(id);
  });
  it("nothing on PORT answers /internal/*", async () => {
    const { pub } = await start();
    expect((await fetch(`${pub}/internal/health`, { headers: auth })).status).toBe(404);
  });
});
