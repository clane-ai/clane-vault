import { describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";
import { CryptoError } from "@clane-vault/crypto";
import { EnvelopeError, openWithKek, unwrapAgentKey, unwrapPersonalAgentKey, wrapAgentKey, wrapPersonalAgentKey } from "../src/envelope.js";
import type { KekContext } from "../src/kek.js";
import { fileKek } from "./helpers.js";

const ids = { orgId: "org1", agentId: "ag1", publicKey: "pk" };

describe("k1 envelope", () => {
  it("wraps an agent key and opens it with the same ids", async () => {
    const kek = await fileKek();
    const key = new Uint8Array(randomBytes(32));
    const env = await wrapAgentKey(kek, ids, key);
    expect(env).toMatch(/^k1\.file-[A-Za-z0-9_-]{12}\.[A-Za-z0-9_-]+\.v1\.[A-Za-z0-9_-]+$/);
    expect(await unwrapAgentKey(kek, ids, env)).toEqual(key);
  });
  it("fails on a wrong public key (AAD) and on another KEK", async () => {
    const kek = await fileKek();
    const env = await wrapAgentKey(kek, ids, new Uint8Array(randomBytes(32)));
    await expect(unwrapAgentKey(kek, { ...ids, publicKey: "other" }, env)).rejects.toBeInstanceOf(CryptoError);
    const err = await unwrapAgentKey(await fileKek(), ids, env).catch((e) => e);
    expect(err).toBeInstanceOf(EnvelopeError);
    expect(err.code).toBe("kek_mismatch");
  });
  it("rejects a malformed envelope", async () => {
    const kek = await fileKek();
    await expect(unwrapAgentKey(kek, ids, "k2.x.y.v1.z")).rejects.toMatchObject({ code: "bad_envelope" });
    await expect(unwrapAgentKey(kek, ids, `k1.${kek.id}.y`)).rejects.toMatchObject({ code: "bad_envelope" });
  });
});

describe("k2 envelope (personal agents)", () => {
  const pids = { ownerUserId: "u1", ownerPublicKey: "opk", agentId: "ag1", publicKey: "pk" };
  it("wraps under k2 and opens only with the same owner key", async () => {
    const real = await fileKek();
    const ctxs: KekContext[] = [];
    const kek = { id: real.id, wrap: (d: Uint8Array, c: KekContext) => { ctxs.push(c); return real.wrap(d, c); }, unwrap: (w: string, c: KekContext) => { ctxs.push(c); return real.unwrap(w, c); } };
    const key = new Uint8Array(randomBytes(32));
    const env = await wrapPersonalAgentKey(kek, pids, key);
    expect(env).toMatch(/^k2\.file-[A-Za-z0-9_-]{12}\.[A-Za-z0-9_-]+\.v1\.[A-Za-z0-9_-]+$/);
    expect(await unwrapPersonalAgentKey(kek, pids, env)).toEqual(key);
    await expect(unwrapPersonalAgentKey(kek, { ...pids, ownerPublicKey: "other" }, env)).rejects.toBeInstanceOf(CryptoError);
    expect(ctxs.length).toBeGreaterThan(0);
    for (const c of ctxs) expect(c).toEqual({ agentId: "ag1", ownerUserId: "u1" });
  });
  it("openWithKek without the k2 tag refuses a k2 envelope, and a k1 one with it", async () => {
    const kek = await fileKek();
    const env = await wrapPersonalAgentKey(kek, pids, new Uint8Array(randomBytes(32)));
    await expect(openWithKek(kek, { agentId: "ag1", ownerUserId: "u1" }, "x", env)).rejects.toMatchObject({ code: "bad_envelope" });
    const k1 = await wrapAgentKey(kek, ids, new Uint8Array(randomBytes(32)));
    await expect(openWithKek(kek, { orgId: "org1", agentId: "ag1" }, "x", k1, "k2")).rejects.toMatchObject({ code: "bad_envelope" });
  });
});
