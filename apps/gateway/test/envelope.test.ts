import { describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";
import { CryptoError } from "@clane-vault/crypto";
import { EnvelopeError, unwrapAgentKey, wrapAgentKey } from "../src/envelope.js";
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
