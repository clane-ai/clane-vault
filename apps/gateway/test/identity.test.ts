import { describe, expect, it } from "vitest";
import { join } from "node:path";
import { readFileSync } from "node:fs";
import { verifyAgentAttestation } from "@clane-vault/crypto";
import { loadOrCreateIdentity } from "../src/identity.js";
import { EnvelopeError } from "../src/envelope.js";
import { fileKek, tempDir } from "./helpers.js";

describe("gateway identity", () => {
  it("is created once, then reloaded, and signs verifiable attestations", async () => {
    const dir = tempDir();
    const file = join(dir, "identity.json");
    const kek = await fileKek(dir);
    const a = await loadOrCreateIdentity(file, kek);
    expect(JSON.parse(readFileSync(file, "utf8"))).toMatchObject({ v: 1, publicKey: a.publicKey });
    const b = await loadOrCreateIdentity(file, kek);
    expect([b.keyId, b.publicKey]).toEqual([a.keyId, a.publicKey]);
    const ids = { orgId: "o", agentId: "a", publicKey: "pk" };
    expect(await verifyAgentAttestation(await b.sign(ids), ids, a)).toBe(true);
  });
  it("gives two replicas starting at once the same identity", async () => {
    const dir = tempDir();
    const kek = await fileKek(dir);
    const [a, b] = await Promise.all([loadOrCreateIdentity(join(dir, "id.json"), kek), loadOrCreateIdentity(join(dir, "id.json"), kek)]);
    expect(a.publicKey).toBe(b.publicKey);
  });
  it("refuses a file sealed under another KEK", async () => {
    const dir = tempDir();
    const file = join(dir, "identity.json");
    await loadOrCreateIdentity(file, await fileKek(dir, "k1"));
    await expect(loadOrCreateIdentity(file, await fileKek(dir, "k2"))).rejects.toBeInstanceOf(EnvelopeError);
  });
});
