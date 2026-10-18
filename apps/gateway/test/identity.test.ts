import { describe, expect, it } from "vitest";
import { join } from "node:path";
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
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
    expect(readdirSync(dir).filter((n) => n.endsWith(".tmp"))).toEqual([]);
  });
  it("refuses a torn or empty file and leaves it in place", async () => {
    const dir = tempDir();
    const kek = await fileKek(dir);
    const file = join(dir, "identity.json");
    const whole = JSON.stringify({ v: 1, publicKey: (await loadOrCreateIdentity(join(dir, "other.json"), kek)).publicKey, sealed: "k1.x" });
    for (const torn of [whole.slice(0, 20), ""]) {
      writeFileSync(file, torn);
      await expect(loadOrCreateIdentity(file, kek)).rejects.toBeInstanceOf(EnvelopeError);
      expect(readFileSync(file, "utf8")).toBe(torn);
    }
  });
  it("refuses a file sealed under another KEK", async () => {
    const dir = tempDir();
    const file = join(dir, "identity.json");
    await loadOrCreateIdentity(file, await fileKek(dir, "k1"));
    await expect(loadOrCreateIdentity(file, await fileKek(dir, "k2"))).rejects.toBeInstanceOf(EnvelopeError);
  });
});
