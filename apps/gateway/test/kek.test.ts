import { describe, expect, it, vi } from "vitest";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { loadKek, type AwsKmsLike } from "../src/kek.js";
import { fileKek, tempDir } from "./helpers.js";

const dek = () => new Uint8Array(randomBytes(32));
const ctx = { orgId: "o", agentId: "a" };

describe("file KEK", () => {
  it("round-trips a DEK; another key or ctx fails; output has no dot", async () => {
    const kek = await fileKek();
    const d = dek();
    const w = await kek.wrap(d, ctx);
    expect(w).not.toContain(".");
    expect(kek.id).toMatch(/^file-[A-Za-z0-9_-]{12}$/);
    expect(await kek.unwrap(w, ctx)).toEqual(d);
    await expect((await fileKek()).unwrap(w, ctx)).rejects.toThrow();
    await expect(kek.unwrap(w, { orgId: "o", agentId: "b" })).rejects.toThrow();
  });
  it("refuses a key file that is not 32 bytes", async () => {
    const p = join(tempDir(), "short");
    writeFileSync(p, randomBytes(31));
    await expect(loadKek(`file:${p}`)).rejects.toThrow("GATEWAY_KEK file must hold exactly 32 bytes");
  });
  it("refuses an unknown prefix", async () => {
    await expect(loadKek("vault:x")).rejects.toThrow();
  });
});

describe("aws-kms KEK", () => {
  it("round-trips and passes the encryption context", async () => {
    const store = new Map<string, Uint8Array>();
    const aws: AwsKmsLike = {
      encrypt: vi.fn(async (i) => {
        const blob = new Uint8Array(randomBytes(40));
        store.set(Buffer.from(blob).toString("hex"), i.Plaintext.slice());
        return { CiphertextBlob: blob };
      }),
      decrypt: vi.fn(async (i) => ({ Plaintext: store.get(Buffer.from(i.CiphertextBlob).toString("hex")) })),
    };
    const kek = await loadKek("aws-kms:arn:aws:kms:eu-west-1:1:key/k", { aws });
    expect(kek.id).toMatch(/^aws-[A-Za-z0-9_-]{12}$/);
    const d = dek();
    const w = await kek.wrap(d, ctx);
    expect(w).not.toContain(".");
    expect(await kek.unwrap(w, ctx)).toEqual(d);
    expect(aws.encrypt).toHaveBeenCalledWith(expect.objectContaining({ KeyId: "arn:aws:kms:eu-west-1:1:key/k", EncryptionContext: { orgId: "o", agentId: "a" } }));
    expect(aws.decrypt).toHaveBeenCalledWith(expect.objectContaining({ EncryptionContext: { orgId: "o", agentId: "a" } }));
  });
});

describe("gcp-kms KEK", () => {
  it("round-trips over REST with the ctx as AAD", async () => {
    const urls: string[] = [];
    const fetch = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      const u = String(url);
      urls.push(u);
      if (u.includes("metadata")) return Response.json({ access_token: "t", expires_in: 3600 });
      expect(new Headers(init?.headers).get("authorization")).toBe("Bearer t");
      const b = JSON.parse(String(init?.body));
      expect(Buffer.from(b.additionalAuthenticatedData, "base64").toString()).toBe("agentId=a;orgId=o");
      // Fake KMS: the "ciphertext" is the reversed plaintext.
      if (u.endsWith(":encrypt")) return Response.json({ ciphertext: Buffer.from(b.plaintext, "base64").reverse().toString("base64") });
      return Response.json({ plaintext: Buffer.from(b.ciphertext, "base64").reverse().toString("base64") });
    }) as unknown as typeof globalThis.fetch;
    const res = "projects/p/locations/global/keyRings/r/cryptoKeys/k";
    const kek = await loadKek(`gcp-kms:${res}`, { fetch });
    expect(kek.id).toMatch(/^gcp-[A-Za-z0-9_-]{12}$/);
    const d = dek();
    const w = await kek.wrap(d, ctx);
    expect(w).not.toContain(".");
    expect(urls.at(-1)).toBe(`https://cloudkms.googleapis.com/v1/${res}:encrypt`);
    expect(await kek.unwrap(w, ctx)).toEqual(d);
    expect(urls.at(-1)).toMatch(/:decrypt$/);
  });
});
