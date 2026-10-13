import { createCipheriv, createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  ATTACHMENT_CHUNK_SIZE, attachmentCiphertextSize, attachmentMetaFor, chunkNonce, chunkPlan, createLink, decryptAttachment, decryptAttachmentMeta,
  decryptChunk, encryptAttachmentMeta, encryptChunk, newAttachment, openLink, randomBytes, safeFilename, unwrapFileKey, wrapFileKey, b64url,
  MAX_ATTACHMENT_BYTES, type AttachmentMeta, type LinkAttachment,
} from "../src/index.js";

const CS = ATTACHMENT_CHUNK_SIZE;
const hex = (u: Uint8Array) => Buffer.from(u).toString("hex");
const sha = (u: Uint8Array) => createHash("sha256").update(u).digest("hex");
const filled = (n: number, seed = 1) => { const u = new Uint8Array(n); for (let i = 0; i < n; i++) u[i] = (i * 31 + seed) & 255; return u; };

/** Encrypts a whole file the way the uploader does: one encryptChunk per chunk. */
async function encryptFile(data: Uint8Array, fileId = crypto.randomUUID()) {
  const a = newAttachment(data.length);
  const meta = attachmentMetaFor({ name: "report.pdf", type: "application/pdf", size: data.length }, sha(data));
  const chunks: Uint8Array[] = [];
  for (let i = 0; i < a.chunkCount; i++) chunks.push(await encryptChunk(a.fileKey, a.nonceBase, fileId, i, a.chunkCount, data.subarray(i * CS, Math.min((i + 1) * CS, data.length))));
  return { ...a, fileId, meta, chunks };
}
async function decryptFile(f: Awaited<ReturnType<typeof encryptFile>>, chunks = f.chunks, meta: AttachmentMeta = f.meta) {
  const parts: Uint8Array[] = [];
  await decryptAttachment({ fileId: f.fileId, fileKey: f.fileKey, nonceBase: f.nonceBase, meta, fetchChunk: async (i) => { const c = chunks[i]; if (!c) throw new Error("missing"); return c; }, sink: (p) => { parts.push(p); } });
  return Buffer.concat(parts);
}

describe("attachment chunk plan", () => {
  it("cuts files into 1 MiB chunks; a zero-byte file is one empty chunk", () => {
    expect(chunkPlan(0)).toEqual({ chunkCount: 1, lastChunkBytes: 0 });
    expect(chunkPlan(1)).toEqual({ chunkCount: 1, lastChunkBytes: 1 });
    expect(chunkPlan(CS)).toEqual({ chunkCount: 1, lastChunkBytes: CS });
    expect(chunkPlan(CS + 1)).toEqual({ chunkCount: 2, lastChunkBytes: 1 });
    expect(chunkPlan(MAX_ATTACHMENT_BYTES).chunkCount).toBe(100);
    expect(() => chunkPlan(MAX_ATTACHMENT_BYTES + 1)).toThrow();
    expect(() => chunkPlan(-1)).toThrow();
    expect(attachmentCiphertextSize(CS * 3)).toBe(CS * 3 + 48);
    expect(attachmentCiphertextSize(0)).toBe(16);
  });
});

describe("attachment encryption", () => {
  for (const [label, n] of [["0 B", 0], ["1 B", 1], ["exactly one chunk", CS], ["one chunk + 1 B", CS + 1], ["three chunks", 3 * CS - 5]] as const) {
    it(`round-trips ${label}`, async () => {
      const data = filled(n);
      const f = await encryptFile(data);
      expect(f.chunks.length).toBe(chunkPlan(n).chunkCount);
      expect(f.chunks.reduce((a, c) => a + c.length, 0)).toBe(attachmentCiphertextSize(n));
      expect((await decryptFile(f)).equals(Buffer.from(data))).toBe(true);
    });
  }

  it("wraps the file key and encrypts metadata under the record key, bound to the record and the file", async () => {
    const recordKey = randomBytes(32), recordId = crypto.randomUUID(), fileId = crypto.randomUUID();
    const fileKey = randomBytes(32);
    const wrapped = await wrapFileKey(recordId, fileId, fileKey, recordKey);
    expect(wrapped.startsWith("v1.")).toBe(true);
    expect(hex(await unwrapFileKey(recordId, fileId, wrapped, recordKey))).toBe(hex(fileKey));
    await expect(unwrapFileKey(crypto.randomUUID(), fileId, wrapped, recordKey)).rejects.toMatchObject({ code: "decrypt_failed" });
    await expect(unwrapFileKey(recordId, crypto.randomUUID(), wrapped, recordKey)).rejects.toMatchObject({ code: "decrypt_failed" });
    await expect(unwrapFileKey(recordId, fileId, wrapped, randomBytes(32))).rejects.toMatchObject({ code: "decrypt_failed" });

    const meta = attachmentMetaFor({ name: "Passport scan.png", type: "image/png", size: 12345 }, "a".repeat(64));
    const enc = await encryptAttachmentMeta(recordId, fileId, meta, recordKey);
    expect(enc).not.toContain("Passport");
    expect(await decryptAttachmentMeta(recordId, fileId, enc, recordKey)).toEqual(meta);
    await expect(decryptAttachmentMeta(recordId, crypto.randomUUID(), enc, recordKey)).rejects.toMatchObject({ code: "decrypt_failed" });
    await expect(decryptAttachmentMeta(crypto.randomUUID(), fileId, enc, recordKey)).rejects.toMatchObject({ code: "decrypt_failed" });
  });

  it("refuses metadata that disagrees with its chunk plan or isn't well formed", async () => {
    const rk = randomBytes(32), rid = crypto.randomUUID(), fid = crypto.randomUUID();
    const good = attachmentMetaFor({ name: "a.txt", type: "text/plain", size: 10 }, "b".repeat(64));
    for (const bad of [{ ...good, chunkCount: 2 }, { ...good, size: CS * 2 }, { ...good, chunkSize: 4096 }, { ...good, mime: "text" }, { ...good, mime: "text/plain; charset=utf-8" },
      { ...good, name: "" }, { ...good, name: "..." }, { ...good, sha256: "zz" }, { ...good, size: -1 }, { ...good, name: "x".repeat(256) }]) {
      await expect(encryptAttachmentMeta(rid, fid, bad as AttachmentMeta, rk)).rejects.toThrow();
    }
    // A row whose ciphertext opens but whose content is inconsistent (written by a buggy or hostile client) is refused.
    const { aeadEncrypt, utf8 } = await import("../src/index.js");
    const forged = await aeadEncrypt(rk, utf8.encode(JSON.stringify({ ...good, chunkCount: 5 })), `attachment-meta:${rid}:${fid}`);
    await expect(decryptAttachmentMeta(rid, fid, forged, rk)).rejects.toMatchObject({ code: "bad_envelope" });
  });

  it("type defaults to octet-stream and names are cut to 255 characters before encryption", () => {
    expect(attachmentMetaFor({ name: "x", type: "", size: 1 }, "c".repeat(64)).mime).toBe("application/octet-stream");
    expect(attachmentMetaFor({ name: "x", type: "not a type", size: 1 }, "c".repeat(64)).mime).toBe("application/octet-stream");
    expect(attachmentMetaFor({ name: "n".repeat(400), type: "text/plain", size: 1 }, "c".repeat(64)).name.length).toBe(255);
  });
});

describe("attachment tampering is detected", () => {
  it("reordered chunks fail", async () => {
    const f = await encryptFile(filled(3 * CS));
    await expect(decryptFile(f, [f.chunks[1]!, f.chunks[0]!, f.chunks[2]!])).rejects.toMatchObject({ code: "decrypt_failed" });
  });

  it("a dropped last chunk fails, and so does lying about the chunk count", async () => {
    const f = await encryptFile(filled(2 * CS + 10));
    await expect(decryptFile(f, f.chunks.slice(0, 2))).rejects.toThrow();
    // Truncated metadata (fewer chunks, smaller size) can't validate the remaining chunks: the count is in each AAD.
    const short = attachmentMetaFor({ name: "report.pdf", type: "application/pdf", size: 2 * CS }, sha(filled(2 * CS + 10).subarray(0, 2 * CS)));
    await expect(decryptFile(f, f.chunks, short)).rejects.toMatchObject({ code: "decrypt_failed" });
    // Every chunk carries the total: decrypting chunk 0 as part of a 2-chunk file fails.
    await expect(decryptChunk(f.fileKey, f.nonceBase, f.fileId, 0, 2, f.chunks[0]!)).rejects.toMatchObject({ code: "decrypt_failed" });
  });

  it("a cut-off last chunk fails its tag", async () => {
    const f = await encryptFile(filled(CS + 100));
    await expect(decryptFile(f, [f.chunks[0]!, f.chunks[1]!.subarray(0, f.chunks[1]!.length - 1)])).rejects.toMatchObject({ code: "decrypt_failed" });
  });

  it("a chunk swapped in from another file (same index) fails, even with the same key", async () => {
    const a = await encryptFile(filled(2 * CS, 1)), b = await encryptFile(filled(2 * CS, 2));
    await expect(decryptFile(a, [a.chunks[0]!, b.chunks[1]!])).rejects.toMatchObject({ code: "decrypt_failed" });
    // Same key and nonce base but another file id (a server re-labelling rows): the AAD differs.
    const pt = filled(100);
    const ct = await encryptChunk(a.fileKey, a.nonceBase, a.fileId, 0, 1, pt);
    await expect(decryptChunk(a.fileKey, a.nonceBase, crypto.randomUUID(), 0, 1, ct)).rejects.toMatchObject({ code: "decrypt_failed" });
  });

  it("an old chunk replayed at another position fails (the index is in nonce and AAD)", async () => {
    const f = await encryptFile(filled(3 * CS));
    await expect(decryptFile(f, [f.chunks[0]!, f.chunks[0]!, f.chunks[2]!])).rejects.toMatchObject({ code: "decrypt_failed" });
  });

  it("a flipped byte, a wrong key or a wrong nonce base fails", async () => {
    const f = await encryptFile(filled(1000));
    const bad = f.chunks[0]!.slice(); bad[10]! ^= 1;
    await expect(decryptFile(f, [bad])).rejects.toMatchObject({ code: "decrypt_failed" });
    await expect(decryptChunk(randomBytes(32), f.nonceBase, f.fileId, 0, 1, f.chunks[0]!)).rejects.toMatchObject({ code: "decrypt_failed" });
    await expect(decryptChunk(f.fileKey, randomBytes(8), f.fileId, 0, 1, f.chunks[0]!)).rejects.toMatchObject({ code: "decrypt_failed" });
  });

  it("a whole-file hash mismatch fails even when every chunk opens", async () => {
    const f = await encryptFile(filled(2000));
    await expect(decryptFile(f, f.chunks, { ...f.meta, sha256: "0".repeat(64) })).rejects.toMatchObject({ code: "decrypt_failed" });
  });

  it("decrypts chunks delivered out of order and hands them to the sink in order", async () => {
    const data = filled(4 * CS + 3);
    const f = await encryptFile(data);
    const order: number[] = [];
    const parts: Uint8Array[] = [];
    await decryptAttachment({ fileId: f.fileId, fileKey: f.fileKey, nonceBase: f.nonceBase, meta: f.meta, parallel: 3,
      fetchChunk: async (i) => { await new Promise((r) => setTimeout(r, (5 - i) * 10)); return f.chunks[i]!; },
      sink: (p, i) => { order.push(i); parts.push(p); } });
    expect(order).toEqual([0, 1, 2, 3, 4]);
    expect(Buffer.concat(parts).equals(Buffer.from(data))).toBe(true);
  });

  it("doesn't stall when the first chunk is slow and later ones fill the back-pressure window", async () => {
    // 12 chunks, 3 workers: chunks 1..11 arrive long before chunk 0, so more than 2 × parallel wait for it.
    const data = filled(11 * CS + 5);
    const f = await encryptFile(data);
    const parts: Uint8Array[] = [];
    const run = decryptAttachment({ fileId: f.fileId, fileKey: f.fileKey, nonceBase: f.nonceBase, meta: f.meta, parallel: 3,
      fetchChunk: async (i) => { await new Promise((r) => setTimeout(r, i === 0 ? 300 : 1)); return f.chunks[i]!; },
      sink: (p) => { parts.push(p); } });
    const timeout = new Promise((_, reject) => setTimeout(() => reject(new Error("stalled")), 5000));
    await Promise.race([run, timeout]);
    expect(Buffer.concat(parts).equals(Buffer.from(data))).toBe(true);
  }, 10_000);
});

describe("attachment nonces", () => {
  it("nonce = base ‖ BE32(index)", () => {
    const base = Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8]);
    expect(hex(chunkNonce(base, 0))).toBe("010203040506070800000000");
    expect(hex(chunkNonce(base, 258))).toBe("010203040506070800000102");
    expect(() => chunkNonce(new Uint8Array(7), 0)).toThrow();
  });

  it("two attempts at the same file never share a key or a nonce", async () => {
    const data = filled(3 * CS);
    const a = await encryptFile(data), b = await encryptFile(data);
    expect(hex(a.fileKey)).not.toBe(hex(b.fileKey));
    expect(hex(a.nonceBase)).not.toBe(hex(b.nonceBase));
    const nonces = new Set<string>();
    for (const f of [a, b]) for (let i = 0; i < f.chunkCount; i++) nonces.add(hex(f.fileKey) + hex(chunkNonce(f.nonceBase, i)));
    expect(nonces.size).toBe(a.chunkCount + b.chunkCount);
    // Identical plaintext gives unrelated ciphertext.
    expect(hex(a.chunks[0]!.subarray(0, 32))).not.toBe(hex(b.chunks[0]!.subarray(0, 32)));
  });

  it("known answer: one chunk under a fixed key, base and index", async () => {
    const key = Uint8Array.from({ length: 32 }, (_, i) => i);
    const base = Uint8Array.from([0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7]);
    const fileId = "00000000-0000-4000-8000-000000000001";
    const pt = new TextEncoder().encode("Clane Vault attachment chunk");
    const ct = await encryptChunk(key, base, fileId, 2, 3, pt);
    // Independent implementation (Node's AES-256-GCM) of the same construction.
    const c = createCipheriv("aes-256-gcm", key, Buffer.from("a0a1a2a3a4a5a6a700000002", "hex"));
    c.setAAD(Buffer.from(`attachment-chunk:${fileId}:2:3`));
    const ref = Buffer.concat([c.update(pt), c.final(), c.getAuthTag()]);
    expect(hex(ct)).toBe(ref.toString("hex"));
    expect(hex(ct)).toBe("95fcc4efc34457e34c96130180afb20d1f931ce01b49ffe2c3137fb195db469ae0e730256f9e6c6e97b6f17d");
    expect(new TextDecoder().decode(await decryptChunk(key, base, fileId, 2, 3, ct))).toBe("Clane Vault attachment chunk");
  });
});

describe("safeFilename", () => {
  it.each([
    ["report.pdf", "report.pdf"],
    ["../../etc/passwd", "_.._etc_passwd"],
    ["C:\\Windows\\evil.exe", "C__Windows_evil.exe"],
    [".bashrc", "bashrc"],
    ["   ", "file"],
    ["", "file"],
    ["...", "file"],
    ["a\u0000b\u0007c\u001fd.txt", "abcd.txt"],
    ["invoice\u202Efdp.exe", "invoicefdp.exe"],
    ["what?<is>|this*.txt", "what__is__this_.txt"],
  ])("%j → %j", (input, out) => expect(safeFilename(input)).toBe(out));

  it("cuts 300-character names to 255, keeping a short extension", () => {
    const s = safeFilename(`${"a".repeat(300)}.pdf`);
    expect(s.length).toBe(255);
    expect(s.endsWith(".pdf")).toBe(true);
  });
});

describe("one-time links with files", () => {
  const file = (): LinkAttachment => ({ fileId: crypto.randomUUID(), fileKey: b64url.encode(randomBytes(32)), nonceBase: b64url.encode(randomBytes(8)),
    meta: attachmentMetaFor({ name: "contract.pdf", type: "application/pdf", size: 5000 }, "d".repeat(64)) });

  it("carries the file keys inside the encrypted payload", async () => {
    const id = crypto.randomUUID();
    const files = [file(), file()];
    const l = await createLink(id, { title: "Lease", password: "pw", attachments: files });
    expect(l.encPayload).not.toContain(files[0]!.fileKey);
    expect((await openLink(id, l.encPayload, l.fragment)).attachments).toEqual(files);
  });

  it("validates the files: at most 25, well-formed keys, no duplicates, valid metadata", async () => {
    const id = crypto.randomUUID();
    await expect(createLink(id, { title: "x", attachments: Array.from({ length: 26 }, file) })).rejects.toThrow(/at most 25/);
    const f = file();
    await expect(createLink(id, { title: "x", attachments: [f, f] })).rejects.toThrow(/id/);
    await expect(createLink(id, { title: "x", attachments: [{ ...file(), fileKey: b64url.encode(randomBytes(16)) }] })).rejects.toThrow(/key/);
    await expect(createLink(id, { title: "x", attachments: [{ ...file(), nonceBase: b64url.encode(randomBytes(12)) }] })).rejects.toThrow(/nonce/);
    await expect(createLink(id, { title: "x", attachments: [{ ...file(), meta: { ...file().meta, chunkCount: 9 } }] })).rejects.toThrow();
    // 25 files with long names still fit the link envelope.
    const many = Array.from({ length: 25 }, () => ({ ...file(), meta: attachmentMetaFor({ name: `${"n".repeat(250)}.pdf`, type: "application/pdf", size: 5000 }, "d".repeat(64)) }));
    const l = await createLink(id, { title: "x", attachments: many });
    expect(l.encPayload.length).toBeLessThan(90_000);
  });

  it("a link without files has no attachments field", async () => {
    const id = crypto.randomUUID();
    const l = await createLink(id, { title: "x", attachments: [] });
    expect(await openLink(id, l.encPayload, l.fragment)).toEqual({ title: "x" });
  });
});
