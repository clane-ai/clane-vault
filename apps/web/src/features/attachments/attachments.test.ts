import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  ATTACHMENT_CHUNK_SIZE, attachmentMetaFor, decryptAttachmentMeta, decryptChunk, decodeNonceBase, encryptChunk, newAttachment, randomBytes, unwrapFileKey,
} from "@clane-vault/crypto";
import { ApiError, type OrgApi } from "@/lib/api";
import { bytesMatch, isExecutable, previewKindOf, sniffImage, TEXT_PREVIEW_MAX } from "./previewSinks";
import { cancelUpload, precheck, resetUploadsForTests, retryUpload, startUpload, uploadsSnapshot, UPLOAD_PARALLEL } from "./uploader";
import { DamagedFileError, fetchPlain, saveFile, triggerDownload, type FileSource } from "./downloader";
import { cancelAllTransfers, trackDownload } from "./transfers";
import { formatBytes, plainSize } from "./format";

const CS = ATTACHMENT_CHUNK_SIZE;
const PNG = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
const u8 = (...a: number[]) => Uint8Array.from(a);
const ascii = (s: string) => new TextEncoder().encode(s);
const sha = async (b: Uint8Array) => [...new Uint8Array(await crypto.subtle.digest("SHA-256", b as BufferSource))].map((x) => x.toString(16).padStart(2, "0")).join("");
function fakeFile(size: number, name = "report.pdf", type = "application/pdf") {
  const data = new Uint8Array(size);
  for (let i = 0; i < size; i++) data[i] = (i * 7 + 3) & 255;
  return { file: new File([data], name, { type }), data };
}
const until = async (cond: () => boolean, ms = 5000) => { const t0 = Date.now(); while (!cond()) { if (Date.now() - t0 > ms) throw new Error("timed out"); await new Promise((r) => setTimeout(r, 5)); } };

describe("preview sinks", () => {
  it("only an allowlist previews: raster images, PDF, small plain text; never SVG, HTML or anything else", () => {
    for (const m of ["image/png", "image/jpeg", "image/gif", "image/webp"]) expect(previewKindOf(m, 100)).toBe("image");
    expect(previewKindOf("application/pdf", 100)).toBe("pdf");
    expect(previewKindOf("text/plain", 100)).toBe("text");
    expect(previewKindOf("text/plain", TEXT_PREVIEW_MAX + 1)).toBeNull();
    for (const m of ["image/svg+xml", "text/html", "application/xhtml+xml", "text/xml", "application/xml", "application/javascript", "application/zip", "application/octet-stream", "image/bmp", "text/csv"]) expect(previewKindOf(m, 100)).toBeNull();
  });

  it("checks magic bytes: a file whose type lies stays download-only", () => {
    expect(bytesMatch("image", "image/png", u8(...PNG, 0, 0))).toBe(true);
    expect(bytesMatch("image", "image/png", u8(0xff, 0xd8, 0xff, 0xe0))).toBe(false); // a JPEG claiming to be PNG
    expect(bytesMatch("image", "image/jpeg", u8(0xff, 0xd8, 0xff, 0xe0))).toBe(true);
    expect(bytesMatch("image", "image/png", ascii("<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>"))).toBe(false);
    expect(bytesMatch("image", "image/gif", ascii("GIF89a....."))).toBe(true);
    expect(bytesMatch("image", "image/webp", ascii("RIFF\x00\x00\x00\x00WEBPVP8 "))).toBe(true);
    expect(bytesMatch("pdf", "application/pdf", ascii("%PDF-1.7\n"))).toBe(true);
    expect(bytesMatch("pdf", "application/pdf", ascii("<html><script>"))).toBe(false);
    expect(bytesMatch("text", "text/plain", ascii("hello\nworld"))).toBe(true);
    expect(bytesMatch("text", "text/plain", u8(0x68, 0x00, 0x69))).toBe(false);
    expect(bytesMatch("text", "text/plain", u8(0xc3, 0x28))).toBe(false); // not UTF-8
    expect(sniffImage(ascii("<svg"))).toBeNull();
  });

  it("flags programs for the download warning", () => {
    expect(isExecutable("setup.exe")).toBe(true);
    expect(isExecutable("run.ps1 ")).toBe(true);
    expect(isExecutable("tool", "application/x-msdownload")).toBe(true);
    expect(isExecutable("passport.png", "image/png")).toBe(false);
    // What the download is saved as decides: trailing dots and bidi controls are dropped by safeFilename.
    expect(isExecutable("setup.exe.")).toBe(true);
    expect(isExecutable("setup.exe‮")).toBe(true);
    expect(isExecutable("invoice‮fdp.exe")).toBe(true);
  });

  it("formats sizes and turns ciphertext sizes back into plaintext sizes", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(1536)).toBe("1.5 KB");
    expect(formatBytes(5 * 1024 * 1024)).toBe("5.0 MB");
    expect(plainSize({ size: 1016, chunkCount: 1 })).toBe(1000);
  });
});

/** A fake server for the uploader: records requests, stores chunk bytes, can fail on demand. */
function fakeApi(o: { failPut?: (index: number, attempt: number) => Error | null } = {}) {
  const calls: { method: string; path: string; body?: unknown }[] = [];
  const chunks = new Map<number, Uint8Array[]>();
  let inFlight = 0, maxInFlight = 0;
  const attempts = new Map<number, number>();
  let created: Record<string, unknown> | null = null;
  const api = {
    post: vi.fn(async (path: string, body?: unknown) => {
      calls.push({ method: "POST", path, body });
      if (path.endsWith("/attachments")) created = body as Record<string, unknown>;
      return path.endsWith("/complete") ? { id: "x", readyAt: "now" } : { id: "x", expiresAt: "later" };
    }),
    get: vi.fn(async (path: string) => { calls.push({ method: "GET", path }); return { state: "uploading", received: [...chunks.keys()] }; }),
    del: vi.fn(async (path: string) => { calls.push({ method: "DELETE", path }); }),
    putBytes: vi.fn(async (path: string, bytes: Uint8Array) => {
      const index = Number(path.split("/").pop());
      const n = (attempts.get(index) ?? 0) + 1;
      attempts.set(index, n);
      calls.push({ method: "PUT", path });
      inFlight++; maxInFlight = Math.max(maxInFlight, inFlight);
      try {
        await new Promise((r) => setTimeout(r, 15));
        const f = o.failPut?.(index, n);
        if (f) throw f;
        chunks.set(index, [...(chunks.get(index) ?? []), bytes.slice()]);
        return { received: chunks.size };
      } finally { inFlight--; }
    }),
  };
  return { api: api as unknown as OrgApi, raw: api, calls, chunks, created: () => created, maxInFlight: () => maxInFlight, attempts };
}

describe("uploader", () => {
  const recordId = crypto.randomUUID();
  let recordKey: Uint8Array;
  beforeEach(() => { recordKey = randomBytes(32); resetUploadsForTests(); });
  afterEach(() => resetUploadsForTests());

  it("plans, reserves, sends chunks 3 at a time and completes; the server gets ciphertext the record key opens", async () => {
    const { file, data } = fakeFile(5 * CS + 123);
    const f = fakeApi();
    const done = vi.fn();
    startUpload({ api: f.api, recordId, recordKey, file, onDone: done });
    await until(() => done.mock.calls.length > 0);
    const body = f.created()! as { id: string; encMeta: string; wrappedFileKey: string; nonceBase: string; size: number; chunkSize: number; chunkCount: number };
    expect(body).toMatchObject({ size: 5 * CS + 123 + 6 * 16, chunkSize: CS, chunkCount: 6 });
    expect(JSON.stringify(body)).not.toContain("report.pdf");
    expect(f.maxInFlight()).toBe(UPLOAD_PARALLEL);
    expect(f.calls.at(-1)).toMatchObject({ method: "POST", path: `/records/${recordId}/attachments/${body.id}/complete` });
    // What the server holds decrypts back to the file under the wrapped key.
    const meta = await decryptAttachmentMeta(recordId, body.id, body.encMeta, recordKey);
    expect(meta).toEqual(attachmentMetaFor({ name: "report.pdf", type: "application/pdf", size: data.length }, await sha(data)));
    const fileKey = await unwrapFileKey(recordId, body.id, body.wrappedFileKey, recordKey);
    const parts: Uint8Array[] = [];
    for (let i = 0; i < 6; i++) parts.push(await decryptChunk(fileKey, decodeNonceBase(body.nonceBase), body.id, i, 6, f.chunks.get(i)![0]!));
    expect(Buffer.concat(parts).equals(Buffer.from(data))).toBe(true);
    // The caller's record key is untouched; the uploader zeroed only its own copy.
    expect(recordKey.some((b) => b !== 0)).toBe(true);
  });

  it("retries a failed chunk with the very same ciphertext (never re-encrypts), within the request and after Retry", async () => {
    const { file } = fakeFile(2 * CS + 5);
    let down = true;
    const f = fakeApi({ failPut: (i) => (i === 1 && down ? new TypeError("Failed to fetch") : null) });
    const seen: Uint8Array[] = [];
    const put = f.raw.putBytes.getMockImplementation()!;
    f.raw.putBytes.mockImplementation(async (path: string, bytes: Uint8Array) => { if (path.endsWith("/1")) seen.push(bytes.slice()); return put(path, bytes); });
    const key = startUpload({ api: f.api, recordId, recordKey, file });
    await until(() => uploadsSnapshot().find((u) => u.key === key)?.status === "failed");
    expect(uploadsSnapshot()[0]!.error).toMatch(/connection/);
    expect(seen.length).toBe(3); // three attempts in the request
    down = false;
    await retryUpload(key);
    await until(() => uploadsSnapshot().find((u) => u.key === key)?.status === "done");
    expect(seen.length).toBe(4);
    for (const s of seen) expect(Buffer.from(s).equals(Buffer.from(seen[0]!))).toBe(true);
    // Chunks the server already had were not sent again.
    expect(f.attempts.get(0)).toBe(1);
    expect(f.attempts.get(2)).toBe(1);
  });

  it("chunk_mismatch: starts over under a new file id and key", async () => {
    const { file } = fakeFile(100);
    const f = fakeApi({ failPut: (_i, n) => (n === 1 ? new ApiError(409, "chunk_mismatch", null) : null) });
    const ids: string[] = [];
    const post = f.raw.post.getMockImplementation()!;
    f.raw.post.mockImplementation(async (path: string, body?: unknown) => { if (path.endsWith("/attachments")) ids.push((body as { id: string }).id); return post(path, body); });
    const key = startUpload({ api: f.api, recordId, recordKey, file });
    await until(() => uploadsSnapshot().find((u) => u.key === key)?.status === "done");
    expect(ids).toHaveLength(2);
    expect(ids[0]).not.toBe(ids[1]);
    expect(f.calls.some((c) => c.method === "DELETE" && c.path.endsWith(ids[0]!))).toBe(true);
  });

  it("cancel stops sending and deletes the reservation; locking cancels everything", async () => {
    const { file } = fakeFile(4 * CS);
    const f = fakeApi();
    const key = startUpload({ api: f.api, recordId, recordKey, file });
    await until(() => f.calls.some((c) => c.method === "PUT"));
    cancelUpload(key);
    expect(f.calls.some((c) => c.method === "DELETE")).toBe(true);
    expect(uploadsSnapshot()).toEqual([]);
    const g = fakeApi();
    startUpload({ api: g.api, recordId, recordKey, file });
    const t = trackDownload();
    await until(() => g.calls.some((c) => c.method === "PUT"));
    cancelAllTransfers();
    expect(uploadsSnapshot()).toEqual([]);
    expect(t.signal.aborted).toBe(true);
    expect(g.calls.some((c) => c.method === "DELETE")).toBe(true);
  });

  it("refuses files that can't fit before any request, with the exact limit", () => {
    const base = { maxFileMb: 10, maxPerRecord: 3, maxRecordMb: 15, existingFiles: 0, existingBytes: 0, pending: [] };
    expect(precheck({ name: "big.iso", size: 11 * 1024 * 1024 }, base)).toMatch(/at most 10 MB/);
    expect(precheck({ name: "a", size: 1 }, { ...base, existingFiles: 2, pending: [{ size: 1 }] })).toMatch(/at most 3 files/);
    expect(precheck({ name: "a", size: 6 * 1024 * 1024 }, { ...base, existingBytes: 10 * 1024 * 1024 })).toMatch(/at most 15 MB/);
    expect(precheck({ name: "a", size: 1 }, base)).toBeNull();
  });

  it("keeps nothing anywhere a reload could resume from", async () => {
    const spies = [vi.spyOn(Storage.prototype, "setItem"), vi.spyOn(globalThis.indexedDB ?? { open: () => undefined }, "open" as never)];
    const { file } = fakeFile(10);
    const f = fakeApi();
    const key = startUpload({ api: f.api, recordId, recordKey, file });
    await until(() => uploadsSnapshot().find((u) => u.key === key)?.status === "done");
    for (const s of spies) expect(s).not.toHaveBeenCalled();
    for (const s of spies) s.mockRestore();
  });

  it("a complete whose answer was lost is done, never deleted: the retry's not_uploading is checked against the server", async () => {
    const { file } = fakeFile(10);
    const f = fakeApi();
    const post = f.raw.post.getMockImplementation()!;
    let completes = 0;
    f.raw.post.mockImplementation(async (path: string, body?: unknown) => {
      if (!path.endsWith("/complete")) return post(path, body);
      completes++;
      // The first complete lands on the server but the answer is lost; the retry finds the file ready.
      if (completes === 1) throw new TypeError("Failed to fetch");
      throw new ApiError(409, "not_uploading", { error: "not_uploading" });
    });
    f.raw.get.mockImplementation(async (path: string) => { f.calls.push({ method: "GET", path }); return { state: completes ? "ready" : "uploading", received: [...f.chunks.keys()] }; });
    const done = vi.fn();
    const key = startUpload({ api: f.api, recordId, recordKey, file, onDone: done });
    await until(() => ["done", "failed"].includes(uploadsSnapshot().find((u) => u.key === key)?.status ?? ""));
    expect(uploadsSnapshot().find((u) => u.key === key)?.status).toBe("done");
    expect(done).toHaveBeenCalled();
    expect(f.calls.some((c) => c.method === "DELETE")).toBe(false);
  });

  it("an upload refused for good (quota) says why, and Retry asks for the file again", async () => {
    const { file } = fakeFile(10);
    const f = fakeApi();
    f.raw.post.mockImplementation(async () => { throw new ApiError(409, "quota_exceeded", { error: "quota_exceeded", scope: "org" }); });
    const key = startUpload({ api: f.api, recordId, recordKey, file });
    await until(() => uploadsSnapshot().find((u) => u.key === key)?.status === "failed");
    expect(uploadsSnapshot()[0]!.error).toMatch(/organisation's file storage is full/);
    await retryUpload(key);
    expect(uploadsSnapshot()[0]!.error).toBe("Add the file again.");
  });
});

describe("downloader", () => {
  async function source(data: Uint8Array, o: { delay?: (i: number) => number; tamper?: boolean; meta?: Partial<ReturnType<typeof attachmentMetaFor>> } = {}): Promise<FileSource & { fetched: number[] }> {
    const fileId = crypto.randomUUID();
    const a = newAttachment(data.length);
    const chunks: Uint8Array[] = [];
    for (let i = 0; i < a.chunkCount; i++) chunks.push(await encryptChunk(a.fileKey, a.nonceBase, fileId, i, a.chunkCount, data.subarray(i * CS, Math.min((i + 1) * CS, data.length))));
    if (o.tamper) chunks[0]![3]! ^= 1;
    const fetched: number[] = [];
    return { fileId, fileKey: a.fileKey, nonceBase: a.nonceBase, meta: { ...attachmentMetaFor({ name: "../secret report.pdf", type: "application/pdf", size: data.length }, await sha(data)), ...o.meta }, fetched,
      fetchChunk: async (i) => { fetched.push(i); await new Promise((r) => setTimeout(r, o.delay?.(i) ?? 0)); return chunks[i]!; } };
  }

  it("fetches in parallel, decrypts out-of-order arrivals and returns the plaintext in order", async () => {
    const { data } = fakeFile(4 * CS + 9);
    const src = await source(data, { delay: (i) => (5 - i) * 15 });
    const parts = await fetchPlain(src);
    expect(Buffer.concat(parts).equals(Buffer.from(data))).toBe(true);
  });

  it("a hash mismatch or a damaged chunk is DamagedFileError and nothing is saved", async () => {
    const { data } = fakeFile(3000);
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);
    await expect(saveFile(await source(data, { meta: { sha256: "0".repeat(64) } }), null)).rejects.toBeInstanceOf(DamagedFileError);
    await expect(saveFile(await source(data, { tamper: true }), null)).rejects.toBeInstanceOf(DamagedFileError);
    expect(click).not.toHaveBeenCalled();
    // Streaming to disk: the writable is aborted, never closed.
    const w = { write: vi.fn(async () => undefined), close: vi.fn(async () => undefined), abort: vi.fn(async () => undefined) };
    await expect(saveFile(await source(data, { tamper: true }), w)).rejects.toBeInstanceOf(DamagedFileError);
    expect(w.abort).toHaveBeenCalled();
    expect(w.close).not.toHaveBeenCalled();
    click.mockRestore();
  });

  it("saves through <a download> as application/octet-stream with a safe name, and revokes the URL", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const blobs: Blob[] = [];
    const create = vi.spyOn(URL, "createObjectURL").mockImplementation((b) => { blobs.push(b as Blob); return "blob:x"; });
    const revoke = vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => undefined);
    let anchor: HTMLAnchorElement | null = null;
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) { anchor = this; });
    const { data } = fakeFile(2000);
    await saveFile(await source(data), null);
    expect(blobs[0]!.type).toBe("application/octet-stream");
    expect(new Uint8Array(await blobs[0]!.arrayBuffer())).toEqual(data);
    expect(anchor!.download).toBe("_secret report.pdf");
    vi.advanceTimersByTime(1500);
    expect(revoke).toHaveBeenCalledWith("blob:x");
    // Even a typed Blob handed to triggerDownload goes out as octet-stream.
    triggerDownload(new Blob(["<h1>x</h1>"], { type: "text/html" }), "page.html");
    expect(blobs[1]!.type).toBe("application/octet-stream");
    create.mockRestore(); revoke.mockRestore(); click.mockRestore(); vi.useRealTimers();
  });

  it("streams to a picked file and closes it when every check passed", async () => {
    const { data } = fakeFile(CS + 50);
    const written: Uint8Array[] = [];
    const w = { write: vi.fn(async (d: Uint8Array) => { written.push(d); }), close: vi.fn(async () => undefined), abort: vi.fn(async () => undefined) };
    await saveFile(await source(data), w);
    expect(w.close).toHaveBeenCalled();
    expect(Buffer.concat(written).equals(Buffer.from(data))).toBe(true);
  });
});
