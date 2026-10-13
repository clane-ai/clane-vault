import { createSHA256 } from "hash-wasm";
import { aeadDecrypt, aeadEncrypt } from "./aead.js";
import { b64url, CryptoError, randomBytes, utf8 } from "./encoding.js";

/**
 * End-to-end-encrypted file attachments (docs/design/2026-10-12-attachments.md §2).
 *
 *   recordKey ──wrap (AAD attachment-key:<recordId>:<fileId>)──► fileKey (random, one file only)
 *   recordKey ──AEAD (AAD attachment-meta:<recordId>:<fileId>)──► { name, mime, size, sha256, chunkSize, chunkCount }
 *   fileKey   ──AES-GCM, nonce = nonceBase ‖ BE32(index), AAD attachment-chunk:<fileId>:<index>:<chunkCount>──► chunks
 *
 * A chunk is never encrypted twice under one key: the uploader keeps each chunk's ciphertext until the server accepted
 * it and resends those bytes; a new attempt (after a reload) is a new file id with a new key and nonce base.
 */

export interface AttachmentMeta { name: string; mime: string; size: number; sha256: string; chunkSize: number; chunkCount: number }

/** Plaintext bytes per chunk (1 MiB): ciphertext + tag stays far below the API's 2 MB body limit. */
export const ATTACHMENT_CHUNK_SIZE = 1_048_576;
/** AES-GCM tag bytes added to every chunk. */
export const ATTACHMENT_TAG_BYTES = 16;
/** The crypto package's ceiling; the server's limit may be lower. */
export const MAX_ATTACHMENT_BYTES = 100 * 1024 * 1024;
export const ATTACHMENT_NONCE_BASE_BYTES = 8;
/** File names are cut to this many characters before they are encrypted. */
export const MAX_ATTACHMENT_NAME = 255;
const MAX_META_BYTES = 2048;
const MIME = /^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}\/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}$/;
const HEX64 = /^[0-9a-f]{64}$/;

const aadKey = (recordId: string, fileId: string) => `attachment-key:${recordId}:${fileId}`;
const aadMeta = (recordId: string, fileId: string) => `attachment-meta:${recordId}:${fileId}`;
const aadChunk = (fileId: string, index: number, chunkCount: number) => `attachment-chunk:${fileId}:${index}:${chunkCount}`;

const isSize = (n: unknown): n is number => typeof n === "number" && Number.isSafeInteger(n) && n >= 0;

/** How a file of `size` plaintext bytes is cut: every chunk but the last is full; a zero-byte file is one empty chunk. */
export function chunkPlan(size: number): { chunkCount: number; lastChunkBytes: number } {
  if (!isSize(size) || size > MAX_ATTACHMENT_BYTES) throw new Error("attachment size is out of range");
  const chunkCount = Math.max(1, Math.ceil(size / ATTACHMENT_CHUNK_SIZE));
  return { chunkCount, lastChunkBytes: size - (chunkCount - 1) * ATTACHMENT_CHUNK_SIZE };
}

/** Ciphertext bytes the server stores for a file of `size` plaintext bytes (what `size` means in the API). */
export const attachmentCiphertextSize = (size: number) => size + ATTACHMENT_TAG_BYTES * chunkPlan(size).chunkCount;

/** Plaintext bytes of chunk `index` of a file of `size` bytes. */
export function chunkPlainBytes(size: number, index: number): number {
  const { chunkCount, lastChunkBytes } = chunkPlan(size);
  if (!Number.isInteger(index) || index < 0 || index >= chunkCount) throw new Error("chunk index is out of range");
  return index === chunkCount - 1 ? lastChunkBytes : ATTACHMENT_CHUNK_SIZE;
}

function need32(k: Uint8Array): Uint8Array {
  if (!(k instanceof Uint8Array) || k.length !== 32) throw new CryptoError("bad_key", "key must be 32 bytes");
  return k;
}

/** A fresh file key and nonce base for one upload attempt of a file of `size` bytes. */
export function newAttachment(size: number): { fileKey: Uint8Array; nonceBase: Uint8Array; chunkCount: number } {
  const { chunkCount } = chunkPlan(size);
  return { fileKey: randomBytes(32), nonceBase: randomBytes(ATTACHMENT_NONCE_BASE_BYTES), chunkCount };
}

export const wrapFileKey = (recordId: string, fileId: string, fileKey: Uint8Array, recordKey: Uint8Array): Promise<string> =>
  aeadEncrypt(need32(recordKey), need32(fileKey), aadKey(recordId, fileId));

export async function unwrapFileKey(recordId: string, fileId: string, wrapped: string, recordKey: Uint8Array): Promise<Uint8Array> {
  return need32(await aeadDecrypt(need32(recordKey), wrapped, aadKey(recordId, fileId)));
}

/**
 * A download filename: control characters, path separators and characters Windows refuses dropped, leading dots and
 * spaces stripped, cut to 255 characters; "file" when nothing is left.
 */
export const safeFilename = (name: string): string => cleanName(name) || "file";

function cleanName(name: string): string {
  // eslint-disable-next-line no-control-regex
  let s = String(name ?? "").normalize("NFC").replace(/[\u0000-\u001f\u007f-\u009f‎‏‪-‮⁦-⁩]/g, "")
    .replace(/[/\\:*?"<>|]/g, "_").replace(/^[.\s]+/, "").replace(/[.\s]+$/, "");
  if (s.length > MAX_ATTACHMENT_NAME) {
    const dot = s.lastIndexOf(".");
    const ext = dot > 0 && s.length - dot <= 16 ? s.slice(dot) : "";
    s = s.slice(0, MAX_ATTACHMENT_NAME - ext.length) + ext;
  }
  return s;
}

/** Throws unless `meta` is well formed and agrees with the chunk plan. */
export function validateAttachmentMeta(meta: AttachmentMeta): AttachmentMeta {
  if (!meta || typeof meta !== "object") throw new Error("attachment metadata must be an object");
  const { name, mime, size, sha256, chunkSize, chunkCount } = meta;
  if (typeof name !== "string" || name.length > MAX_ATTACHMENT_NAME || cleanName(name) === "") throw new Error("attachment name is invalid");
  if (typeof mime !== "string" || !MIME.test(mime)) throw new Error("attachment type is invalid");
  if (!isSize(size) || size > MAX_ATTACHMENT_BYTES) throw new Error("attachment size is invalid");
  if (typeof sha256 !== "string" || !HEX64.test(sha256)) throw new Error("attachment hash is invalid");
  if (chunkSize !== ATTACHMENT_CHUNK_SIZE || chunkCount !== chunkPlan(size).chunkCount) throw new Error("attachment chunks don't match its size");
  return { name, mime: mime.toLowerCase(), size, sha256, chunkSize, chunkCount };
}

/** The metadata to encrypt for a file: its name cut to 255 characters and its type defaulting to octet-stream. */
export function attachmentMetaFor(file: { name: string; type?: string; size: number }, sha256: string): AttachmentMeta {
  const name = file.name.length > MAX_ATTACHMENT_NAME ? file.name.slice(0, MAX_ATTACHMENT_NAME) : file.name;
  const mime = file.type && MIME.test(file.type) ? file.type.toLowerCase() : "application/octet-stream";
  return { name: cleanName(name) ? name : "file", mime, size: file.size, sha256, chunkSize: ATTACHMENT_CHUNK_SIZE, chunkCount: chunkPlan(file.size).chunkCount };
}

export async function encryptAttachmentMeta(recordId: string, fileId: string, meta: AttachmentMeta, recordKey: Uint8Array): Promise<string> {
  const m = validateAttachmentMeta(meta);
  const pt = utf8.encode(JSON.stringify({ name: m.name, mime: m.mime, size: m.size, sha256: m.sha256, chunkSize: m.chunkSize, chunkCount: m.chunkCount }));
  if (pt.length > MAX_META_BYTES) throw new Error("attachment metadata is too large");
  return aeadEncrypt(need32(recordKey), pt, aadMeta(recordId, fileId));
}

/** Opens and validates metadata: a row that is malformed or disagrees with its chunk plan is refused (bad_envelope). */
export async function decryptAttachmentMeta(recordId: string, fileId: string, encMeta: string, recordKey: Uint8Array): Promise<AttachmentMeta> {
  const pt = await aeadDecrypt(need32(recordKey), encMeta, aadMeta(recordId, fileId));
  if (pt.length > MAX_META_BYTES) throw new CryptoError("bad_envelope", "attachment metadata is too large");
  try { return validateAttachmentMeta(JSON.parse(utf8.decode(pt)) as AttachmentMeta); }
  catch { throw new CryptoError("bad_envelope", "attachment metadata is invalid"); }
}

/** The 12-byte nonce of chunk `index`: nonceBase (8 random bytes) ‖ big-endian 32-bit index. */
export function chunkNonce(nonceBase: Uint8Array, index: number): Uint8Array {
  if (!(nonceBase instanceof Uint8Array) || nonceBase.length !== ATTACHMENT_NONCE_BASE_BYTES) throw new CryptoError("bad_key", "nonce base must be 8 bytes");
  if (!Number.isInteger(index) || index < 0 || index > 0xffffffff) throw new Error("chunk index is out of range");
  const n = new Uint8Array(12);
  n.set(nonceBase, 0);
  new DataView(n.buffer).setUint32(8, index, false);
  return n;
}

function checkPosition(fileId: string, index: number, chunkCount: number) {
  if (typeof fileId !== "string" || fileId === "") throw new Error("file id is required");
  if (!Number.isInteger(chunkCount) || chunkCount < 1 || chunkCount > Math.ceil(MAX_ATTACHMENT_BYTES / ATTACHMENT_CHUNK_SIZE)) throw new Error("chunk count is out of range");
  if (!Number.isInteger(index) || index < 0 || index >= chunkCount) throw new Error("chunk index is out of range");
}

const importChunkKey = (fileKey: Uint8Array) => crypto.subtle.importKey("raw", need32(fileKey) as BufferSource, "AES-GCM", false, ["encrypt", "decrypt"]);

/** Encrypts one chunk (raw AES-256-GCM, ciphertext ‖ tag). Call once per chunk and keep the result for retries. */
export async function encryptChunk(fileKey: Uint8Array, nonceBase: Uint8Array, fileId: string, index: number, chunkCount: number, plaintext: Uint8Array): Promise<Uint8Array> {
  checkPosition(fileId, index, chunkCount);
  if (plaintext.length > ATTACHMENT_CHUNK_SIZE) throw new Error("chunk is too large");
  const k = await importChunkKey(fileKey);
  return new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: chunkNonce(nonceBase, index) as BufferSource, additionalData: utf8.encode(aadChunk(fileId, index, chunkCount)) as BufferSource }, k, plaintext as BufferSource));
}

/** Decrypts one chunk; a wrong key, position, total, file or any changed byte is decrypt_failed. */
export async function decryptChunk(fileKey: Uint8Array, nonceBase: Uint8Array, fileId: string, index: number, chunkCount: number, ciphertext: Uint8Array): Promise<Uint8Array> {
  checkPosition(fileId, index, chunkCount);
  if (ciphertext.length < ATTACHMENT_TAG_BYTES || ciphertext.length > ATTACHMENT_CHUNK_SIZE + ATTACHMENT_TAG_BYTES) throw new CryptoError("decrypt_failed");
  const k = await importChunkKey(fileKey);
  try {
    return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: chunkNonce(nonceBase, index) as BufferSource, additionalData: utf8.encode(aadChunk(fileId, index, chunkCount)) as BufferSource }, k, ciphertext as BufferSource));
  } catch {
    throw new CryptoError("decrypt_failed");
  }
}

/** Streaming SHA-256 (hex) for whole-file checks: update with each plaintext chunk in order, then digest. */
export async function sha256Stream(): Promise<{ update(data: Uint8Array): void; digest(): string }> {
  const h = await createSHA256();
  h.init();
  return { update: (d) => { h.update(d); }, digest: () => h.digest("hex") };
}

/** base64url of the nonce base (how the API carries it). */
export const encodeNonceBase = (n: Uint8Array) => b64url.encode(n);
export function decodeNonceBase(s: string): Uint8Array {
  const n = b64url.decode(s);
  if (n.length !== ATTACHMENT_NONCE_BASE_BYTES) throw new CryptoError("bad_envelope", "nonce base must be 8 bytes");
  return n;
}

/**
 * Decrypts and checks a whole file from chunks delivered in any order by `fetchChunk`: exactly `chunkCount` chunks,
 * each at its own position, each the planned length, the total equal to `meta.size` and the SHA-256 equal to
 * `meta.sha256`. `sink` gets the plaintext chunks in order. Throws CryptoError("decrypt_failed") on any mismatch.
 */
export async function decryptAttachment(o: {
  fileId: string; fileKey: Uint8Array; nonceBase: Uint8Array; meta: AttachmentMeta;
  fetchChunk: (index: number) => Promise<Uint8Array>; sink: (plain: Uint8Array, index: number) => void | Promise<void>;
  parallel?: number; signal?: AbortSignal; onProgress?: (doneBytes: number) => void;
}): Promise<void> {
  const { fileId, fileKey, nonceBase, meta } = o;
  const m = validateAttachmentMeta(meta);
  const hasher = await sha256Stream();
  const ready = new Map<number, Uint8Array>();
  let next = 0, done = 0, fetched = 0;
  const parallel = Math.max(1, Math.min(o.parallel ?? 3, 8));
  // One flush at a time (a chain), so the sink and the hash see the chunks strictly in order.
  let flushing: Promise<void> = Promise.resolve();
  const flush = () => (flushing = flushing.then(drain));
  const drain = async () => {
    while (ready.has(next)) {
      const p = ready.get(next)!;
      ready.delete(next);
      hasher.update(p);
      await o.sink(p, next);
      done += p.length;
      o.onProgress?.(done);
      next++;
    }
  };
  let failure: unknown = null;
  const worker = async () => {
    for (;;) {
      if (failure) return;
      o.signal?.throwIfAborted();
      const i = fetched++;
      if (i >= m.chunkCount) return;
      const ct = await o.fetchChunk(i);
      const pt = await decryptChunk(fileKey, nonceBase, fileId, i, m.chunkCount, ct);
      if (pt.length !== chunkPlainBytes(m.size, i)) throw new CryptoError("decrypt_failed", "chunk length doesn't match the file");
      ready.set(i, pt);
      // Hand over what is in order first: the worker that brings chunk `next` must never wait behind the window.
      await flush();
      // Back-pressure: never more than a few decrypted chunks wait for an earlier one (this one isn't fetching more).
      while (ready.size > parallel * 2 && !failure) await new Promise((r) => setTimeout(r, 5));
    }
  };
  await Promise.all(Array.from({ length: parallel }, () => worker().catch((e: unknown) => { failure ??= e; })));
  if (failure) throw failure;
  await flush();
  if (next !== m.chunkCount || done !== m.size) throw new CryptoError("decrypt_failed", "file is incomplete");
  if (hasher.digest() !== m.sha256) throw new CryptoError("decrypt_failed", "file hash doesn't match");
}
