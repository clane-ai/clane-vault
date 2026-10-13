import {
  ATTACHMENT_CHUNK_SIZE, attachmentCiphertextSize, attachmentMetaFor, chunkPlan, encodeNonceBase, encryptAttachmentMeta, encryptChunk, newAttachment,
  sha256Stream, wrapFileKey, type AttachmentMeta,
} from "@clane-vault/crypto";
import { ApiError, type OrgApi } from "@/lib/api";
import { formatBytes } from "./format";

/**
 * The upload state machine (docs/attachments.md, spec 2026-10-12-attachments.md §4.1–4.3, §2.2):
 *   hash → reserve (POST) → chunks, 3 at a time (PUT) → complete (POST)
 * Each chunk is encrypted once and its ciphertext kept until the server accepted it; retries (and Retry after a
 * failure) resend those exact bytes. A file key is never used to encrypt a chunk index twice: a fresh start (the server
 * lost the upload, or answered chunk_mismatch) is a new file id with a new key. Nothing survives a reload (no resume
 * state is stored anywhere); locking the vault cancels every upload and zeroes its keys.
 */

export type UploadStatus = "hashing" | "uploading" | "completing" | "failed" | "done" | "cancelled";
export interface UploadItem {
  key: string; recordId: string; name: string; size: number;
  /** Plaintext bytes the server has accepted. */ sent: number;
  status: UploadStatus; error?: string;
  /** The attachment id of the current attempt (the file row that replaces this one when it's done). */ fileId?: string;
}

interface Job {
  item: UploadItem; file: Blob & { name: string; type: string }; api: OrgApi; recordKey: Uint8Array; onDone?: () => void;
  fid: string | null; fileKey: Uint8Array | null; nonceBase: Uint8Array | null; meta: AttachmentMeta | null;
  /** SHA-256 of each plaintext chunk from the hash pass: a file that changes on disk meanwhile is caught. */
  chunkHashes: string[];
  /** Ciphertext encrypted under the current key and not yet accepted (resent on retry). */
  kept: Map<number, Uint8Array>;
  /** Every index ever encrypted under the current key (never encrypted again). */
  encrypted: Set<number>;
  accepted: Set<number>;
  controller: AbortController;
  restarts: number;
}

export const UPLOAD_PARALLEL = 3;
const RETRIES = 3;
const MAX_RESTARTS = 1;

const jobs = new Map<string, Job>();
let snapshot: UploadItem[] = [];
const listeners = new Set<() => void>();
function emit() {
  snapshot = [...jobs.values()].map((j) => ({ ...j.item }));
  for (const l of listeners) l();
}
export const subscribeUploads = (l: () => void) => { listeners.add(l); return () => { listeners.delete(l); }; };
export const uploadsSnapshot = () => snapshot;
const active = (s: UploadStatus) => s === "hashing" || s === "uploading" || s === "completing";
export const uploadsInFlight = () => snapshot.some((u) => active(u.status));

/** Leaving the page with uploads in flight asks first (the ciphertext in memory would be lost). */
function guardUnload(e: BeforeUnloadEvent) { if (uploadsInFlight()) { e.preventDefault(); e.returnValue = ""; } }
if (typeof window !== "undefined") window.addEventListener("beforeunload", guardUnload);

class Stop extends Error { constructor(public readonly reason: "cancelled" | "restart" | "fatal", message: string = reason) { super(message); } }

const hex = (b: ArrayBuffer) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
const slice = async (f: Blob, i: number) => new Uint8Array(await f.slice(i * ATTACHMENT_CHUNK_SIZE, Math.min((i + 1) * ATTACHMENT_CHUNK_SIZE, f.size)).arrayBuffer());

/** What the server's refusals mean to the person uploading. */
export function uploadErrorMessage(e: unknown, name: string): string {
  if (!(e instanceof ApiError)) return e instanceof Stop && e.reason === "fatal" ? e.message : "The upload failed. Check your connection and retry.";
  const b = (e.body ?? {}) as { max?: number; maxMb?: number; scope?: string };
  switch (e.code) {
    case "file_too_large": return `${name} is larger than the ${b.max ?? "allowed"} MB limit.`;
    case "quota_exceeded": return b.scope === "org" ? "Your organisation's file storage is full. Remove files or ask an admin." : b.scope === "user" ? "Your file storage is full. Remove some files first." : "This server's file storage is full. Ask the server admin.";
    case "too_many_files": return `A record holds at most ${b.max ?? 25} files.`;
    case "record_too_large": return `A record's files can add up to at most ${b.maxMb ?? 250} MB.`;
    case "daily_upload_limit": return "You've reached today's upload limit. Try again tomorrow.";
    case "attachments_disabled": return "Your organisation has turned file uploads off.";
    case "in_trash": return "This record is in the trash.";
    case "forbidden": case "not_found": return "You can't add files to this record.";
    case "rate_limited": return "Too many requests. Wait a minute and retry.";
    default: return "The upload failed. Check your connection and retry.";
  }
}

async function withRetry<T>(j: Job, fn: () => Promise<T>): Promise<T> {
  for (let attempt = 0; ; attempt++) {
    if (j.controller.signal.aborted) throw new Stop("cancelled");
    try { return await fn(); }
    catch (e) {
      if (j.controller.signal.aborted) throw new Stop("cancelled");
      // Only network trouble, rate limits and server errors are worth repeating with the same bytes.
      const transient = !(e instanceof ApiError) || e.status >= 500 || e.status === 429;
      if (!transient || attempt >= RETRIES - 1) throw e;
      await new Promise((r) => setTimeout(r, 400 * 2 ** attempt));
    }
  }
}

function zeroKeys(j: Job) { j.fileKey?.fill(0); j.fileKey = null; j.kept.clear(); }

/** A fresh start: a new id, key and nonce base; nothing encrypted under the old key is reused. */
function freshKey(j: Job) {
  zeroKeys(j);
  const a = newAttachment(j.file.size);
  j.fid = crypto.randomUUID(); j.fileKey = a.fileKey; j.nonceBase = a.nonceBase; j.item.fileId = j.fid;
  j.encrypted = new Set(); j.accepted = new Set(); j.item.sent = 0;
}

async function hashPass(j: Job) {
  const { chunkCount } = chunkPlan(j.file.size);
  const whole = await sha256Stream();
  j.chunkHashes = [];
  for (let i = 0; i < chunkCount; i++) {
    if (j.controller.signal.aborted) throw new Stop("cancelled");
    const p = await slice(j.file, i);
    whole.update(p);
    j.chunkHashes.push(hex(await crypto.subtle.digest("SHA-256", p as BufferSource)));
  }
  j.meta = attachmentMetaFor({ name: j.file.name, type: j.file.type, size: j.file.size }, whole.digest());
}

async function reserve(j: Job) {
  const fid = j.fid!, meta = j.meta!;
  const body = {
    id: fid, encMeta: await encryptAttachmentMeta(j.item.recordId, fid, meta, j.recordKey), wrappedFileKey: await wrapFileKey(j.item.recordId, fid, j.fileKey!, j.recordKey),
    nonceBase: encodeNonceBase(j.nonceBase!), size: attachmentCiphertextSize(j.file.size), chunkSize: ATTACHMENT_CHUNK_SIZE, chunkCount: meta.chunkCount,
  };
  try { await withRetry(j, () => j.api.post(`/records/${j.item.recordId}/attachments`, body)); }
  catch (e) {
    // A retried create whose first answer got lost: the reservation is ours if the server lists it as our upload.
    if (!(e instanceof ApiError && e.code === "exists")) throw e;
    await j.api.get(`/records/${j.item.recordId}/attachments/${fid}/upload`);
  }
}

/** Whether the server already holds this attempt as a ready file. */
async function isReady(j: Job): Promise<boolean> {
  try { return (await j.api.get<{ state: string }>(`/records/${j.item.recordId}/attachments/${j.fid}/upload`)).state === "ready"; }
  catch { return false; }
}

/** The ciphertext of chunk `i`: kept from an earlier attempt, or encrypted now (once). */
async function cipherFor(j: Job, i: number): Promise<Uint8Array> {
  const kept = j.kept.get(i);
  if (kept) return kept;
  if (j.encrypted.has(i)) throw new Stop("restart", "chunk ciphertext lost");
  const p = await slice(j.file, i);
  if (hex(await crypto.subtle.digest("SHA-256", p as BufferSource)) !== j.chunkHashes[i]) throw new Stop("fatal", `${j.item.name} changed while it was uploading. Add it again.`);
  j.encrypted.add(i);
  const ct = await encryptChunk(j.fileKey!, j.nonceBase!, j.fid!, i, j.meta!.chunkCount, p);
  j.kept.set(i, ct);
  return ct;
}

async function sendChunks(j: Job) {
  const n = j.meta!.chunkCount;
  const todo = Array.from({ length: n }, (_, i) => i).filter((i) => !j.accepted.has(i));
  let next = 0;
  const worker = async () => {
    while (next < todo.length) {
      const i = todo[next++]!;
      const ct = await cipherFor(j, i);
      try {
        await withRetry(j, () => j.api.putBytes(`/records/${j.item.recordId}/attachments/${j.fid}/chunks/${i}`, ct, j.controller.signal));
      } catch (e) {
        if (e instanceof ApiError && e.code === "chunk_mismatch") throw new Stop("restart");
        throw e;
      }
      j.kept.delete(i);
      j.accepted.add(i);
      j.item.sent += i === n - 1 ? j.file.size - (n - 1) * ATTACHMENT_CHUNK_SIZE : ATTACHMENT_CHUNK_SIZE;
      emit();
    }
  };
  const results = await Promise.allSettled(Array.from({ length: Math.min(UPLOAD_PARALLEL, todo.length) }, worker));
  const failed = results.find((r): r is PromiseRejectedResult => r.status === "rejected");
  if (failed) throw failed.reason;
}

async function run(j: Job) {
  try {
    for (;;) {
      try {
        if (!j.meta) { j.item.status = "hashing"; emit(); await hashPass(j); }
        if (!j.fid) { freshKey(j); await reserve(j); }
        j.item.status = "uploading"; emit();
        await sendChunks(j);
        j.item.status = "completing"; emit();
        try { await withRetry(j, () => j.api.post(`/records/${j.item.recordId}/attachments/${j.fid}/complete`, {})); }
        catch (e) {
          // Some chunk didn't land after all (a lost answer): send what's missing, then complete.
          if (e instanceof ApiError && e.code === "incomplete") { for (const m of (e.body as { missing?: number[] }).missing ?? []) j.accepted.delete(m); continue; }
          // An earlier complete landed but its answer was lost: the file is ready (never cancel it as a failed upload).
          if (e instanceof ApiError && e.code === "not_uploading" && await isReady(j)) break;
          throw e;
        }
        break;
      } catch (e) {
        if (e instanceof Stop && e.reason === "restart" && j.restarts < MAX_RESTARTS) {
          j.restarts++;
          const old = j.fid;
          j.fid = null;
          if (old) void j.api.del(`/records/${j.item.recordId}/attachments/${old}`).catch(() => undefined);
          continue;
        }
        throw e;
      }
    }
    j.item.status = "done"; j.item.sent = j.file.size;
    finish(j);
    j.onDone?.();
    // Done rows leave the list once the vault shows the file.
    setTimeout(() => { jobs.delete(j.item.key); emit(); }, 1500);
  } catch (e) {
    if (e instanceof Stop && e.reason === "cancelled") return;
    j.item.status = "failed";
    j.item.error = uploadErrorMessage(e, j.item.name);
    // A refusal that a retry can't change ends the upload for good.
    if (e instanceof ApiError && e.status < 500 && e.status !== 429) { const fid = j.fid; j.fid = null; finish(j); if (fid) void j.api.del(`/records/${j.item.recordId}/attachments/${fid}`).catch(() => undefined); }
    emit();
  }
}

function finish(j: Job) { zeroKeys(j); j.recordKey.fill(0); emit(); }

export interface StartUpload {
  api: OrgApi; recordId: string;
  /** Copied: the uploader zeroes its copy when the upload ends. */ recordKey: Uint8Array;
  file: Blob & { name: string; type: string }; onDone?: () => void;
}

/** Starts one upload; returns its key (for cancel and retry). */
export function startUpload(s: StartUpload): string {
  const key = crypto.randomUUID();
  const j: Job = {
    item: { key, recordId: s.recordId, name: s.file.name || "file", size: s.file.size, sent: 0, status: "hashing" },
    file: s.file, api: s.api, recordKey: s.recordKey.slice(), onDone: s.onDone,
    fid: null, fileKey: null, nonceBase: null, meta: null, chunkHashes: [], kept: new Map(), encrypted: new Set(), accepted: new Set(),
    controller: new AbortController(), restarts: 0,
  };
  jobs.set(key, j);
  emit();
  void run(j);
  return key;
}

/** Retry after a failure, in the same session: what the server already has stays, kept ciphertext is resent as is. */
export async function retryUpload(key: string): Promise<void> {
  const j = jobs.get(key);
  if (!j || j.item.status !== "failed") return;
  if (j.recordKey.every((b) => b === 0)) { j.item.error = "Add the file again."; emit(); return; }
  j.item.error = undefined; j.item.status = "uploading"; j.controller = new AbortController(); emit();
  if (j.fid) {
    try {
      const st = await j.api.get<{ state: string; received: number[] }>(`/records/${j.item.recordId}/attachments/${j.fid}/upload`);
      if (st.state === "uploading") for (const i of st.received) { j.accepted.add(i); j.kept.delete(i); }
    } catch (e) {
      // The server no longer has it (expired or swept): start over under a new key.
      if (e instanceof ApiError && e.status === 404) j.fid = null;
    }
  }
  void run(j);
}

/** Cancels an upload: stops sending, tells the server to drop it, zeroes the keys. */
export function cancelUpload(key: string): void {
  const j = jobs.get(key);
  if (!j) return;
  j.controller.abort();
  const fid = j.fid;
  if (fid && j.item.status !== "done") void j.api.del(`/records/${j.item.recordId}/attachments/${fid}`).catch(() => undefined);
  j.item.status = "cancelled";
  finish(j);
  jobs.delete(key);
  emit();
}

/** Dismisses a failed row. */
export const dismissUpload = (key: string) => cancelUpload(key);

/** Locking the vault (or signing out): every upload stops and forgets its keys. */
export function cancelAllUploads(): void { for (const k of [...jobs.keys()]) cancelUpload(k); }

/** Refuses a file before any request when it can't fit (size, count, record total), with the exact limit. */
export function precheck(file: { name: string; size: number }, o: { maxFileMb: number; maxPerRecord: number; maxRecordMb: number; existingFiles: number; existingBytes: number; pending: { size: number }[] }): string | null {
  if (file.size > o.maxFileMb * 1024 * 1024) return `${file.name} is ${formatBytes(file.size)}: files can be at most ${o.maxFileMb} MB.`;
  if (o.existingFiles + o.pending.length >= o.maxPerRecord) return `A record holds at most ${o.maxPerRecord} files.`;
  const total = o.existingBytes + o.pending.reduce((s, p) => s + p.size, 0) + file.size;
  if (total > o.maxRecordMb * 1024 * 1024) return `A record's files can add up to at most ${o.maxRecordMb} MB.`;
  return null;
}

/** Tests only: forget every upload without touching the network. */
export function resetUploadsForTests() { for (const j of jobs.values()) j.controller.abort(); jobs.clear(); emit(); }
