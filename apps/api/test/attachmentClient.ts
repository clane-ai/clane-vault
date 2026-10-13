import { createHash, randomUUID } from "node:crypto";
import type { FastifyInstance, LightMyRequestResponse } from "fastify";
import { expect } from "vitest";
import {
  attachmentCiphertextSize, attachmentMetaFor, decryptAttachment, decryptAttachmentMeta, decodeNonceBase, encodeNonceBase, encryptAttachmentMeta, encryptChunk,
  newAttachment, unwrapFileKey, wrapFileKey, ATTACHMENT_CHUNK_SIZE,
} from "@clane-vault/crypto";

/**
 * A test client for attachments (docs/design/2026-10-12-attachments.md §4): the browser's uploader and
 * downloader without the browser. `who` is any signed-in test user; requests carry their active org.
 */
export type Who = { id: string; accessToken: string; orgId?: string | null };
type T = { app: FastifyInstance };
let ip = 0;
const addr = () => `10.240.${(++ip >> 8) & 255}.${ip & 255}`;

export const sha = (u: Uint8Array) => createHash("sha256").update(u).digest("hex");
export function bytes(n: number, seed = 7): Uint8Array {
  const u = new Uint8Array(n);
  let x = seed;
  for (let i = 0; i < n; i++) { x = (x * 1103515245 + 12345) >>> 0; u[i] = x >>> 24; }
  return u;
}

export function attReq(t: T, u: Who, method: "GET" | "POST" | "PUT" | "DELETE" | "PATCH", url: string, payload?: unknown, o: { org?: string | null; raw?: boolean; ip?: string; contentType?: string } = {}) {
  const org = o.org === undefined ? u.orgId : o.org;
  return t.app.inject({ method, url: `/api/v1${url}`, remoteAddress: o.ip ?? addr(),
    headers: { authorization: `Bearer ${u.accessToken}`, ...(org ? { "x-org-id": org } : {}), ...(o.raw ? { "content-type": o.contentType ?? "application/octet-stream" } : {}) },
    ...(payload !== undefined ? { payload: payload as string } : {}) });
}

/** Everything an upload needs before the first request, encrypted the way the web client does it. */
export async function prepare(recordId: string, recordKey: Uint8Array, data: Uint8Array, name = "report.pdf", type = "application/pdf") {
  const id = randomUUID();
  const a = newAttachment(data.length);
  const meta = attachmentMetaFor({ name, type, size: data.length }, sha(data));
  const chunks: Uint8Array[] = [];
  for (let i = 0; i < a.chunkCount; i++) chunks.push(await encryptChunk(a.fileKey, a.nonceBase, id, i, a.chunkCount, data.subarray(i * ATTACHMENT_CHUNK_SIZE, Math.min((i + 1) * ATTACHMENT_CHUNK_SIZE, data.length))));
  const body = { id, encMeta: await encryptAttachmentMeta(recordId, id, meta, recordKey), wrappedFileKey: await wrapFileKey(recordId, id, a.fileKey, recordKey),
    nonceBase: encodeNonceBase(a.nonceBase), size: attachmentCiphertextSize(data.length), chunkSize: ATTACHMENT_CHUNK_SIZE, chunkCount: a.chunkCount };
  return { id, body, chunks, meta, fileKey: a.fileKey, nonceBase: a.nonceBase };
}
export type Prepared = Awaited<ReturnType<typeof prepare>>;

export const create = (t: T, u: Who, recordId: string, p: Prepared, o: { org?: string | null } = {}) => attReq(t, u, "POST", `/records/${recordId}/attachments`, p.body, o);
export const putChunk = (t: T, u: Who, recordId: string, fid: string, index: number, data: Uint8Array, o: { org?: string | null; ip?: string } = {}) =>
  attReq(t, u, "PUT", `/records/${recordId}/attachments/${fid}/chunks/${index}`, Buffer.from(data), { ...o, raw: true });
export const complete = (t: T, u: Who, recordId: string, fid: string, o: { org?: string | null } = {}) => attReq(t, u, "POST", `/records/${recordId}/attachments/${fid}/complete`, {}, o);
export const getChunk = (t: T, u: Who, recordId: string, fid: string, index: number, o: { org?: string | null; ip?: string } = {}) =>
  attReq(t, u, "GET", `/records/${recordId}/attachments/${fid}/chunks/${index}`, undefined, o);

const ok = (r: LightMyRequestResponse, code: number) => expect(r.statusCode, r.body).toBe(code);

/** Create, every chunk, complete: a ready file. */
export async function upload(t: T, u: Who, recordId: string, recordKey: Uint8Array, data: Uint8Array, o: { org?: string | null; name?: string; type?: string } = {}) {
  const p = await prepare(recordId, recordKey, data, o.name, o.type);
  ok(await create(t, u, recordId, p, o), 201);
  for (let i = 0; i < p.chunks.length; i++) ok(await putChunk(t, u, recordId, p.id, i, p.chunks[i]!, o), 200);
  ok(await complete(t, u, recordId, p.id, o), 200);
  return p;
}

/** What a reader does: list, unwrap with the record key, fetch every chunk, decrypt and check. Returns the plaintext. */
export async function download(t: T, u: Who, recordId: string, recordKey: Uint8Array, fid: string, o: { org?: string | null } = {}): Promise<Buffer> {
  const list = await attReq(t, u, "GET", `/records/${recordId}/attachments`, undefined, o);
  ok(list, 200);
  const row = (list.json().attachments as { id: string; encMeta: string; wrappedFileKey: string; nonceBase: string }[]).find((x) => x.id === fid);
  if (!row) throw new Error("not listed");
  const meta = await decryptAttachmentMeta(recordId, fid, row.encMeta, recordKey);
  const fileKey = await unwrapFileKey(recordId, fid, row.wrappedFileKey, recordKey);
  const parts: Uint8Array[] = [];
  await decryptAttachment({ fileId: fid, fileKey, nonceBase: decodeNonceBase(row.nonceBase), meta, sink: (p) => { parts.push(p); },
    fetchChunk: async (i) => { const r = await getChunk(t, u, recordId, fid, i, o); ok(r, 200); return new Uint8Array(r.rawPayload); } });
  return Buffer.concat(parts);
}
