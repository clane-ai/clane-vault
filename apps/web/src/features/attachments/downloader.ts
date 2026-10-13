import { decryptAttachment, safeFilename, type AttachmentMeta } from "@clane-vault/crypto";

/**
 * Downloads (docs/attachments.md, spec §4.4, §7.5): chunks fetched 3 at a time, each decrypted and checked as it
 * arrives, the whole file's SHA-256 compared at the end. Nothing decrypted is ever stored (no IndexedDB, no Cache API,
 * no localStorage); a file that fails any check is discarded.
 */
export interface FileSource {
  fileId: string; fileKey: Uint8Array; nonceBase: Uint8Array; meta: AttachmentMeta;
  fetchChunk: (index: number, signal?: AbortSignal) => Promise<Uint8Array>;
}

export class DamagedFileError extends Error { constructor() { super("This file is damaged. Ask the person who added it to upload it again."); this.name = "DamagedFileError"; } }

/** The whole plaintext, in order (for previews and the Blob fallback). */
export async function fetchPlain(src: FileSource, o: { signal?: AbortSignal; onProgress?: (done: number) => void } = {}): Promise<Uint8Array[]> {
  const parts: Uint8Array[] = [];
  try {
    await decryptAttachment({ fileId: src.fileId, fileKey: src.fileKey, nonceBase: src.nonceBase, meta: src.meta, parallel: 3, signal: o.signal, onProgress: o.onProgress,
      fetchChunk: (i) => src.fetchChunk(i, o.signal), sink: (p) => { parts.push(p); } });
  } catch (e) {
    parts.length = 0;
    if (e instanceof Error && (e as { code?: string }).code === "decrypt_failed") throw new DamagedFileError();
    throw e;
  }
  return parts;
}

type Writable = { write(d: Uint8Array): Promise<void>; close(): Promise<void>; abort(): Promise<void> };
type SavePicker = (o: { suggestedName: string }) => Promise<{ createWritable(): Promise<Writable> }>;

/**
 * Asks where to save first (Chrome and Edge, File System Access API: decrypted chunks stream to disk, a few MiB of
 * memory), else null. Call it straight from the click: the picker needs the user's gesture.
 */
export async function pickSaveTarget(name: string): Promise<Writable | null> {
  const picker = (window as unknown as { showSaveFilePicker?: SavePicker }).showSaveFilePicker;
  if (!picker) return null;
  const handle = await picker.call(window, { suggestedName: safeFilename(name) });
  return handle.createWritable();
}

/**
 * Saves a file: into `target` when the picker gave one (aborted, so nothing is kept, if a check fails), else as an
 * `application/octet-stream` Blob through <a download> (never a navigation, never rendered by the browser).
 */
export async function saveFile(src: FileSource, target: Writable | null, o: { signal?: AbortSignal; onProgress?: (done: number) => void } = {}): Promise<void> {
  if (target) {
    try {
      await decryptAttachment({ fileId: src.fileId, fileKey: src.fileKey, nonceBase: src.nonceBase, meta: src.meta, parallel: 3, signal: o.signal, onProgress: o.onProgress,
        fetchChunk: (i) => src.fetchChunk(i, o.signal), sink: (p) => target.write(p) });
      await target.close();
    } catch (e) {
      await target.abort().catch(() => undefined);
      if (e instanceof Error && (e as { code?: string }).code === "decrypt_failed") throw new DamagedFileError();
      throw e;
    }
    return;
  }
  const parts = await fetchPlain(src, o);
  triggerDownload(new Blob(parts as BlobPart[], { type: "application/octet-stream" }), src.meta.name);
}

/** <a download> for a Blob; the object URL is revoked right after. The Blob's type is always octet-stream. */
export function triggerDownload(blob: Blob, name: string) {
  const safe = blob.type === "application/octet-stream" ? blob : new Blob([blob], { type: "application/octet-stream" });
  const url = URL.createObjectURL(safe);
  const a = document.createElement("a");
  a.href = url;
  a.download = safeFilename(name);
  a.rel = "noopener";
  a.style.display = "none";
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
