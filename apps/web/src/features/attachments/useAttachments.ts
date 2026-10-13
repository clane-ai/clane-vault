import { useCallback, useMemo, useSyncExternalStore } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { decodeNonceBase, decryptAttachmentMeta, unwrapFileKey, type AttachmentMeta } from "@clane-vault/crypto";
import { toast } from "sonner";
import { ApiError } from "@/lib/api";
import { useOrgPolicies } from "@/lib/policies";
import { useOrgApi, useScope } from "@/lib/scope";
import { useSession } from "@/lib/session";
import type { SyncAttachment, VaultRecord } from "@/features/vault/types";
import { fetchPlain, pickSaveTarget, saveFile, type FileSource } from "./downloader";
import { plainSize } from "./format";
import { trackDownload } from "./transfers";
import { precheck, startUpload, subscribeUploads, uploadsSnapshot, type UploadItem } from "./uploader";

/** A file row: what the server sent and, when it opens, its metadata (null: "Can't open this file"). */
export interface FileRow { att: SyncAttachment; meta: AttachmentMeta | null; size: number }

export interface AttachmentLimits { enabled: boolean; maxFileMb: number; maxPerRecord: number; maxRecordMb: number; uploadsAllowed: boolean; previews: boolean }

/** The server's limits for files (GET /attachments/limits) with the active org's policy applied (it can only lower them). */
export function useAttachmentLimits(): AttachmentLimits {
  const oapi = useOrgApi();
  const { offline, user } = useSession();
  const policy = useOrgPolicies().attachments;
  const q = useQuery({
    queryKey: ["attachment-limits", user?.id ?? ""], enabled: !offline && !!user, staleTime: 10 * 60_000, retry: false,
    queryFn: () => oapi.get<{ enabled: boolean; maxFileMb: number; maxPerRecord: number; maxRecordMb: number }>("/attachments/limits")
      .catch((e: unknown) => { if (e instanceof ApiError && e.status === 404) return { enabled: false, maxFileMb: 0, maxPerRecord: 0, maxRecordMb: 0 }; throw e; }),
  });
  const s = q.data ?? { enabled: true, maxFileMb: 100, maxPerRecord: 25, maxRecordMb: 250 };
  return { ...s, maxFileMb: Math.min(s.maxFileMb, policy.maxFileMb ?? Infinity), uploadsAllowed: s.enabled && policy.allowed, previews: policy.previews };
}

/** A record's files with their metadata decrypted under the record key (lazily, per record; wiped with the vault cache on lock). */
export function useFileRows(record: VaultRecord): { rows: FileRow[]; loading: boolean } {
  const scope = useScope();
  const atts = useMemo(() => record.attachments ?? [], [record.attachments]);
  const ids = atts.map((a) => a.id).join(",");
  const q = useQuery({
    queryKey: ["vault", scope, "att-meta", record.id, ids], enabled: atts.length > 0 && !!record.recordKey, staleTime: Infinity,
    queryFn: async () => {
      const rk = record.recordKey!.slice();
      try {
        if (rk.every((b) => b === 0)) throw new Error("Vault locked");
        return Promise.all(atts.map(async (a): Promise<FileRow> => ({ att: a, size: plainSize(a), meta: await decryptAttachmentMeta(record.id, a.id, a.encMeta, rk).catch(() => null) })));
      } finally { rk.fill(0); }
    },
  });
  const rows = q.data ?? atts.map((a) => ({ att: a, meta: null, size: plainSize(a) }));
  return { rows, loading: q.isLoading && atts.length > 0 };
}

/** Uploads in progress (or failed) for a record, from the uploader. */
export function useUploads(recordId?: string): UploadItem[] {
  const all = useSyncExternalStore(subscribeUploads, uploadsSnapshot, uploadsSnapshot);
  return useMemo(() => (recordId ? all.filter((u) => u.recordId === recordId) : all), [all, recordId]);
}

/** Starting uploads on an existing record: limits checked before any request, the vault refreshed as each one finishes. */
export function useAttach(record: VaultRecord | null) {
  const oapi = useOrgApi();
  const qc = useQueryClient();
  const scope = useScope();
  const limits = useAttachmentLimits();
  const pending = useUploads(record?.id);
  return useCallback((files: File[]) => {
    if (!record) return;
    if (!record.recordKey) { toast.error("This record can't be opened."); return; }
    if (!limits.uploadsAllowed) { toast.error("Your organisation has turned file uploads off."); return; }
    const queued: { size: number }[] = pending.filter((u) => u.status !== "done" && u.status !== "cancelled");
    const existing = record.attachments ?? [];
    for (const file of files) {
      const why = precheck(file, { maxFileMb: limits.maxFileMb, maxPerRecord: limits.maxPerRecord, maxRecordMb: limits.maxRecordMb, existingFiles: existing.length,
        existingBytes: existing.reduce((s, a) => s + plainSize(a), 0), pending: queued });
      if (why) { toast.error(why); continue; }
      queued.push({ size: file.size });
      startUpload({ api: oapi, recordId: record.id, recordKey: record.recordKey, file, onDone: () => { void qc.invalidateQueries({ queryKey: ["vault", scope] }); } });
    }
  }, [record, limits, pending, oapi, qc, scope]);
}

/** The source of one file's chunks on a record (unwrapping its key under the record key). */
async function sourceFor(oapi: ReturnType<typeof useOrgApi>, record: VaultRecord, row: FileRow): Promise<FileSource> {
  if (!row.meta || !row.att.wrappedFileKey || !row.att.nonceBase) throw new Error("This file can't be opened.");
  if (!record.recordKey) throw new Error("This record can't be opened.");
  const rk = record.recordKey.slice();
  try {
    const fileKey = await unwrapFileKey(record.id, row.att.id, row.att.wrappedFileKey, rk);
    return { fileId: row.att.id, fileKey, nonceBase: decodeNonceBase(row.att.nonceBase), meta: row.meta,
      fetchChunk: (i, signal) => oapi.getBytes(`/records/${record.id}/attachments/${row.att.id}/chunks/${i}`, signal) };
  } finally { rk.fill(0); }
}

/** Download, preview and remove for a record's files. */
export function useFileActions(record: VaultRecord) {
  const oapi = useOrgApi();
  const qc = useQueryClient();
  const scope = useScope();
  /** Saves the file (asks where first when the browser can stream to disk). */
  const download = useCallback(async (row: FileRow, onProgress?: (done: number) => void) => {
    const target = row.meta ? await pickSaveTarget(row.meta.name).catch((e: unknown) => { if ((e as Error).name === "AbortError") throw e; return null; }) : null;
    const t = trackDownload();
    const src = await sourceFor(oapi, record, row);
    try { await saveFile(src, target, { signal: t.signal, onProgress }); }
    finally { src.fileKey.fill(0); t.done(); }
  }, [oapi, record]);
  /** The whole plaintext for a preview (the caller checks magic bytes before showing anything). */
  const read = useCallback(async (row: FileRow, signal?: AbortSignal, onProgress?: (done: number) => void) => {
    const t = trackDownload();
    // Stops on the caller's signal (the sheet closed) or on lock.
    const both = signal ? AbortSignal.any([signal, t.signal]) : t.signal;
    const src = await sourceFor(oapi, record, row);
    try { return await fetchPlain(src, { signal: both, onProgress }); }
    finally { src.fileKey.fill(0); t.done(); }
  }, [oapi, record]);
  const remove = useCallback(async (row: FileRow) => {
    await oapi.del(`/records/${record.id}/attachments/${row.att.id}`);
    await qc.invalidateQueries({ queryKey: ["vault", scope] });
  }, [oapi, record.id, qc, scope]);
  return { download, read, remove };
}

/** Dropping files on a record: allowed for people who can edit it, online, when the org allows uploads. */
export function useRecordDrop(record: VaultRecord | null) {
  const { offline } = useSession();
  const limits = useAttachmentLimits();
  const attach = useAttach(record);
  const canDrop = !!record && !offline && !record.deleted && (record.permission === "owner" || record.permission === "edit") && limits.uploadsAllowed && !!record.recordKey;
  return { canDrop, onFiles: attach, enabled: limits.enabled };
}
