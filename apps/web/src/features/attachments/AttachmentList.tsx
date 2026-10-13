import { useState } from "react";
import { AlertTriangle, Download, Eye, LockKeyhole, RotateCw, Trash2, X } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { relativeTime } from "@/lib/time";
import { useSession } from "@/lib/session";
import { cn } from "@/lib/utils";
import type { VaultRecord } from "@/features/vault/types";
import { DamagedFileError } from "./downloader";
import { AttachButton } from "./AttachmentDropZone";
import { fileIcon, formatBytes } from "./format";
import { PreviewSheet } from "./PreviewSheet";
import { isExecutable, previewKindOf } from "./previewSinks";
import { cancelUpload, dismissUpload, retryUpload, type UploadItem } from "./uploader";
import { useAttach, useAttachmentLimits, useFileActions, useFileRows, useUploads, type FileRow } from "./useAttachments";

function UploadRow({ u }: { u: UploadItem }) {
  const pct = u.size ? Math.round((100 * u.sent) / u.size) : 100;
  const failed = u.status === "failed";
  return (
    <li className="flex flex-col gap-1.5 border-b border-border-default px-4 py-3 last:border-b-0" data-testid="upload-row" aria-label={`Uploading ${u.name}`}>
      <div className="flex items-center gap-2">
        <span className="min-w-0 flex-1 truncate text-[13.5px] text-text-primary">{u.name}</span>
        {failed ? <>
          <Button type="button" variant="ghost" size="sm" onClick={() => void retryUpload(u.key)}><RotateCw className="size-3.5" />Retry</Button>
          <Button type="button" variant="ghost" size="icon" aria-label={`Dismiss ${u.name}`} onClick={() => dismissUpload(u.key)}><X className="size-4" /></Button>
        </> : u.status !== "done" && <Button type="button" variant="ghost" size="sm" onClick={() => cancelUpload(u.key)}>Cancel</Button>}
      </div>
      {failed ? <p role="alert" className="text-[12.5px] text-red-500">{u.error}</p> : <>
        <div className="h-1.5 overflow-hidden rounded-full bg-well" role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={pct} aria-label={`${u.name} upload progress`}>
          <div className="h-full rounded-full bg-blue-500 transition-[width] duration-200" style={{ width: `${pct}%` }} />
        </div>
        <p className="font-mono text-[11.5px] text-text-tertiary">
          {u.status === "hashing" ? "Encrypting…" : u.status === "completing" ? "Finishing…" : u.status === "done" ? "Uploaded" : `${formatBytes(u.sent)} of ${formatBytes(u.size)}`}
        </p>
      </>}
    </li>
  );
}

function FileLine({ row, opening, canDownload, canRemove, offline, previews, onPreview, onDownload, onRemove, busy }: {
  row: FileRow; /** Metadata still being decrypted. */ opening: boolean; canDownload: boolean; canRemove: boolean; offline: boolean; previews: boolean;
  onPreview: () => void; onDownload: () => void; onRemove: () => void; busy: string | null;
}) {
  const [confirm, setConfirm] = useState<"remove" | "exe" | null>(null);
  const m = row.meta;
  const Icon = m ? fileIcon(m.mime, m.name) : AlertTriangle;
  const exe = !!m && isExecutable(m.name, m.mime);
  const canPreview = !!m && previews && !!previewKindOf(m.mime, m.size);
  return (
    <li className="flex flex-col gap-2 border-b border-border-default px-4 py-3 last:border-b-0" data-testid="file-row">
      <div className="flex items-center gap-3">
        <span className={cn("grid size-8 shrink-0 place-items-center rounded-[8px]", m || opening ? "bg-well text-text-secondary" : "bg-red-tint text-red-500")}>{opening ? null : <Icon className="size-4" />}</span>
        <span className="min-w-0 flex-1">
          <span className="flex items-center gap-1.5 text-[14px] text-text-primary">
            <span className="min-w-0 break-all">{m ? m.name : opening ? "Opening…" : "Can't open this file"}</span>
            {!canDownload && m && <LockKeyhole aria-label="Locked" className="size-3.5 shrink-0 text-text-tertiary" />}
          </span>
          <span className="block text-[12px] leading-snug text-text-secondary">
            {formatBytes(row.size)} · Added by {row.att.createdByName} · <span title={new Date(row.att.createdAt).toLocaleString()}>{relativeTime(row.att.createdAt)}</span>
            {offline && " · Available online"}
          </span>
        </span>
        {m && canDownload && (
          <span className="-mr-2 flex shrink-0 items-center gap-0.5">
            {busy ? <span className="px-2 font-mono text-[11.5px] text-text-tertiary" role="status">{busy}</span> : <>
              {canPreview && <Button type="button" variant="ghost" size="icon" aria-label={`Preview ${m.name}`} title="Preview" disabled={offline} onClick={onPreview}><Eye className="size-4" /></Button>}
              <Button type="button" variant="ghost" size="icon" aria-label={`Download ${m.name}`} title="Download" disabled={offline} onClick={() => (exe ? setConfirm("exe") : onDownload())}><Download className="size-4" /></Button>
            </>}
            {canRemove && !busy && <Button type="button" variant="ghost" size="icon" aria-label={`Remove ${m.name}`} title="Remove" disabled={offline} className="hover:bg-red-tint hover:text-red-500" onClick={() => setConfirm("remove")}><Trash2 className="size-4" /></Button>}
          </span>
        )}
      </div>
      {confirm === "exe" && m && (
        <div role="alert" className="flex flex-wrap items-center gap-2 rounded-[10px] border border-amber-500/40 bg-amber-500/10 px-3 py-2">
          <p className="min-w-0 flex-1 text-[12.5px] text-text-primary">{m.name} is a program added by {row.att.createdByName}. Only open it if you expected it.</p>
          <Button type="button" variant="ghost" size="sm" onClick={() => setConfirm(null)}>Cancel</Button>
          <Button type="button" variant="outline" size="sm" onClick={() => { setConfirm(null); onDownload(); }}>Download anyway</Button>
        </div>
      )}
      {confirm === "remove" && m && (
        <div className="flex flex-wrap items-center gap-2 rounded-[10px] border border-border-default bg-app px-3 py-2">
          <p className="min-w-0 flex-1 text-[12.5px] text-text-primary">Remove {m.name}? Everyone who can open this record loses it.</p>
          <Button type="button" variant="ghost" size="sm" onClick={() => setConfirm(null)}>Cancel</Button>
          <Button type="button" variant="destructive" size="sm" onClick={() => { setConfirm(null); onRemove(); }}>Remove</Button>
        </div>
      )}
    </li>
  );
}

/**
 * The record panel's Files section (docs/attachments.md), the same for every record type: each file with its size and
 * who added it; Preview (allowlisted types only), Download and Remove by permission. "Use only" holders see the list
 * with a lock and no buttons (the server refuses them the bytes). Offline: listed, "Available online".
 */
export function FilesSection({ record, editor }: { record: VaultRecord; /** In the editor: "files are saved as they upload". */ editor?: boolean }) {
  const { offline } = useSession();
  const limits = useAttachmentLimits();
  const all = useUploads(record.id);
  const { rows, loading } = useFileRows(record);
  // A finished upload gives way to its file row as soon as the vault lists it.
  const uploads = all.filter((u) => u.status !== "cancelled" && !(u.status === "done" && rows.some((r) => r.att.id === u.fileId)));
  const attach = useAttach(record);
  const actions = useFileActions(record);
  const [preview, setPreview] = useState<FileRow | null>(null);
  const [busy, setBusy] = useState<Record<string, string>>({});
  const canEdit = (record.permission === "owner" || record.permission === "edit") && !record.deleted;
  const canDownload = record.permission !== "use";
  const canAdd = canEdit && !offline && limits.uploadsAllowed && !!record.recordKey;
  if (!limits.enabled && rows.length === 0) return null;
  if (!rows.length && !uploads.length && !canAdd) return null;

  async function download(row: FileRow) {
    const id = row.att.id;
    const total = row.meta?.size ?? 0;
    setBusy((b) => ({ ...b, [id]: "0 %" }));
    try {
      await actions.download(row, (done) => setBusy((b) => ({ ...b, [id]: `${total ? Math.floor((100 * done) / total) : 100} %` })));
    } catch (e) {
      if ((e as Error).name !== "AbortError") toast.error(e instanceof DamagedFileError ? e.message : "Couldn't download the file. Try again.");
    } finally { setBusy((b) => { const n = { ...b }; delete n[id]; return n; }); }
  }
  async function remove(row: FileRow) {
    try { await actions.remove(row); toast.success("File removed"); }
    catch { toast.error("Couldn't remove the file. Try again."); }
  }

  return (
    <section className="flex flex-col gap-2" aria-label="Files">
      <div className="flex items-center justify-between gap-2">
        <h3 className="font-mono text-[10.5px] font-normal tracking-[.12em] text-text-tertiary uppercase">Files{rows.length ? ` · ${rows.length}` : ""}</h3>
        {canAdd && <AttachButton onFiles={attach} />}
      </div>
      {(rows.length > 0 || uploads.length > 0) && (
        <ul className="overflow-hidden rounded-[12px] border border-border-default bg-card">
          {rows.map((r) => (
            <FileLine key={r.att.id} row={r} opening={loading} canDownload={canDownload && !record.deleted} canRemove={canEdit} offline={offline} previews={limits.previews}
              busy={busy[r.att.id] ?? null} onPreview={() => setPreview(r)} onDownload={() => void download(r)} onRemove={() => void remove(r)} />
          ))}
          {uploads.map((u) => <UploadRow key={u.key} u={u} />)}
        </ul>
      )}
      {!canDownload && rows.length > 0 && <p className="text-[12px] text-text-secondary">Use only: you can see these files, not open them. Ask the owner for Can view to download.</p>}
      {record.deleted && rows.length > 0 && <p className="text-[12px] text-text-secondary">Restore the record to open its files.</p>}
      {offline && rows.length > 0 && <p className="text-[12px] text-text-secondary">Files need a connection: they aren't part of the offline copy.</p>}
      {editor && canAdd && <p className="text-[12px] text-text-tertiary">Files are saved as they upload, separately from the record's fields.</p>}
      {!rows.length && !uploads.length && canAdd && !editor && <p className="text-[12.5px] text-text-tertiary">No files yet. Attach one or drop it on this panel. Files are encrypted on this device before they're uploaded.</p>}
      <PreviewSheet row={preview} read={actions.read} onDownload={(r) => void download(r)} onClose={() => setPreview(null)} />
    </section>
  );
}
