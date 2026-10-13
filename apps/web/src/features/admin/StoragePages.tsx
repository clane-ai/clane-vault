import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Download, HardDrive, Paperclip, RefreshCw, TriangleAlert } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import { useOrgApi } from "@/lib/scope";
import { relativeTime } from "@/lib/time";
import { cn } from "@/lib/utils";
import { formatBytes } from "@/features/attachments/format";
import type { VaultFolder, VaultRecord } from "@/features/vault/types";
import { download } from "./risk/model";
import { INSTANCE_STORAGE_KEY, useInstanceStorage, useOrgStorage, usedPercent } from "./storage";

const card = "rounded-[14px] border border-border-default bg-card shadow-[var(--shadow-card)]";
const h2 = "font-display text-[15px] font-semibold tracking-[-0.01em] text-text-primary";
const th = "px-3 py-2 text-left font-mono text-[10.5px] font-normal tracking-[.1em] text-text-tertiary uppercase";

/** A used / quota bar: orange from 80 %, red from 90 % (uploads stop at 100 %). */
export function UsageBar({ used, quota, label }: { used: number; quota: number; label: string }) {
  const p = usedPercent(used, quota);
  return (
    <div className="flex flex-col gap-1.5">
      <div className="flex items-baseline gap-2">
        <span className="font-display text-[22px] leading-none font-semibold text-text-primary tabular-nums">{formatBytes(used)}</span>
        <span className="text-[13px] text-text-secondary">of {formatBytes(quota)}</span>
        <span className={cn("ml-auto font-mono text-[12px] tabular-nums", p > 90 ? "text-red-500" : p >= 80 ? "text-orange-ink" : "text-text-secondary")}>{p}%</span>
      </div>
      <div className="h-2 overflow-hidden rounded-full bg-well" role="progressbar" aria-label={label} aria-valuemin={0} aria-valuemax={100} aria-valuenow={p}>
        <div className={cn("h-full rounded-full", p > 90 ? "bg-red-500" : p >= 80 ? "bg-orange-500" : "bg-blue-500")} style={{ width: `${p}%` }} />
      </div>
    </div>
  );
}

/** The per-member table (Risk dashboard's Storage tile and Organisation settings → Storage), with a CSV export. */
export function StorageMembers({ onClose }: { onClose?: () => void }) {
  const q = useOrgStorage();
  const oapi = useOrgApi();
  const [exporting, setExporting] = useState(false);
  async function exportCsv() {
    setExporting(true);
    try { download(await oapi.text("/admin/storage/members.csv"), `storage-by-member-${new Date().toISOString().slice(0, 10)}.csv`); }
    catch { toast.error("Couldn't export. Try again."); }
    finally { setExporting(false); }
  }
  const members = q.data?.members ?? [];
  return (
    <section aria-label="File storage by member" className={cn(card, "flex flex-col gap-3 p-4")}>
      <div className="flex flex-wrap items-center gap-2">
        <h2 className={cn(h2, "mr-auto")}>File storage by member</h2>
        <Button type="button" variant="outline" size="sm" disabled={exporting} onClick={() => void exportCsv()}><Download className="size-3.5" />{exporting ? "Exporting…" : "Export CSV"}</Button>
        {onClose && <Button type="button" variant="ghost" size="sm" onClick={onClose}>Close</Button>}
      </div>
      <p className="text-[13px] text-text-secondary">Files on the records each member owns in this organisation's shared folders. File names and types are encrypted: only sizes are known here.</p>
      {q.isLoading ? <p className="text-[14px] text-text-secondary">Loading…</p> : q.error ? <p role="alert" className="text-[14px] text-red-500">Couldn't load storage.</p> : (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[480px] text-[13px]">
            <thead><tr className="border-b border-border-default"><th className={th}>Member</th><th className={th}>Files</th><th className={th}>Size</th></tr></thead>
            <tbody>
              {members.length === 0 && <tr><td colSpan={3} className="px-3 py-6 text-center text-text-secondary">No files yet.</td></tr>}
              {members.map((m) => (
                <tr key={m.userId} className="border-b border-border-default last:border-b-0">
                  <td className="px-3 py-2"><span className="block text-text-primary">{m.name}</span><span className="block text-[12px] text-text-secondary">{m.email}</span></td>
                  <td className="px-3 py-2 tabular-nums text-text-secondary">{m.files}</td>
                  <td className="px-3 py-2 tabular-nums text-text-primary">{formatBytes(m.bytes)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

/** Organisation settings → Storage: usage against the quota, the largest records (titles the viewer can open) and the limits. */
export function OrgStorageSection({ records, folders }: { records: VaultRecord[]; folders: VaultFolder[] }) {
  const q = useOrgStorage();
  if (q.isLoading) return <p className="text-[14px] text-text-secondary">Loading…</p>;
  if (q.error || !q.data) return <p role="alert" className="text-[14px] text-red-500">Couldn't load storage.</p>;
  const s = q.data;
  const title = (id: string) => records.find((r) => r.id === id)?.body?.title ?? null;
  const folder = (id: string | null) => (id ? folders.find((f) => f.id === id)?.name ?? null : null);
  return (
    <>
      <section className="flex flex-col gap-3">
        <h2 className={h2}>File storage</h2>
        <div className={cn(card, "flex flex-col gap-3 p-4")}>
          <UsageBar used={s.used} quota={s.quota} label="Organisation file storage used" />
          <p className="text-[13px] text-text-secondary">{s.files} {s.files === 1 ? "file" : "files"} on records in this organisation's shared folders. Uploads are refused once the quota is full; files in the trash still count until the record is deleted forever.</p>
          {usedPercent(s.used, s.quota) > 90 && <p role="alert" className="flex items-start gap-2 text-[13px] text-red-500"><TriangleAlert className="mt-0.5 size-4 shrink-0" />Over 90 % used. Remove files you no longer need, or ask the server admin for a larger quota.</p>}
        </div>
      </section>
      <section className="flex flex-col gap-3">
        <h2 className={h2}>Limits</h2>
        <ul className={cn(card, "flex flex-col divide-y divide-border-default text-[13.5px]")}>
          <li className="flex justify-between gap-3 px-4 py-2.5"><span className="text-text-secondary">Largest file</span><span className="text-text-primary">{s.limits.maxFileMb} MB{s.policy.maxFileMb ? " (your policy)" : ""}</span></li>
          <li className="flex justify-between gap-3 px-4 py-2.5"><span className="text-text-secondary">Files per record</span><span className="text-text-primary">{s.limits.maxPerRecord}</span></li>
          <li className="flex justify-between gap-3 px-4 py-2.5"><span className="text-text-secondary">All files of one record</span><span className="text-text-primary">{s.limits.maxRecordMb} MB</span></li>
          <li className="flex justify-between gap-3 px-4 py-2.5"><span className="text-text-secondary">New uploads</span><span className="text-text-primary">{s.policy.allowed ? "Allowed" : "Off (existing files stay)"}</span></li>
          <li className="flex justify-between gap-3 px-4 py-2.5"><span className="text-text-secondary">Previews</span><span className="text-text-primary">{s.policy.previews ? "Images, PDFs and text" : "Off: download only"}</span></li>
          <li className="flex justify-between gap-3 px-4 py-2.5"><span className="text-text-secondary">Files in one-time links</span><span className="text-text-primary">{s.policy.linksAllowAttachments ? "Allowed (opt-in per link)" : "Not allowed"}</span></li>
        </ul>
        <p className="text-[12.5px] text-text-tertiary">Change these in Policies. The server's own limit ({s.limits.serverMaxFileMb} MB a file) can only be lowered by policy.</p>
      </section>
      <section className="flex flex-col gap-3">
        <h2 className={h2}>Largest records</h2>
        <div className={cn(card, "overflow-x-auto")}>
          <table className="w-full min-w-[520px] text-[13px]">
            <thead><tr className="border-b border-border-default"><th className={th}>Record</th><th className={th}>Owner</th><th className={th}>Folder</th><th className={th}>Files</th><th className={th}>Size</th></tr></thead>
            <tbody>
              {s.largest.length === 0 && <tr><td colSpan={5} className="px-3 py-6 text-center text-text-secondary">No files yet.</td></tr>}
              {s.largest.map((r) => (
                <tr key={r.recordId} className="border-b border-border-default last:border-b-0">
                  <td className="px-3 py-2 text-text-primary">{title(r.recordId) ?? <span className="font-mono text-[12px] text-text-tertiary" title="You can't open this record">{r.recordId.slice(0, 8)}…</span>}</td>
                  <td className="px-3 py-2 text-text-secondary">{r.ownerName}</td>
                  <td className="px-3 py-2 text-text-secondary">{folder(r.folderId) ?? "—"}</td>
                  <td className="px-3 py-2 tabular-nums text-text-secondary">{r.files}</td>
                  <td className="px-3 py-2 tabular-nums text-text-primary">{formatBytes(r.bytes)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
      <StorageMembers />
    </>
  );
}

/** Server → Storage (instance admins): backend, usage against the instance quota, per organisation, GC and backups. */
export function ServerStorageSection() {
  const q = useInstanceStorage();
  const qc = useQueryClient();
  const sweep = useMutation({
    mutationFn: () => api.post("/admin/instance/storage/sweep", {}),
    onSuccess: () => { toast.success("Clean-up finished"); void qc.invalidateQueries({ queryKey: INSTANCE_STORAGE_KEY }); },
    onError: () => toast.error("Couldn't run the clean-up. Try again."),
  });
  if (q.isLoading) return <p className="text-[14px] text-text-secondary">Loading…</p>;
  if (q.error || !q.data) return <p role="alert" className="text-[14px] text-red-500">Couldn't load storage.</p>;
  const s = q.data;
  return (
    <>
      <section className="flex flex-col gap-3">
        <h2 className={h2}>File storage</h2>
        <div className={cn(card, "flex flex-col gap-3 p-4")}>
          <UsageBar used={s.used} quota={s.quota} label="Server file storage used" />
          <p className="flex items-center gap-2 text-[13px] text-text-secondary"><HardDrive className="size-4 shrink-0" />
            {s.backend === "db" ? "Files are stored in the database: every backup includes them." : `Files are stored in S3 (${s.s3?.bucket ?? ""}${s.s3?.endpoint ? ` at ${s.s3.endpoint}` : ""}). Back the bucket up yourself (versioning or replication).`}
          </p>
          {s.backend === "s3" && s.rows.db > 0 && <p role="alert" className="text-[13px] text-orange-ink">{s.rows.db} {s.rows.db === 1 ? "file is" : "files are"} still in the database. Run attachments-move --to s3 (docs/attachments.md); backups keep including chunk data until then.</p>}
          {s.warn && <p role="alert" className="flex items-start gap-2 text-[13px] text-red-500"><TriangleAlert className="mt-0.5 size-4 shrink-0" />Over 80 % of ATTACHMENT_INSTANCE_QUOTA_MB is used.{s.backend === "db" ? " Consider ATTACHMENT_STORAGE=s3 before raising it." : ""}</p>}
        </div>
      </section>
      <section className="flex flex-col gap-3">
        <h2 className={h2}>By organisation</h2>
        <div className={cn(card, "overflow-x-auto")}>
          <table className="w-full min-w-[480px] text-[13px]">
            <thead><tr className="border-b border-border-default"><th className={th}>Organisation</th><th className={th}>Files</th><th className={th}>Used</th><th className={th}>Quota</th></tr></thead>
            <tbody>
              {s.perOrg.map((o) => (
                <tr key={o.orgId} className="border-b border-border-default last:border-b-0">
                  <td className="px-3 py-2 text-text-primary">{o.name}</td><td className="px-3 py-2 tabular-nums text-text-secondary">{o.files}</td>
                  <td className="px-3 py-2 tabular-nums text-text-primary">{formatBytes(o.bytes)}</td><td className="px-3 py-2 tabular-nums text-text-secondary">{usedPercent(o.bytes, o.quota)}% of {formatBytes(o.quota)}</td>
                </tr>
              ))}
              <tr><td className="px-3 py-2 text-text-primary">Private records (everyone)</td><td className="px-3 py-2 tabular-nums text-text-secondary">{s.personal.files}</td><td className="px-3 py-2 tabular-nums text-text-primary">{formatBytes(s.personal.bytes)}</td><td className="px-3 py-2 text-text-secondary">{s.quotas.userMb} MB each</td></tr>
            </tbody>
          </table>
        </div>
      </section>
      <section className="flex flex-col gap-3">
        <div className="flex items-center gap-2"><h2 className={cn(h2, "mr-auto")}>Clean-up</h2>
          <Button type="button" variant="outline" size="sm" disabled={sweep.isPending} onClick={() => sweep.mutate()}><RefreshCw className={cn("size-3.5", sweep.isPending && "animate-spin")} />Run now</Button></div>
        <div className={cn(card, "flex flex-col gap-1.5 p-4 text-[13px] text-text-secondary")}>
          <p>{s.gc ? `Last run ${relativeTime(s.gc.at)}: ${s.gc.abandoned} abandoned uploads, ${s.gc.deleted} removed files and ${s.gc.tombstones} purged files cleaned up${s.gc.failures ? `, ${s.gc.failures} failures (retried next time)` : ""}.` : "Not run yet since the server started (it runs every 10 minutes)."}</p>
          {s.backend === "s3" && <p>Orphan check: {s.gc?.orphanPassAt ? `${s.gc.orphansFound} found and removed ${relativeTime(s.gc.orphanPassAt)}` : "not run yet"} (once a day).</p>}
          <p>{s.rows.uploading} uploads in progress · {s.rows.pendingDelete} removals pending · {s.tombstones} purged S3 files waiting.</p>
        </div>
      </section>
      <section className="flex flex-col gap-3">
        <h2 className={h2}>Backups</h2>
        <div className={cn(card, "flex flex-col gap-1.5 p-4 text-[13px] text-text-secondary")}>
          <p>{s.backup.chunkDataExcluded ? "Backups leave out file chunks (they are in S3): back the bucket up separately." : "Backups include every file (dumped at compression level 1: ciphertext doesn't compress)."}</p>
          {s.backup.lastSuccess && <p>Last backup {relativeTime(s.backup.lastSuccess.startedAt)}: {s.backup.lastSuccess.bytes !== null ? formatBytes(s.backup.lastSuccess.bytes) : "—"}{s.backup.lastSuccess.attachmentBytes !== null ? `, of which files ${formatBytes(s.backup.lastSuccess.attachmentBytes)}` : ""}.</p>}
        </div>
      </section>
    </>
  );
}

/** Instance admins: a strip when file storage passes 80 % of the instance quota. */
export function StorageBanner({ onOpen }: { onOpen: () => void }) {
  const q = useInstanceStorage();
  if (!q.data?.warn) return null;
  return (
    <div role="alert" className="flex shrink-0 items-center gap-2.5 border-b border-[var(--orange-tint-border)] bg-orange-tint px-6 py-2 text-[13px] text-text-primary max-[760px]:px-3">
      <Paperclip className="size-4 shrink-0 text-orange-ink" />
      <p className="min-w-0 flex-1">File storage is {usedPercent(q.data.used, q.data.quota)}% full ({formatBytes(q.data.used)} of {formatBytes(q.data.quota)}). <button type="button" onClick={onOpen} className="font-medium text-orange-ink underline-offset-2 hover:underline">View storage</button></p>
    </div>
  );
}
