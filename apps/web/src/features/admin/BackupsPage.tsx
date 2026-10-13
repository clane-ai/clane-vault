import { useState } from "react";
import { PageHeader } from "@/components/SectionLayout";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { CalendarClock, Check, Copy, DatabaseBackup, FolderArchive, HardDrive, KeyRound, LoaderCircle, TriangleAlert, type LucideIcon } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { ApiError, api } from "@/lib/api";
import { relativeTime } from "@/lib/time";
import { cn } from "@/lib/utils";
import { Chip } from "@/features/vault/people";
import { BACKUPS_KEY, destinationLabel, formatBytes, restoreFrom, useBackups, type BackupRun, type BackupStatus } from "./backups";

const card = "rounded-[14px] border border-border-default bg-card shadow-[var(--shadow-card)]";
const h2 = "font-display text-[15px] font-semibold tracking-[-0.01em] text-text-primary";
const STATUS: Record<BackupRun["status"], { label: string; tone: "green" | "orange" | "red" }> = {
  success: { label: "Succeeded", tone: "green" }, running: { label: "Running", tone: "orange" }, failed: { label: "Failed", tone: "red" },
};
const utc = (iso: string) => new Date(iso).toISOString().slice(0, 16).replace("T", " ") + " UTC";

function CopyCode({ text, label }: { text: string; label: string }) {
  const [done, setDone] = useState(false);
  return (
    <div className="flex items-start gap-2 rounded-[10px] border border-border-default bg-well py-2 pr-1.5 pl-3">
      <code className="min-w-0 flex-1 font-mono text-[12px] leading-[1.6] break-all whitespace-pre-wrap text-text-primary">{text}</code>
      <Button type="button" variant="ghost" size="icon-sm" aria-label={label} title="Copy"
        onClick={async () => { try { await navigator.clipboard.writeText(text); setDone(true); toast.success("Copied"); setTimeout(() => setDone(false), 1500); } catch { toast.error("Couldn't copy"); } }}>
        {done ? <Check className="size-3.5" /> : <Copy className="size-3.5" />}
      </Button>
    </div>
  );
}

function Stat({ icon: Icon, label, children, sub }: { icon: LucideIcon; label: string; children: React.ReactNode; sub?: React.ReactNode }) {
  return (
    <div className="flex min-w-0 gap-3">
      <span className="grid size-8 shrink-0 place-items-center rounded-[9px] bg-well text-text-tertiary"><Icon className="size-4" /></span>
      <div className="min-w-0">
        <p className="font-mono text-[10.5px] tracking-[.1em] text-text-tertiary uppercase">{label}</p>
        <p className="truncate text-[14px] font-medium text-text-primary">{children}</p>
        {sub && <p className="truncate text-[12.5px] text-text-secondary">{sub}</p>}
      </div>
    </div>
  );
}

function StatusCard({ s, onRun, starting }: { s: BackupStatus; onRun: () => void; starting: boolean }) {
  const busy = s.running || starting;
  const last = s.lastSuccess;
  return (
    <section className={cn(card, "flex flex-col gap-4 p-4")} aria-label="Backup status">
      <div className="flex flex-wrap items-center gap-3">
        <div className="min-w-0 flex-1">
          <h2 className={h2}>Scheduled backups</h2>
          <p className="text-[13px] text-text-secondary">Encrypted with your age key before they leave the server. Kept for {s.retentionDays} days.</p>
        </div>
        <Button type="button" onClick={onRun} disabled={busy} aria-busy={busy}>
          {busy ? <LoaderCircle className="size-4 animate-spin" /> : <DatabaseBackup className="size-4" />}{busy ? "Backing up…" : "Back up now"}
        </Button>
      </div>
      <div className="grid grid-cols-2 gap-4 max-[560px]:grid-cols-1">
        <Stat icon={DatabaseBackup} label="Last backup" sub={last ? `${formatBytes(last.bytes)} · ${utc(last.finishedAt ?? last.startedAt)}` : "No backup has finished yet"}>
          {last ? relativeTime(last.finishedAt ?? last.startedAt) : "Never"}
        </Stat>
        <Stat icon={CalendarClock} label="Next run" sub={<span className="font-mono text-[12px]">{s.schedule} ({s.timezone})</span>}>
          {s.nextRun ? `${relativeTime(s.nextRun)} · ${utc(s.nextRun).slice(11)}` : "—"}
        </Stat>
      </div>
      <div className="flex flex-col gap-1.5 border-t border-border-default pt-3">
        <p className="font-mono text-[10.5px] tracking-[.1em] text-text-tertiary uppercase">Destinations</p>
        {s.destinations.map((d) => (
          <p key={destinationLabel(d)} className="flex min-w-0 items-center gap-2 text-[13px] text-text-primary">
            {d.type === "s3" ? <FolderArchive className="size-4 shrink-0 text-text-tertiary" /> : <HardDrive className="size-4 shrink-0 text-text-tertiary" />}
            <span className="truncate font-mono text-[12.5px]">{destinationLabel(d)}</span>
            {d.type === "s3" && d.endpoint && <span className="truncate text-[12px] text-text-tertiary">{d.endpoint}</span>}
          </p>
        ))}
      </div>
      {s.attachments && (
        <p className="border-t border-border-default pt-3 text-[12.5px] leading-snug text-text-secondary" data-testid="backup-attachments">
          {s.attachments.chunkDataExcluded
            ? "File attachments are stored in S3 and left out of these backups: back the bucket up separately (versioning or replication)."
            : `File attachments are stored in the database and included in every backup${last?.attachmentBytes ? ` (${formatBytes(last.attachmentBytes)} of files in the last one)` : ""}.`}
        </p>
      )}
    </section>
  );
}

function OffCard() {
  return (
    <section className={cn(card, "flex flex-col gap-3 p-4")} aria-label="Backup status">
      <div className="flex items-center gap-2"><h2 className={h2}>Backups are off</h2><Chip>Off</Chip></div>
      <p className="text-[13px] text-text-secondary">
        Turn on scheduled, encrypted backups to S3-compatible storage or a mounted folder. Set these in the server's <code className="font-mono text-[12px]">.env</code> and restart:
      </p>
      <CopyCode label="Copy settings" text={"BACKUP_ENABLED=true\nBACKUP_AGE_RECIPIENT=age1…\nBACKUP_S3_BUCKET=…   # and/or BACKUP_LOCAL_DIR=/backups"} />
      <p className="text-[12.5px] text-text-tertiary">See the Backups section of the install README for storage examples and how to make the age key.</p>
    </section>
  );
}

function RunsTable({ runs }: { runs: BackupRun[] }) {
  if (runs.length === 0) return <p className="px-4 py-6 text-center text-[13px] text-text-secondary">No backups yet.</p>;
  return (
    <table className="w-full table-fixed text-left text-[13px]">
      <thead>
        <tr className="border-b border-border-default font-mono text-[10.5px] tracking-[.1em] text-text-tertiary uppercase">
          <th className="w-[30%] px-4 py-2.5 font-normal max-[560px]:w-[45%]">Time</th>
          <th className="w-[14%] px-2 py-2.5 font-normal max-[560px]:hidden">Trigger</th>
          <th className="w-[16%] px-2 py-2.5 font-normal max-[560px]:w-[30%]">Status</th>
          <th className="w-[12%] px-2 py-2.5 font-normal max-[560px]:w-[25%]">Size</th>
          <th className="px-2 py-2.5 pr-4 font-normal max-[760px]:hidden">Object</th>
        </tr>
      </thead>
      <tbody>
        {runs.map((r) => (
          <tr key={r.id} className="border-b border-border-default align-top last:border-b-0">
            <td className="px-4 py-2.5"><span className="block text-text-primary" title={utc(r.startedAt)}>{relativeTime(r.startedAt)}</span>
              <span className="block font-mono text-[11px] text-text-tertiary">{utc(r.startedAt)}</span></td>
            <td className="px-2 py-2.5 text-text-secondary max-[560px]:hidden">{r.trigger === "manual" ? "Manual" : "Schedule"}</td>
            <td className="px-2 py-2.5"><Chip tone={STATUS[r.status].tone}>{STATUS[r.status].label}</Chip>
              {r.error && <span className="mt-1 block text-[11.5px] break-words text-red-500" title={r.error}>{r.error}</span>}</td>
            <td className="px-2 py-2.5 font-mono text-[12px] text-text-secondary tabular-nums">{formatBytes(r.bytes)}</td>
            <td className="truncate px-2 py-2.5 pr-4 font-mono text-[11.5px] text-text-secondary max-[760px]:hidden" title={r.objectKey ?? undefined}>{r.objectKey ?? "—"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function RestorePanel({ s }: { s: BackupStatus }) {
  const from = s.lastSuccess?.objectKey ? restoreFrom(s.destinations[0], s.lastSuccess.objectKey) : "<object key or file>";
  const cli = "docker compose exec clane-vault node dist/src/scripts/restore.js";
  // -T: no TTY, so the key file can be piped in.
  const cliStdin = "docker compose exec -T clane-vault node dist/src/scripts/restore.js";
  return (
    <section className={cn(card, "flex flex-col gap-3 p-4")} aria-label="Restore">
      <div><h2 className={h2}>Restore a backup</h2>
        <p className="text-[13px] text-text-secondary">Run these on the server, next to <code className="font-mono text-[12px]">docker-compose.yml</code>. The restore goes into a new, empty schema; nothing is overwritten.</p></div>
      <ol className="flex list-decimal flex-col gap-2.5 pl-5 text-[13px] text-text-primary marker:text-text-tertiary">
        <li className="flex flex-col gap-1.5">List the backups:
          <CopyCode label="Copy step 1" text={`${cli} --list`} /></li>
        <li className="flex flex-col gap-1.5">Restore one into a new schema. Your age identity (private key) file is read from standard input, so it never lands in the container:
          <CopyCode label="Copy step 2" text={`${cliStdin} --from ${from} --identity - --target-schema ${s.schema}_restored < backup-key.txt`} /></li>
        <li>Follow the printed next steps: point <code className="font-mono text-[12px]">DATABASE_URL</code> at the restored schema and restart.</li>
      </ol>
    </section>
  );
}

export default function BackupsPage() {
  const qc = useQueryClient();
  const q = useBackups();
  const run = useMutation({
    mutationFn: () => api.post<{ id: string }>("/admin/backups/run"),
    onSuccess: () => { toast.success("Backup started"); void qc.invalidateQueries({ queryKey: BACKUPS_KEY }); },
    onError: (e) => toast.error(e instanceof ApiError && e.code === "backup_running" ? "A backup is already running." : "Couldn't start the backup. Try again."),
  });
  const s = q.data;

  return (
    <section className="flex min-h-0 min-w-0 flex-1 flex-col" aria-label="Backups">
      <PageHeader title="Backups" />
      <div className="relative min-h-0 flex-1 overflow-y-auto px-6 py-5 max-[760px]:px-3">
        <div className="mx-auto flex max-w-[760px] flex-col gap-6">
          {q.isLoading ? <p className="text-[14px] text-text-secondary">Loading…</p> : q.error || !s ? <p role="alert" className="text-[14px] text-red-500">Couldn't load backup status.</p> : (<>
            {s.enabled ? <StatusCard s={s} onRun={() => run.mutate()} starting={run.isPending} /> : <OffCard />}

            {s.enabled && s.lastRun?.status === "failed" && (
              <div role="alert" className="flex gap-3 rounded-[12px] border border-[var(--red-tint-border)] bg-red-tint p-3.5 text-[13px] text-text-primary">
                <TriangleAlert className="mt-0.5 size-4 shrink-0 text-red-500" />
                <p><span className="font-medium">The last backup failed</span> {relativeTime(s.lastRun.finishedAt ?? s.lastRun.startedAt)}{s.lastRun.error ? `: ${s.lastRun.error}` : "."} Check the server logs for <code className="font-mono text-[12px]">backup.failure</code>.</p>
              </div>
            )}

            <div className="flex gap-3 rounded-[12px] border border-[var(--orange-tint-border)] bg-orange-tint p-3.5 text-[13px] text-orange-ink" role="note">
              <KeyRound className="mt-0.5 size-4 shrink-0" />
              <p><span className="font-medium">Back up your .env separately — SERVER_SECRET protects everyone's 2FA.</span> Keep it, and the age private key, in your secrets manager, not next to the backups. Without SERVER_SECRET, a restored vault can't check anyone's authenticator codes.</p>
            </div>

            <section className="flex flex-col gap-3" aria-label="Recent backups">
              <h2 className={h2}>Recent backups <span className="font-mono text-[12px] font-normal text-text-tertiary">{s.runs.length}</span></h2>
              <div className={cn(card, "overflow-hidden")}><RunsTable runs={s.runs} /></div>
            </section>

            {s.enabled && <RestorePanel s={s} />}
          </>)}
        </div>
      </div>
    </section>
  );
}
