import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { useSession } from "@/lib/session";
import { useOrgsInfo } from "@/features/orgs/orgs";

export type BackupDestination = { type: "s3"; bucket: string; prefix: string; endpoint?: string } | { type: "local"; dir: string };
export interface BackupRun {
  id: string; startedAt: string; finishedAt: string | null; status: "running" | "success" | "failed"; trigger: "schedule" | "manual";
  bytes: number | null; destinations: BackupDestination[]; objectKey: string | null; error: string | null;
  /** Attachment ciphertext in the database when the run started (absent from servers before 1.6). */ attachmentBytes?: number | null;
}
export interface BackupStatus {
  enabled: boolean; schedule: string; timezone: string; nextRun: string | null; retentionDays: number; schema: string;
  destinations: BackupDestination[]; running: boolean; lastSuccess: BackupRun | null; lastRun: BackupRun | null; runs: BackupRun[];
  /** Where file attachments live and whether dumps leave their chunks out (docs/attachments.md). */
  attachments?: { storage: "db" | "s3"; chunkDataExcluded: boolean };
}

export const BACKUPS_KEY = ["admin-backups"] as const;
/** A daily schedule plus slack: older than this and the last good backup counts as stale. */
export const STALE_AFTER_MS = 26 * 3600e3;

/** Instance-admin-only backup status (backups are of the whole server, not an org); polls quickly while a backup runs. */
export function useBackups(opts: { enabled?: boolean } = {}) {
  const { user } = useSession();
  const instanceAdmin = !!useOrgsInfo().data?.instanceAdmin;
  return useQuery({
    queryKey: [...BACKUPS_KEY, user?.id ?? ""],
    queryFn: () => api.get<BackupStatus>("/admin/backups"),
    enabled: !!user && instanceAdmin && opts.enabled !== false,
    refetchInterval: (q) => (q.state.data?.running ? 2000 : 5 * 60_000),
  });
}

export type BackupAlert = { kind: "failed"; at: string; error: string | null } | { kind: "stale"; lastSuccess: string | null } | { kind: "off" } | null;

/** What the app-shell banner should say, if anything. */
export function backupAlert(s: BackupStatus | undefined, now: number = Date.now()): BackupAlert {
  if (!s) return null;
  if (!s.enabled) return { kind: "off" };
  if (s.lastRun?.status === "failed") return { kind: "failed", at: s.lastRun.finishedAt ?? s.lastRun.startedAt, error: s.lastRun.error };
  if (s.running) return null;
  const last = s.lastSuccess ? new Date(s.lastSuccess.finishedAt ?? s.lastSuccess.startedAt).getTime() : null;
  // A fresh install has no backup yet; only nag once the first scheduled run should have happened.
  if (last === null) return s.runs.length > 0 ? { kind: "stale", lastSuccess: null } : null;
  return now - last > STALE_AFTER_MS ? { kind: "stale", lastSuccess: s.lastSuccess!.finishedAt ?? s.lastSuccess!.startedAt } : null;
}

export function formatBytes(n: number | null | undefined): string {
  if (n == null) return "—";
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let v = n / 1024, i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v >= 10 ? v.toFixed(0) : v.toFixed(1)} ${units[i]}`;
}

export const destinationLabel = (d: BackupDestination) => (d.type === "s3" ? `s3://${d.bucket}/${d.prefix}` : d.dir);
/** What to pass to `restore.js --from` for an object in this destination. */
export const restoreFrom = (d: BackupDestination | undefined, objectKey: string) =>
  !d ? objectKey : d.type === "s3" ? `${d.prefix}${objectKey}` : `${d.dir.replace(/\/$/, "")}/${objectKey}`;
