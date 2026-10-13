import { useState } from "react";
import { DatabaseBackup, TriangleAlert, X } from "lucide-react";
import { relativeTime } from "@/lib/time";
import { backupAlert, useBackups } from "./backups";
import { storageKey } from "@/lib/base";

const OFF_DISMISSED = storageKey("cv.backups-off-dismissed");
const readDismissed = () => { try { return localStorage.getItem(OFF_DISMISSED) === "1"; } catch { return false; } };

/** Admin-only strip at the top of the app: backups failing or stale, or (dismissably) switched off. */
export function BackupBanner({ onOpen }: { onOpen: () => void }) {
  const q = useBackups();
  const [offDismissed, setOffDismissed] = useState(readDismissed);
  const alert = backupAlert(q.data);
  if (!alert) return null;

  if (alert.kind === "off") {
    if (offDismissed) return null;
    return (
      <div role="status" className="flex shrink-0 items-center gap-2.5 border-b border-border-default bg-well px-6 py-2 text-[13px] text-text-secondary max-[760px]:px-3">
        <DatabaseBackup className="size-4 shrink-0 text-text-tertiary" />
        <p className="min-w-0 flex-1">Backups are off. <button type="button" onClick={onOpen} className="font-medium text-text-primary underline-offset-2 hover:underline">Set up backups</button></p>
        <button type="button" aria-label="Dismiss" className="grid size-6 place-items-center rounded-[6px] text-text-tertiary hover:bg-card hover:text-text-primary"
          onClick={() => { setOffDismissed(true); try { localStorage.setItem(OFF_DISMISSED, "1"); } catch { /* private mode */ } }}><X className="size-3.5" /></button>
      </div>
    );
  }

  const text = alert.kind === "failed"
    ? `The last database backup failed ${relativeTime(alert.at)}.`
    : alert.lastSuccess ? `No successful database backup since ${relativeTime(alert.lastSuccess)}.` : "No database backup has succeeded yet.";
  return (
    <div role="alert" className="flex shrink-0 items-center gap-2.5 border-b border-[var(--red-tint-border)] bg-red-tint px-6 py-2 text-[13px] text-text-primary max-[760px]:px-3">
      <TriangleAlert className="size-4 shrink-0 text-red-500" />
      <p className="min-w-0 flex-1">{text} <button type="button" onClick={onOpen} className="font-medium text-red-500 underline-offset-2 hover:underline">View backups</button></p>
    </div>
  );
}
