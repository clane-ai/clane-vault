import { CloudOff } from "lucide-react";
import { relativeTime } from "@/lib/time";

/** Strip at the top of the vault while the server can't be reached: the device's copy, read-only. */
export function OfflineBanner({ savedAt }: { savedAt: string | null }) {
  return (
    <div role="status" data-testid="offline-banner" className="flex shrink-0 items-center gap-2.5 border-b border-amber-500/30 bg-amber-500/10 px-6 py-2 text-[13px] text-text-primary max-[760px]:px-3">
      <CloudOff aria-hidden="true" className="size-4 shrink-0 text-amber-500" />
      <p className="min-w-0 flex-1"><strong className="font-semibold">Offline — read only.</strong>{" "}
        <span className="text-text-secondary">Showing the copy saved on this device{savedAt ? ` ${relativeTime(savedAt)}` : ""}. Changes come back when the connection does.</span></p>
    </div>
  );
}

/** In place of pages that need the server (settings, share links, admin) while offline. */
export function OfflineOnlyPanel({ what }: { what: string }) {
  return (
    <div className="grid flex-1 place-items-center px-6 py-16 text-center">
      <div className="flex max-w-[360px] flex-col items-center gap-2">
        <CloudOff aria-hidden="true" className="size-8 text-text-tertiary" />
        <p className="font-display text-[17px] font-semibold text-text-primary">{what} need a connection</p>
        <p className="text-[13.5px] text-text-secondary">You're offline. The vault is read only until the connection is back.</p>
      </div>
    </div>
  );
}
