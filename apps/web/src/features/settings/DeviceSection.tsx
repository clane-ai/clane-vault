import { useState } from "react";
import { CloudOff } from "lucide-react";
import { Switch } from "@/components/ui/switch";
import { useSession } from "@/lib/session";
import { offlineEnabled } from "@/lib/offline";
import { cn } from "@/lib/utils";

const card = "rounded-[14px] border border-border-default bg-card p-4 shadow-[var(--shadow-card)]";

/** Settings → This device: the offline copy (docs/install-app.md). Per device, on by default. */
export function DeviceSection() {
  const { setOfflineCopy } = useSession();
  const [on, setOn] = useState(offlineEnabled);
  return (
    <section className="flex flex-col gap-3" aria-label="This device">
      <h2 className="font-display text-[15px] font-semibold tracking-[-0.01em] text-text-primary">This device</h2>
      <div className={cn(card, "flex items-start gap-3")}>
        <span className="grid size-9 shrink-0 place-items-center rounded-[10px] bg-well text-text-tertiary"><CloudOff className="size-4" /></span>
        <div className="min-w-0 flex-1">
          <label htmlFor="offline-copy" className="text-[14px] font-medium text-text-primary">Offline copy</label>
          <p className="text-[13px] leading-relaxed text-text-secondary">
            Keeps your encrypted vault on this device so you can open it read-only without a connection, with your master password.
            Nothing is stored decrypted. It's deleted when you sign out{on ? "" : "; turning this off deleted it already"}.
          </p>
        </div>
        <Switch id="offline-copy" aria-label="Offline copy" checked={on} onCheckedChange={(v) => { setOn(v); setOfflineCopy(v); }} />
      </div>
    </section>
  );
}
