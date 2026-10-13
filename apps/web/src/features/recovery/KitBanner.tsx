import { useState } from "react";
import { KeyRound, X } from "lucide-react";
import { RecoveryKitDialog } from "@/features/settings/SettingsPage";
import { useSecurity } from "./recovery";

/**
 * "Create your recovery kit" strip for accounts without one. Dismissing hides it until the next unlock or sign-in
 * (the vault remounts), so it keeps coming back until the kit exists.
 */
export function KitBanner() {
  const sec = useSecurity();
  const [dismissed, setDismissed] = useState(false);
  const [open, setOpen] = useState(false);
  const show = sec.data && sec.data.recoveryKit === null && !dismissed;
  return (
    <>
      {show && (
        <div role="status" aria-label="Recovery kit" className="flex shrink-0 items-center gap-2.5 border-b border-[var(--orange-tint-border)] bg-orange-tint px-6 py-2 text-[13px] text-text-primary max-[760px]:px-3">
          <KeyRound className="size-4 shrink-0 text-orange-ink" />
          <p className="min-w-0 flex-1">Create your recovery kit. If you forget your master password, it's how you get back into your vault.
            {" "}<button type="button" onClick={() => setOpen(true)} className="font-medium text-orange-ink underline-offset-2 hover:underline">Create recovery kit</button></p>
          <button type="button" aria-label="Remind me later" title="Remind me later" className="grid size-6 place-items-center rounded-[6px] text-text-tertiary hover:bg-card hover:text-text-primary" onClick={() => setDismissed(true)}><X className="size-3.5" /></button>
        </div>
      )}
      <RecoveryKitDialog open={open} mode="create" onClose={() => setOpen(false)} />
    </>
  );
}
