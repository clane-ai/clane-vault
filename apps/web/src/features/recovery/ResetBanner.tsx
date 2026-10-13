import { useState } from "react";
import { History, X } from "lucide-react";
import { useSecurity } from "./recovery";

/**
 * After an admin recovery (a scoped reset): what the reset left locked, until the old recovery kit or old master password
 * restores it (Settings → Security). Not shown when the reset lost nothing.
 */
export function ResetBanner({ onOpen }: { onOpen: () => void }) {
  const a = useSecurity().data?.keyArchive;
  const [dismissed, setDismissed] = useState(false);
  if (!a || dismissed || (a.privateItems === 0 && a.otherOrgs === 0)) return null;
  const parts = [a.privateItems ? `${a.privateItems} private ${a.privateItems === 1 ? "item" : "items"}` : null, a.otherOrgs ? `your access in ${a.otherOrgs} other ${a.otherOrgs === 1 ? "organisation" : "organisations"}` : null].filter(Boolean);
  return (
    <div role="status" aria-label="Items from before your reset" className="flex shrink-0 items-center gap-2.5 border-b border-[var(--orange-tint-border)] bg-orange-tint px-6 py-2 text-[13px] text-text-primary max-[760px]:px-3">
      <History className="size-4 shrink-0 text-orange-ink" />
      <p className="min-w-0 flex-1">{parts.join(" and ")} {a.privateItems + a.otherOrgs === 1 ? "is" : "are"} locked from before your password reset. Your old recovery kit or old master password brings them back.
        {" "}<button type="button" onClick={onOpen} className="font-medium text-orange-ink underline-offset-2 hover:underline">Restore</button></p>
      <button type="button" aria-label="Hide" title="Hide" className="grid size-6 place-items-center rounded-[6px] text-text-tertiary hover:bg-card hover:text-text-primary" onClick={() => setDismissed(true)}><X className="size-3.5" /></button>
    </div>
  );
}
