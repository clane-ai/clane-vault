import { cn } from "@/lib/utils";
import { REASON_LABEL, type AttentionReason } from "./attention";

/** Amber chips ("Weak", "Reused", "Old") for Needs-attention rows. */
export function ReasonChips({ reasons, className }: { reasons: AttentionReason[]; className?: string }) {
  return (
    <span className={cn("flex shrink-0 gap-1", className)}>
      {reasons.map((r) => (
        <span key={r} className="rounded-[6px] bg-amber-500/15 px-1.5 py-px text-[11px] font-medium text-[color-mix(in_srgb,var(--amber-500)_55%,var(--text-primary))]">{REASON_LABEL[r]}</span>
      ))}
    </span>
  );
}
