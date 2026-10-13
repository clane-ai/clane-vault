import { cn } from "@/lib/utils";

const TONE = ["bg-red-500", "bg-red-500", "bg-amber-500", "bg-amber-500", "bg-green-600"] as const;
const TEXT = ["text-red-500", "text-red-500", "text-text-secondary", "text-text-secondary", "text-green-600"] as const;

/** Four short segments + label. Score 0–4 (zxcvbn). */
export function StrengthMeter({ score, label, className }: { score: 0 | 1 | 2 | 3 | 4; label: string; className?: string }) {
  const filled = Math.max(1, score);
  return (
    <span className={cn("inline-flex items-center gap-2", className)}>
      <span className="flex gap-1" aria-hidden="true">
        {[1, 2, 3, 4].map((i) => <span key={i} className={cn("h-1 w-5 rounded-full", i <= filled ? TONE[score] : "bg-well")} />)}
      </span>
      <span className={cn("text-[12px] font-medium", TEXT[score])}>{label}</span>
    </span>
  );
}
