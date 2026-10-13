import { useCallback, useEffect, useMemo, useState } from "react";
import { RefreshCw } from "lucide-react";
import { DEFAULT_GENERATOR, generatePassword, type GeneratorOptions } from "@clane-vault/crypto";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { passwordStrength } from "@/lib/strength";
import { CopyButton } from "./CopyButton";
import { StrengthMeter } from "./StrengthMeter";

const TOGGLES: { key: keyof Pick<GeneratorOptions, "upper" | "lower" | "digits" | "symbols">; label: string }[] =
  [{ key: "upper", label: "A–Z" }, { key: "lower", label: "a–z" }, { key: "digits", label: "0–9" }, { key: "symbols", label: "Symbols" }];

export function GeneratorPanel({ onUse }: { onUse?: (pw: string) => void }) {
  const [opts, setOpts] = useState<GeneratorOptions>(DEFAULT_GENERATOR);
  const [pw, setPw] = useState(() => generatePassword(DEFAULT_GENERATOR));
  const regen = useCallback((o: GeneratorOptions) => { try { setPw(generatePassword(o)); } catch { /* keep last if no set chosen */ } }, []);
  useEffect(() => regen(opts), [opts, regen]);
  const s = useMemo(() => passwordStrength(pw), [pw]);
  const onlyOne = TOGGLES.filter((t) => opts[t.key]).length === 1;
  return (
    <div className="flex flex-col gap-5">
      <div className="flex flex-col gap-3 rounded-[12px] border border-border-default bg-app p-4">
        <span data-testid="generated" className="min-h-[44px] break-all font-mono text-[16px] leading-relaxed text-text-primary">{pw}</span>
        <div className="flex items-center justify-between gap-2">
          <StrengthMeter score={s.score} label={s.label} />
          <span className="flex gap-0.5">
            <Button variant="ghost" size="icon" aria-label="Regenerate" title="Regenerate" onClick={() => regen(opts)}><RefreshCw className="size-4" /></Button>
            <CopyButton value={pw} label="Copy generated password" />
          </span>
        </div>
      </div>
      <div className="flex flex-col gap-3">
        <div className="flex items-center justify-between">
          <Label htmlFor="gen-length" className="text-[13px]">Length</Label>
          <span className="rounded-[6px] bg-well px-2 py-0.5 font-mono text-[12px] text-text-primary" aria-hidden="true">{opts.length}</span>
        </div>
        <input id="gen-length" type="range" min={8} max={64} value={opts.length} onChange={(e) => setOpts({ ...opts, length: Number(e.target.value) })} className="w-full accent-[var(--blue-500)]" />
      </div>
      <div className="overflow-hidden rounded-[12px] border border-border-default">
        {TOGGLES.map((t) => (
          <label key={t.key} className="flex items-center justify-between gap-2 border-b border-border-default px-4 py-3 text-[14px] last:border-b-0">
            <span className={t.key === "symbols" ? "" : "font-mono text-[13.5px]"}>{t.label}</span>
            <Switch aria-label={t.label} checked={opts[t.key]} disabled={opts[t.key] && onlyOne} onCheckedChange={(c) => setOpts({ ...opts, [t.key]: c })} />
          </label>
        ))}
      </div>
      {onUse && <Button onClick={() => onUse(pw)}>Use password</Button>}
    </div>
  );
}
