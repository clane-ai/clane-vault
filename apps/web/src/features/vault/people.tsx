import { useEffect, useState } from "react";
import { Link } from "react-router";
import { b64url, keyFingerprint } from "@clane-vault/crypto";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { cn } from "@/lib/utils";
import { PERMISSION_LABEL, type Grant } from "./types";

export function initials(name: string) {
  const parts = name.trim().split(/\s+/).filter(Boolean);
  return ((parts[0]?.[0] ?? "") + (parts.length > 1 ? parts[parts.length - 1]![0] : "")).toUpperCase() || "?";
}

const TINTS = ["bg-blue-tint text-blue-500", "bg-orange-tint text-orange-ink", "bg-green-tint text-green-600", "bg-purple-tint text-purple-ink"] as const;
const tintFor = (s: string) => { let h = 0; for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) | 0; return TINTS[Math.abs(h) % TINTS.length]; };

export function PersonAvatar({ name, id, size = 32, className }: { name: string; id?: string; size?: 24 | 32; className?: string }) {
  return (
    <span aria-hidden="true" className={cn("grid shrink-0 place-items-center rounded-full font-display font-semibold select-none", tintFor(id ?? name),
      size === 24 ? "size-6 text-[9.5px] tracking-[-.02em]" : "size-8 text-[12px]", className)}>{initials(name)}</span>
  );
}

/** Up to `max` overlapping avatars plus a "+n" chip. `ringClassName`: the ring follows the surface underneath (default the card). */
export function AvatarStack({ people, max = 4, ringClassName = "ring-card" }: { people: { userId: string; name: string }[]; max?: number; ringClassName?: string }) {
  const shown = people.slice(0, max);
  return (
    <span className="flex items-center -space-x-1" aria-hidden="true">
      {shown.map((p) => <PersonAvatar key={p.userId} id={p.userId} name={p.name} size={24} className={cn("ring-[1.5px]", ringClassName)} />)}
      {people.length > max && <span className={cn("grid size-6 place-items-center rounded-full bg-well font-mono text-[10px] text-text-secondary ring-[1.5px]", ringClassName)}>+{people.length - max}</span>}
    </span>
  );
}

/** A person's public-key fingerprint, to compare out of band (spec §5.6: keys come from the server). */
export function Fingerprint({ publicKey, className }: { publicKey: string | undefined; className?: string }) {
  const [fp, setFp] = useState<string | null>(null);
  useEffect(() => {
    let alive = true;
    if (!publicKey) { setFp(null); return; }
    try { void keyFingerprint(b64url.decode(publicKey)).then((x) => alive && setFp(x)).catch(() => alive && setFp(null)); } catch { setFp(null); }
    return () => { alive = false; };
  }, [publicKey]);
  if (!fp) return null;
  return <span title="Key fingerprint. Compare it with the person to be sure it's really their key." className={cn("font-mono text-[11px] tracking-[.02em] text-text-tertiary", className)}>{fp}</span>;
}

export function PermissionSelect({ value, onChange, label, disabled, className }: { value: Grant; onChange: (p: Grant) => void; label: string; disabled?: boolean; className?: string }) {
  return (
    <Select value={value} onValueChange={(v) => onChange(v as Grant)} disabled={disabled}>
      <SelectTrigger aria-label={label} className={cn("h-8 w-[118px] shrink-0 text-[13px]", className)}><SelectValue /></SelectTrigger>
      <SelectContent align="end">
        {(["edit", "view", "use"] as const).map((p) => <SelectItem key={p} value={p}>{PERMISSION_LABEL[p]}</SelectItem>)}
      </SelectContent>
    </Select>
  );
}

/** One person row: avatar · name/email/fingerprint · trailing controls. */
export function PersonRow({ id, name, email, publicKey, badge, href, children }: { id: string; name: string; email?: string; publicKey?: string; badge?: React.ReactNode;
  /** Opens the person's page (admin People → member). */ href?: string; children?: React.ReactNode }) {
  return (
    <li className="flex flex-wrap items-center gap-x-3 gap-y-1.5 border-b border-border-default py-2.5 last:border-b-0" aria-label={name}>
      <PersonAvatar id={id} name={name} />
      {/* Phones: the actions (permission, buttons) get their own line under the name. */}
      <span className="min-w-0 flex-1 max-[560px]:basis-[calc(100%-3rem)]">
        <span className="flex items-center gap-2">{href ? <Link to={href} className="truncate text-[14px] font-medium text-text-primary underline-offset-2 hover:underline">{name}</Link>
          : <span className="truncate text-[14px] font-medium text-text-primary">{name}</span>}{badge}</span>
        {email && <span className="block truncate text-[12.5px] text-text-secondary">{email}</span>}
        <Fingerprint publicKey={publicKey} className="block" />
      </span>
      {children && <span className="contents max-[560px]:flex max-[560px]:w-full max-[560px]:justify-end">{children}</span>}
    </li>
  );
}

export function Chip({ children, tone = "neutral" }: { children: React.ReactNode; tone?: "neutral" | "blue" | "green" | "orange" | "red" }) {
  const t = { neutral: "border-border-default bg-app text-text-secondary", blue: "border-[var(--blue-tint-border)] bg-blue-tint text-blue-ink", green: "border-[var(--green-tint-border)] bg-green-tint text-green-600",
    orange: "border-[var(--orange-tint-border)] bg-orange-tint text-orange-ink", red: "border-[var(--red-tint-border)] bg-red-tint text-red-500" }[tone];
  return <span className={cn("inline-flex shrink-0 items-center rounded-[6px] border px-1.5 py-px text-[11px] font-medium", t)}>{children}</span>;
}
