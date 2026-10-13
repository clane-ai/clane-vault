import { useEffect, useState, type FormEvent } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ShieldCheck } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { ApiError } from "@/lib/api";
import { useOrgApi, useScope } from "@/lib/scope";
import { useSession } from "@/lib/session";
import { relativeTime } from "@/lib/time";
import { cn } from "@/lib/utils";
import { useReloadOrgs } from "@/features/orgs/orgs";

/** The full policy set as admins edit it (docs/policies.md); members only ever see the client part. */
export interface AdminPolicies {
  autoLockMinutes: number | null; minPasswordLength: number; minPasswordScore: number;
  links: { allowed: boolean; maxExpiryHours: 1 | 24 | 168; requirePassword: boolean; allowAttachments?: boolean };
  /** File attachments (docs/attachments.md); absent from servers before 1.6. */
  attachments?: { allowed: boolean; maxFileMb: number | null; previews: boolean };
  offlineAllowed: boolean; extensionAllowed: boolean; breachCheckAllowed: boolean; ipAllowlist: string[]; ownerBreakGlass: boolean;
}
interface PoliciesView { policies: AdminPolicies; changedAt: string | null; changedBy: { id: string; name: string } | null; yourIp: string | null }

const card = "rounded-[14px] border border-border-default bg-card p-4 shadow-[var(--shadow-card)]";
const h2 = "font-display text-[15px] font-semibold tracking-[-0.01em] text-text-primary";
const SCORES = ["Any", "Weak or better", "Fair or better", "Good or better", "Strong"] as const;
const EXPIRY: [1 | 24 | 168, string][] = [[1, "1 hour"], [24, "24 hours"], [168, "7 days"]];

function Toggle({ id, label, line, checked, onChange, disabled }: { id: string; label: string; line: string; checked: boolean; onChange: (v: boolean) => void; disabled?: boolean }) {
  return (
    <div className="flex items-start gap-3">
      <div className="min-w-0 flex-1"><label htmlFor={id} className="text-[14px] font-medium text-text-primary">{label}</label><p className="text-[12.5px] text-text-secondary">{line}</p></div>
      <Switch id={id} aria-label={label} checked={checked} onCheckedChange={onChange} disabled={disabled} />
    </div>
  );
}

/** Organisation settings → Policies (owners and admins of the active org). */
export function OrgPoliciesSection() {
  const { org } = useSession();
  const oapi = useOrgApi();
  const qc = useQueryClient();
  const reload = useReloadOrgs();
  const KEY = ["admin-policies", useScope()];
  const q = useQuery({ queryKey: KEY, queryFn: () => oapi.get<PoliciesView>("/admin/settings/policies") });
  const [p, setP] = useState<AdminPolicies | null>(null);
  const [ips, setIps] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => { if (q.data) { setP(q.data.policies); setIps(q.data.policies.ipAllowlist.join("\n")); } }, [q.data]);
  if (!org || org.role === "member") return null;
  const isOwner = org.role === "owner";
  const set = <K extends keyof AdminPolicies>(k: K, v: AdminPolicies[K]) => setP((x) => (x ? { ...x, [k]: v } : x));
  const setLinks = (v: Partial<AdminPolicies["links"]>) => setP((x) => (x ? { ...x, links: { ...x.links, ...v } } : x));
  const setFiles = (v: Partial<NonNullable<AdminPolicies["attachments"]>>) => setP((x) => (x?.attachments ? { ...x, attachments: { ...x.attachments, ...v } } : x));

  async function save(e: FormEvent) {
    e.preventDefault();
    if (!p) return;
    setBusy(true); setError(null);
    try {
      const ipAllowlist = ips.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean);
      const r = await oapi.put<PoliciesView>("/admin/settings/policies", { ...p, ipAllowlist });
      qc.setQueryData(KEY, r);
      await reload(); // members' clients read the new policies with the org list
      toast.success("Policies saved");
    } catch (err) {
      const c = err instanceof ApiError ? err.code : "";
      setError(c === "would_lock_out" ? `That allowlist leaves out your own address (${q.data?.yourIp ?? "unknown"}). Add it first, or you'd lock yourself out.`
        : c === "owner_only" ? "Only the owner can change the owner's break-glass access, or narrow the allowlist while break-glass is off."
        : c === "invalid_request" ? "Check the values: networks look like 203.0.113.0/24 or 2001:db8::/32, auto-lock is 1 to 1440 minutes, length 12 to 128, largest file 1 to 1024 MB." : "Couldn't save the policies. Try again.");
    } finally { setBusy(false); }
  }

  return (
    <section className="flex flex-col gap-3" aria-label="Policies">
      <div><h2 className={h2}>Policies</h2><p className="text-[13px] text-text-secondary">Rules for everyone in {org.name}. Apps enforce them; the server enforces links and the IP allowlist.</p></div>
      {!p ? <p className="text-[14px] text-text-secondary">{q.error ? "Couldn't load the policies." : "Loading…"}</p> : (
        <form onSubmit={save} className={cn(card, "flex flex-col gap-4")} noValidate>
          <div className="grid gap-4 sm:grid-cols-3">
            <div className="flex flex-col gap-1.5"><Label htmlFor="pol-lock">Auto-lock after (minutes idle)</Label>
              <Input id="pol-lock" inputMode="numeric" placeholder="15 (default)" value={p.autoLockMinutes ?? ""} onChange={(e) => set("autoLockMinutes", e.target.value.trim() === "" ? null : Number(e.target.value.replace(/\D/g, "")) || 0)} /></div>
            <div className="flex flex-col gap-1.5"><Label htmlFor="pol-len">Master password: minimum length</Label>
              <Input id="pol-len" inputMode="numeric" value={p.minPasswordLength} onChange={(e) => set("minPasswordLength", Number(e.target.value.replace(/\D/g, "")) || 0)} /></div>
            <div className="flex flex-col gap-1.5"><Label htmlFor="pol-score">Minimum strength</Label>
              <Select value={String(p.minPasswordScore)} onValueChange={(v) => set("minPasswordScore", Number(v))}>
                <SelectTrigger id="pol-score"><SelectValue /></SelectTrigger>
                <SelectContent>{SCORES.map((l, i) => <SelectItem key={i} value={String(i)}>{l}</SelectItem>)}</SelectContent>
              </Select></div>
          </div>
          <p className="-mt-2 text-[12px] text-text-tertiary">The password rule is checked when people sign up, join and change their master password.</p>

          <div className="flex flex-col gap-3 border-t border-border-default pt-4">
            <Toggle id="pol-links" label="One-time links" line="Members with edit rights can share a record through a one-time link. Turning this off revokes the organisation's live links." checked={p.links.allowed} onChange={(v) => setLinks({ allowed: v })} />
            {p.links.allowed && (
              <div className="flex flex-wrap items-end gap-4 pl-0">
                <div className="flex flex-col gap-1.5"><Label htmlFor="pol-expiry">Longest expiry</Label>
                  <Select value={String(p.links.maxExpiryHours)} onValueChange={(v) => setLinks({ maxExpiryHours: Number(v) as 1 | 24 | 168 })}>
                    <SelectTrigger id="pol-expiry" className="w-[150px]"><SelectValue /></SelectTrigger>
                    <SelectContent>{EXPIRY.map(([h, l]) => <SelectItem key={h} value={String(h)}>{l}</SelectItem>)}</SelectContent>
                  </Select></div>
                <label className="flex items-center gap-2 pb-2 text-[13.5px] text-text-primary"><Switch aria-label="Require a link password" checked={p.links.requirePassword} onCheckedChange={(v) => setLinks({ requirePassword: v })} />Require a link password</label>
                {p.links.allowAttachments !== undefined && <label className="flex items-center gap-2 pb-2 text-[13.5px] text-text-primary"><Switch aria-label="Allow files in links" checked={p.links.allowAttachments} onCheckedChange={(v) => setLinks({ allowAttachments: v })} />Allow files in links</label>}
              </div>
            )}
          </div>

          {p.attachments && (
            <div className="flex flex-col gap-3 border-t border-border-default pt-4">
              <Toggle id="pol-files" label="File attachments" line="Members with edit rights can attach files to records. Off: no new uploads; files already attached stay listed and downloadable." checked={p.attachments.allowed} onChange={(v) => setFiles({ allowed: v })} />
              {p.attachments.allowed && (
                <div className="flex flex-col gap-1.5"><Label htmlFor="pol-filemb">Largest file (MB)</Label>
                  <Input id="pol-filemb" inputMode="numeric" className="w-[150px]" placeholder="Server limit" value={p.attachments.maxFileMb ?? ""}
                    onChange={(e) => setFiles({ maxFileMb: e.target.value.trim() === "" ? null : Number(e.target.value.replace(/\D/g, "")) || 0 })} />
                  <p className="text-[12px] text-text-tertiary">Empty: the server's limit. It can only be lowered here, never raised.</p></div>
              )}
              <Toggle id="pol-previews" label="File previews" line="Images, PDFs and plain text open in a preview after decryption. Off: every file is download-only." checked={p.attachments.previews} onChange={(v) => setFiles({ previews: v })} />
            </div>
          )}

          <div className="flex flex-col gap-3 border-t border-border-default pt-4">
            <Toggle id="pol-offline" label="Offline copies" line="Members may keep an encrypted copy of the vault on their device for use without a connection." checked={p.offlineAllowed} onChange={(v) => set("offlineAllowed", v)} />
            <Toggle id="pol-ext" label="Browser extension" line="Members may use the browser extension with this organisation." checked={p.extensionAllowed} onChange={(v) => set("extensionAllowed", v)} />
            <Toggle id="pol-hibp" label="Breach check" line="Members may opt in to checking their passwords against Have I Been Pwned (only a 5-character hash prefix leaves the device)." checked={p.breachCheckAllowed} onChange={(v) => set("breachCheckAllowed", v)} />
          </div>

          <div className="flex flex-col gap-2 border-t border-border-default pt-4">
            <Label htmlFor="pol-ips">IP allowlist</Label>
            <p className="text-[12.5px] text-text-secondary">Only these networks reach the organisation (one per line, IPv4 or IPv6 CIDR). Empty: anywhere. Private records stay reachable.{q.data?.yourIp ? ` Your address: ${q.data.yourIp}.` : ""}</p>
            <Textarea id="pol-ips" rows={3} spellCheck={false} className="font-mono text-[13px]" placeholder={"203.0.113.0/24\n2001:db8::/32"} value={ips} onChange={(e) => setIps(e.target.value)} />
            <Toggle id="pol-glass" label="Owner break-glass" line={isOwner ? "You (the owner) can still reach the organisation from anywhere, so a wrong list can't lock everyone out. Each use is logged." : "The owner can still reach the organisation from anywhere. Only the owner changes this."}
              checked={p.ownerBreakGlass} onChange={(v) => set("ownerBreakGlass", v)} disabled={!isOwner} />
          </div>

          {error && <p role="alert" className="text-[13px] text-red-500">{error}</p>}
          <div className="flex flex-wrap items-center gap-3 border-t border-border-default pt-3">
            <p className="flex min-w-0 flex-1 items-center gap-1.5 font-mono text-[11.5px] text-text-tertiary"><ShieldCheck className="size-3.5" />
              {q.data?.changedAt ? `Changed ${relativeTime(q.data.changedAt)}${q.data.changedBy ? ` by ${q.data.changedBy.name}` : ""}` : "Defaults"}</p>
            <Button type="submit" disabled={busy}>{busy ? "Saving…" : "Save policies"}</Button>
          </div>
        </form>
      )}
    </section>
  );
}
