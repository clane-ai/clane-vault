import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, Copy, Globe } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { ApiError } from "@/lib/api";
import { useOrgApi, useScope } from "@/lib/scope";
import { cn } from "@/lib/utils";
import { Chip } from "@/features/vault/people";

export interface DomainJoinView {
  enabled: boolean; role: "member" | "admin"; groups: { id: string; name: string }[]; domains: { domain: string; verified: boolean }[];
  emailConfigured: boolean; joinUrl: string; canEdit: boolean; updatedAt: string | null; updatedBy: { id: string; name: string } | null;
}

const ERRORS: Record<string, string> = {
  owner_only: "Only the organisation's owner can change this.",
  domain_not_verified: "Verify a domain above first (a DNS TXT record).",
  email_required: "Set up email first: the join link is always emailed.",
  group_not_found: "One of the chosen groups no longer exists.",
};
const errorText = (e: unknown) => (e instanceof ApiError ? ERRORS[e.code] : undefined) ?? "Couldn't save. Try again.";

/**
 * Email domain auto-join (docs/provisioning.md), Keeper's "email auto-provisioning": anyone with an address in a domain
 * this organisation verified (the SSO domain check) may ask to join as a member, into the chosen groups. They prove the
 * address by the emailed link and set up their master password and authenticator as usual. Off by default; the owner
 * switches it.
 */
export function DomainJoinSection() {
  const oapi = useOrgApi();
  const qc = useQueryClient();
  const scope = useScope();
  const KEY = ["domain-join", scope];
  const q = useQuery({ queryKey: KEY, queryFn: () => oapi.get<DomainJoinView>("/admin/settings/domain-join") });
  const groupsQ = useQuery({ queryKey: ["admin-groups", scope], queryFn: () => oapi.get<{ groups: { id: string; name: string }[] }>("/admin/groups") });
  const d = q.data;
  // The groups being edited (null: what's saved).
  const [draft, setDraft] = useState<string[] | null>(null);
  const groupIds = draft ?? d?.groups.map((g) => g.id) ?? [];
  const setGroupIds = (f: (cur: string[]) => string[]) => setDraft(f(groupIds));
  const [copied, setCopied] = useState(false);
  const save = useMutation({
    mutationFn: (b: { enabled: boolean; groupIds: string[] }) => oapi.put<DomainJoinView>("/admin/settings/domain-join", b),
    onSuccess: (v, b) => { qc.setQueryData(KEY, v); setDraft(null); toast.success(b.enabled === d?.enabled ? "Auto-join groups saved" : b.enabled ? "Email domain auto-join is on" : "Email domain auto-join is off"); },
    onError: (e) => toast.error(errorText(e)),
  });
  if (!d) return null;
  const verified = d.domains.filter((x) => x.verified);
  const blocked = !verified.length ? ERRORS.domain_not_verified : !d.emailConfigured ? ERRORS.email_required : null;
  const groups = groupsQ.data?.groups ?? [];
  const dirty = [...groupIds].sort().join() !== d.groups.map((g) => g.id).sort().join();
  const card = "rounded-[14px] border border-border-default bg-card px-4 py-4 shadow-[var(--shadow-card)]";

  return (
    <section className="flex flex-col gap-3" aria-label="Email domain auto-join">
      <h2 className="font-display text-[15px] font-semibold tracking-[-0.01em] text-text-primary">Email domain auto-join</h2>
      <div className={cn(card, "flex flex-col gap-4")}>
        <div className="flex items-start gap-3">
          <div className="min-w-0 flex-1">
            <label htmlFor="domain-join" className="text-[13.5px] font-medium text-text-primary">Let people with a verified work address join</label>
            <p className="text-[12.5px] text-text-secondary">Anyone with an address in a verified domain can ask to join this organisation as a member. They get a link by email, then create their account with a master password and authenticator (or sign in and accept, if they have one). Public email providers never count.</p>
          </div>
          <Switch id="domain-join" checked={d.enabled} disabled={!d.canEdit || save.isPending || (!d.enabled && !!blocked)} onCheckedChange={(v) => save.mutate({ enabled: v, groupIds })} />
        </div>
        {!d.canEdit && <p className="text-[12.5px] text-text-secondary">Only the organisation's owner can change this.</p>}
        {d.canEdit && blocked && !d.enabled && <p role="note" className="text-[12.5px] text-orange-ink">{blocked}</p>}

        <div className="flex flex-col gap-1.5">
          <p className="text-[13px] font-medium text-text-primary">Verified domains</p>
          {verified.length ? (
            <ul className="flex flex-wrap gap-1.5" aria-label="Verified domains">
              {verified.map((x) => <li key={x.domain} className="inline-flex items-center gap-1.5 rounded-[8px] border border-border-default bg-well px-2 py-1 font-mono text-[12.5px] text-text-primary"><Globe className="size-3.5 text-text-tertiary" />{x.domain}<Chip tone="green">Verified</Chip></li>)}
            </ul>
          ) : <p className="text-[12.5px] text-text-secondary">None yet. Add and verify your domain under Domains above; a domain verified by another organisation can't be used.</p>}
        </div>

        <fieldset className="flex flex-col gap-1.5">
          <legend className="mb-1.5 text-[13px] font-medium text-text-primary">Groups for people who join</legend>
          {groups.length === 0 ? <p className="text-[12.5px] text-text-secondary">No groups yet.</p> : (
            <div className="flex flex-wrap gap-1.5">
              {groups.map((g) => {
                const on = groupIds.includes(g.id);
                return (
                  <button key={g.id} type="button" role="checkbox" aria-checked={on} disabled={!d.canEdit}
                    onClick={() => setGroupIds((cur) => (on ? cur.filter((x) => x !== g.id) : [...cur, g.id]))}
                    className={cn("inline-flex h-7 items-center gap-1 rounded-full border px-2.5 text-[12.5px] font-medium disabled:opacity-60", on ? "border-[var(--blue-tint-border)] bg-blue-tint text-blue-ink" : "border-border-default bg-card text-text-secondary hover:bg-well")}>
                    {on && <Check className="size-3" />}{g.name}
                  </button>
                );
              })}
            </div>
          )}
          <p className="text-[12px] text-text-tertiary">They join as members. Folders shared with these groups still wait for a folder owner or editor to approve them.</p>
          {d.canEdit && dirty && <div><Button type="button" size="sm" onClick={() => save.mutate({ enabled: d.enabled, groupIds })} disabled={save.isPending}>Save groups</Button></div>}
        </fieldset>

        {d.enabled && (
          <div className="flex flex-col gap-1.5 border-t border-border-default pt-3">
            <p className="text-[13px] font-medium text-text-primary">Join page</p>
            <div className="flex min-w-0 items-center gap-2 rounded-[9px] border border-border-default bg-well px-2.5 py-1.5">
              <span className="min-w-0 flex-1 truncate font-mono text-[12.5px] text-text-primary">{d.joinUrl}</span>
              <Button type="button" variant="ghost" size="sm" onClick={async () => { await navigator.clipboard.writeText(d.joinUrl).catch(() => undefined); setCopied(true); setTimeout(() => setCopied(false), 1500); }}>
                {copied ? <Check className="size-3.5 text-green-600" /> : <Copy className="size-3.5" />}Copy
              </Button>
            </div>
            <p className="text-[12px] text-text-tertiary">Share it with your team: they enter their work email there. It's also linked from the sign-in page.</p>
          </div>
        )}
      </div>
    </section>
  );
}
