import { useState, type FormEvent } from "react";
import { Check, ChevronsUpDown, Mail, Plus, Settings, X } from "lucide-react";
import { useNavigate } from "react-router";
import { spacePrefix } from "@/lib/paths";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { DropdownMenu, DropdownMenuContent, DropdownMenuGroup, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api, ApiError } from "@/lib/api";
import { useSession, type Org } from "@/lib/session";
import { cn } from "@/lib/utils";
import { OrgAvatar } from "./OrgLogo";
import { ROLE_LABEL, useOrgsInfo, useReloadOrgs, type Invitation } from "./orgs";
import { PasswordPolicyCheck, isStricter } from "./PasswordPolicyCheck";

const menuLabel = "px-2.5 pt-1.5 pb-1 font-mono text-[10.5px] font-normal tracking-[.12em] text-text-tertiary uppercase";

/** Create an organisation: the creator becomes its owner and it becomes the active org. */
export function CreateOrgDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const reload = useReloadOrgs();
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!name.trim()) return setError("Give it a name.");
    setBusy(true); setError(null);
    try {
      const org = await api.post<Org>("/orgs", { name: name.trim() });
      await reload(org.id);
      toast.success(`${org.name} created`);
      setName(""); onClose();
    } catch (err) {
      const c = err instanceof ApiError ? err.code : "";
      setError(c === "org_creation_disabled" ? "Creating organisations is turned off on this server." : c === "org_limit" ? "You already own as many organisations as this server allows."
        : c === "invalid_request" ? "Use a plain name (up to 60 characters, no links or email addresses)." : "Couldn't create it. Try again.");
    } finally { setBusy(false); }
  }
  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Create organisation</DialogTitle>
          <DialogDescription>You'll be its owner. Invite people from People once it exists. Your private records stay in your Personal space.</DialogDescription>
        </DialogHeader>
        <form onSubmit={submit} className="flex flex-col gap-3" noValidate>
          <div className="flex flex-col gap-1.5"><Label htmlFor="org-name">Name</Label>
            <Input id="org-name" autoFocus maxLength={60} value={name} onChange={(e) => setName(e.target.value)} placeholder="Acme Ltd" /></div>
          {error && <p role="alert" className="text-[13px] text-red-500">{error}</p>}
          <div className="flex justify-end gap-2">
            <Button type="button" variant="ghost" onClick={onClose}>Cancel</Button>
            <Button type="submit" disabled={busy}>{busy ? "Creating…" : "Create"}</Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

/** Accepting switches to the org; declining just removes the invitation. */
function useInvitationAction() {
  const reload = useReloadOrgs();
  return async (inv: Invitation, kind: "accept" | "decline") => {
    try {
      await api.post(`/me/invitations/${inv.orgId}/${kind}`);
      await reload(kind === "accept" ? inv.orgId : undefined);
      toast.success(kind === "accept" ? `You joined ${inv.orgName}` : "Invitation declined");
    } catch { toast.error("Couldn't do that. Try again."); }
  };
}

function InvitationItems({ inv, onAct }: { inv: Invitation; onAct: (inv: Invitation, kind: "accept" | "decline") => Promise<void> }) {
  return (
    <DropdownMenuGroup aria-label={`Invitation to ${inv.orgName}`}>
      <p className="px-2.5 pt-1 text-[13px] text-text-primary"><span className="font-medium">{inv.orgName}</span>
        <span className="text-text-secondary"> · {ROLE_LABEL[inv.role]}{inv.invitedBy ? ` · from ${inv.invitedBy}` : ""}</span></p>
      <DropdownMenuItem onSelect={() => void onAct(inv, "accept")}><Check />Accept and switch</DropdownMenuItem>
      <DropdownMenuItem onSelect={() => void onAct(inv, "decline")} className="text-text-secondary"><X />Decline</DropdownMenuItem>
    </DropdownMenuGroup>
  );
}

/**
 * Top of the sidebar: the active space (Personal or an organisation) and a menu to switch, accept invitations, create
 * an organisation or open its settings. Switching navigates: the URL names the space (lib/paths). A badge counts pending
 * invitations.
 */
export function OrgSwitcher({ onSettings, compact = false }: { onSettings: () => void; /** The sidebar's icon rail: just the org's logo or initials. */ compact?: boolean }) {
  const { org, orgs = [] } = useSession();
  const navigate = useNavigate();
  const open = (o: Org | null) => { if ((o?.id ?? null) !== (org?.id ?? null)) navigate(`${spacePrefix(o)}/vault`); };
  const info = useOrgsInfo();
  const [creating, setCreating] = useState(false);
  const accept = useInvitationAction();
  // An org with a stricter master password rule checks it before joining (docs/policies.md).
  const [checking, setChecking] = useState<Invitation | null>(null);
  const act = async (inv: Invitation, kind: "accept" | "decline") => (kind === "accept" && isStricter(inv.passwordPolicy) ? setChecking(inv) : accept(inv, kind));
  // Admin recovery is per organisation (per-org key pairs): joining or creating another org changes nothing in this one.
  const guard = (then: Invitation | "create") => { if (then === "create") setCreating(true); else void act(then, "accept"); };
  const invitations = info.data?.invitations ?? [];
  const label = org ? org.name : "Personal";
  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <button type="button" aria-label={`Space: ${label}${invitations.length ? `, ${invitations.length} invitation${invitations.length === 1 ? "" : "s"}` : ""}`} title={label}
            className={cn("relative flex w-full items-center gap-2.5 rounded-[10px] text-left transition-colors duration-150 hover:bg-white/[.06] aria-expanded:bg-white/[.06]",
              compact ? "justify-center p-1" : "border border-[var(--border-dark-1)] bg-white/[.03] px-2.5 py-2")}>
            <OrgAvatar org={org} size={compact ? 32 : 28} />
            {!compact && <span className="min-w-0 flex-1">
              <span className="block truncate text-[13.5px] font-medium text-[var(--text-on-dark)]" data-testid="active-org">{label}</span>
              <span className="block font-mono text-[10.5px] tracking-[.04em] text-[var(--text-dark-tertiary)]">{org ? ROLE_LABEL[org.role] : "Only you"}</span>
            </span>}
            {invitations.length > 0 && <span className={cn("grid min-w-[18px] place-items-center rounded-full bg-amber-500 px-1 font-mono text-[10.5px] font-semibold text-navy-900", compact && "absolute -top-1 -right-1")} aria-hidden="true">{invitations.length}</span>}
            {!compact && <ChevronsUpDown className="size-4 shrink-0 text-[var(--text-dark-tertiary)]" />}
          </button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="start" side={compact ? "right" : "bottom"} sideOffset={compact ? 10 : 6} className="w-[280px]">
          <DropdownMenuGroup aria-label="Personal">
            <DropdownMenuItem onSelect={() => open(null)} aria-current={!org ? "true" : undefined}>
              <OrgAvatar org={null} size={24} tone="light" className="rounded-[6px]" />
              <span className="min-w-0 flex-1 truncate">Personal</span>
              <span className="font-mono text-[10.5px] text-text-tertiary">Only you</span>
              <Check className={cn("size-4", !org ? "text-blue-500" : "invisible")} />
            </DropdownMenuItem>
          </DropdownMenuGroup>
          <DropdownMenuSeparator />
          <DropdownMenuLabel className={menuLabel}>Organisations</DropdownMenuLabel>
          <DropdownMenuGroup aria-label="Organisations">
            {orgs.map((o) => (
              <DropdownMenuItem key={o.id} onSelect={() => open(o)} aria-current={o.id === org?.id ? "true" : undefined}>
                <OrgAvatar org={o} size={24} tone="light" className="rounded-[6px]" />
                <span className="min-w-0 flex-1 truncate">{o.name}</span>
                <span className="font-mono text-[10.5px] text-text-tertiary">{ROLE_LABEL[o.role]}</span>
                <Check className={cn("size-4", o.id === org?.id ? "text-blue-500" : "invisible")} />
              </DropdownMenuItem>
            ))}
            {orgs.length === 0 && <p className="px-2.5 py-1.5 text-[13px] text-text-secondary">You aren't in an organisation yet.</p>}
          </DropdownMenuGroup>
          {invitations.length > 0 && (<>
            <DropdownMenuSeparator />
            <DropdownMenuLabel className={cn(menuLabel, "flex items-center gap-1.5")}><Mail className="size-3" />Invitations</DropdownMenuLabel>
            {invitations.map((i) => <InvitationItems key={i.orgId} inv={i} onAct={async (inv, kind) => { if (kind === "accept") guard(inv); else await act(inv, kind); }} />)}
          </>)}
          <DropdownMenuSeparator />
          {info.data?.allowOrgCreation === true && <DropdownMenuItem onSelect={() => guard("create")}><Plus />Create organisation</DropdownMenuItem>}
          {org && <DropdownMenuItem onSelect={onSettings}><Settings />Organisation settings</DropdownMenuItem>}
        </DropdownMenuContent>
      </DropdownMenu>
      <CreateOrgDialog open={creating} onClose={() => setCreating(false)} />
      {checking?.passwordPolicy && <PasswordPolicyCheck open orgName={checking.orgName} policy={checking.passwordPolicy} onClose={() => setChecking(null)}
        onPass={() => { const inv = checking; setChecking(null); void accept(inv, "accept"); }} />}
    </>
  );
}
