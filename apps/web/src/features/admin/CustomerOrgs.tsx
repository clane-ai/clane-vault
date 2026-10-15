import { useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Building2, Copy } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ApiError, forOrg } from "@/lib/api";
import { cn } from "@/lib/utils";
import { Chip } from "@/features/vault/people";

const card = "rounded-[14px] border border-border-default bg-card p-4 shadow-[var(--shadow-card)]";
const h2 = "font-display text-[15px] font-semibold tracking-[-0.01em] text-text-primary";
const th = "px-3 py-2 text-left font-mono text-[10.5px] font-normal tracking-[.1em] text-text-tertiary uppercase";
// The server's own routes: no organisation header.
const sapi = forOrg(null);

export interface CustomerOrg { id: string; name: string; ownerEmail: string; createdAt: string; status: "pending" | "expired" | "accepted"; expiresAt: string | null }
interface CustomerOrgList { orgs: CustomerOrg[]; hostedMode: boolean; emailConfigured: boolean }
interface Sent { org: CustomerOrg; emailed: boolean; inviteUrl?: string }
export const CUSTOMER_ORGS_KEY = ["admin-instance-orgs"] as const;

const ERRORS: Record<string, string> = {
  invalid_request: "Use a plain organisation name (up to 60 characters, no links or email addresses) and a valid email address.",
  self: "That's your own address. Create an organisation for yourself from the organisation menu instead.",
  email_required: "Set up email first (Server → Email): on this server invitations are only sent by email.",
  too_soon: "It was sent less than 5 minutes ago. Try again in a few minutes.",
  invite_cooldown: "They declined less than a day ago. Try again tomorrow.",
  accepted: "They've already accepted.",
  not_found: "That organisation no longer exists.",
};
const errorText = (e: unknown, fallback: string) => (e instanceof ApiError ? ERRORS[e.code] ?? fallback : "Couldn't reach the server.");
const STATUS: Record<CustomerOrg["status"], { label: string; tone: "blue" | "neutral" | "green" }> = {
  pending: { label: "Pending", tone: "blue" }, expired: { label: "Expired", tone: "neutral" }, accepted: { label: "Accepted", tone: "green" },
};
const day = (iso: string) => new Date(iso).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" });

/** A link to pass on (self-hosted, when it can't be emailed): shown once. */
function InviteLink({ url, email }: { url: string; email: string }) {
  return (
    <div className="flex flex-col gap-1">
      <span className="text-[12.5px] text-text-secondary">Send this link to {email} yourself (it works for 7 days and is shown once):</span>
      <div className="flex min-w-0 items-center gap-2 rounded-[9px] border border-border-default bg-well px-2.5 py-1.5">
        <code className="min-w-0 flex-1 truncate font-mono text-[12.5px] text-text-primary" title={url}>{url}</code>
        <button type="button" aria-label="Copy invitation link" className="text-text-tertiary hover:text-text-primary" onClick={() => { void navigator.clipboard?.writeText(url).then(() => toast.success("Copied"), () => undefined); }}><Copy className="size-3.5" /></button>
      </div>
    </div>
  );
}

const sentText = (r: Sent) => (r.emailed ? `The invitation was emailed to ${r.org.ownerEmail}.` : r.inviteUrl ? "" : `No email was sent to ${r.org.ownerEmail} (email isn't set up or failed).`);

/**
 * Server → Customer organisations: an instance admin creates an organisation with no members and invites its owner, then
 * follows the invitation (POST/GET /admin/instance/orgs). Only what the operator typed shows: never members or data.
 */
export function CustomerOrgsSection() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: CUSTOMER_ORGS_KEY, queryFn: () => sapi.get<CustomerOrgList>("/admin/instance/orgs") });
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [created, setCreated] = useState<Sent | null>(null);
  const [resent, setResent] = useState<Sent | null>(null);
  const [cancelling, setCancelling] = useState<CustomerOrg | null>(null);
  const refresh = () => qc.invalidateQueries({ queryKey: CUSTOMER_ORGS_KEY });

  const create = useMutation({
    mutationFn: (b: { name: string; ownerEmail: string }) => sapi.post<Sent>("/admin/instance/orgs", b),
    onSuccess: (r) => { setCreated(r); setName(""); setEmail(""); void refresh(); },
    onError: (e) => setError(errorText(e, "Couldn't create it. Try again.")),
  });
  const resend = useMutation({
    mutationFn: (o: CustomerOrg) => sapi.post<Sent>(`/admin/instance/orgs/${o.id}/resend`),
    onSuccess: (r) => { setResent(r); void refresh(); if (r.emailed) toast.success(`Invitation sent again to ${r.org.ownerEmail}`); },
    onError: (e) => toast.error(errorText(e, "Couldn't resend it. Try again.")),
  });
  const cancel = useMutation({
    mutationFn: (o: CustomerOrg) => sapi.del(`/admin/instance/orgs/${o.id}`),
    onSuccess: (_r, o) => { toast.success(`${o.name} deleted and its invitation cancelled`); if (resent?.org.id === o.id) setResent(null); void refresh(); },
    onError: (e) => { toast.error(errorText(e, "Couldn't cancel it. Try again.")); void refresh(); },
    onSettled: () => setCancelling(null),
  });

  function submit(e: FormEvent) {
    e.preventDefault(); setError(null); setCreated(null);
    if (!name.trim() || !email.trim()) return setError("Enter the organisation's name and its owner's email address.");
    create.mutate({ name: name.trim(), ownerEmail: email.trim() });
  }

  const orgs = q.data?.orgs ?? [];
  const noEmail = q.data && q.data.hostedMode && !q.data.emailConfigured;
  return (
    <section className="flex flex-col gap-3" aria-label="Customer organisations">
      <div>
        <h2 className={h2}>Customer organisations</h2>
        <p className="text-[13px] leading-relaxed text-text-secondary">
          Creates an organisation with no members and invites its owner. You don't join it and can't see inside it: the owner sets it up and invites their people.
          Their browser makes the organisation's keys when they first open it.
        </p>
      </div>
      <form onSubmit={submit} noValidate aria-label="Create an organisation for a customer" className={cn(card, "flex flex-col gap-3")}>
        <div className="grid gap-3 sm:grid-cols-2">
          <div className="flex flex-col gap-1.5"><Label htmlFor="customer-org-name">Organisation name</Label>
            <Input id="customer-org-name" maxLength={60} placeholder="Acme Ltd" value={name} onChange={(e) => setName(e.target.value)} /></div>
          <div className="flex flex-col gap-1.5"><Label htmlFor="customer-org-owner">Owner's email address</Label>
            <Input id="customer-org-owner" type="email" spellCheck={false} autoComplete="off" placeholder="name@acme.com" value={email} onChange={(e) => setEmail(e.target.value)} /></div>
        </div>
        {noEmail && <p className="text-[12.5px] text-orange-ink">Email isn't set up on this server, and here invitations are only sent by email. Set it up in Server → Email first.</p>}
        {error && <p role="alert" className="text-[13px] text-red-500">{error}</p>}
        {created && (
          <div role="status" className="flex flex-col gap-2 rounded-[10px] border border-border-default bg-well px-3 py-2.5 text-[13px] text-text-primary">
            <p><span className="font-medium">{created.org.name}</span> was created. {sentText(created)}</p>
            {created.inviteUrl && <InviteLink url={created.inviteUrl} email={created.org.ownerEmail} />}
          </div>
        )}
        <div className="flex justify-end">
          <Button type="submit" disabled={create.isPending}>{create.isPending ? "Creating…" : "Create and invite owner"}</Button>
        </div>
      </form>

      <div className={cn(card, "p-0")}>
        {q.isLoading ? <p className="p-4 text-[14px] text-text-secondary">Loading…</p> : q.error ? <p role="alert" className="p-4 text-[14px] text-red-500">Couldn't load the organisations.</p>
          : !orgs.length ? (
            <div className="flex items-center gap-3 p-4 text-[13px] text-text-secondary"><Building2 className="size-4 shrink-0 text-text-tertiary" />No organisations created for customers yet.</div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[560px] text-[13px]" aria-label="Organisations created for customers">
                <thead><tr className="border-b border-border-default"><th className={th}>Organisation</th><th className={th}>Created</th><th className={th}>Owner</th><th className={th}>Invitation</th><th className={th}><span className="sr-only">Actions</span></th></tr></thead>
                <tbody>
                  {orgs.map((o) => (
                    <tr key={o.id} aria-label={o.name} className="border-b border-border-default align-top last:border-b-0">
                      <td className="px-3 py-2.5 font-medium text-text-primary">{o.name}</td>
                      <td className="px-3 py-2.5 whitespace-nowrap text-text-secondary">{day(o.createdAt)}</td>
                      <td className="px-3 py-2.5 font-mono text-[12.5px] text-text-secondary">{o.ownerEmail}
                        {resent?.org.id === o.id && resent.inviteUrl && <div className="mt-2 font-sans"><InviteLink url={resent.inviteUrl} email={o.ownerEmail} /></div>}</td>
                      <td className="px-3 py-2.5 whitespace-nowrap"><Chip tone={STATUS[o.status].tone}>{STATUS[o.status].label}</Chip>
                        {o.status === "pending" && o.expiresAt && <span className="ml-2 text-[12px] text-text-tertiary">until {day(o.expiresAt)}</span>}</td>
                      <td className="px-3 py-2 text-right whitespace-nowrap">
                        {o.status !== "accepted" && (<>
                          <Button type="button" size="sm" variant="outline" aria-label={`Resend invite for ${o.name}`} disabled={resend.isPending} onClick={() => resend.mutate(o)}>Resend invite</Button>
                          <Button type="button" size="sm" variant="ghost" aria-label={`Cancel ${o.name}`} className="ml-1 text-red-500 hover:bg-red-tint hover:text-red-500" onClick={() => setCancelling(o)}>Cancel</Button>
                        </>)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
      </div>

      <Dialog open={cancelling !== null} onOpenChange={(o) => !o && !cancel.isPending && setCancelling(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Cancel the invitation and delete {cancelling?.name}?</DialogTitle>
            <DialogDescription>Nobody has joined it, so there's nothing in it. The invitation link to {cancelling?.ownerEmail} stops working.</DialogDescription>
          </DialogHeader>
          <div className="flex justify-end gap-2">
            <Button type="button" variant="ghost" onClick={() => setCancelling(null)} disabled={cancel.isPending}>Keep it</Button>
            <Button type="button" variant="destructive" onClick={() => cancelling && cancel.mutate(cancelling)} disabled={cancel.isPending}>{cancel.isPending ? "Deleting…" : "Cancel and delete"}</Button>
          </div>
        </DialogContent>
      </Dialog>
    </section>
  );
}
