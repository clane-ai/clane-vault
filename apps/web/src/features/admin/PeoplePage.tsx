import { useEffect, useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Download, FolderSync, UserPlus, UsersRound } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { ApiError } from "@/lib/api";
import { useSession } from "@/lib/session";
import { useOrgApi, useScope } from "@/lib/scope";
import { Chip, PersonRow } from "@/features/vault/people";
import { RecoveryRequestsSection } from "./RecoveryRequests";
import { PageHeader } from "@/components/SectionLayout";
import { InviteDialog } from "./InviteDialog";
import { PendingInvites } from "./PendingInvites";
import { OnboardingChecklist } from "./Onboarding";
import { INVITES_KEY, ONBOARDING_KEY } from "./provisioning";
import { planMessage } from "./plan";

export type Role = "admin" | "member";
export type Status = "active" | "pending_2fa" | "disabled";
interface AdminUser { id: string; name: string; email: string; role: Role | "owner"; status: Status; createdAt: string; publicKey: string }
/**
 * The same answer whoever the address belongs to (no account oracle): a one-time copyable link in self-hosted mode,
 * nothing but "emailed" in hosted mode.
 */
interface CreatedInvite { invited: true; email: string; role: Role; emailed: boolean; inviteUrl?: string }
export type Action = "disable" | "enable" | "reset-2fa" | "remove" | "make-admin" | "make-member";
type Confirm = { user: AdminUser; action: Action } | null;

export const STATUS: Record<Status, { label: string; tone: "green" | "orange" | "red" }> = {
  active: { label: "Active", tone: "green" }, pending_2fa: { label: "Needs 2FA setup", tone: "orange" }, disabled: { label: "Disabled", tone: "red" },
};
export const CONFIRM: Record<Action, { title: (n: string) => string; line: string; button: string; done: string }> = {
  disable: { title: (n) => `Disable ${n}?`, line: "They lose access to this organisation right away (its team folders, shares and links) until you enable them again. Their account, private records and other organisations are not affected.", button: "Disable", done: "Disabled" },
  enable: { title: (n) => `Enable ${n}?`, line: "They get their access to this organisation back.", button: "Enable", done: "Enabled" },
  remove: { title: (n) => `Remove ${n} from this organisation?`, line: "They leave every team folder here; records they created in them pass to the folder owner, and their shares and links in this organisation end. Their account and private records stay theirs.", button: "Remove", done: "Removed" },
  "make-admin": { title: (n) => `Make ${n} an admin?`, line: "Admins invite and manage people in this organisation and see its recovery requests. Other admins are told.", button: "Make admin", done: "Now an admin" },
  "make-member": { title: (n) => `Make ${n} a member?`, line: "They lose admin rights in this organisation, and escrows held by them here are deleted.", button: "Make member", done: "Now a member" },
  "reset-2fa": { title: (n) => `Reset 2FA for ${n}?`, line: "They are signed out everywhere and set up a new authenticator the next time they sign in. Use this when they lost their phone.", button: "Reset 2FA", done: "2FA reset" },
};

export default function PeoplePage({ onOpenMigrate, pendingReady = 0 }: { onOpenMigrate?: () => void; pendingReady?: number } = {}) {
  const { user, keys } = useSession();
  const qc = useQueryClient();
  const KEY = ["admin-people", useScope()];
  const oapi = useOrgApi();
  const scope = useScope();
  const q = useQuery({ queryKey: KEY, queryFn: () => oapi.get<{ users: AdminUser[] }>("/admin/people") });
  const refetch = () => {
    for (const k of [KEY, [INVITES_KEY, scope], [ONBOARDING_KEY, scope], ["people"]]) void qc.invalidateQueries({ queryKey: k });
  };
  const [inviting, setInviting] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<Role>("member");
  const [error, setError] = useState<string | null>(null);
  // Invite links are returned once; this browser keeps the ones it created for the session so the admin can copy them again.
  const [links, setLinks] = useState<Record<string, string>>({});
  const [confirm, setConfirm] = useState<Confirm>(null);
  // Invite links are bearer secrets: drop them when the vault locks and when the page goes away.
  useEffect(() => { if (!keys) setLinks({}); }, [keys]);
  useEffect(() => () => setLinks({}), []);

  const invite = useMutation({
    mutationFn: (v: { email: string; role: Role }) => oapi.post<CreatedInvite>("/admin/invites", v),
    onSuccess: (r) => { if (r.inviteUrl) setLinks((l) => ({ ...l, [r.email]: r.inviteUrl! })); refetch(); },
  });
  const act = useMutation({ mutationFn: (c: NonNullable<Confirm>) =>
    c.action === "remove" ? oapi.del(`/admin/members/${c.user.id}`)
      : c.action === "make-admin" || c.action === "make-member" ? oapi.patch(`/admin/members/${c.user.id}`, { role: c.action === "make-admin" ? "admin" : "member" })
      : oapi.post(`/admin/users/${c.user.id}/${c.action}`), onSuccess: refetch });

  /** CSV of the members or of the invitations (docs/provisioning.md). */
  async function exportCsv(what: "people" | "invites") {
    setExporting(true);
    try {
      const csv = await oapi.text(`/admin/${what}/export.csv`);
      const url = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
      const a = document.createElement("a");
      a.href = url; a.download = `${what === "people" ? "members" : "invitations"}-${new Date().toISOString().slice(0, 10)}.csv`;
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch { toast.error("Couldn't export. Try again."); }
    finally { setExporting(false); }
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    const addr = email.trim();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(addr)) return setError("Enter a valid email address.");
    setError(null);
    try {
      const r = await invite.mutateAsync({ email: addr, role });
      setEmail("");
      toast.success(r.emailed ? `Invite emailed to ${r.email}` : r.inviteUrl ? `Invite created for ${r.email}. Copy the link and send it to them.` : `Invited ${r.email}`);
    } catch (err) {
      const c = err instanceof ApiError ? err.code : "";
      setError(planMessage(err) ?? (c === "invite_cooldown" ? "That address declined (or was cancelled) recently. Try again tomorrow." : c === "invite_limit" ? "This organisation has sent its invites for today. Try again tomorrow."
        : c === "email_required" ? "Invites are sent by email here, and email isn't set up on this server." : "Couldn't create the invite. Try again."));
    }
  }

  const users = q.data?.users ?? [];
  const card = "rounded-[14px] border border-border-default bg-card px-4 shadow-[var(--shadow-card)]";
  const h2 = "font-display text-[15px] font-semibold tracking-[-0.01em] text-text-primary";

  return (
    <section className="flex min-h-0 min-w-0 flex-1 flex-col" aria-label="People">
      <PageHeader title="People">
        <DropdownMenu>
          <DropdownMenuTrigger asChild><Button type="button" variant="outline" size="sm" disabled={exporting}><Download className="size-3.5" />{exporting ? "Exporting…" : "Export CSV"}</Button></DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem onSelect={() => void exportCsv("people")}><UsersRound />Members</DropdownMenuItem>
            <DropdownMenuItem onSelect={() => void exportCsv("invites")}><UserPlus />Invitations</DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
        <Button type="button" size="sm" onClick={() => setInviting(true)}><UserPlus className="size-3.5" />Invite people</Button>
      </PageHeader>
      <div className="relative min-h-0 flex-1 overflow-y-auto px-6 py-5 max-[760px]:px-3">
        <div className="mx-auto flex max-w-[760px] flex-col gap-6">
          <OnboardingChecklist onInvite={() => setInviting(true)} />
          <RecoveryRequestsSection />
          {pendingReady > 0 && (
            <div role="status" className="flex flex-wrap items-center gap-2.5 rounded-[12px] border border-[var(--orange-tint-border)] bg-orange-tint px-4 py-2.5 text-[13px] text-text-primary">
              <FolderSync className="size-4 shrink-0 text-orange-ink" />
              <p className="min-w-0 flex-1">{pendingReady} {pendingReady === 1 ? "person has" : "people have"} registered and can now be added to their Keeper folders.</p>
              {onOpenMigrate && <Button type="button" variant="outline" size="sm" onClick={onOpenMigrate}>Complete pending members</Button>}
            </div>
          )}
          <section className="flex flex-col gap-3" aria-label="Invite someone">
            <div className="flex flex-wrap items-end justify-between gap-2">
              <div><h2 className={h2}>Invite someone</h2><p className="text-[13px] text-text-secondary">They get a link to create their account. Links work for 7 days.</p></div>
              <Button type="button" variant="ghost" size="sm" onClick={() => setInviting(true)}>Invite several people or upload a CSV</Button>
            </div>
            <form onSubmit={submit} className={`${card} flex flex-wrap items-end gap-3 py-4`} noValidate>
              <div className="flex min-w-[220px] flex-1 flex-col gap-1.5"><Label htmlFor="invite-email">Email</Label>
                <Input id="invite-email" type="email" autoComplete="off" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="name@company.com" /></div>
              <div className="flex flex-col gap-1.5"><Label htmlFor="invite-role">Role</Label>
                <Select value={role} onValueChange={(v) => setRole(v as Role)}>
                  <SelectTrigger id="invite-role" className="w-[130px]"><SelectValue /></SelectTrigger>
                  <SelectContent><SelectItem value="member">Member</SelectItem><SelectItem value="admin">Admin</SelectItem></SelectContent>
                </Select></div>
              <Button type="submit" disabled={invite.isPending}><UserPlus className="size-4" />{invite.isPending ? "Inviting…" : "Invite"}</Button>
              {error && <p role="alert" className="w-full text-[13px] text-red-500">{error}</p>}
            </form>
          </section>

          <PendingInvites links={links} onLinks={(l) => setLinks((cur) => ({ ...cur, ...l }))} onChanged={refetch} />

          <section className="flex flex-col gap-3" aria-label="Everyone">
            <h2 className={h2}>Everyone <span className="font-mono text-[12px] font-normal text-text-tertiary">{users.length}</span></h2>
            {q.isLoading ? <p className="text-[14px] text-text-secondary">Loading…</p> : q.error ? <p role="alert" className="text-[14px] text-red-500">Couldn't load people.</p> : (
              <ul className={card}>
                {users.map((u) => (
                  <PersonRow key={u.id} id={u.id} href={`/admin/people/${u.id}`} name={u.name} email={u.email} publicKey={u.publicKey}
                    badge={<><Chip tone={STATUS[u.status].tone}>{STATUS[u.status].label}</Chip>{u.role === "owner" && <Chip tone="blue">Owner</Chip>}{u.role === "admin" && <Chip tone="blue">Admin</Chip>}{u.id === user?.id && <Chip>You</Chip>}</>}>
                    {u.id !== user?.id && u.role !== "owner" && (
                      <span className="flex shrink-0 items-center gap-1 max-[560px]:min-w-0 max-[560px]:shrink max-[560px]:flex-wrap max-[560px]:justify-end">
                        {u.status !== "disabled" && <Button type="button" variant="ghost" size="sm" onClick={() => setConfirm({ user: u, action: "reset-2fa" })}>Reset 2FA</Button>}
                        {u.status === "disabled"
                          ? <Button type="button" variant="outline" size="sm" onClick={() => setConfirm({ user: u, action: "enable" })}>Enable</Button>
                          : <Button type="button" variant="ghost" size="sm" className="text-red-500 hover:bg-red-tint hover:text-red-500" onClick={() => setConfirm({ user: u, action: "disable" })}>Disable</Button>}
                        {u.status !== "disabled" && <Button type="button" variant="ghost" size="sm" onClick={() => setConfirm({ user: u, action: u.role === "admin" ? "make-member" : "make-admin" })}>{u.role === "admin" ? "Make member" : "Make admin"}</Button>}
                        <Button type="button" variant="ghost" size="sm" className="text-red-500 hover:bg-red-tint hover:text-red-500" onClick={() => setConfirm({ user: u, action: "remove" })}>Remove</Button>
                      </span>
                    )}
                  </PersonRow>
                ))}
              </ul>
            )}
          </section>
        </div>
      </div>

      <InviteDialog open={inviting} onOpenChange={setInviting} onSent={(r) => {
        const fresh = Object.fromEntries(r.results.filter((x) => x.inviteUrl).map((x) => [x.email, x.inviteUrl!]));
        if (Object.keys(fresh).length) setLinks((l) => ({ ...l, ...fresh }));
        refetch();
      }} />

      <Dialog open={!!confirm} onOpenChange={(o) => !o && setConfirm(null)}>
        <DialogContent>
          {confirm && (<>
            <DialogHeader>
              <DialogTitle>{CONFIRM[confirm.action].title(confirm.user.name)}</DialogTitle>
              <DialogDescription>{CONFIRM[confirm.action].line}</DialogDescription>
            </DialogHeader>
            <div className="flex justify-end gap-2">
              <Button type="button" variant="ghost" onClick={() => setConfirm(null)}>Cancel</Button>
              <Button type="button" variant={confirm.action === "enable" || confirm.action === "make-admin" ? "default" : "destructive"} onClick={() => {
                const c = confirm; setConfirm(null);
                act.mutate(c, { onSuccess: () => toast.success(CONFIRM[c.action].done), onError: (err) => toast.error(err instanceof ApiError && err.code === "other_orgs"
                  ? "They're also in other organisations: only an admin of all of them (or the server's admin) can do that." : "Couldn't do that. Try again.") });
              }}>{CONFIRM[confirm.action].button}</Button>
            </div>
          </>)}
        </DialogContent>
      </Dialog>
    </section>
  );
}
