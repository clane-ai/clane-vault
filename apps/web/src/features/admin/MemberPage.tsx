import { useState } from "react";
import { useSpacePaths } from "@/lib/space";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router";
import { Folder, HeartPulse, LifeBuoy, ScrollText, UsersRound } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { SectionPage } from "@/components/SectionLayout";
import { ApiError } from "@/lib/api";
import { useSession } from "@/lib/session";
import { useOrgApi, useScope } from "@/lib/scope";
import { relativeTime } from "@/lib/time";
import { cn } from "@/lib/utils";
import { Chip, PersonAvatar } from "@/features/vault/people";
import { PERMISSION_LABEL, type Permission, type VaultFolder } from "@/features/vault/types";
import { CONFIRM, STATUS, type Action, type Status } from "./PeoplePage";

/** GET /admin/members/:userId (docs: admin pages). Folder names are encrypted: shown when the admin can open the folder. */
export interface MemberDetail {
  member: { id: string; name: string; email: string; role: "owner" | "admin" | "member"; status: Status; joinedAt: string; twoFactor: boolean };
  groups: { id: string; name: string }[];
  folders: { id: string; permission: Permission; direct: Permission | null; owner: boolean }[];
  health: { score: number; total: number; weak: number; reused: number; old: number; breached: number | null; reportedAt: string } | null;
  recovery: { enabled: boolean; acknowledged: boolean; escrowed: boolean; pendingRequest: boolean };
}

const card = "rounded-[14px] border border-border-default bg-card p-4 shadow-[var(--shadow-card)]";
const h2 = "flex items-center gap-2 font-display text-[15px] font-semibold tracking-[-0.01em] text-text-primary";
const ROLE: Record<MemberDetail["member"]["role"], string> = { owner: "Owner", admin: "Admin", member: "Member" };

/** Admin → People → one member: role and status, groups, team folders, password health, recovery status and actions. */
export default function MemberPage({ userId, folders }: { userId: string; folders: VaultFolder[] }) {
  // Admin pages of the active org (lib/paths): /o/:org/admin/...
  const adminBase = useSpacePaths().admin();
  const { user } = useSession();
  const oapi = useOrgApi();
  const qc = useQueryClient();
  const navigate = useNavigate();
  const KEY = ["admin-member", useScope(), userId];
  const q = useQuery({ queryKey: KEY, queryFn: () => oapi.get<MemberDetail>(`/admin/members/${userId}`), retry: (n, e) => !(e instanceof ApiError && e.status === 404) && n < 1 });
  const [confirm, setConfirm] = useState<Action | null>(null);
  const act = useMutation({
    mutationFn: (a: Action) => a === "remove" ? oapi.del(`/admin/members/${userId}`)
      : a === "make-admin" || a === "make-member" ? oapi.patch(`/admin/members/${userId}`, { role: a === "make-admin" ? "admin" : "member" })
      : oapi.post(`/admin/users/${userId}/${a}`),
    onSuccess: (_d, a) => {
      void qc.invalidateQueries({ queryKey: ["admin-people"] }); void qc.invalidateQueries({ queryKey: ["people"] });
      if (a === "remove") navigate(`${adminBase}/people`); else void qc.invalidateQueries({ queryKey: KEY });
    },
  });
  const d = q.data;
  const notFound = q.error instanceof ApiError && q.error.status === 404;
  const title = d?.member.name ?? (notFound ? "Not found" : "Member");
  const folderName = (id: string) => folders.find((f) => f.id === id && !f.deleted)?.name ?? null;
  const self = d?.member.id === user?.id;
  const manageable = d && !self && d.member.role !== "owner";

  return (
    <SectionPage title={title} label="Member" keepHeadings>
      {q.isLoading ? <p className="text-[14px] text-text-secondary">Loading…</p>
        : notFound ? <p className="text-[14px] text-text-secondary">This person isn't in this organisation (any more). <Link to={`${adminBase}/people`} className="font-medium text-[var(--link)]">Back to People</Link></p>
        : !d ? <p role="alert" className="text-[14px] text-red-500">Couldn't load this member.</p> : (<>
          <section className={cn(card, "flex flex-col gap-3")} aria-label="Profile">
            <div className="flex flex-wrap items-center gap-3">
              <PersonAvatar id={d.member.id} name={d.member.name} />
              <div className="min-w-0 flex-1">
                <p className="flex flex-wrap items-center gap-2 text-[15px] font-medium text-text-primary">{d.member.name}
                  <Chip tone={STATUS[d.member.status].tone}>{STATUS[d.member.status].label}</Chip>{d.member.role !== "member" && <Chip tone="blue">{ROLE[d.member.role]}</Chip>}{self && <Chip>You</Chip>}</p>
                <p className="truncate font-mono text-[12.5px] text-text-secondary">{d.member.email}</p>
                <p className="text-[12.5px] text-text-tertiary">Joined {relativeTime(d.member.joinedAt) || new Date(d.member.joinedAt).toLocaleDateString()} · two-step sign-in {d.member.twoFactor ? "on" : "not set up yet"}</p>
              </div>
            </div>
            <div className="flex flex-wrap gap-1.5 border-t border-border-default pt-3">
              <Button asChild variant="outline" size="sm"><Link to={`${adminBase}/events?actor=${d.member.id}`}><ScrollText className="size-3.5" />Their events</Link></Button>
              {manageable && (<>
                {d.member.status !== "disabled" && <Button type="button" variant="ghost" size="sm" onClick={() => setConfirm(d.member.role === "admin" ? "make-member" : "make-admin")}>{d.member.role === "admin" ? "Make member" : "Make admin"}</Button>}
                {d.member.status !== "disabled" && <Button type="button" variant="ghost" size="sm" onClick={() => setConfirm("reset-2fa")}>Reset 2FA</Button>}
                {d.member.status === "disabled"
                  ? <Button type="button" variant="outline" size="sm" onClick={() => setConfirm("enable")}>Enable</Button>
                  : <Button type="button" variant="ghost" size="sm" className="text-red-500 hover:bg-red-tint hover:text-red-500" onClick={() => setConfirm("disable")}>Disable</Button>}
                <Button type="button" variant="ghost" size="sm" className="text-red-500 hover:bg-red-tint hover:text-red-500" onClick={() => setConfirm("remove")}>Remove</Button>
              </>)}
            </div>
          </section>

          <section className="flex flex-col gap-3" aria-label="Groups">
            <h2 className={h2}><UsersRound className="size-4 text-text-tertiary" />Groups <span className="font-mono text-[12px] font-normal text-text-tertiary">{d.groups.length}</span></h2>
            {d.groups.length === 0 ? <p className="text-[13px] text-text-secondary">Not in any group.</p> : (
              <ul className="flex flex-wrap gap-1.5">
                {d.groups.map((g) => <li key={g.id}><Link to={`${adminBase}/groups/${g.id}`} className="inline-flex rounded-full border border-border-default bg-card px-3 py-1 text-[13px] text-text-primary hover:border-border-strong">{g.name}</Link></li>)}
              </ul>
            )}
          </section>

          <section className="flex flex-col gap-3" aria-label="Team folders">
            <h2 className={h2}><Folder className="size-4 text-text-tertiary" />Team folders <span className="font-mono text-[12px] font-normal text-text-tertiary">{d.folders.length}</span></h2>
            {d.folders.length === 0 ? <p className="text-[13px] text-text-secondary">In no team folder.</p> : (
              <ul className={cn(card, "py-1")}>
                {d.folders.map((f) => (
                  <li key={f.id} className="flex flex-wrap items-center gap-2 border-b border-border-default py-2.5 last:border-b-0">
                    <span className="min-w-0 flex-1 truncate text-[14px] text-text-primary">{folderName(f.id) ?? <span className="text-text-tertiary italic">A folder you aren't in</span>}</span>
                    <Chip tone={f.owner ? "blue" : "neutral"}>{f.owner ? "Owner" : PERMISSION_LABEL[f.permission]}</Chip>
                    {!f.owner && <span className="font-mono text-[11px] text-text-tertiary">{f.direct ? (f.direct === f.permission ? "direct" : "direct + group") : "via group"}</span>}
                  </li>
                ))}
              </ul>
            )}
          </section>

          <section className="flex flex-col gap-3" aria-label="Password health">
            <h2 className={h2}><HeartPulse className="size-4 text-text-tertiary" />Password health</h2>
            {d.health ? (
              <div className={cn(card, "flex flex-wrap items-center gap-x-6 gap-y-2")}>
                <p className="font-display text-[28px] leading-none font-semibold tabular-nums"><span className={d.health.score >= 80 ? "text-green-600" : d.health.score >= 50 ? "text-orange-ink" : "text-red-500"}>{d.health.score}</span></p>
                {([["Passwords", d.health.total], ["Weak", d.health.weak], ["Reused", d.health.reused], ["Old", d.health.old], ["Breached", d.health.breached ?? "—"]] as const).map(([k, v]) => (
                  <p key={k} className="text-[13px] text-text-secondary">{k} <span className="font-mono text-text-primary tabular-nums">{v}</span></p>
                ))}
                <p className="w-full text-[12px] text-text-tertiary">Reported by their app {relativeTime(d.health.reportedAt) || new Date(d.health.reportedAt).toLocaleDateString()}. Counts only; their passwords never leave their device.</p>
              </div>
            ) : <p className="text-[13px] text-text-secondary">No report yet: their app sends one after they next unlock.</p>}
          </section>

          <section className="flex flex-col gap-3" aria-label="Account recovery">
            <h2 className={h2}><LifeBuoy className="size-4 text-text-tertiary" />Account recovery</h2>
            <div className={cn(card, "text-[13px] text-text-secondary")}>
              {!d.recovery.enabled ? <p>Admin recovery is off in this organisation: only their own recovery kit restores their access. <Link to={`${adminBase}/org/recovery`} className="font-medium text-[var(--link)]">Admin recovery</Link></p> : (
                <p>Admin recovery is on. {d.recovery.escrowed ? "Their key is escrowed to this organisation's admins." : d.recovery.acknowledged ? "Not escrowed yet: it is once they next unlock." : "They haven't confirmed it yet, so nothing is escrowed."}</p>
              )}
              {d.recovery.pendingRequest && <p className="mt-2 font-medium text-orange-ink">They asked for a password reset. <Link to={`${adminBase}/people`} className="text-[var(--link)]">Review it under People</Link></p>}
            </div>
          </section>
        </>)}

      <Dialog open={!!confirm && !!d} onOpenChange={(o) => !o && setConfirm(null)}>
        <DialogContent>
          {confirm && d && (<>
            <DialogHeader>
              <DialogTitle>{CONFIRM[confirm].title(d.member.name)}</DialogTitle>
              <DialogDescription>{CONFIRM[confirm].line}</DialogDescription>
            </DialogHeader>
            <div className="flex justify-end gap-2">
              <Button type="button" variant="ghost" onClick={() => setConfirm(null)}>Cancel</Button>
              <Button type="button" variant={confirm === "enable" || confirm === "make-admin" ? "default" : "destructive"} onClick={() => {
                const a = confirm; setConfirm(null);
                act.mutate(a, { onSuccess: () => toast.success(CONFIRM[a].done), onError: (err) => toast.error(err instanceof ApiError && err.code === "other_orgs"
                  ? "They're also in other organisations: only an admin of all of them (or the server's admin) can do that." : "Couldn't do that. Try again.") });
              }}>{CONFIRM[confirm].button}</Button>
            </div>
          </>)}
        </DialogContent>
      </Dialog>
    </SectionPage>
  );
}
