import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, Copy, Mail, RefreshCw, Search } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { ApiError } from "@/lib/api";
import { copySecret } from "@/lib/clipboard";
import { useOrgApi, useScope } from "@/lib/scope";
import { relativeTime } from "@/lib/time";
import { Chip } from "@/features/vault/people";
import { INVITES_KEY, type InvitesResponse, type PendingInvite, type ResendAllResponse, type ResendResponse } from "./provisioning";

type Filter = "pending" | "expired" | "all";

const RESEND_ERRORS: Record<string, string> = {
  too_soon: "It was sent a few minutes ago. Try again later.",
  invite_limit: "This organisation has sent its invitations for today. Try again tomorrow.",
  email_required: "Invites are sent by email here, and email isn't set up on this server.",
  not_found: "That invitation is gone (accepted, declined or revoked).",
};

function CopyLink({ url }: { url: string }) {
  const [done, setDone] = useState(false);
  return (
    <Button type="button" variant="outline" size="sm" onClick={async () => { await copySecret(url, 120_000); setDone(true); toast.success("Invite link copied"); setTimeout(() => setDone(false), 1500); }}>
      {done ? <Check className="size-3.5" /> : <Copy className="size-3.5" />}Copy invite link
    </Button>
  );
}

const when = (iso: string) => relativeTime(iso) || new Date(iso).toLocaleDateString();

/**
 * Pending (and recently expired) invitations with a filter, Resend per row, Resend all pending, and Revoke. Self-hosted,
 * a new link from a resend is kept in this browser for the session (`links`, by address) so it can be copied.
 */
export function PendingInvites({ links, onLinks, onChanged }: { links: Record<string, string>; onLinks: (l: Record<string, string>) => void; onChanged: () => void }) {
  const oapi = useOrgApi();
  const qc = useQueryClient();
  const KEY = [INVITES_KEY, useScope()];
  const q = useQuery({ queryKey: KEY, queryFn: () => oapi.get<InvitesResponse>("/admin/invites?status=all") });
  const [filter, setFilter] = useState<Filter>("pending");
  const [search, setSearch] = useState("");
  const [revoking, setRevoking] = useState<string | null>(null);
  const [confirmAll, setConfirmAll] = useState(false);
  const refresh = () => { void qc.invalidateQueries({ queryKey: KEY }); onChanged(); };

  const resend = useMutation({ mutationFn: (i: PendingInvite) => oapi.post<ResendResponse>(`/admin/invites/${i.id}/resend`),
    onSuccess: (r) => {
      if (r.inviteUrl) onLinks({ [r.email]: r.inviteUrl });
      toast.success(r.emailed ? `Invitation emailed again to ${r.email}` : r.inviteUrl ? `New link for ${r.email}. Copy it and send it to them.` : `Invitation to ${r.email} renewed`);
      refresh();
    },
    onError: (e) => toast.error((e instanceof ApiError && RESEND_ERRORS[e.code]) || "Couldn't resend. Try again.") });
  const resendAll = useMutation({ mutationFn: () => oapi.post<ResendAllResponse>("/admin/invites/resend-all", {}),
    onSuccess: (r) => {
      const fresh = Object.fromEntries(r.results.filter((x) => x.inviteUrl).map((x) => [x.email, x.inviteUrl!]));
      if (Object.keys(fresh).length) onLinks(fresh);
      const capped = r.results.filter((x) => x.status === "invite_limit").length;
      toast.success(`Resent ${r.resent} ${r.resent === 1 ? "invitation" : "invitations"}${r.skipped ? ` · ${r.skipped} skipped${capped ? " (today's limit)" : r.results.some((x) => x.status === "seat_limit") ? " (no seat left)" : " (sent recently)"}` : ""}`);
      refresh();
    },
    onError: (e) => toast.error((e instanceof ApiError && RESEND_ERRORS[e.code]) || "Couldn't resend. Try again.") });
  const revoke = useMutation({ mutationFn: (id: string) => oapi.del(`/admin/invites/${id}`), onSuccess: refresh });

  const all = q.data?.invites ?? [];
  const term = search.trim().toLowerCase();
  const shown = all.filter((i) => (filter === "all" || (filter === "expired") === i.expired) && (!term || i.email.includes(term)));
  const pendingCount = q.data?.counts.pending ?? 0;
  const hosted = !!q.data?.hostedMode;
  const card = "rounded-[14px] border border-border-default bg-card px-4 shadow-[var(--shadow-card)]";
  if (!q.data || all.length === 0) return null;

  return (
    <section className="flex flex-col gap-3" aria-label="Invitations">
      <div className="flex flex-wrap items-end justify-between gap-2">
        <div>
          <h2 className="font-display text-[15px] font-semibold tracking-[-0.01em] text-text-primary">Invitations <span className="font-mono text-[12px] font-normal text-text-tertiary">{pendingCount}</span></h2>
          <p className="text-[12.5px] text-text-secondary">{q.data.cap.remaining} of {q.data.cap.perDay} invitations left today (new ones and resends).</p>
        </div>
        {pendingCount > 0 && (confirmAll ? (
          <span className="flex items-center gap-2">
            <span className="text-[13px] text-text-primary">Resend {pendingCount} pending?</span>
            <Button type="button" variant="ghost" size="sm" onClick={() => setConfirmAll(false)}>Cancel</Button>
            <Button type="button" size="sm" disabled={resendAll.isPending} onClick={() => { setConfirmAll(false); resendAll.mutate(); }}>Resend all</Button>
          </span>
        ) : <Button type="button" variant="outline" size="sm" disabled={resendAll.isPending} onClick={() => setConfirmAll(true)}><RefreshCw className="size-3.5" />{resendAll.isPending ? "Resending…" : "Resend all pending"}</Button>)}
      </div>
      <div className="flex flex-wrap gap-2">
        <div className="relative min-w-[200px] flex-1">
          <Search className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-text-tertiary" />
          <Input aria-label="Filter invitations" placeholder="Filter by email" value={search} onChange={(e) => setSearch(e.target.value)} className="h-9 pl-8" />
        </div>
        <Select value={filter} onValueChange={(v) => setFilter(v as Filter)}>
          <SelectTrigger aria-label="Invitation status" className="h-9 w-[150px]"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="pending">Pending ({q.data.counts.pending})</SelectItem>
            <SelectItem value="expired">Expired ({q.data.counts.expired})</SelectItem>
            <SelectItem value="all">All</SelectItem>
          </SelectContent>
        </Select>
      </div>
      {shown.length === 0 ? <p className="text-[13px] text-text-secondary">No {filter === "all" ? "" : `${filter} `}invitations{term ? ` matching "${search.trim()}"` : ""}.</p> : (
        <ul className={card}>
          {shown.map((i) => (
            <li key={i.id} className="flex flex-wrap items-center gap-3 border-b border-border-default py-3 last:border-b-0" aria-label={i.email}>
              <span className="grid size-8 shrink-0 place-items-center rounded-full bg-well text-text-tertiary"><Mail className="size-4" /></span>
              <span className="min-w-0 flex-1 max-[560px]:basis-[calc(100%-2.75rem)]">
                <span className="flex flex-wrap items-center gap-2">
                  <span className="truncate text-[14px] font-medium text-text-primary">{i.email}</span>
                  {i.expired ? <Chip tone="orange">Expired</Chip> : <Chip>Invited</Chip>}
                  {i.role === "admin" && <Chip tone="blue">Admin</Chip>}
                  {i.source === "domain" && <Chip tone="green">Domain auto-join</Chip>}
                </span>
                <span className="block text-[12.5px] text-text-secondary">
                  {i.expired ? `Expired ${when(i.expiresAt)}` : `Expires ${when(i.expiresAt)}`}
                  {i.lastSentAt ? ` · sent ${when(i.lastSentAt)}` : ""}
                  {i.invitedBy ? ` · by ${i.invitedBy.name}` : ""}
                </span>
                {i.groups.length > 0 && <span className="block truncate text-[12.5px] text-text-secondary">Groups when they join: {i.groups.map((g) => g.name).join(", ")}</span>}
              </span>
              {revoking === i.id ? (
                <span className="flex items-center gap-2">
                  <span className="text-[13px] text-text-primary">Revoke this invite?</span>
                  <Button type="button" variant="ghost" size="sm" onClick={() => setRevoking(null)}>Cancel</Button>
                  <Button type="button" variant="destructive" size="sm" onClick={() => { setRevoking(null); revoke.mutate(i.id, { onSuccess: () => toast.success("Invite revoked"), onError: () => toast.error("Couldn't revoke. Try again.") }); }}>Revoke</Button>
                </span>
              ) : (
                <span className="flex flex-wrap items-center justify-end gap-1">
                  {links[i.email] ? <CopyLink url={links[i.email]!} /> : hosted ? <span className="px-1 text-[12px] text-text-tertiary">Sent by email</span> : null}
                  <Button type="button" variant="ghost" size="sm" aria-label={`Resend invitation to ${i.email}`} disabled={resend.isPending && resend.variables?.id === i.id} onClick={() => resend.mutate(i)}><RefreshCw className="size-3.5" />Resend</Button>
                  <Button type="button" variant="ghost" size="sm" className="text-red-500 hover:bg-red-tint hover:text-red-500" onClick={() => setRevoking(i.id)}>Revoke</Button>
                </span>
              )}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
