import { useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, Copy, LifeBuoy } from "lucide-react";
import { toast } from "sonner";
import { createMembershipRecoveryGrant, openMembershipEscrow, unlockMembershipKeys } from "@clane-vault/crypto";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ApiError } from "@/lib/api";
import { copySecret } from "@/lib/clipboard";
import { useSession } from "@/lib/session";
import { useOrgApi, useScope } from "@/lib/scope";
import { relativeTime } from "@/lib/time";
import { Chip } from "@/features/vault/people";

export interface RecoveryRequest {
  id: string; status: "pending" | "approved"; createdAt: string; approvedAt: string | null; approvedBy: string | null; expiresAt: string | null;
  user: { id: string; name: string; email: string }; canApprove: boolean;
  /** The member's 2FA was reset: a second admin must approve, and the link waits out a delay before it can be used. */
  twoFactorReset?: boolean;
}

/** `scope`: user and active org (useScope); without it, every org's (for invalidation). */
export const recoveryRequestsKey = (scope?: string) => (scope ? ["admin-recovery-requests", scope] as const : ["admin-recovery-requests"] as const);

/** Open "reset my password" requests of the active org (its admins only). */
export function useRecoveryRequests(isAdmin: boolean) {
  const { user } = useSession();
  const oapi = useOrgApi();
  return useQuery({
    queryKey: recoveryRequestsKey(useScope()), enabled: isAdmin && !!user, refetchInterval: 60_000,
    queryFn: () => oapi.get<{ requests: RecoveryRequest[] }>("/admin/recovery-requests").then((r) => r.requests),
  });
}

type Approved = { link: string; expiresAt: string };

/**
 * Approve: fresh 2FA → this admin's escrow → (on this device) open it with my membership key in this org, check it is
 * the member's key there, and re-wrap it under a one-time secret → store the blob → show the link once. The secret only
 * exists in the link's fragment. What it restores is the member's access to this organisation, nothing else.
 */
function ApproveDialog({ request, onClose }: { request: RecoveryRequest; onClose: () => void }) {
  const { user, keys, org } = useSession();
  const oapi = useOrgApi();
  const qc = useQueryClient();
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<Approved | null>(null);
  const [copied, setCopied] = useState(false);

  async function approve(e: FormEvent) {
    e.preventDefault();
    if (!user || !keys || !org) return;
    setBusy(true); setError(null);
    try {
      const esc = await oapi.post<{ sealedKey: string; memberPublicKey: string; adminPublicKey: string; member: { id: string }; approvalToken: string }>(
        `/admin/recovery-requests/${request.id}/escrow`, { code });
      if (esc.member.id !== request.user.id) throw new Error("mismatch");
      // My membership key in this org that the escrow is sealed to.
      const mine = (await oapi.get<{ keys: { publicKey: string; wrappedPrivateKey: string }[] }>("/membership-key")).keys.find((k) => k.publicKey === esc.adminPublicKey);
      if (!mine) throw new ApiError(409, "no_escrow", null);
      const own = await unlockMembershipKeys(keys.userKey, { orgId: org.id, userId: user.id }, mine);
      try {
        // Opens only with my key, and only if it is the private key of the member's listed key (checked inside).
        const member = await openMembershipEscrow(own, esc.sealedKey, { userId: esc.member.id, adminId: user.id }, esc.memberPublicKey);
        try {
          const grant = await createMembershipRecoveryGrant(request.id, { orgId: org.id, userId: esc.member.id }, member);
          const res = await oapi.post<{ linkBase: string; expiresAt: string }>(`/admin/recovery-requests/${request.id}/approve`,
            { approvalToken: esc.approvalToken, memberPublicKey: esc.memberPublicKey, wrappedMembershipKey: grant.wrappedMembershipKey, proof: grant.proof });
          setDone({ link: `${res.linkBase}#${grant.fragment}`, expiresAt: res.expiresAt });
          void qc.invalidateQueries({ queryKey: recoveryRequestsKey() });
        } finally { member.privateKey.fill(0); }
      } finally { own.privateKey.fill(0); }
    } catch (err) {
      const c = err instanceof ApiError ? err.code : "";
      setError(c === "totp_invalid" ? "That code didn't work. Try the newest code from your authenticator."
        : c === "locked" ? "Too many failed attempts. Try again in 15 minutes."
        : c === "no_escrow" ? `${request.user.name}'s key for this organisation isn't escrowed to you yet. Another admin can approve, or ask them to unlock once on a device they still use.`
        : c === "not_pending" ? "This request was already handled." : c === "policy_off" ? "Admin account recovery is off."
        : c === "two_person_required" ? `You reset ${request.user.name}'s two-step sign-in, so another admin must approve this reset.`
        : c === "approver_too_new" ? `${request.user.name}'s two-step sign-in was reset, so only an admin who was already an admin a week before that reset can approve.`
        : "Couldn't approve. The escrow may be damaged; try another admin or ask them to use their recovery kit.");
    } finally { setBusy(false); setCode(""); }
  }

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="sm:max-w-[560px]">
        <DialogHeader>
          <DialogTitle>{done ? `Send this link to ${request.user.name}` : `Approve password reset for ${request.user.name}?`}</DialogTitle>
          <DialogDescription>
            {done ? `Send it yourself, by a channel you trust (in person, a call, your chat app). It works once, until ${new Date(done.expiresAt).toLocaleString()}. ${request.user.name} also needs their own 2FA code; you never see their new password.`
              : `Only approve if you've confirmed it's really ${request.user.name} (${request.user.email}) asking, for example by a call. You'll open their key for this organisation on this device to make a one-time link; it restores their access here only.`}
          </DialogDescription>
        </DialogHeader>
        {done ? (
          <div className="flex flex-col gap-3">
            <div className="flex items-start gap-2 rounded-[10px] border border-border-default bg-well py-2 pr-1.5 pl-3">
              <code data-testid="recovery-link" className="min-w-0 flex-1 font-mono text-[12px] leading-[1.6] break-all text-text-primary">{done.link}</code>
              <Button type="button" variant="ghost" size="icon-sm" aria-label="Copy recovery link" onClick={async () => { await copySecret(done.link, 120_000); setCopied(true); toast.success("Recovery link copied"); setTimeout(() => setCopied(false), 1500); }}>
                {copied ? <Check className="size-3.5" /> : <Copy className="size-3.5" />}
              </Button>
            </div>
            <p className="text-[12.5px] text-text-secondary">Ask {request.user.name} to open it in a private (incognito) window on their own device. This link is shown once; if it's lost, cancel it and ask them to request again.</p>
            {request.twoFactorReset && <p className="text-[12.5px] text-text-secondary">Their two-step sign-in was reset, so the link only works once the waiting period after that reset has passed (24 hours by default); it stays valid for 24 hours after that.</p>}
            <div className="flex justify-end"><Button type="button" onClick={onClose}>Done</Button></div>
          </div>
        ) : (
          <form onSubmit={approve} className="flex flex-col gap-3">
            <div className="flex flex-col gap-1.5"><Label htmlFor="approve-code">Your 6-digit authenticator code</Label>
              <Input id="approve-code" inputMode="numeric" autoComplete="one-time-code" maxLength={6} autoFocus className="w-[180px] font-mono tracking-[0.3em]" value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} /></div>
            {error && <p role="alert" className="text-[13px] text-red-500">{error}</p>}
            <div className="flex justify-end gap-2">
              <Button type="button" variant="ghost" onClick={onClose}>Cancel</Button>
              <Button type="submit" disabled={busy || code.length !== 6 || !keys}>{busy ? "Approving…" : "Approve and create link"}</Button>
            </div>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
}

const card = "rounded-[14px] border border-border-default bg-card px-4 shadow-[var(--shadow-card)]";

/** People → "Password reset requests": shown only while there are open requests. */
export function RecoveryRequestsSection() {
  const { user } = useSession();
  const oapi = useOrgApi();
  const qc = useQueryClient();
  const q = useRecoveryRequests(user?.role === "admin");
  const [approving, setApproving] = useState<RecoveryRequest | null>(null);
  const deny = useMutation({
    mutationFn: (id: string) => oapi.post(`/admin/recovery-requests/${id}/deny`),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: recoveryRequestsKey() }); toast.success("Request denied"); },
    onError: () => toast.error("Couldn't deny. Try again."),
  });
  const list = q.data ?? [];
  if (!list.length) return null;
  return (
    <section className="flex flex-col gap-3" aria-label="Password reset requests">
      <div>
        <h2 className="font-display text-[15px] font-semibold tracking-[-0.01em] text-text-primary">Password reset requests <span className="font-mono text-[12px] font-normal text-text-tertiary">{list.length}</span></h2>
        <p className="text-[13px] text-text-secondary">Confirm who's asking before you approve. The link you get works once, for 24 hours.</p>
      </div>
      <ul className={card}>
        {list.map((r) => (
          <li key={r.id} aria-label={`Reset request from ${r.user.email}`} className="flex flex-wrap items-center gap-3 border-b border-border-default py-3 last:border-b-0">
            <span className="grid size-8 shrink-0 place-items-center rounded-full bg-orange-tint text-orange-ink"><LifeBuoy className="size-4" /></span>
            <span className="min-w-0 flex-1">
              <span className="flex items-center gap-2"><span className="truncate text-[14px] font-medium text-text-primary">{r.user.name}</span>
                {r.status === "pending" ? <Chip tone="orange">Waiting</Chip> : <Chip tone="blue">Link sent</Chip>}</span>
              <span className="block truncate text-[12.5px] text-text-secondary">{r.user.email} · asked {relativeTime(r.createdAt)}
                {r.status === "approved" && r.expiresAt ? ` · link expires ${relativeTime(r.expiresAt)}` : ""}
                {r.status === "pending" && !r.canApprove ? (r.user.id === user?.id || r.twoFactorReset ? " · another admin must approve" : " · not escrowed to you yet") : ""}</span>
            </span>
            <span className="flex items-center gap-1">
              {r.status === "pending" && r.canApprove && <Button type="button" size="sm" onClick={() => setApproving(r)}>Approve</Button>}
              <Button type="button" variant="ghost" size="sm" className="text-red-500 hover:bg-red-tint hover:text-red-500" onClick={() => deny.mutate(r.id)}>{r.status === "approved" ? "Cancel link" : "Deny"}</Button>
            </span>
          </li>
        ))}
      </ul>
      {approving && <ApproveDialog request={approving} onClose={() => setApproving(null)} />}
    </section>
  );
}
