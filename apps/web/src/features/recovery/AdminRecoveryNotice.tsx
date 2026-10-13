import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { ShieldAlert } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { api } from "@/lib/api";
import { useSession } from "@/lib/session";
import { securityKey, useSecurity } from "./recovery";

/**
 * One-time, blocking notice when the organisation has turned admin recovery on and this user hasn't confirmed it yet.
 * Nothing is escrowed before they press Continue (the server enforces the acknowledgement too).
 */
export function AdminRecoveryNotice() {
  const { user, signOut } = useSession();
  const qc = useQueryClient();
  const sec = useSecurity();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // One organisation at a time: each one's admins get the user's key only after this user confirms for that org.
  const pending = sec.data?.orgs?.find((o) => o.ackRequired) ?? null;
  const open = !!sec.data?.adminRecoveryEnabled && !!sec.data.adminRecoveryAckRequired;
  const orgName = pending?.orgName ?? "Your organisation";
  async function ack() {
    setBusy(true); setError(null);
    try {
      await api.post("/me/admin-recovery-ack", pending ? { orgId: pending.orgId } : {});
      await qc.invalidateQueries({ queryKey: securityKey(user?.id ?? "") });
    } catch { setError("Couldn't save that. Check your connection and try again."); }
    finally { setBusy(false); }
  }
  return (
    <Dialog open={open}>
      <DialogContent showCloseButton={false} onEscapeKeyDown={(e) => e.preventDefault()} onPointerDownOutside={(e) => e.preventDefault()} onInteractOutside={(e) => e.preventDefault()}>
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2"><ShieldAlert className="size-5 text-orange-ink" />{orgName} turned on admin recovery</DialogTitle>
          <DialogDescription>
            From now on the admins of {orgName} can help you reset your master password and restore your access to {orgName}'s shared folders and items. They can't open your private items or other organisations' items: your recovery kit restores those. When you continue, your key for {orgName} is sealed to each of its admins on this device.
          </DialogDescription>
        </DialogHeader>
        <p className="text-[13px] leading-relaxed text-text-secondary">A reset still needs a one-time link and your own two-step sign-in code. If you have questions about this, ask your admin before you continue.</p>
        {error && <p role="alert" className="text-[13px] text-red-500">{error}</p>}
        <div className="flex justify-end gap-2">
          <Button type="button" variant="ghost" onClick={() => void signOut()}>Sign out</Button>
          <Button type="button" onClick={ack} disabled={busy}>{busy ? "Saving…" : "Continue"}</Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
