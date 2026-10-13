import { useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useSession } from "@/lib/session";
import { BASE_PASSWORD_POLICY, checkMasterPassword, passwordRuleText, type PasswordPolicy } from "@/lib/policies";

/** Whether an organisation's master password rule goes beyond the app's own floor (then accepting checks it first). */
export const isStricter = (p?: PasswordPolicy | null) => !!p && (p.minLength > BASE_PASSWORD_POLICY.minLength || p.minScore > BASE_PASSWORD_POLICY.minScore);

/**
 * Before joining an organisation with a master password rule (docs/policies.md): the member types their master
 * password, which is checked against their own account on this device and then against the rule. Nothing is sent.
 */
export function PasswordPolicyCheck({ orgName, policy, open, onPass, onClose }: { orgName: string; policy: PasswordPolicy; open: boolean; onPass: () => void; onClose: () => void }) {
  const { proveMaster } = useSession();
  const [pw, setPw] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const close = () => { setPw(""); setError(null); onClose(); };
  async function submit(e: FormEvent) {
    e.preventDefault(); setBusy(true); setError(null);
    try {
      await proveMaster(pw);
      const why = checkMasterPassword(pw, policy);
      if (why) setError(`${why} ${orgName} requires this before you join.`);
      else { setPw(""); onPass(); }
    } catch (err) { setError(`${(err as Error).message}.`); }
    finally { setBusy(false); }
  }
  return (
    <Dialog open={open} onOpenChange={(o) => !o && close()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{orgName} has a master password rule</DialogTitle>
          <DialogDescription>{passwordRuleText(policy)} Enter your master password to check it. It stays on this device.</DialogDescription>
        </DialogHeader>
        <form onSubmit={submit} className="flex flex-col gap-3">
          <div className="flex flex-col gap-1.5"><Label htmlFor="policy-pw">Master password</Label>
            <Input id="policy-pw" type="password" autoComplete="current-password" value={pw} onChange={(e) => setPw(e.target.value)} /></div>
          {error && <p role="alert" className="text-[13px] text-red-500">{error}</p>}
          <div className="flex justify-end gap-2">
            <Button type="button" variant="ghost" onClick={close}>Cancel</Button>
            <Button type="submit" disabled={busy || !pw}>{busy ? "Checking…" : "Check and join"}</Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
