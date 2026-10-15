import { useState, type FormEvent } from "react";
import { useMutation } from "@tanstack/react-query";
import { Smartphone } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ApiError, forOrg } from "@/lib/api";
import { cn } from "@/lib/utils";

const card = "rounded-[14px] border border-border-default bg-card p-4 shadow-[var(--shadow-card)]";
// The server's own routes: no organisation header.
const sapi = forOrg(null);

const ERRORS: Record<string, string> = {
  not_found: "No account uses that address.",
  self: "That's your own account. Reset your own authenticator with the reset-2fa command on the server.",
  disabled: "That account is disabled. Enable it before resetting its authenticator.",
  invalid_request: "Enter an email address.",
  rate_limited: "Too many resets in a minute. Wait a moment and try again.",
  totp_invalid: "That code didn't work. Wait for the next code from your authenticator and try again.",
  locked: "Too many failed attempts. Your account is locked for 15 minutes.",
};
/** Errors about the instance admin's own code: shown in the confirmation step, which stays open. */
const CODE_ERRORS = new Set(["totp_invalid", "locked"]);
const errorText = (e: unknown) => (e instanceof ApiError ? ERRORS[e.status === 429 ? "rate_limited" : e.code] ?? "Couldn't reset it. Try again." : "Couldn't reach the server.");

/**
 * Server → Accounts: resets someone's authenticator by email address (POST /admin/instance/users/reset-2fa). The only
 * way to reset an organisation owner's; works without seeing into their organisations. A confirmation step first, with
 * the instance admin's own fresh authenticator code (the server checks it before anything else).
 */
export function ResetAuthenticatorCard() {
  const [email, setEmail] = useState("");
  const [confirming, setConfirming] = useState<string | null>(null);
  const [result, setResult] = useState<{ ok: boolean; text: string } | null>(null);
  const [code, setCode] = useState("");
  const [codeError, setCodeError] = useState<string | null>(null);
  const close = () => { setConfirming(null); setCode(""); setCodeError(null); };
  const reset = useMutation({
    mutationFn: (b: { email: string; code: string }) => sapi.post<{ ok: true; email: string; emailed: boolean }>("/admin/instance/users/reset-2fa", b),
    onSuccess: (r) => {
      close(); setEmail("");
      setResult({ ok: true, text: `${r.email} is signed out everywhere and will set up a new authenticator at their next sign-in. ${r.emailed ? "They were emailed about it." : "No email was sent (email isn't set up or failed): tell them yourself."}` });
    },
    onError: (e) => {
      setCode("");
      if (e instanceof ApiError && CODE_ERRORS.has(e.code)) return setCodeError(errorText(e));
      close(); setResult({ ok: false, text: errorText(e) });
    },
  });
  function submit(e: FormEvent) {
    e.preventDefault(); setResult(null);
    const address = email.trim().toLowerCase();
    if (!address.includes("@")) return setResult({ ok: false, text: ERRORS.invalid_request! });
    setConfirming(address);
  }
  return (
    <section className={cn(card, "flex flex-col gap-3")} aria-label="Reset someone's authenticator">
      <div className="flex items-start gap-3">
        <span className="grid size-9 shrink-0 place-items-center rounded-[10px] bg-well text-text-tertiary"><Smartphone className="size-4" /></span>
        <div className="min-w-0 flex-1">
          <h2 className="text-[14px] font-medium text-text-primary">Reset someone's authenticator</h2>
          <p className="text-[13px] leading-relaxed text-text-secondary">
            For anyone on this server who lost their authenticator app, organisation owners included. Their organisations' admins can't reset an owner's.
            Confirm it's really them first, by a call or in person.
          </p>
        </div>
      </div>
      <form onSubmit={submit} noValidate className="flex flex-wrap items-end gap-2 pl-12 max-[560px]:pl-0">
        <div className="flex min-w-[220px] flex-1 flex-col gap-1.5">
          <Label htmlFor="reset-2fa-email">Their email address</Label>
          <Input id="reset-2fa-email" type="email" autoComplete="off" spellCheck={false} placeholder="name@company.com" value={email} onChange={(e) => { setEmail(e.target.value); setResult(null); }} />
        </div>
        <Button type="submit" variant="outline" disabled={!email.trim() || reset.isPending}>Reset authenticator</Button>
      </form>
      {result && <p role={result.ok ? "status" : "alert"} className={cn("pl-12 text-[13px] max-[560px]:pl-0", result.ok ? "text-green-600" : "text-red-500")}>{result.text}</p>}
      <Dialog open={confirming !== null} onOpenChange={(o) => !o && !reset.isPending && close()}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Reset the authenticator of {confirming}?</DialogTitle>
            <DialogDescription>
              They're signed out on every device and must set up a new authenticator app at their next sign-in. Their vault and organisations don't change. The reset is logged and they're emailed.
            </DialogDescription>
          </DialogHeader>
          <form noValidate className="flex flex-col gap-3" onSubmit={(e) => { e.preventDefault(); setCodeError(null); if (confirming && code.length === 6) reset.mutate({ email: confirming, code }); }}>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="reset-2fa-code">Your authenticator code</Label>
              <Input id="reset-2fa-code" inputMode="numeric" autoComplete="one-time-code" maxLength={6} className="w-[180px] font-mono tracking-[0.3em]" value={code}
                onChange={(e) => { setCode(e.target.value.replace(/\D/g, "")); setCodeError(null); }} />
              <p className="text-[12px] text-text-tertiary">The 6-digit code from your own authenticator app: resetting someone else's needs a fresh one each time.</p>
            </div>
            {codeError && <p role="alert" className="text-[13px] text-red-500">{codeError}</p>}
            <div className="flex justify-end gap-2">
              <Button type="button" variant="ghost" onClick={close} disabled={reset.isPending}>Cancel</Button>
              <Button type="submit" variant="destructive" disabled={reset.isPending || code.length !== 6}>{reset.isPending ? "Resetting…" : "Reset authenticator"}</Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>
    </section>
  );
}
