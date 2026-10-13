import { useState, type FormEvent } from "react";
import { Smartphone } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ApiError } from "@/lib/api";
import { useSession } from "@/lib/session";

/**
 * After an SSO sign-in that skipped the authenticator code (the organisation trusts its identity provider's MFA), the
 * session only reaches that organisation. Anything else (another organisation, the private vault alone) asks for the
 * code once (403 `totp_step_up_required`).
 */
export function TotpStepUpPanel() {
  const { stepUp } = useSession();
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  async function submit(e: FormEvent) {
    e.preventDefault(); setBusy(true); setError(null);
    try { await stepUp(code); }
    catch (err) { setError(err instanceof ApiError && err.code === "locked" ? "Too many failed attempts. Try again later." : "That code didn't work. Try the newest code from your app."); setCode(""); }
    finally { setBusy(false); }
  }
  return (
    <section aria-label="Confirm with your authenticator" className="grid min-h-0 flex-1 place-items-center px-6 py-10">
      <form onSubmit={submit} className="flex w-full max-w-[400px] flex-col items-center gap-4 text-center" noValidate>
        <span className="grid size-12 place-items-center rounded-[14px] bg-blue-tint text-blue-500"><Smartphone className="size-6" /></span>
        <h2 className="font-display text-[20px] font-semibold text-text-primary">Confirm with your authenticator</h2>
        <p className="text-[14px] leading-relaxed text-text-secondary">You signed in with your organisation's single sign-on, which covers that organisation only. Enter the code from your authenticator app to open everything else.</p>
        <div className="flex w-full flex-col gap-1.5 text-left"><Label htmlFor="step-up-code">6-digit code from your authenticator app</Label>
          <Input id="step-up-code" inputMode="numeric" autoComplete="one-time-code" maxLength={6} autoFocus className="font-mono tracking-[0.3em]" value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} /></div>
        {error && <p role="alert" className="text-[13px] text-red-500">{error}</p>}
        <Button type="submit" variant="cta" size="lg" className="h-11 w-full" disabled={busy || code.length !== 6}>{busy ? "Checking…" : "Confirm"}</Button>
      </form>
    </section>
  );
}
