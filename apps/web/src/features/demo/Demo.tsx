import { useState } from "react";
import { useNavigate } from "react-router";
import { FlaskConical } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { ApiError } from "@/lib/api";
import { rememberSpace, useSession } from "@/lib/session";
import { spacePrefix } from "@/lib/paths";
import { useReportBusy } from "@/features/auth/authBusy";
import { startDemo, type DemoStep } from "./startDemo";
import { deletedAt } from "./demoUnlock";

/** Public demo (docs/demo.md): the code's home, linked from the sandbox banner. */
export const SELF_HOST_URL = "https://github.com/clane-ai/clane-vault";

const lifetime = (minutes: number) => (minutes % 60 === 0 ? `${minutes / 60} hour${minutes === 60 ? "" : "s"}` : `${minutes} minutes`);

/** "Try the demo" on the sign-in page of a demo server: a private sandbox with made-up data, signed in at once. */
export function TryDemo({ ttlMinutes }: { ttlMinutes: number }) {
  const { completeRecovery } = useSession();
  const nav = useNavigate();
  const [step, setStep] = useState<DemoStep | null>(null);
  const [error, setError] = useState<string | null>(null);
  useReportBusy(step !== null);

  async function go() {
    setError(null); setStep("account");
    try {
      const r = await startDemo(setStep);
      // Open the sandbox's organisation, not the (nearly empty) Personal space.
      const org = r.res.orgs?.[0];
      rememberSpace(r.res.user.id, org?.id ?? null);
      // The keys were made on this device a moment ago: install them as they are (no password prompt, no recovery kit).
      completeRecovery(r.res, r.keys, r.authKey, { requireKit: false });
      if (!r.seeded) toast.error("Some of the sample data couldn't be added. The sandbox works without it.");
      nav(org ? `${spacePrefix(org)}/vault` : "/");
    } catch (e) {
      setStep(null);
      setError(e instanceof ApiError && e.code === "rate_limited" ? "Too many demo sandboxes from your network. Try again in an hour." : "Couldn't start the demo. Check your connection and try again.");
    }
  }

  return (
    <section aria-label="Demo" className="flex flex-col gap-2 border-t border-border-default pt-5">
      <Button type="button" variant="outline" size="lg" className="h-11 w-full" onClick={() => void go()} disabled={step !== null}>
        <FlaskConical className="size-4" />{step === "account" ? "Creating your sandbox…" : step === "data" ? "Adding sample data…" : "Try the demo"}
      </Button>
      <p className="text-[12.5px] text-text-secondary">Opens a private sandbox with made-up data, no sign-up needed. It's deleted {lifetime(ttlMinutes)} after you start, so don't enter real passwords.</p>
      {error && <p role="alert" className="text-[13px] text-red-500">{error}</p>}
    </section>
  );
}

/** The strip at the top of the app in a demo sandbox. */
export function DemoBanner({ expiresAt }: { expiresAt: string }) {
  return (
    <div role="status" aria-label="Demo sandbox" data-testid="demo-banner" className="flex shrink-0 items-center gap-2.5 border-b border-[var(--orange-tint-border)] bg-orange-tint px-6 py-2 text-[13px] text-text-primary max-[760px]:px-3">
      <FlaskConical aria-hidden="true" className="size-4 shrink-0 text-orange-ink" />
      <p className="min-w-0 flex-1">Demo sandbox. Deleted at {deletedAt(expiresAt)}. Don't enter real passwords.</p>
      <a href={SELF_HOST_URL} target="_blank" rel="noopener noreferrer" className="shrink-0 font-medium text-orange-ink underline-offset-2 hover:underline">Self-host it</a>
    </div>
  );
}

/** In place of settings the demo server turns off (single sign-on, email). */
export function DemoUnavailable({ what }: { what: string }) {
  return (
    <p className="rounded-[10px] border border-border-default bg-well px-3.5 py-3 text-[13.5px] text-text-secondary">
      {what} can't be set up in the demo sandbox. <a href={SELF_HOST_URL} target="_blank" rel="noopener noreferrer" className="font-medium text-[var(--link)] hover:underline">Self-host it</a> to try it with your own settings.
    </p>
  );
}
