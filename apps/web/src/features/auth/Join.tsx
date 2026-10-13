import { useEffect, useRef, useState, type FormEvent } from "react";
import { Link, useNavigate, useParams } from "react-router";
import { MailCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api, ApiError } from "@/lib/api";
import { useSession } from "@/lib/session";
import { useReloadOrgs } from "@/features/orgs/orgs";
import { AuthLayout } from "./AuthLayout";
import { SignInForm } from "./SignIn";
import Unlock from "./Unlock";

const looksLikeEmail = (s: string) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s);

/**
 * /join: "join with your work email" (email domain auto-join, docs/provisioning.md). The answer is the same whatever
 * the address: if its domain lets people join an organisation here, a link is emailed.
 */
export function JoinRequest() {
  const [email, setEmail] = useState("");
  const [state, setState] = useState<"idle" | "busy" | "sent">("idle");
  const [error, setError] = useState<string | null>(null);
  async function submit(e: FormEvent) {
    e.preventDefault();
    const addr = email.trim();
    if (!looksLikeEmail(addr)) return setError("Enter your work email address.");
    setError(null); setState("busy");
    try { await api.post("/auth/domain-join", { email: addr }); setState("sent"); }
    catch (err) { setState("idle"); setError(err instanceof ApiError && err.code === "rate_limited" ? "Too many tries. Wait a minute and try again." : "Couldn't send that. Try again."); }
  }
  if (state === "sent") return (
    <AuthLayout title="Check your email">
      <div className="flex flex-col gap-4" role="status">
        <span className="grid size-11 place-items-center rounded-[12px] bg-green-tint text-green-600"><MailCheck className="size-5" /></span>
        <p className="text-[14px] leading-relaxed text-text-secondary">If your organisation lets people with <span className="font-mono text-text-primary">{email.trim()}</span>'s domain join, we've emailed you a link. It works for 7 days.</p>
        <p className="text-[13px] text-text-secondary">Nothing arrived? Check your spam folder, or ask your admin to invite you.</p>
        <Button asChild variant="outline"><Link to="/sign-in">Back to sign in</Link></Button>
      </div>
    </AuthLayout>
  );
  return (
    <AuthLayout title="Join your organisation" subtitle="Use your work email. If your organisation lets people with your address join, we'll email you a link to create your account.">
      <form onSubmit={submit} className="flex flex-col gap-4" noValidate>
        <div className="flex flex-col gap-1.5"><Label htmlFor="join-email">Work email</Label>
          <Input id="join-email" type="email" inputMode="email" autoComplete="email" autoFocus spellCheck={false} placeholder="name@company.com" value={email} onChange={(e) => setEmail(e.target.value)} aria-invalid={error ? true : undefined} /></div>
        {error && <p role="alert" className="text-[13px] text-red-500">{error}</p>}
        <Button type="submit" variant="cta" size="lg" className="h-11 w-full" disabled={state === "busy"}>{state === "busy" ? "Sending…" : "Email me a link"}</Button>
        <p className="text-[12.5px] text-text-tertiary">Already have an account? <Link to="/sign-in" className="font-medium text-[var(--link)] hover:underline">Sign in</Link></p>
      </form>
    </AuthLayout>
  );
}

/**
 * /join/:token: an emailed join link for someone who already has an account. Signed in (here if needed), the link is
 * claimed for that account and becomes an invitation to accept from the organisation menu (where the organisation's
 * master password rule is checked).
 */
export function JoinClaim() {
  const { token = "" } = useParams();
  const { state, signIn, beginTwoFactor } = useSession();
  const nav = useNavigate();
  const reload = useReloadOrgs();
  const [result, setResult] = useState<{ kind: "invited" | "member"; orgName: string } | { kind: "invalid" } | null>(null);
  const started = useRef(false);
  useEffect(() => {
    if (state !== "unlocked" || started.current) return;
    started.current = true;
    api.post<{ orgId: string; orgName: string; status: "invited" | "member" }>("/me/join", { token })
      .then(async (r) => { await reload().catch(() => undefined); setResult({ kind: r.status, orgName: r.orgName }); })
      .catch(() => setResult({ kind: "invalid" }));
  }, [state, token, reload]);

  if (state === "loading") return <AuthLayout title="Joining…"><p className="text-text-secondary">One moment…</p></AuthLayout>;
  if (state === "locked") return <Unlock />;
  if (state === "signed_out") return (
    <AuthLayout title="Sign in to join" subtitle="This link is for an existing account. Sign in with the address it was sent to.">
      <SignInForm signIn={signIn} onDone={() => undefined} onNeedsSetup={(setupToken, password) => { beginTwoFactor(setupToken, password); nav("/setup-2fa", { state: { setupToken } }); }} />
    </AuthLayout>
  );
  if (!result) return <AuthLayout title="Joining…"><p className="text-text-secondary" role="status">Checking your link…</p></AuthLayout>;
  if (result.kind === "invalid") return (
    <AuthLayout title="This link doesn't work" subtitle="It may have expired or been used, or it was sent to another address than the one you're signed in with.">
      <Button asChild variant="outline"><Link to="/">Go to your vault</Link></Button>
    </AuthLayout>
  );
  return (
    <AuthLayout title={result.kind === "member" ? `You're already in ${result.orgName}` : `Your invitation to ${result.orgName} is ready`}
      subtitle={result.kind === "member" ? undefined : "Accept it from the organisation menu at the top left of your vault."}>
      <Button asChild><Link to="/">Open your vault</Link></Button>
    </AuthLayout>
  );
}
