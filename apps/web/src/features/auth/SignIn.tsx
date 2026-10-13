import { useEffect, useRef, useState, type FormEvent } from "react";
import { Link, useNavigate, useSearchParams } from "react-router";
import { Building2, ChevronDown, KeyRound, LifeBuoy, Smartphone, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { useSession, type SignInResult } from "@/lib/session";
import { api, ApiError } from "@/lib/api";
import { productName } from "@/brand";
import { AuthLayout } from "./AuthLayout";
import { useReportBusy } from "./authBusy";
import { discoverSso, SSO_ERRORS, startSso, type SsoOrg } from "./sso";

const MESSAGES: Record<string, string> = {
  invalid_credentials: "Email or master password is not right.",
  totp_invalid: "That code didn't work. Check the time on your phone and try the newest code.",
  rate_limited: "Too many attempts. Wait a minute and try again.",
};

const HELP = {
  totp: {
    title: "Lost authenticator?",
    text: "Ask your admin to reset two-step sign-in for your account. Next time you sign in, you'll scan a new QR code. If you also forgot your master password, ask for the reset first, then use your recovery kit.",
  },
} as const;

const looksLikeEmail = (v: string) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);

/** Whether this organisation lets admins reset master passwords (public and organisation-wide). */
function useAdminRecoveryEnabled() {
  const [on, setOn] = useState(false);
  useEffect(() => {
    let live = true;
    api.get<{ adminRecoveryEnabled: boolean }>("/auth/recovery/options").then((r) => { if (live) setOn(!!r.adminRecoveryEnabled); }).catch(() => undefined);
    return () => { live = false; };
  }, []);
  return on;
}

/** "Ask an admin to reset my password": email only, and the same answer whether or not the account exists. */
function AskAdmin({ initialEmail }: { initialEmail: string }) {
  const [email, setEmail] = useState(initialEmail);
  const [sent, setSent] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!looksLikeEmail(email.trim())) return setError("Enter your email address.");
    setBusy(true); setError(null);
    try { await api.post("/auth/recovery/admin/request", { email: email.trim() }); setSent(true); }
    catch (err) { setError(err instanceof ApiError && err.code === "rate_limited" ? "Too many requests. Wait a minute and try again." : "Couldn't send the request. Try again."); }
    finally { setBusy(false); }
  }
  if (sent) return <p role="status" className="mt-1 text-[13px] leading-relaxed text-text-secondary">If that account exists, your admins can see your request now. An admin will send you a one-time link (it works for 24 hours). You'll need your authenticator app to use it.</p>;
  return (
    <form onSubmit={submit} className="mt-2 flex flex-col gap-2" noValidate>
      <p className="text-[13px] leading-relaxed text-text-secondary">Your admin approves the reset and sends you a one-time link. Admins never see your new password.</p>
      <Label htmlFor="ask-email" className="sr-only">Email address for the reset request</Label>
      <div className="flex gap-2">
        <Input id="ask-email" type="email" placeholder="name@company.com" value={email} onChange={(e) => setEmail(e.target.value)} className="h-9" />
        <Button type="submit" size="sm" className="h-9" disabled={busy}>{busy ? "Sending…" : "Ask admin"}</Button>
      </div>
      {error && <p role="alert" className="text-[13px] text-red-500">{error}</p>}
    </form>
  );
}

/** "Need help?" menu under the sign-in button; picking an item shows its answer in a note below (or opens recovery). */
export function NeedHelp({ email = "" }: { email?: string }) {
  const [topic, setTopic] = useState<"totp" | "admin" | null>(null);
  const nav = useNavigate();
  const adminRecovery = useAdminRecoveryEnabled();
  const title = topic === "admin" ? "Ask an admin to reset my password" : topic ? HELP[topic].title : "";
  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center">
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button type="button" className="-ml-1 inline-flex items-center gap-1 rounded-[6px] px-1 py-0.5 text-[13px] font-medium text-[var(--link)] hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/40">
              Need help?<ChevronDown aria-hidden="true" className="size-3.5" />
            </button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="start" className="w-[300px]">
            <DropdownMenuItem onSelect={() => nav(email && looksLikeEmail(email) ? `/recover?email=${encodeURIComponent(email)}` : "/recover")}><KeyRound />Forgot master password? Use your recovery kit</DropdownMenuItem>
            {adminRecovery && <DropdownMenuItem onSelect={() => setTopic("admin")}><LifeBuoy />Ask an admin to reset my password</DropdownMenuItem>}
            <DropdownMenuItem onSelect={() => setTopic("totp")}><Smartphone />Lost authenticator?</DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
      {topic && (
        <div role="note" aria-label={title} className="relative rounded-[10px] border border-border-default bg-well px-3.5 py-3 pr-9">
          <p className="text-[13px] font-medium text-text-primary">{title}</p>
          {topic === "admin" ? <AskAdmin initialEmail={email} /> : <p className="mt-1 text-[13px] leading-relaxed text-text-secondary">{HELP[topic].text}</p>}
          <button type="button" aria-label="Close help" onClick={() => setTopic(null)} className="absolute top-2 right-2 grid size-6 place-items-center rounded-[6px] text-text-tertiary hover:bg-card hover:text-text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/40">
            <X aria-hidden="true" className="size-3.5" />
          </button>
        </div>
      )}
    </div>
  );
}

/** "Continue with <org> SSO" buttons, or an organisation ID field for SSO without a known domain. */
function SsoChoices({ orgs, onSso, busy }: { orgs: SsoOrg[]; onSso: (slug: string) => void; busy: string | null }) {
  return (
    <div className="flex flex-col gap-2" role="group" aria-label="Single sign-on">
      {orgs.map((o) => (
        <Button key={o.slug} type="button" variant="outline" size="lg" className="h-11 w-full" disabled={!!busy} onClick={() => onSso(o.slug)}>
          <Building2 className="size-4" />{busy === o.slug ? "Opening…" : `Continue with ${o.name} SSO`}
        </Button>
      ))}
    </div>
  );
}

/** Two steps, like most vault logins: email first, then the master password (and the 2FA code when the server asks). */
export function SignInForm({ signIn, onDone, onNeedsSetup, onSso = (org, email) => startSso(org, { email }), ssoError }: {
  signIn: (e: string, p: string, c?: string) => Promise<SignInResult>; onDone: () => void; onNeedsSetup: (setupToken: string, password: string) => void;
  /** Starts single sign-on with an organisation (by slug); leaves the page. */ onSso?: (org: string, email?: string) => Promise<void>;
  /** An SSO attempt that came back with an error (`?sso_error=`). */ ssoError?: string | null;
}) {
  const [step, setStep] = useState<"email" | "password">("email");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [askCode, setAskCode] = useState(false);
  const [error, setError] = useState<string | null>(ssoError ? SSO_ERRORS[ssoError] ?? SSO_ERRORS.sso_failed! : null);
  const [busy, setBusy] = useState(false);
  const [ssoOrgs, setSsoOrgs] = useState<SsoOrg[]>([]);
  const [ssoSlug, setSsoSlug] = useState<string | null>(null);
  const [ssoBusy, setSsoBusy] = useState<string | null>(null);
  const emailRef = useRef<HTMLInputElement>(null);
  useReportBusy(busy || !!ssoBusy);

  async function sso(slug: string, withEmail?: string) {
    setSsoBusy(slug); setError(null);
    try { await onSso(slug, withEmail); }
    catch (e) { setError(e instanceof ApiError ? SSO_ERRORS[e.code] ?? SSO_ERRORS.sso_failed! : `Can't reach ${productName}. Check your connection and try again.`); setSsoBusy(null); }
  }

  function next(e: FormEvent) {
    e.preventDefault();
    const v = email.trim();
    if (!v) { setError("Enter your email address."); emailRef.current?.focus(); return; }
    if (!looksLikeEmail(v)) { setError("That doesn't look like an email address."); emailRef.current?.focus(); return; }
    setEmail(v); setError(null); setStep("password"); setSsoOrgs([]);
    // Single sign-on offered for this address's domain (verified by the organisation): shown above the password.
    void discoverSso(v).then((orgs) => setSsoOrgs(orgs));
  }

  function change() {
    setStep("email"); setPassword(""); setCode(""); setAskCode(false); setError(null);
    requestAnimationFrame(() => emailRef.current?.focus());
  }

  async function submit(e: FormEvent) {
    e.preventDefault(); setBusy(true); setError(null);
    try {
      const r = await signIn(email.trim(), password, askCode ? code : undefined);
      if (r.kind === "ok") return onDone();
      if (r.kind === "needs_totp_setup") return onNeedsSetup(r.setupToken, password);
      if (r.code === "totp_required") { setAskCode(true); return; }
      if (r.code === "locked") { setError(`Too many failed attempts. Try again in ${Math.ceil((r.retryAfterSeconds ?? 900) / 60)} minutes.`); return; }
      setError(MESSAGES[r.code] ?? "Something went wrong. Try again.");
    } catch { setError(`Can't reach ${productName}. Check your connection and try again.`); }
    finally { setBusy(false); }
  }

  const errorText = error && <p role="alert" className="text-[13px] text-red-500">{error}</p>;

  if (step === "email") return (
    <div className="flex flex-col gap-5">
      <form onSubmit={next} className="flex flex-col gap-4" noValidate>
        <div className="flex flex-col gap-1.5"><Label htmlFor="email">Email address</Label>
          <Input ref={emailRef} id="email" type="email" inputMode="email" autoComplete="username" autoFocus spellCheck={false} placeholder="name@company.com"
            value={email} onChange={(e) => setEmail(e.target.value)} aria-invalid={error ? true : undefined} required /></div>
        {errorText}
        <Button type="submit" variant="cta" size="lg" className="h-11 w-full">Next</Button>
      </form>
      {ssoSlug === null ? (
        <button type="button" onClick={() => { setSsoSlug(""); setError(null); }} className="-mt-2 self-start text-[13px] font-medium text-[var(--link)] hover:underline">Sign in with SSO</button>
      ) : (
        <form className="-mt-2 flex flex-col gap-1.5" noValidate onSubmit={(e) => { e.preventDefault(); const s = ssoSlug.trim().toLowerCase(); if (s) void sso(s, looksLikeEmail(email.trim()) ? email.trim() : undefined); }}>
          <Label htmlFor="sso-org">Organisation ID for single sign-on</Label>
          <div className="flex gap-2">
            <Input id="sso-org" autoFocus spellCheck={false} placeholder="acme-1a2b3c4d" value={ssoSlug} onChange={(e) => setSsoSlug(e.target.value)} className="h-9 font-mono" />
            <Button type="submit" size="sm" className="h-9" disabled={!ssoSlug.trim() || !!ssoBusy}>{ssoBusy ? "Opening…" : "Continue"}</Button>
          </div>
          <p className="text-[12px] text-text-tertiary">Your admin finds it in Organisation settings → Single sign-on.</p>
        </form>
      )}
      <NeedHelp email={email.trim()} />
    </div>
  );

  return (
    <div className="flex flex-col gap-5">
      {ssoOrgs.length > 0 && !askCode && (<>
        <SsoChoices orgs={ssoOrgs} busy={ssoBusy} onSso={(slug) => void sso(slug, email)} />
        <p className="-my-2 text-center text-[12px] text-text-tertiary">or use your master password only</p>
      </>)}
      <form onSubmit={submit} className="flex flex-col gap-4" noValidate>
        {/* Keeps the username next to the password for browser password managers. */}
        <input type="email" name="username" autoComplete="username" value={email} readOnly hidden />
        <div className="flex items-center gap-3 rounded-full border border-border-default bg-well py-1 pr-1 pl-1">
          <span aria-hidden="true" className="grid size-7 shrink-0 place-items-center rounded-full bg-card font-mono text-[12px] font-medium text-text-secondary uppercase">{email.charAt(0)}</span>
          <span className="min-w-0 flex-1 truncate font-mono text-[13px] text-text-primary" title={email}><span className="sr-only">Signing in as </span>{email}</span>
          <Button type="button" variant="ghost" size="sm" className="rounded-full" onClick={change} aria-label={`Change email address (${email})`}>Change</Button>
        </div>
        <div className="flex flex-col gap-1.5"><Label htmlFor="password">Master password</Label>
          <Input id="password" type="password" autoComplete="current-password" autoFocus value={password} onChange={(e) => setPassword(e.target.value)} disabled={askCode} required /></div>
        {askCode && (
          <div className="flex flex-col gap-1.5"><Label htmlFor="code">6-digit code from your authenticator app</Label>
            <Input id="code" inputMode="numeric" autoComplete="one-time-code" maxLength={6} className="font-mono tracking-[0.3em]" value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} autoFocus /></div>
        )}
        {errorText}
        <Button type="submit" variant="cta" size="lg" className="h-11 w-full" disabled={busy}>{busy ? "Checking…" : "Sign in"}</Button>
      </form>
      <NeedHelp email={email} />
    </div>
  );
}

export default function SignIn() {
  const { signIn, beginTwoFactor, reason } = useSession();
  const nav = useNavigate();
  const [params] = useSearchParams();
  return (
    <AuthLayout title="Sign in" titleInHeader>
      {reason === "expired" && <p role="status" className="rounded-[10px] border border-border-default bg-well px-3.5 py-2.5 text-[13px] text-text-secondary">Your session ended. Sign in again.</p>}
      <SignInForm signIn={signIn} ssoError={params.get("sso_error")} onDone={() => nav("/")} onNeedsSetup={(setupToken, password) => { beginTwoFactor(setupToken, password); nav("/setup-2fa", { state: { setupToken } }); }} />
      <p className="text-[13px] text-text-secondary">New here? <Link to="/join" className="font-medium text-[var(--link)] hover:underline">Join your organisation with your work email</Link></p>
    </AuthLayout>
  );
}
