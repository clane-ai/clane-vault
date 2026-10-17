import { useEffect, useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router";
import { createAccount, type KdfParams } from "@clane-vault/crypto";
import { BadgeCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api, ApiError } from "@/lib/api";
import { useSession } from "@/lib/session";
import { productName } from "@/brand";
import { AuthLayout } from "./AuthLayout";
import { useReportBusy } from "./authBusy";
import { RegisterForm } from "./Register";
import { safeReturnTo } from "./sso";

/** What the server says the proof is for (`POST /auth/sso/proof`). */
export type ProofInfo =
  | { mode: "login"; email: string; accountEmail: string; kdf: { kdfSalt: string; kdfParams: KdfParams }; org: { name: string; slug: string }; returnTo: string; totpSkipped: boolean; joins: "member" | null }
  | { mode: "register"; email: string; org: { name: string; slug: string }; returnTo: string; name: string | null; adminRecoveryEnabled: boolean; joins: "member" | "invite" };

const MESSAGES: Record<string, string> = {
  invalid_credentials: "That master password is not right.",
  totp_invalid: "That code didn't work. Check the time on your phone and try the newest code.",
  rate_limited: "Too many attempts. Wait a minute and try again.",
  seat_limit: "This organisation has no free seats. Ask an admin of the organisation to add seats.",
};

/** Reads the proof from the URL fragment (never sent to a server). */
function readFragment(): { proof: string | null; returnTo: string } {
  const p = new URLSearchParams(window.location.hash.slice(1));
  return { proof: p.get("proof"), returnTo: safeReturnTo(p.get("returnTo")) };
}

/** After the identity provider: the master password (it still unlocks the vault), or the new account's form. */
export default function SsoComplete() {
  const nav = useNavigate();
  const { signInWithSso, beginTwoFactor } = useSession();
  const [frag] = useState(readFragment);
  const [info, setInfo] = useState<ProofInfo | null>(null);
  const [invalid, setInvalid] = useState(!frag.proof);
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [askCode, setAskCode] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  useReportBusy(busy);

  useEffect(() => {
    // The proof leaves the address bar (and history) at once.
    if (window.location.hash) window.history.replaceState(window.history.state, "", window.location.pathname);
    if (!frag.proof) return;
    let live = true;
    api.post<ProofInfo>("/auth/sso/proof", { proof: frag.proof })
      .then((r) => { if (live) setInfo(r); })
      .catch(() => { if (live) setInvalid(true); });
    return () => { live = false; };
  }, [frag.proof]);

  // Nothing more precise asked for: that organisation's vault (a session from its SSO may reach only that org at first).
  const asked = safeReturnTo(info?.returnTo ?? frag.returnTo);
  const goTo = asked === "/" && info ? `/o/${encodeURIComponent(info.org.slug)}/vault` : asked;

  async function login(e: FormEvent) {
    e.preventDefault();
    if (!info || !frag.proof || info.mode !== "login") return;
    setBusy(true); setError(null);
    try {
      const r = await signInWithSso(frag.proof, info.accountEmail, password, askCode ? code : undefined, info.kdf);
      if (r.kind === "ok") { nav(goTo, { replace: true }); return; }
      if (r.kind === "needs_totp_setup") { beginTwoFactor(r.setupToken, password); nav("/setup-2fa", { state: { setupToken: r.setupToken }, replace: true }); return; }
      if (r.code === "totp_required") { setAskCode(true); return; }
      if (r.code === "sso_proof_invalid") { setInvalid(true); return; }
      if (r.code === "locked") { setError(`Too many failed attempts. Try again in ${Math.ceil((r.retryAfterSeconds ?? 900) / 60)} minutes.`); return; }
      setError(MESSAGES[r.code] ?? "Something went wrong. Try again.");
    } catch { setError(`Can't reach ${productName}. Check your connection and try again.`); }
    finally { setBusy(false); }
  }

  async function register(v: { name: string; password: string }) {
    if (!info || !frag.proof) return;
    setBusy(true); setError(null);
    try {
      const acct = await createAccount(v.password);
      const { setupToken } = await api.post<{ setupToken: string }>("/auth/sso/register", { proof: frag.proof, name: v.name, authKey: acct.authKey, material: acct.material });
      beginTwoFactor(setupToken, v.password);
      nav("/setup-2fa", { state: { setupToken }, replace: true });
    } catch (e) {
      if (e instanceof ApiError && e.code === "sso_proof_invalid") { setInvalid(true); return; }
      setError(e instanceof ApiError && e.code === "invalid_request" ? "Use a plain name (up to 60 characters, no links or email addresses)."
        : (e instanceof ApiError && MESSAGES[e.code]) || "Couldn't create your account. Try again.");
    } finally { setBusy(false); }
  }

  if (invalid) return (
    <AuthLayout title="Single sign-on expired" subtitle="This sign-in was already used, took longer than 5 minutes, or was opened in another browser.">
      <Link to="/sign-in" className="text-[14px] font-medium text-[var(--link)] hover:underline">Back to sign in</Link>
    </AuthLayout>
  );
  if (!info) return <AuthLayout title="Single sign-on" subtitle="Checking your sign-in…"><span /></AuthLayout>;

  const verified = (
    <p role="status" className="flex items-start gap-2 rounded-[10px] border border-[var(--green-tint-border)] bg-green-tint px-3 py-2.5 text-[13px] text-text-primary">
      <BadgeCheck aria-hidden="true" className="mt-px size-4 shrink-0 text-green-600" />
      <span>{info.org.name} confirmed you as <span className="font-mono">{info.email}</span>.{info.joins === "member" ? ` You'll join ${info.org.name}.` : ""}</span>
    </p>
  );

  if (info.mode === "register") return (
    <AuthLayout title={`Create your ${productName} account`} subtitle={`Signed in with ${info.org.name}. Choose a master password: it encrypts your vault and never leaves this device.`}>
      {verified}
      <RegisterForm email={info.email} initialName={info.name ?? ""} onSubmit={(v) => void register(v)} busy={busy} adminRecovery={info.adminRecoveryEnabled} footer={null} />
      {error && <p role="alert" className="text-[13px] text-red-500">{error}</p>}
    </AuthLayout>
  );

  return (
    <AuthLayout title="Unlock with your master password" subtitle={`Single sign-on proved who you are; your master password still unlocks your vault.${info.totpSkipped ? ` ${info.org.name}'s sign-in already checked your second factor.` : ""}`}>
      {verified}
      <form onSubmit={login} className="flex flex-col gap-4" noValidate>
        <input type="email" name="username" autoComplete="username" value={info.accountEmail} readOnly hidden />
        <div className="flex flex-col gap-1.5"><Label htmlFor="sso-password">Master password</Label>
          <Input id="sso-password" type="password" autoComplete="current-password" autoFocus value={password} onChange={(e) => setPassword(e.target.value)} disabled={askCode} /></div>
        {askCode && (
          <div className="flex flex-col gap-1.5"><Label htmlFor="sso-code">6-digit code from your authenticator app</Label>
            <Input id="sso-code" inputMode="numeric" autoComplete="one-time-code" maxLength={6} className="font-mono tracking-[0.3em]" value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} autoFocus /></div>
        )}
        {error && <p role="alert" className="text-[13px] text-red-500">{error}</p>}
        <Button type="submit" variant="cta" size="lg" className="h-11 w-full" disabled={busy || !password}>{busy ? "Checking…" : "Unlock"}</Button>
      </form>
      <Link to="/sign-in" className="text-[13px] text-[var(--link)] hover:underline">Use another account</Link>
    </AuthLayout>
  );
}
