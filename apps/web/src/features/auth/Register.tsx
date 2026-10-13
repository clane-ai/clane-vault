import { useEffect, useState, type FormEvent } from "react";
import { useNavigate, useParams } from "react-router";
import { createAccount } from "@clane-vault/crypto";
import { ShieldAlert } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api, ApiError } from "@/lib/api";
import { useSession } from "@/lib/session";
import { productName } from "@/brand";
import { AuthLayout } from "./AuthLayout";
import { useReportBusy } from "./authBusy";
import { BASE_PASSWORD_POLICY, checkMasterPassword, passwordRuleText, type PasswordPolicy } from "@/lib/policies";

export function RegisterForm({ email, onSubmit, busy, adminRecovery = false, onSendCode, initialName = "", footer, policy = BASE_PASSWORD_POLICY }: { email: string; onSubmit: (v: { name: string; password: string; emailCode?: string }) => void; busy?: boolean;
  /** The inviting organisation's master password rule (docs/policies.md). */ policy?: PasswordPolicy;
  /** Prefilled name (e.g. from the identity provider). */ initialName?: string;
  /** Replaces the "already have an account?" note (null: none). */ footer?: React.ReactNode;
  /** The organisation's admin-recovery policy is on: say so before the account exists. */ adminRecovery?: boolean;
  /** Hosted servers: a 6-digit code emailed to the invited address is needed too. */ onSendCode?: () => Promise<void> }) {
  const [name, setName] = useState(initialName);
  const [code, setCode] = useState("");
  const [codeState, setCodeState] = useState<"idle" | "sending" | "sent" | "failed">("idle");
  const [password, setPassword] = useState("");
  const [repeat, setRepeat] = useState("");
  const [error, setError] = useState<string | null>(null);
  useReportBusy(!!busy);
  function submit(e: FormEvent) {
    e.preventDefault();
    if (!name.trim()) return setError("Add your name so teammates can find you.");
    const weak = checkMasterPassword(password, policy);
    if (weak) return setError(weak);
    if (password !== repeat) return setError("The passwords don't match.");
    if (onSendCode && !/^\d{6}$/.test(code)) return setError("Enter the 6-digit code we emailed you.");
    setError(null); onSubmit({ name: name.trim(), password, ...(onSendCode ? { emailCode: code } : {}) });
  }
  async function send() {
    setCodeState("sending");
    try { await onSendCode!(); setCodeState("sent"); } catch { setCodeState("failed"); }
  }
  return (
    <form onSubmit={submit} className="flex flex-col gap-4" noValidate>
      <p className="text-[14px] text-text-secondary">Signing up as <span className="font-mono text-text-primary">{email}</span></p>
      <div className="flex flex-col gap-1.5"><Label htmlFor="name">Your name</Label><Input id="name" value={name} onChange={(e) => setName(e.target.value)} /></div>
      <div className="flex flex-col gap-1.5"><Label htmlFor="pw">Master password</Label><Input id="pw" type="password" autoComplete="new-password" aria-describedby="pw-rule" value={password} onChange={(e) => setPassword(e.target.value)} />
        <p id="pw-rule" className="text-[12.5px] text-text-tertiary">{passwordRuleText(policy)}</p></div>
      <div className="flex flex-col gap-1.5"><Label htmlFor="pw2">Repeat master password</Label><Input id="pw2" type="password" autoComplete="new-password" value={repeat} onChange={(e) => setRepeat(e.target.value)} /></div>
      {onSendCode && (
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="email-code">Code from your email</Label>
          <div className="flex gap-2">
            <Input id="email-code" inputMode="numeric" autoComplete="one-time-code" maxLength={6} className="w-[150px] font-mono tracking-[0.3em]" value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} />
            <Button type="button" variant="outline" onClick={() => void send()} disabled={codeState === "sending"}>{codeState === "sent" ? "Send again" : "Email me a code"}</Button>
          </div>
          <p className="text-[12.5px] text-text-secondary">{codeState === "sent" ? `Sent to ${email}. It works for 10 minutes.` : codeState === "failed" ? "Couldn't send the code. Try again in a minute." : "We email a code to the invited address to make sure it's yours."}</p>
        </div>
      )}
      <p className="rounded-[10px] border border-[var(--orange-tint-border)] bg-orange-tint px-3 py-2.5 text-[13px] text-orange-ink">
        Your master password encrypts your vault on this device. Nobody can look it up for you. After you sign up you'll save a recovery kit: the only way back in if you forget it{adminRecovery ? ", besides an admin reset" : ""}.
      </p>
      {adminRecovery && (
        <p role="note" aria-label="Admin recovery" className="flex gap-2 rounded-[10px] border border-border-default bg-well px-3 py-2.5 text-[13px] text-text-secondary">
          <ShieldAlert aria-hidden="true" className="mt-px size-4 shrink-0 text-text-tertiary" />
          <span><span className="font-medium text-text-primary">Your organisation's admins can restore your access to it.</span> If you forget your master password, an admin can approve a reset that brings back what you hold in this organisation. Admins can't open your private items.</span>
        </p>
      )}
      {error && <p role="alert" className="text-[13px] text-red-500">{error}</p>}
      <Button type="submit" variant="cta" size="lg" className="h-11" disabled={busy}>{busy ? "Creating your keys…" : "Create account"}</Button>
      {footer === undefined ? <p className="text-[12.5px] text-text-tertiary">Already have an account? Sign in instead: the invitation is waiting in the organisation menu.</p> : footer}
    </form>
  );
}

export default function Register() {
  const { token = "" } = useParams();
  const nav = useNavigate();
  const { beginTwoFactor } = useSession();
  const [formError, setFormError] = useState<string | null>(null);
  const [email, setEmail] = useState<string | null>(null);
  const [orgName, setOrgName] = useState<string | null>(null);
  const [emailVerification, setEmailVerification] = useState(false);
  const [state, setState] = useState<"loading" | "ready" | "invalid" | "busy">("loading");
  const [adminRecovery, setAdminRecovery] = useState(false);
  const [policy, setPolicy] = useState<PasswordPolicy>(BASE_PASSWORD_POLICY);
  useEffect(() => {
    api.get<{ email: string; orgName?: string; adminRecoveryEnabled?: boolean; emailVerification?: boolean; passwordPolicy?: PasswordPolicy }>(`/auth/invite/${token}`).then((r) => {
      if (r.passwordPolicy) setPolicy(r.passwordPolicy);
      setEmail(r.email); setOrgName(r.orgName || null); setEmailVerification(!!r.emailVerification);
      // The inviting organisation's admin-recovery policy decides the disclosure.
      setAdminRecovery(!!r.adminRecoveryEnabled);
      setState("ready");
    }).catch(() => setState("invalid"));
  }, [token]);

  async function onSubmit(v: { name: string; password: string; emailCode?: string }) {
    setState("busy"); setFormError(null);
    try {
      const acct = await createAccount(v.password);
      const { setupToken } = await api.post<{ setupToken: string }>("/auth/register", { inviteToken: token, name: v.name, authKey: acct.authKey, material: acct.material, ...(v.emailCode ? { emailCode: v.emailCode } : {}) });
      beginTwoFactor(setupToken, v.password);
      nav("/setup-2fa", { state: { setupToken } });
    } catch (e) {
      if (e instanceof ApiError && e.code === "invite_invalid") return setState("invalid");
      if (e instanceof ApiError && (e.code === "email_code_invalid" || e.code === "email_code_required")) { setFormError("That code didn't work. Send a new one and try again."); setState("ready"); return; }
      if (e instanceof ApiError && e.code === "invalid_request") { setFormError("Use a plain name (up to 60 characters, no links or email addresses)."); setState("ready"); return; }
      setFormError("Couldn't create your account. Check your connection and try again.");
      setState("ready");
    }
  }

  if (state === "invalid") return <AuthLayout title="This invite doesn't work" subtitle="It may have expired or been used. Ask your admin for a new one." ><span /></AuthLayout>;
  return (
    <AuthLayout title={`Create your ${productName} account`} subtitle={orgName ? `You're joining ${orgName}.` : undefined}>
      {email ? <><RegisterForm email={email} onSubmit={onSubmit} busy={state === "busy"} adminRecovery={adminRecovery} policy={policy}
        onSendCode={emailVerification ? async () => { await api.post("/auth/register/code", { inviteToken: token }); } : undefined} />{formError && <p role="alert" className="text-[13px] text-red-500">{formError}</p>}</> : <p className="text-text-secondary">Checking your invite…</p>}
    </AuthLayout>
  );
}
