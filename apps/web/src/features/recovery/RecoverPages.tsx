import { useEffect, useRef, useState, type FormEvent } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router";
import QRCode from "qrcode";
import {
  adminRecoveryProof, changeMasterPassword, createAccount, deriveLoginKeys, keysFromUserKey, openMembershipRecoveryGrant, openRecoveryWrap, parseRecoveryCode,
  recoveryAuthFor, unlockAccount, wrapMembershipKeys, RecoveryCodeError, type AccountMaterial, type KdfParams, type MembershipKeys, type UnlockedKeys,
} from "@clane-vault/crypto";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useSession, type AuthResponse } from "@/lib/session";
import { productName } from "@/brand";
import { AuthLayout } from "@/features/auth/AuthLayout";
import { ReportBusy } from "@/features/auth/authBusy";
import { apiUrl } from "@/lib/base";

/** POST to a public auth endpoint, optionally with a one-purpose bearer token (setup or recovery). Never throws on HTTP errors. */
export async function authCall<T>(path: string, body: unknown, bearer?: string): Promise<{ status: number; data: T }> {
  const res = await fetch(apiUrl(`/auth${path}`), {
    method: "POST", credentials: "same-origin",
    headers: { "content-type": "application/json", ...(bearer ? { authorization: `Bearer ${bearer}` } : {}) }, body: JSON.stringify(body),
  });
  return { status: res.status, data: (await res.json().catch(() => ({}))) as T };
}

type ErrorBody = { error?: string; retryAfterSeconds?: number; email?: string };
const lockedText = (s?: number) => `Too many failed attempts. Try again in ${Math.ceil((s ?? 900) / 60)} minutes.`;
const errorText = (r: ErrorBody | null, fallback: string) =>
  r?.error === "locked" ? lockedText(r.retryAfterSeconds) : r?.error === "rate_limited" ? "Too many attempts. Wait a minute and try again." : r?.error === "totp_invalid"
    ? "That code didn't work. Check the time on your phone and try the newest code." : fallback;

const Err = ({ text }: { text: string | null }) => (text ? <p role="alert" className="text-[13px] text-red-500">{text}</p> : null);

function TotpField({ value, onChange, label = "6-digit code from your authenticator app" }: { value: string; onChange: (v: string) => void; label?: string }) {
  return (
    <div className="flex flex-col gap-1.5"><Label htmlFor="rec-code">{label}</Label>
      <Input id="rec-code" inputMode="numeric" autoComplete="one-time-code" maxLength={6} autoFocus className="font-mono tracking-[0.3em]" value={value} onChange={(e) => onChange(e.target.value.replace(/\D/g, ""))} /></div>
  );
}

/** For accounts whose 2FA an admin reset: set up a new authenticator inside the recovery flow, then continue with its code. */
function InlineTotpSetup({ setupToken, onVerified }: { setupToken: string; onVerified: () => void }) {
  const [qr, setQr] = useState<string | null>(null);
  const [secret, setSecret] = useState("");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const started = useRef(false);
  useEffect(() => {
    if (started.current) return;
    started.current = true;
    void authCall<{ otpauthUrl: string; secret: string }>("/totp/setup", {}, setupToken).then(async ({ status, data }) => {
      if (status !== 200) return setError("Couldn't start two-step setup. Start the recovery again.");
      setSecret(data.secret); setQr(await QRCode.toDataURL(data.otpauthUrl, { margin: 1, width: 176 }));
    });
  }, [setupToken]);
  async function submit(e: FormEvent) {
    e.preventDefault(); setBusy(true); setError(null);
    try {
      const { status } = await authCall("/totp/verify", { code }, setupToken);
      if (status !== 200) { setError("That code didn't work. Try the newest code from the app."); return; }
      onVerified();
    } finally { setBusy(false); }
  }
  return (
    <form onSubmit={submit} className="flex flex-col gap-4">
      <p className="text-[14px] text-text-secondary">Your two-step sign-in was reset. Scan this with your authenticator app first.</p>
      <div className="grid place-items-center rounded-[12px] border border-border-default bg-white p-3">{qr ? <img src={qr} alt="QR code for your authenticator app" width={176} height={176} /> : <span className="h-[176px]" />}</div>
      <p className="text-[13px] text-text-secondary">Can't scan? Enter this key: <span className="font-mono break-all text-text-primary">{secret}</span></p>
      <TotpField value={code} onChange={setCode} label="6-digit code" />
      <Err text={error} />
      <ReportBusy busy={busy} />
      <Button type="submit" variant="cta" size="lg" className="h-11" disabled={busy || code.length !== 6}>Turn on and continue</Button>
    </form>
  );
}

/** New master password, then the finish call: the server swaps the password-derived parts and signs out everywhere. */
function NewPasswordStep({ recoveryToken, keys, material, onDone }: {
  recoveryToken: string; keys: UnlockedKeys; material: AccountMaterial; onDone: (res: AuthResponse, authKey: string) => void;
}) {
  const [pw, setPw] = useState("");
  const [repeat, setRepeat] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  async function submit(e: FormEvent) {
    e.preventDefault();
    if (pw.length < 12) return setError("Use at least 12 characters.");
    if (pw !== repeat) return setError("The passwords don't match.");
    setBusy(true); setError(null);
    try {
      const changed = await changeMasterPassword(pw, keys, material);
      const { status, data } = await authCall<AuthResponse & ErrorBody>("/recovery/finish", { authKey: changed.authKey, material: changed.material }, recoveryToken);
      if (status === 200) return onDone(data, changed.authKey);
      setError(status === 410 || status === 401 ? "This recovery has expired or was already used. Start again." : errorText(data, "Couldn't set your new password. Try again."));
    } catch { setError(`Can't reach ${productName}. Check your connection and try again.`); }
    finally { setBusy(false); }
  }
  return (
    <form onSubmit={submit} className="flex flex-col gap-4" noValidate>
      <p className="text-[14px] text-text-secondary">Your vault key is recovered on this device. Choose a new master password.</p>
      <div className="flex flex-col gap-1.5"><Label htmlFor="new-pw">New master password</Label><Input id="new-pw" type="password" autoComplete="new-password" autoFocus value={pw} onChange={(e) => setPw(e.target.value)} /></div>
      <div className="flex flex-col gap-1.5"><Label htmlFor="new-pw2">Repeat new master password</Label><Input id="new-pw2" type="password" autoComplete="new-password" value={repeat} onChange={(e) => setRepeat(e.target.value)} /></div>
      <p className="text-[13px] text-text-secondary">Saving it signs you out on every other device.</p>
      <Err text={error} />
      <ReportBusy busy={busy} />
      <Button type="submit" variant="cta" size="lg" className="h-11" disabled={busy}>{busy ? "Saving…" : "Set new master password"}</Button>
    </form>
  );
}

type Recovered = { recoveryToken: string; keys: UnlockedKeys; material: AccountMaterial };

/** Sign-in → Need help? → Forgot master password? Use your recovery kit. */
export function RecoverWithKitPage() {
  const nav = useNavigate();
  const [params] = useSearchParams();
  const { completeRecovery } = useSession();
  const [step, setStep] = useState<"details" | "totp" | "setup" | "password">("details");
  const [email, setEmail] = useState(params.get("email") ?? "");
  const [code, setCode] = useState("");
  const [totp, setTotp] = useState("");
  const [setupToken, setSetupToken] = useState<string | null>(null);
  const [afterSetup, setAfterSetup] = useState(false);
  const [recovered, setRecovered] = useState<Recovered | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const keyRef = useRef<Uint8Array | null>(null);
  useEffect(() => () => { keyRef.current?.fill(0); }, []);

  async function check(withCode?: string): Promise<void> {
    const key = keyRef.current!;
    const { status, data } = await authCall<ErrorBody & { needsTotpSetup?: boolean; setupToken?: string; recoveryToken?: string; userId?: string; recoveryWrap?: string; material?: AccountMaterial }>(
      "/recovery/kit", { email: email.trim(), recoveryAuth: await recoveryAuthFor(key), ...(withCode ? { code: withCode } : {}) });
    if (status === 200 && data.needsTotpSetup && data.setupToken) { setSetupToken(data.setupToken); setStep("setup"); return; }
    if (status === 200 && data.recoveryToken && data.recoveryWrap && data.material && data.userId) {
      let userKey: Uint8Array | null = null;
      try {
        userKey = await openRecoveryWrap(data.userId, key, data.recoveryWrap);
        const keys = await keysFromUserKey(userKey, data.material);
        key.fill(0); keyRef.current = null;
        setRecovered({ recoveryToken: data.recoveryToken, keys, material: data.material }); setStep("password");
      } catch { userKey?.fill(0); setError("This recovery code doesn't open the vault. Check it and try again."); setStep("details"); }
      return;
    }
    if (data.error === "totp_required") { setStep("totp"); return; }
    if (data.error === "invalid_recovery") { setError("Email or recovery code is not right."); setStep("details"); return; }
    setError(errorText(data, "Something went wrong. Try again."));
  }

  async function submitDetails(e: FormEvent) {
    e.preventDefault(); setError(null);
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) return setError("Enter the email address of your account.");
    let key: Uint8Array;
    try { key = await parseRecoveryCode(code); }
    catch (err) {
      return setError(err instanceof RecoveryCodeError && err.reason === "checksum"
        ? "That recovery code has a typo. Check each group against your kit." : "That doesn't look like a complete recovery code (14 groups of 4).");
    }
    keyRef.current?.fill(0); keyRef.current = key;
    setBusy(true);
    try { await check(); } catch { setError(`Can't reach ${productName}. Check your connection and try again.`); } finally { setBusy(false); }
  }

  async function submitTotp(e: FormEvent) {
    e.preventDefault(); setError(null); setBusy(true);
    try { await check(totp); } catch { setError(`Can't reach ${productName}. Check your connection and try again.`); } finally { setBusy(false); }
  }

  return (
    <AuthLayout title="Recover your vault" subtitle={step === "details" ? "Use the recovery kit you saved when you created your account." : undefined}>
      <ReportBusy busy={busy} />
      {step === "details" && (
        <form onSubmit={submitDetails} className="flex flex-col gap-4" noValidate>
          <div className="flex flex-col gap-1.5"><Label htmlFor="rec-email">Email address</Label>
            <Input id="rec-email" type="email" autoComplete="username" spellCheck={false} value={email} onChange={(e) => setEmail(e.target.value)} autoFocus={!email} /></div>
          <div className="flex flex-col gap-1.5"><Label htmlFor="rec-kit">Recovery code</Label>
            <textarea id="rec-kit" rows={3} autoComplete="off" spellCheck={false} autoFocus={!!email} placeholder="XXXX-XXXX-XXXX-…"
              className="rounded-[9px] border border-border-default bg-card px-3 py-2 font-mono text-[14px] tracking-[.06em] uppercase text-text-primary outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/25"
              value={code} onChange={(e) => setCode(e.target.value)} /></div>
          <Err text={error} />
          <Button type="submit" variant="cta" size="lg" className="h-11" disabled={busy}>{busy ? "Checking…" : "Continue"}</Button>
          <p className="text-[13px] text-text-secondary">You'll also need your authenticator app. No kit? <Link to="/sign-in" className="text-[var(--link)] hover:underline">Back to sign in</Link></p>
        </form>
      )}
      {step === "totp" && (
        <form onSubmit={submitTotp} className="flex flex-col gap-4">
          <p className="text-[14px] text-text-secondary">{afterSetup ? "Authenticator set up. Enter the next code it shows (each code works once)." : "Recovery code accepted. Confirm it's you with two-step sign-in."}</p>
          <TotpField value={totp} onChange={setTotp} />
          <Err text={error} />
          <Button type="submit" variant="cta" size="lg" className="h-11" disabled={busy || totp.length !== 6}>{busy ? "Checking…" : "Continue"}</Button>
        </form>
      )}
      {step === "setup" && setupToken && <InlineTotpSetup setupToken={setupToken} onVerified={() => { setError(null); setAfterSetup(true); setTotp(""); setStep("totp"); }} />}
      {step === "setup" && <Err text={error} />}
      {step === "password" && recovered && (
        <NewPasswordStep {...recovered} onDone={(res, authKey) => { completeRecovery(res, recovered.keys, authKey, { requireKit: true }); nav("/", { replace: true }); }} />
      )}
    </AuthLayout>
  );
}

/** What the admin link restores: one organisation's membership key (docs/design/2026-10-08-per-org-keypairs.md). */
/** `kdf`: restore mode only. The wrapped user key comes after the current master password checks out (never with the link). */
type LinkGrant = { recoveryToken: string; userId: string; orgId: string; orgName: string; key: MembershipKeys; kdf?: { kdfSalt: string; kdfParams: KdfParams } };

/**
 * Scoped reset: a new master password and new account keys; only the organisation whose admin approved comes back.
 * Private items and other organisations stay locked until the old kit or old password restores them (Settings).
 */
function ScopedPasswordStep({ grant, onDone }: { grant: LinkGrant; onDone: (res: AuthResponse, keys: UnlockedKeys, authKey: string) => void }) {
  const [pw, setPw] = useState("");
  const [repeat, setRepeat] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  async function submit(e: FormEvent) {
    e.preventDefault();
    if (pw.length < 12) return setError("Use at least 12 characters.");
    if (pw !== repeat) return setError("The passwords don't match.");
    setBusy(true); setError(null);
    try {
      const acct = await createAccount(pw);
      const membership = await wrapMembershipKeys(acct.keys.userKey, { orgId: grant.orgId, userId: grant.userId }, grant.key);
      const { status, data } = await authCall<AuthResponse & ErrorBody>("/recovery/finish", { authKey: acct.authKey, material: acct.material, membership }, grant.recoveryToken);
      if (status === 200) return onDone(data, acct.keys, acct.authKey);
      acct.keys.userKey.fill(0); acct.keys.privateKey.fill(0);
      setError(status === 410 || status === 401 ? "This recovery has expired or was already used. Ask your admin for a new link." : errorText(data, "Couldn't set your new password. Try again."));
    } catch { setError(`Can't reach ${productName}. Check your connection and try again.`); }
    finally { setBusy(false); }
  }
  return (
    <form onSubmit={submit} className="flex flex-col gap-4" noValidate>
      <p className="text-[14px] text-text-secondary">This restores what you have in <span className="font-medium text-text-primary">{grant.orgName}</span>. Your private items and other organisations stay locked: your recovery kit or your old master password brings them back later, from Settings.</p>
      <div className="flex flex-col gap-1.5"><Label htmlFor="new-pw">New master password</Label><Input id="new-pw" type="password" autoComplete="new-password" autoFocus value={pw} onChange={(e) => setPw(e.target.value)} /></div>
      <div className="flex flex-col gap-1.5"><Label htmlFor="new-pw2">Repeat new master password</Label><Input id="new-pw2" type="password" autoComplete="new-password" value={repeat} onChange={(e) => setRepeat(e.target.value)} /></div>
      <p className="text-[13px] text-text-secondary">Saving it signs you out on every other device.</p>
      <Err text={error} />
      <ReportBusy busy={busy} />
      <Button type="submit" variant="cta" size="lg" className="h-11" disabled={busy}>{busy ? "Saving…" : "Set new master password"}</Button>
    </form>
  );
}

/** The account was reset since this org's escrow: restore that organisation under the current master password (no reset). */
function RestoreMembershipStep({ grant, onDone }: { grant: LinkGrant; onDone: () => void }) {
  const [pw, setPw] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  async function submit(e: FormEvent) {
    e.preventDefault(); setBusy(true); setError(null);
    try {
      if (!grant.kdf) { setError("This link has expired or was already used. Ask your admin for a new one."); return; }
      const { wrapKey, authKey } = await deriveLoginKeys(pw, grant.kdf.kdfSalt, grant.kdf.kdfParams);
      let keys: UnlockedKeys;
      try {
        // The server checks the password (counted toward the lockout) before it hands out the wrapped user key.
        const got = await authCall<ErrorBody & { material?: AccountMaterial }>("/recovery/restore-membership/material", { authKey }, grant.recoveryToken);
        if (got.status === 401 && got.data.error === "invalid_credentials") { setError("That master password is not right."); return; }
        if (got.status !== 200 || !got.data.material) { setError(got.status === 410 || got.status === 401 ? "This link has expired or was already used. Ask your admin for a new one." : errorText(got.data, "Couldn't restore access. Try again.")); return; }
        try { keys = await unlockAccount(wrapKey, got.data.material); } catch { setError("That master password is not right."); return; }
      } finally { wrapKey.fill(0); }
      const m = await wrapMembershipKeys(keys.userKey, { orgId: grant.orgId, userId: grant.userId }, grant.key);
      keys.userKey.fill(0); keys.privateKey.fill(0);
      const { status, data } = await authCall<ErrorBody>("/recovery/restore-membership", { authKey, ...m }, grant.recoveryToken);
      if (status === 200) return onDone();
      setError(status === 410 || status === 401 ? "This link has expired or was already used. Ask your admin for a new one." : errorText(data, "Couldn't restore access. Try again."));
    } catch { setError(`Can't reach ${productName}. Check your connection and try again.`); }
    finally { setBusy(false); setPw(""); }
  }
  return (
    <form onSubmit={submit} className="flex flex-col gap-4" noValidate>
      <p className="text-[14px] text-text-secondary">Your master password was already reset. Enter your <span className="font-medium text-text-primary">current</span> master password to get your access to {grant.orgName} back.</p>
      <div className="flex flex-col gap-1.5"><Label htmlFor="cur-pw">Current master password</Label><Input id="cur-pw" type="password" autoComplete="current-password" autoFocus value={pw} onChange={(e) => setPw(e.target.value)} /></div>
      <Err text={error} />
      <ReportBusy busy={busy} />
      <Button type="submit" variant="cta" size="lg" className="h-11" disabled={busy || !pw}>{busy ? "Restoring…" : `Restore ${grant.orgName}`}</Button>
    </form>
  );
}

/** The one-time link an admin sent: /recover/<request id>#<secret>. The secret stays in this tab and never reaches the server. */
export function AdminRecoveryLinkPage() {
  const { id = "" } = useParams();
  const nav = useNavigate();
  const { completeRecovery } = useSession();
  const [fragment] = useState(() => window.location.hash.replace(/^#/, ""));
  const [step, setStep] = useState<"start" | "totp" | "setup" | "password" | "restore" | "restored" | "invalid">(fragment ? "start" : "invalid");
  const [email, setEmail] = useState<string | null>(null);
  const [totp, setTotp] = useState("");
  const [setupToken, setSetupToken] = useState<string | null>(null);
  const [afterSetup, setAfterSetup] = useState(false);
  const [grant, setGrant] = useState<LinkGrant | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const started = useRef(false);
  useEffect(() => () => { grant?.key.privateKey.fill(0); }, [grant]);

  // Keep the secret out of the address bar and history once read.
  useEffect(() => { if (window.location.hash) window.history.replaceState(window.history.state, "", window.location.pathname); }, []);

  async function check(withCode?: string) {
    let proof: string;
    try { proof = await adminRecoveryProof(fragment); } catch { setStep("invalid"); return; }
    const { status, data } = await authCall<ErrorBody & { needsTotpSetup?: boolean; setupToken?: string; recoveryToken?: string; userId?: string; mode?: "reset" | "restore";
      orgId?: string; orgName?: string; memberPublicKey?: string; wrappedMembershipKey?: string; kdf?: { kdfSalt: string; kdfParams: KdfParams } }>(
      `/recovery/admin/${id}`, { proof, ...(withCode ? { code: withCode } : {}) });
    if (data.email) setEmail(data.email);
    if (status === 200 && data.needsTotpSetup && data.setupToken) { setSetupToken(data.setupToken); setStep("setup"); return; }
    if (status === 200 && data.recoveryToken && data.wrappedMembershipKey && data.memberPublicKey && data.orgId && data.userId && (data.mode !== "restore" || data.kdf)) {
      try {
        // The key must be the one the link names, opened with this link's secret (bound to request, org and account).
        const key = await openMembershipRecoveryGrant(id, { orgId: data.orgId, userId: data.userId }, fragment, data.wrappedMembershipKey, data.memberPublicKey);
        setGrant({ recoveryToken: data.recoveryToken, userId: data.userId, orgId: data.orgId, orgName: data.orgName ?? "your organisation", key, kdf: data.kdf });
        setStep(data.mode === "restore" ? "restore" : "password");
      } catch { setStep("invalid"); }
      return;
    }
    if (data.error === "totp_required") { setStep("totp"); return; }
    if (data.error === "invalid_link" || status === 400) { setStep("invalid"); return; }
    if (data.error === "approver_too_new") { setError("For your safety this reset must be approved by an admin who has been an admin for longer. Ask another admin to approve a new request."); return; }
    if (data.error === "two_person_required") { setError("For your safety this reset needs a second admin: the admin who reset your two-step sign-in can't also approve it. Ask another admin."); return; }
    if (data.error === "reset_delay") { setError(`Your two-step sign-in was reset recently. For your safety you can continue in about ${Math.ceil((data.retryAfterSeconds ?? 3600) / 3600)} hours, with this same link if it hasn't expired.`); return; }
    setError(errorText(data, "Something went wrong. Try again."));
  }

  useEffect(() => {
    if (started.current) return;
    started.current = true;
    if (!fragment || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) { setStep("invalid"); return; }
    setBusy(true);
    void check().catch(() => setError(`Can't reach ${productName}. Check your connection and try again.`)).finally(() => setBusy(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps -- runs once for the link in hand
  }, []);

  async function submitTotp(e: FormEvent) {
    e.preventDefault(); setError(null); setBusy(true);
    try { await check(totp); } catch { setError(`Can't reach ${productName}. Check your connection and try again.`); } finally { setBusy(false); }
  }

  if (step === "invalid") return (
    <AuthLayout title="This recovery link doesn't work" subtitle="It may have expired (links work for 24 hours), been used already, or been cancelled. Ask your admin for a new one.">
      <Link to="/sign-in" className="text-[14px] text-[var(--link)] hover:underline">Back to sign in</Link>
    </AuthLayout>
  );

  return (
    <AuthLayout title="Reset your master password" subtitle={email ? `Admin-approved recovery for ${email}.` : "Admin-approved recovery."}>
      <ReportBusy busy={busy} />
      {step === "start" && <p role="status" className="text-[14px] text-text-secondary">Checking your link…</p>}
      {step === "start" && <Err text={error} />}
      {step === "totp" && (
        <form onSubmit={submitTotp} className="flex flex-col gap-4">
          <p className="text-[14px] text-text-secondary">{afterSetup ? "Authenticator set up. Enter the next code it shows (each code works once)." : "Confirm it's you with two-step sign-in. Your admin can't do this step for you."}</p>
          <TotpField value={totp} onChange={setTotp} />
          <Err text={error} />
          <Button type="submit" variant="cta" size="lg" className="h-11" disabled={busy || totp.length !== 6}>{busy ? "Checking…" : "Continue"}</Button>
        </form>
      )}
      {step === "setup" && setupToken && <InlineTotpSetup setupToken={setupToken} onVerified={() => { setError(null); setAfterSetup(true); setTotp(""); setStep("totp"); }} />}
      {step === "setup" && <Err text={error} />}
      {step === "password" && grant && (
        <ScopedPasswordStep grant={grant} onDone={(res, keys, authKey) => { completeRecovery(res, keys, authKey, { requireKit: true }); nav("/", { replace: true }); }} />
      )}
      {step === "restore" && grant && <RestoreMembershipStep grant={grant} onDone={() => setStep("restored")} />}
      {step === "restored" && (
        <div className="flex flex-col gap-3">
          <p role="status" className="text-[14px] text-text-secondary">Your access to {grant?.orgName ?? "the organisation"} is back. Sign in as usual.</p>
          <Link to="/sign-in" className="text-[14px] text-[var(--link)] hover:underline">Sign in</Link>
        </div>
      )}
    </AuthLayout>
  );
}
