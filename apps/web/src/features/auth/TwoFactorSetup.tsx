import { useEffect, useRef, useState, type FormEvent } from "react";
import { Link, Navigate, useLocation, useNavigate } from "react-router";
import QRCode from "qrcode";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useSession } from "@/lib/session";
import { AuthLayout } from "./AuthLayout";
import { ReportBusy } from "./authBusy";
import { apiUrl } from "@/lib/base";

async function setupCall<T>(path: string, token: string, body: unknown): Promise<{ ok: boolean; data: T }> {
  const res = await fetch(apiUrl(`/auth${path}`), { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${token}` }, body: JSON.stringify(body) });
  return { ok: res.ok, data: (await res.json().catch(() => null)) as T };
}

export default function TwoFactorSetup() {
  const loc = useLocation() as { state?: { setupToken: string; password: string } };
  const nav = useNavigate();
  const { completeTwoFactor } = useSession();
  const [qr, setQr] = useState<string | null>(null);
  const [secret, setSecret] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [setupFailed, setSetupFailed] = useState(false);
  const [busy, setBusy] = useState(false);
  const started = useRef<string | null>(null);
  const st = loc.state;

  useEffect(() => {
    if (!st || started.current === st.setupToken) return;
    started.current = st.setupToken;
    setupCall<{ otpauthUrl: string; secret: string }>("/totp/setup", st.setupToken, {}).then(async ({ ok, data }) => {
      if (!ok || !data) return setSetupFailed(true);
      setSecret(data.secret); setQr(await QRCode.toDataURL(data.otpauthUrl, { margin: 1, width: 192 }));
    }).catch(() => setSetupFailed(true));
  }, [st]);

  if (!st) return <Navigate to="/sign-in" replace />;

  async function submit(e: FormEvent) {
    e.preventDefault(); setError(null); setBusy(true);
    try {
      const { ok, data } = await setupCall<{ accessToken: string; user: never; material: never; error?: string }>("/totp/verify", st!.setupToken, { code });
      if (!ok) return setError("That code didn't work. Try the newest code from the app.");
      await completeTwoFactor(data);
      nav("/", { replace: true });
    } catch { setError("Couldn't finish sign-in. Go back to sign in and try again."); }
    finally { setBusy(false); }
  }

  if (setupFailed) return (
    <AuthLayout title="Couldn't start two-step setup" subtitle="Your sign-in link may have expired.">
      <p role="alert" className="text-[13px] text-red-500">Setup didn't start. Go back and sign in again.</p>
      <Link to="/sign-in" className="text-[14px] text-blue-500 underline">Back to sign in</Link>
    </AuthLayout>
  );

  return (
    <AuthLayout title="Turn on two-step sign-in" subtitle="Scan this with Microsoft Authenticator, Google Authenticator or 1Password.">
      <div className="grid place-items-center rounded-[12px] bg-white p-3 border border-border-default">{qr ? <img src={qr} alt="QR code for your authenticator app" width={192} height={192} /> : <span className="h-[192px]" />}</div>
      <p className="text-[13px] text-text-secondary">Can't scan? Enter this key: <span className="font-mono text-text-primary break-all">{secret}</span></p>
      <ReportBusy busy={busy} />
      <form onSubmit={submit} className="flex flex-col gap-4">
        <div className="flex flex-col gap-1.5"><Label htmlFor="code">6-digit code</Label>
          <Input id="code" inputMode="numeric" maxLength={6} className="font-mono tracking-[0.3em]" value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} /></div>
        {error && <p role="alert" className="text-[13px] text-red-500">{error}</p>}
        <Button type="submit" variant="cta" size="lg" className="h-11" disabled={code.length !== 6 || busy}>Turn on and continue</Button>
      </form>
    </AuthLayout>
  );
}
