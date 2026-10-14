import { useState, type FormEvent } from "react";
import { Link } from "react-router";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useSession } from "@/lib/session";
import { AuthLayout } from "./AuthLayout";
import { ReportBusy } from "./authBusy";
import { useDemoUnlock } from "@/features/demo/demoUnlock";

export default function Unlock() {
  const { user, unlock, signOut, offline } = useSession();
  const [pw, setPw] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  // A demo sandbox opens again by itself (its visitor never saw the master password).
  const demoOpening = useDemoUnlock(user, unlock, offline);
  async function submit(e: FormEvent) {
    e.preventDefault(); setBusy(true); setError(null);
    try { await unlock(pw); } catch (err) { setError((err as Error).message + "."); } finally { setBusy(false); setPw(""); }
  }
  return (
    <AuthLayout title="Vault locked" subtitle={offline
      ? `You're offline. Enter the master password for ${user?.email} to open the copy saved on this device (read only).`
      : `Signed in as ${user?.email}. Enter your master password to unlock.`}>
      <ReportBusy busy={busy || demoOpening} />
      <form onSubmit={submit} className="flex flex-col gap-4">
        <div className="flex flex-col gap-1.5"><Label htmlFor="pw">Master password</Label>
          <Input id="pw" type="password" autoComplete="current-password" autoFocus value={pw} onChange={(e) => setPw(e.target.value)} /></div>
        {error && <p role="alert" className="text-[13px] text-red-500">{error}</p>}
        <Button type="submit" variant="cta" size="lg" className="h-11" disabled={busy || !pw}>{busy ? "Unlocking…" : offline ? "Unlock offline copy" : "Unlock"}</Button>
        <Button type="button" variant="ghost" onClick={signOut}>Sign out</Button>
        {!offline && <Link to={`/recover?email=${encodeURIComponent(user?.email ?? "")}`} className="text-center text-[13px] text-[var(--link)] hover:underline">Forgot master password? Use your recovery kit</Link>}
      </form>
    </AuthLayout>
  );
}
