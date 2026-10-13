import { useState } from "react";
import { Building2, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useNavigate } from "react-router";
import { useSession, type Org } from "@/lib/session";
import { spacePrefix } from "@/lib/paths";
import { startSso } from "./sso";

/** The active org requires its SSO and this session didn't come from it (403 `sso_required`). */
export function SsoRequiredPanel({ org, go }: { org: Org; go?: (url: string) => void }) {
  const { user } = useSession();
  const navigate = useNavigate();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  async function start() {
    setBusy(true); setError(null);
    try { await startSso(org.slug, { email: user?.email, returnTo: `${spacePrefix(org)}/vault` }, go); }
    catch { setError("Couldn't reach the identity provider. Try again in a moment."); setBusy(false); }
  }
  return (
    <section aria-label="Single sign-on required" className="grid min-h-0 flex-1 place-items-center px-6 py-10">
      <div className="flex max-w-[440px] flex-col items-center gap-4 text-center">
        <span className="grid size-12 place-items-center rounded-[14px] bg-blue-tint text-blue-500"><ShieldCheck className="size-6" /></span>
        <h2 className="font-display text-[20px] font-semibold text-text-primary">{org.name} requires single sign-on</h2>
        <p className="text-[14px] leading-relaxed text-text-secondary">Sign in with {org.name}'s identity provider to open its team folders and shares. Your private records and other organisations stay available with your master password.</p>
        <Button type="button" variant="cta" size="lg" className="h-11" onClick={() => void start()} disabled={busy}><Building2 className="size-4" />{busy ? "Opening…" : `Sign in with ${org.name} SSO`}</Button>
        <Button type="button" variant="ghost" size="sm" onClick={() => navigate("/p/vault")}>Go to your Personal vault</Button>
        {error && <p role="alert" className="text-[13px] text-red-500">{error}</p>}
      </div>
    </section>
  );
}
