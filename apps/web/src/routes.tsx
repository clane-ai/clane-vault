import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { Link, Navigate, Route, Routes, useLocation } from "react-router";
import { ShieldOff } from "lucide-react";
import { Button } from "@/components/ui/button";
import { wantedSpace } from "@/lib/space";
import { useSession } from "@/lib/session";
import { useBrand } from "@/brand";
import { VaultMark, useReducedMotion } from "@/components/brand/VaultMark";
import SignIn from "@/features/auth/SignIn";
import Register from "@/features/auth/Register";
import TwoFactorSetup from "@/features/auth/TwoFactorSetup";
import Unlock from "@/features/auth/Unlock";
import SsoComplete from "@/features/auth/SsoComplete";
import OAuthAuthorize from "@/features/auth/OAuthAuthorize";
import { JoinClaim, JoinRequest } from "@/features/auth/Join";
import VaultScreen from "@/features/vault/VaultScreen";
import PublicLinkPage from "@/features/links/PublicLinkPage";
import { AdminRecoveryLinkPage, RecoverWithKitPage } from "@/features/recovery/RecoverPages";
import { RecoveryKitPanel } from "@/features/recovery/RecoveryKit";
import { AuthLayout } from "@/features/auth/AuthLayout";

/** Full-page boot loader: the mark's working spin while the session resumes. */
export function Loading() {
  const { productName } = useBrand();
  return (
    <div className="grid h-full min-h-dvh place-items-center bg-app" role="status">
      <div className="flex flex-col items-center gap-5">
        <VaultMark size={54} state="working" decorative />
        <p className="font-mono text-[12.5px] tracking-[.02em] text-text-secondary">Opening {productName}…</p>
      </div>
    </div>
  );
}

/**
 * Plays the mark's "unlocked" beat once over the vault as it opens (after sign-in, unlock or account setup):
 * an overlay that fades out by itself and never takes clicks. Skipped for reduced motion.
 */
export function UnlockFlash() {
  const { state } = useSession();
  const reduce = useReducedMotion();
  const prev = useRef(state);
  const [show, setShow] = useState(false);
  useEffect(() => {
    const was = prev.current;
    prev.current = state;
    if (state === "unlocked" && (was === "locked" || was === "signed_out") && !reduce) setShow(true);
    if (state !== "unlocked") setShow(false);
  }, [state, reduce]);
  useEffect(() => {
    if (!show) return;
    const t = window.setTimeout(() => setShow(false), 950);
    return () => window.clearTimeout(t);
  }, [show]);
  if (!show) return null;
  return (
    <div aria-hidden="true" data-testid="unlock-flash" className="vault-unlock-overlay pointer-events-none fixed inset-0 z-[70] grid place-items-center bg-card">
      <VaultMark size={72} state="unlocked" decorative />
    </div>
  );
}

/** Where to go after signing in: the page asked for before (a bookmark or a reload while signed out), else the vault. */
const backTo = (state: unknown) => {
  const from = (state as { from?: { pathname?: string; search?: string } } | null)?.from;
  return from?.pathname && from.pathname.startsWith("/") && !from.pathname.startsWith("//") ? `${from.pathname}${from.search ?? ""}` : "/";
};

function PublicOnly({ children }: { children: React.ReactNode }) {
  const { state } = useSession();
  const location = useLocation();
  if (state === "loading") return <Loading />;
  if (state !== "signed_out") return <Navigate to={backTo(location.state)} replace />;
  return children;
}

/** Right after sign-up or a recovery: the recovery kit comes before the vault. */
function KitRequiredScreen({ mode }: { mode: "signup" | "recovery" }) {
  return (
    <AuthLayout title={mode === "recovery" ? "Save your new recovery kit" : "Save your recovery kit"}>
      <RecoveryKitPanel mode={mode} onDone={() => undefined} />
    </AuthLayout>
  );
}

/** A link to an organisation the user isn't in (or that doesn't exist: the page never says which). */
function NoSuchSpace() {
  return (
    <AuthLayout title="You can't open this organisation">
      <div className="flex flex-col items-center gap-4 text-center" data-testid="no-space-access">
        <span className="grid size-12 place-items-center rounded-[14px] bg-well text-text-tertiary"><ShieldOff className="size-5" /></span>
        <p className="text-[14px] leading-relaxed text-text-secondary">This link is for an organisation you aren't a member of, or it no longer exists. If you were invited, accept the invitation from the organisation menu first.</p>
        <Button asChild><Link to="/p/vault">Go to your Personal vault</Link></Button>
      </div>
    </AuthLayout>
  );
}

/**
 * The URL is the source of truth for the active space (lib/paths): when it names another space than the one the
 * session holds, the session switches (dropping the old space's caches and keys) before anything renders, so the
 * previous space's data never shows, not even for a frame. The vault screen is keyed by the space, so switching also
 * clears selections, open panels and searches.
 */
export function SpaceGate({ children }: { children: (spaceKey: string) => React.ReactNode }) {
  const { org, orgs, switchOrg } = useSession();
  const location = useLocation();
  const want = wantedSpace(location.pathname, orgs);
  const current = org?.id ?? null;
  const target = want === undefined || want === "unknown" ? current : want?.id ?? null;
  const mismatch = target !== current;
  // Before paint: the switch re-renders synchronously, so the mismatched frame below is never shown.
  useLayoutEffect(() => { if (mismatch) switchOrg(target); }, [mismatch, target, switchOrg]);
  if (want === "unknown") return <NoSuchSpace />;
  if (mismatch) return <Loading />;
  return children(current ?? "personal");
}

function Guard() {
  const { state, kitRequired } = useSession();
  const location = useLocation();
  if (state === "loading") return <Loading />;
  // Signed out on an app page: sign in, then come back to it.
  if (state === "signed_out") return <Navigate to="/sign-in" replace state={location.pathname !== "/" ? { from: { pathname: location.pathname, search: location.search } } : undefined} />;
  if (state === "locked") return <Unlock />;
  if (kitRequired) return <KitRequiredScreen mode={kitRequired} />;
  return <SpaceGate>{(space) => <VaultScreen key={space} />}</SpaceGate>;
}

export function AppRoutes() {
  return (
    <>
    <UnlockFlash />
    <Routes>
      <Route path="/sign-in" element={<PublicOnly><SignIn /></PublicOnly>} />
      <Route path="/invite/:token" element={<PublicOnly><Register /></PublicOnly>} />
      {/* Email domain auto-join (docs/provisioning.md): ask for a link, and claim one with an existing account. */}
      <Route path="/join" element={<PublicOnly><JoinRequest /></PublicOnly>} />
      <Route path="/join/:token" element={<JoinClaim />} />
      <Route path="/s/:id" element={<PublicLinkPage />} />
      <Route path="/recover" element={<RecoverWithKitPage />} />
      <Route path="/recover/:id" element={<AdminRecoveryLinkPage />} />
      <Route path="/setup-2fa" element={<TwoFactorSetup />} />
      <Route path="/sso/complete" element={<SsoComplete />} />
      <Route path="/oauth/authorize" element={<OAuthAuthorize />} />
      <Route path="/*" element={<Guard />} />
    </Routes>
    </>
  );
}
