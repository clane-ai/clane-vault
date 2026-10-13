import { spacePrefix } from "@/lib/paths";
import { useState, type FormEvent } from "react";
import { Link, Navigate } from "react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Download, HeartPulse, KeyRound, LifeBuoy, MonitorSmartphone, Puzzle, ShieldAlert, ShieldCheck, Smartphone, UserRound } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Switch } from "@/components/ui/switch";
import { ApiError } from "@/lib/api";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useSession } from "@/lib/session";
import { useOrgApi, useScope } from "@/lib/scope";
import { relativeTime } from "@/lib/time";
import { cn } from "@/lib/utils";
import { Chip } from "@/features/vault/people";
import { RecoveryKitPanel } from "@/features/recovery/RecoveryKit";
import { useSecurity } from "@/features/recovery/recovery";
import { KeyArchiveSection } from "@/features/recovery/KeyArchive";
import { OrgDetailsSection } from "@/features/orgs/OrgSettings";
import { ROLE_LABEL } from "@/features/orgs/orgs";
import { UserAvatar } from "@/features/vault/Sidebar";
import { SectionLayout, SectionPage, type NavGroup } from "@/components/SectionLayout";
import { useInstallPrompt } from "@/pwa/install";
import type { SettingsSection } from "@/lib/paths";
import { DeviceSection } from "./DeviceSection";
import { ExtensionSection } from "./ExtensionSection";

const card = "rounded-[14px] border border-border-default bg-card p-4 shadow-[var(--shadow-card)]";
const h2 = "font-display text-[15px] font-semibold tracking-[-0.01em] text-text-primary";

export interface OrgSettings {
  adminRecovery: { enabled: boolean; changedAt: string | null; changedBy: { id: string; name: string } | null };
  escrows: { total: number; members: number };
}

/** Plain words for what the policy means, shown to everyone (Settings → Security) and in the admin switch dialog. */
export const ADMIN_RECOVERY_DISCLOSURE = "Your organisation's admins can restore your access to it";
export const ADMIN_RECOVERY_WARNING = "Admins will be able to help any member reset their master password and restore what they hold in this organisation. Never their private items or other organisations' items.";

/** The kit dialog: create, or replace (master password first, then the new code). */
export function RecoveryKitDialog({ open, mode, onClose }: { open: boolean; mode: "create" | "regenerate"; onClose: () => void }) {
  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="sm:max-w-[560px]">
        <DialogHeader>
          <DialogTitle>{mode === "regenerate" ? "Regenerate recovery kit" : "Create your recovery kit"}</DialogTitle>
          <DialogDescription className="sr-only">Generate, save and confirm your recovery code.</DialogDescription>
        </DialogHeader>
        {open && <RecoveryKitPanel mode={mode} onDone={onClose} onCancel={onClose} />}
      </DialogContent>
    </Dialog>
  );
}


/** Settings → Account: the recovery kit (create or replace). */
function RecoveryKitCard() {
  const sec = useSecurity();
  const [kitOpen, setKitOpen] = useState(false);
  const kit = sec.data?.recoveryKit ?? null;
  return (
    <div className={cn(card, "flex flex-wrap items-center gap-3")} aria-label="Recovery kit" role="group">
      <span className="grid size-9 shrink-0 place-items-center rounded-[10px] bg-well text-text-tertiary"><KeyRound className="size-4" /></span>
      <div className="min-w-0 flex-1 max-[560px]:basis-[calc(100%-3rem)]">
        <p className="flex items-center gap-2 text-[14px] font-medium text-text-primary">Recovery kit {sec.data && (kit ? <Chip tone="green">Saved</Chip> : <Chip tone="orange">Not created</Chip>)}</p>
        <p className="text-[13px] text-text-secondary">
          {kit ? `Created ${relativeTime(kit.createdAt) || new Date(kit.createdAt).toLocaleDateString()}. Lets you set a new master password if you forget it (with your authenticator).`
            : "Without a kit, a forgotten master password means losing your private records."}
        </p>
      </div>
      <Button type="button" variant={kit ? "outline" : "default"} onClick={() => setKitOpen(true)} disabled={!sec.data}>{kit ? "Regenerate recovery kit" : "Create recovery kit"}</Button>
      <RecoveryKitDialog open={kitOpen} mode={kit ? "regenerate" : "create"} onClose={() => setKitOpen(false)} />
    </div>
  );
}

/** Settings → Security: who can recover the account (admin escrow per organisation). */
function WhoCanRecover() {
  const sec = useSecurity();
  const admin = sec.data?.adminRecoveryEnabled ?? false;
  const orgs = sec.data?.orgs ?? [];
  const recoverers = orgs.map((o) => o.orgName);
  return (
    <div role="note" aria-label="Who can recover your vault" className={cn(card, "flex gap-3")}>
      <span className="grid size-9 shrink-0 place-items-center rounded-[10px] bg-well text-text-tertiary">{admin ? <ShieldAlert className="size-4" /> : <ShieldCheck className="size-4" />}</span>
      <div className="min-w-0 flex-1">
        {admin ? (<>
          <p className="text-[14px] font-medium text-text-primary">{recoverers.length ? `Admins of ${recoverers.join(", ")} can recover your account` : ADMIN_RECOVERY_DISCLOSURE}</p>
          <p className="text-[13px] leading-relaxed text-text-secondary">Admin account recovery is on{recoverers.length > 1 ? " in each of these organisations" : ""}: your key for that organisation is also sealed to each of its admins. Such an admin can approve a password reset and restore what you hold in that organisation only. They can't open your private items or other organisations' items; your recovery kit restores those. You set your new password yourself, with a one-time link and your own 2FA code.</p>
          <ul aria-label="Who holds your escrow" className="mt-2 flex flex-col gap-1 text-[13px] text-text-secondary">
            {orgs.map((o) => (
              <li key={o.orgId}><span className="font-medium text-text-primary">{o.orgName}:</span>{" "}
                {o.ackRequired ? "waiting for your confirmation" : o.escrowHolders?.length ? `held by ${o.escrowHolders.map((h) => `${h.name} (${h.email})`).join(", ")}` : "not set up yet (it is once you've unlocked here)"}</li>
            ))}
          </ul>
        </>) : (<>
          <p className="text-[14px] font-medium text-text-primary">Only you can open your vault</p>
          <p className="text-[13px] leading-relaxed text-text-secondary">Admins can't reset your master password or read your private records. Your recovery kit is the way back in.</p>
        </>)}
      </div>
    </div>
  );
}

const h2Block = (title: string, line?: string) => <div><h2 className={h2}>{title}</h2>{line && <p className="text-[13px] text-text-secondary">{line}</p>}</div>;

/** Settings → Account (everyone): who you are, your master password, your recovery kit and your organisations. */
export function AccountSettings() {
  const { user, org, orgs = [] } = useSession();
  if (!user) return null;
  return (
    <SectionPage title="Account" keepHeadings>
      <section className="flex flex-col gap-3" aria-label="Profile">
        {h2Block("Profile")}
        <div className={cn(card, "flex items-center gap-3")}>
          <UserAvatar name={user.name} size={44} className="text-text-primary ring-border-default" />
          <div className="min-w-0 flex-1">
            <p className="truncate text-[15px] font-medium text-text-primary">{user.name}</p>
            <p className="truncate font-mono text-[12.5px] text-text-secondary">{user.email}</p>
          </div>
          {org && <Chip tone="blue">{ROLE_LABEL[org.role]}</Chip>}
        </div>
      </section>
      <section className="flex flex-col gap-3" aria-label="Master password and recovery kit">
        {h2Block("Master password", "It unlocks your vault on this device and never leaves it. Nobody can look it up or reset it for you.")}
        <div className={cn(card, "flex gap-3")}>
          <span className="grid size-9 shrink-0 place-items-center rounded-[10px] bg-well text-text-tertiary"><KeyRound className="size-4" /></span>
          <p className="min-w-0 flex-1 text-[13px] leading-relaxed text-text-secondary">If you forget it, your recovery kit (with your authenticator) lets you set a new one{org ? ". An admin of your organisation can also help if they turned on admin recovery (see Security)" : ""}.</p>
        </div>
        <RecoveryKitCard />
      </section>
      {/* A member of one organisation sees just that organisation (and Leave) below; otherwise the list. */}
      {(orgs.length !== 1 || org?.role !== "member") && <section className="flex flex-col gap-3" aria-label="Your organisations">
        {h2Block("Organisations", orgs.length ? "Switch organisation at the top of the sidebar. Your private records show in every organisation." : "You aren't in an organisation. Your private records are here.")}
        {orgs.length > 0 && (
          <ul className={cn(card, "py-1")}>
            {orgs.map((o) => (
              <li key={o.id} className="flex items-center gap-2 border-b border-border-default py-2.5 last:border-b-0">
                <span className="min-w-0 flex-1 truncate text-[14px] text-text-primary">{o.name}{o.id === org?.id && <span className="ml-2 font-mono text-[11px] text-text-tertiary">current</span>}</span>
                <Chip>{ROLE_LABEL[o.role]}</Chip>
              </li>
            ))}
          </ul>
        )}
        {org && org.role !== "member" && <p className="text-[13px] text-text-secondary">You manage {org.name}: its people, policies and settings are in <Link to={`${spacePrefix(org)}/admin`} className="font-medium text-[var(--link)] underline-offset-2 hover:underline">Admin</Link>.</p>}
      </section>}
      {org?.role === "member" && <OrgDetailsSection />}
    </SectionPage>
  );
}

/** Settings → Security (everyone): two-step sign-in, who can recover the account, and items from before a reset. */
export function SecuritySettings() {
  return (
    <SectionPage title="Security" keepHeadings>
      <section className="flex flex-col gap-3" aria-label="Two-step sign-in">
        {h2Block("Two-step sign-in")}
        <div className={cn(card, "flex gap-3")}>
          <span className="grid size-9 shrink-0 place-items-center rounded-[10px] bg-well text-text-tertiary"><Smartphone className="size-4" /></span>
          <div className="min-w-0 flex-1">
            <p className="flex items-center gap-2 text-[14px] font-medium text-text-primary">Authenticator app <Chip tone="green">On</Chip></p>
            <p className="text-[13px] leading-relaxed text-text-secondary">Every sign-in asks for a code from your authenticator. Recovery keeps it too: if you lose your authenticator as well as your master password, ask an admin to reset 2FA first, then recover.</p>
          </div>
        </div>
      </section>
      <section className="flex flex-col gap-3" aria-label="Account recovery">
        {h2Block("Account recovery")}
        <WhoCanRecover />
        <KeyArchiveSection />
      </section>
    </SectionPage>
  );
}

/** Settings → This device: the offline copy and installing the app. */
export function DeviceSettings() {
  const install = useInstallPrompt();
  return (
    <SectionPage title="This device">
      <DeviceSection />
      <section className="flex flex-col gap-3" aria-label="Install the app">
        {h2Block("Install the app")}
        <div className={cn(card, "flex flex-wrap items-center gap-3")}>
          <span className="grid size-9 shrink-0 place-items-center rounded-[10px] bg-well text-text-tertiary"><Download className="size-4" /></span>
          <p className="min-w-0 flex-1 text-[13px] leading-relaxed text-text-secondary max-[560px]:basis-[calc(100%-3rem)]">
            {install ? "Install it as an app: its own window, and it opens offline with the offline copy." : "Use your browser's Install option (address bar or menu). On iPhone and iPad: Share → Add to Home Screen. Already installed? You're set."}
          </p>
          {install && <Button type="button" onClick={() => void install()}>Install app</Button>}
        </div>
      </section>
    </SectionPage>
  );
}

/** Settings → Browser extension. */
export function ExtensionSettings() {
  return <SectionPage title="Browser extension"><ExtensionSection /></SectionPage>;
}


/** Switching admin recovery on: the warning, then the admin's master password and a fresh 2FA code. */
function TurnOnForm({ onDone, onCancel }: { onDone: (d: OrgSettings) => void; onCancel: () => void }) {
  const { proveMaster } = useSession();
  const oapi = useOrgApi();
  const [pw, setPw] = useState("");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  async function submit(e: FormEvent) {
    e.preventDefault(); setBusy(true); setError(null);
    try {
      const authKey = await proveMaster(pw);
      onDone(await oapi.put<OrgSettings>("/admin/settings/admin-recovery", { enabled: true, authKey, code }));
    } catch (err) {
      const c = err instanceof ApiError ? err.code : "";
      setError(c === "totp_invalid" ? "That code didn't work. Wait for the next code and try again." : c === "locked" ? "Too many failed attempts. Try again in 15 minutes."
        : c === "invalid_credentials" ? "That master password is not right." : err instanceof ApiError ? "Couldn't change the setting. Try again." : `${(err as Error).message}.`);
    } finally { setBusy(false); setPw(""); setCode(""); }
  }
  return (
    <form onSubmit={submit} className="flex flex-col gap-3">
      <div className="flex flex-col gap-1.5"><Label htmlFor="on-pw">Your master password</Label>
        <Input id="on-pw" type="password" autoComplete="current-password" value={pw} onChange={(e) => setPw(e.target.value)} /></div>
      <div className="flex flex-col gap-1.5"><Label htmlFor="on-code">6-digit code from your authenticator app</Label>
        <Input id="on-code" inputMode="numeric" autoComplete="one-time-code" maxLength={6} className="w-[180px] font-mono tracking-[0.3em]" value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} /></div>
      {error && <p role="alert" className="text-[13px] text-red-500">{error}</p>}
      <div className="flex justify-end gap-2">
        <Button type="button" variant="ghost" onClick={onCancel}>Cancel</Button>
        <Button type="submit" variant="destructive" disabled={busy || !pw || code.length !== 6}>{busy ? "Turning on…" : "Turn on"}</Button>
      </div>
    </form>
  );
}

/** Admin → Admin recovery: the active org's admin-recovery policy (its admins only). */
export function AdminRecoverySection() {
  const qc = useQueryClient();
  const KEY = ["admin-settings", useScope()];
  const oapi = useOrgApi();
  const q = useQuery({ queryKey: KEY, queryFn: () => oapi.get<OrgSettings>("/admin/settings") });
  const [confirm, setConfirm] = useState<boolean | null>(null);
  const set = useMutation({
    mutationFn: (enabled: false) => oapi.put<OrgSettings>("/admin/settings/admin-recovery", { enabled }),
    onSuccess: (d) => { qc.setQueryData(KEY, d); void qc.invalidateQueries({ queryKey: ["security"] }); void qc.invalidateQueries({ queryKey: ["admin-recovery-requests"] }); },
  });
  const s = q.data?.adminRecovery;
  return (
    <section className="flex flex-col gap-3" aria-label="Admin account recovery">
      <h2 className={h2}>Account recovery in this organisation</h2>
      <div className={cn(card, "flex flex-col gap-3")}>
        <div className="flex items-start gap-3">
          <span className="grid size-9 shrink-0 place-items-center rounded-[10px] bg-well text-text-tertiary"><LifeBuoy className="size-4" /></span>
          <div className="min-w-0 flex-1">
            <label htmlFor="admin-recovery" className="text-[14px] font-medium text-text-primary">Admin account recovery</label>
            <p className="text-[13px] leading-relaxed text-text-secondary">Members who forget their master password can ask an admin for a one-time reset link. Off by default. {ADMIN_RECOVERY_WARNING}</p>
          </div>
          <Switch id="admin-recovery" checked={!!s?.enabled} disabled={!q.data || set.isPending} onCheckedChange={(v) => setConfirm(v)} aria-label="Admin account recovery" />
        </div>
        {s && (
          <p className="pl-12 font-mono text-[11.5px] text-text-tertiary max-[560px]:pl-0">
            {s.enabled ? "On" : "Off"}{s.changedAt ? ` · changed ${relativeTime(s.changedAt)}${s.changedBy ? ` by ${s.changedBy.name}` : ""}` : ""}
            {s.enabled && q.data ? ` · ${q.data.escrows.members} ${q.data.escrows.members === 1 ? "person" : "people"} escrowed` : ""}
          </p>
        )}
        {s?.enabled && <p className="pl-12 text-[12.5px] text-text-secondary max-[560px]:pl-0">Escrows are made when each member next unlocks. A newly promoted admin can approve a member's request only after that member unlocks again.</p>}
      </div>
      <Dialog open={confirm !== null} onOpenChange={(o) => !o && setConfirm(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{confirm ? "Turn on admin account recovery?" : "Turn off admin account recovery?"}</DialogTitle>
            <DialogDescription>
              {confirm
                ? `${ADMIN_RECOVERY_WARNING} Each member is told (by email and in the app) and their key for this organisation is sealed to every admin once they confirm. Turning it off later deletes the escrows; a key an admin already opened is replaced on the member's next unlock.`
                : "Every escrowed key is deleted right away and open reset requests end. Members then rely on their own recovery kits."}
            </DialogDescription>
          </DialogHeader>
          {confirm ? (
            <TurnOnForm onCancel={() => setConfirm(null)} onDone={(d) => {
              setConfirm(null); qc.setQueryData(KEY, d); void qc.invalidateQueries({ queryKey: ["security"] }); toast.success("Admin account recovery is on");
            }} />
          ) : (
            <div className="flex justify-end gap-2">
              <Button type="button" variant="ghost" onClick={() => setConfirm(null)}>Cancel</Button>
              <Button type="button" onClick={() => {
                setConfirm(null);
                set.mutate(false, { onSuccess: () => toast.success("Admin account recovery is off; escrows deleted"), onError: () => toast.error("Couldn't change the setting. Try again.") });
              }}>Turn off</Button>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </section>
  );
}

/** The Settings sub-navigation: personal sections only, the same for everyone. */
export function settingsNav(noKit: boolean): NavGroup[] {
  return [{ label: "Your account", items: [
    { id: "account", label: "Account", icon: UserRound, to: "/settings/account", dot: noKit },
    { id: "security", label: "Security", icon: ShieldCheck, to: "/settings/security" },
    { id: "device", label: "This device", icon: MonitorSmartphone, to: "/settings/device" },
    { id: "extension", label: "Browser extension", icon: Puzzle, to: "/settings/extension" },
    { id: "health", label: "Password health", icon: HeartPulse, to: "/settings/health" },
  ] }];
}

/**
 * Settings (/settings/*): every user's own sections beside a sub-navigation; admin pages live under /admin.
 * `health`: the vault's password health page (it needs the decrypted vault, which the shell holds).
 */
export function SettingsArea({ section, mobile, health }: { section: SettingsSection | null; mobile: boolean; health: React.ReactNode }) {
  const noKit = useSecurity().data?.recoveryKit === null;
  if (section === null && !mobile) return <Navigate to="/settings/account" replace />;
  return (
    <SectionLayout title="Settings" base="/settings" groups={settingsNav(noKit)} active={section} mobile={mobile}>
      {section === "account" ? <AccountSettings /> : section === "security" ? <SecuritySettings /> : section === "device" ? <DeviceSettings />
        : section === "extension" ? <ExtensionSettings /> : section === "health" ? health : null}
    </SectionLayout>
  );
}
