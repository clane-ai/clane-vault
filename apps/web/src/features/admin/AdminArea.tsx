import { Link, Navigate, useNavigate } from "react-router";
import { Building, Building2, DatabaseBackup, FolderSync, HardDrive, HeartPulse, KeyRound, LifeBuoy, ListChecks, Mail, Palette, ScrollText, ShieldAlert, ShieldOff, UserRoundCog, UserRoundSearch, UsersRound, type LucideIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { PageHeader, SectionLayout, SectionPage, type NavGroup } from "@/components/SectionLayout";
import { adminPath, isServerSection, spacePrefix, type AdminSection } from "@/lib/paths";
import { useSpacePaths } from "@/lib/space";
import { useSession } from "@/lib/session";
import type { VaultFolder, VaultRecord } from "@/features/vault/types";
import { OrgDetailsSection } from "@/features/orgs/OrgSettings";
import { OrgPoliciesSection } from "@/features/policies/OrgPoliciesSection";
import { GroupsSection } from "@/features/groups/GroupsSection";
import GroupPage from "@/features/groups/GroupPage";
import { TeamHealth } from "@/features/health/HealthPage";
import MigratePage from "@/features/migrate/MigratePage";
import { AdminRecoverySection } from "@/features/settings/SettingsPage";
import { SsoSettingsSection } from "@/features/settings/SsoSettings";
import { EmailSettingsSection } from "@/features/settings/EmailSettings";
import { DemoUnavailable } from "@/features/demo/Demo";
import { useBrand } from "@/brand";
import { BrandingSection } from "@/features/settings/BrandingSection";
import PeoplePage from "./PeoplePage";
import MemberPage from "./MemberPage";
import EventLogPage from "./EventLogPage";
import BackupsPage from "./BackupsPage";
import { OrgStorageSection, ServerStorageSection } from "./StoragePages";
import RiskPage from "./risk/RiskPage";
import { CustomerOrgsSection } from "./CustomerOrgs";
import { ResetAuthenticatorCard } from "./ResetAuthenticator";
import { PlanGate, TrialLine } from "./PlanLock";

/**
 * The Admin sub-navigation: the active org's pages (/o/:org/admin/...) for its owners and admins, Server (/server/...)
 * for instance admins. `orgPrefix`: the active org's space prefix (null in Personal: no org pages).
 */
export function adminNav(o: { isAdmin: boolean; isInstanceAdmin: boolean; peopleBadge?: number; migrateBadge?: number; orgPrefix?: string | null }): NavGroup[] {
  const item = (id: AdminSection, label: string, icon: LucideIcon, badge?: number) => ({ id, label, icon, to: adminPath(o.orgPrefix ?? null, id), badge });
  const groups: NavGroup[] = [];
  if (o.isAdmin && o.orgPrefix) {
    groups.push({ label: "Organisation", items: [
      item("risk", "Risk dashboard", ShieldAlert),
      item("people", "People", UserRoundCog, o.peopleBadge), item("groups", "Groups", UsersRound), item("events", "Event log", ScrollText),
      item("health", "Password health", HeartPulse), item("migrate", "Migrate from Keeper", FolderSync, o.migrateBadge),
    ] });
    groups.push({ label: "Organisation settings", items: [
      item("org/general", "General", Building2), item("org/policies", "Policies", ListChecks), item("org/sso", "Single sign-on", KeyRound),
      item("org/recovery", "Admin recovery", LifeBuoy), item("org/email", "Email", Mail), item("org/storage", "Storage", HardDrive),
    ] });
  }
  if (o.isInstanceAdmin) groups.push({ label: "Server", items: [item("server/organisations", "Customer organisations", Building), item("server/accounts", "Accounts", UserRoundSearch),
    item("server/branding", "Branding", Palette), item("server/email", "Email", Mail), item("server/backups", "Backups", DatabaseBackup), item("server/storage", "Storage", HardDrive)] });
  return groups;
}

/** An admin URL for someone without the role: never the admin page itself. */
export function NoAccess() {
  const paths = useSpacePaths();
  return (
    <section className="flex min-h-0 min-w-0 flex-1 flex-col" aria-label="No access">
      <PageHeader title="No access" back={null} />
      <div className="grid flex-1 place-items-center px-6 py-10">
        <div className="flex max-w-[420px] flex-col items-center gap-3 text-center">
          <span className="grid size-12 place-items-center rounded-[14px] bg-well text-text-tertiary"><ShieldOff className="size-5" /></span>
          <h2 className="font-display text-[17px] font-semibold text-text-primary">You don't have access to this page</h2>
          <p className="text-[13.5px] leading-relaxed text-text-secondary">Admin pages are for your organisation's owners and admins (and the server's own settings for its admins). Your own settings are in Settings.</p>
          <div className="mt-1 flex flex-wrap justify-center gap-2">
            <Button asChild><Link to="/settings">Go to Settings</Link></Button>
            <Button asChild variant="outline"><Link to={paths.list("vault")}>Back to the vault</Link></Button>
          </div>
        </div>
      </div>
    </section>
  );
}

/**
 * Admin (/admin/*): a sub-navigation beside the page. Who sees what is decided here and by the server (every admin
 * request checks the role): sections the viewer may not use show NoAccess, never their UI.
 */
export function AdminArea({ section, detailId, mobile, isAdmin, isInstanceAdmin, loading, folders, records, vaultLoading, pendingReady, recoveryPending }: {
  section: AdminSection | null; detailId: string | null; mobile: boolean; isAdmin: boolean; isInstanceAdmin: boolean;
  /** Still finding out whether they're an instance admin. */ loading: boolean;
  folders: VaultFolder[]; records: VaultRecord[]; vaultLoading: boolean; pendingReady: number; recoveryPending: number;
}) {
  const { org } = useSession();
  const { demo } = useBrand();
  const navigate = useNavigate();
  const paths = useSpacePaths();
  // Org pages exist only inside an organisation's space; the server's pages anywhere (for instance admins).
  const orgAdmin = isAdmin && !!org;
  const groups = adminNav({ isAdmin: orgAdmin, isInstanceAdmin, peopleBadge: pendingReady + recoveryPending, migrateBadge: pendingReady, orgPrefix: org ? spacePrefix(org) : null });
  const allowed = (s: AdminSection) => (isServerSection(s) ? isInstanceAdmin : orgAdmin);
  const first = groups[0]?.items[0];
  if (!first || (section && !allowed(section))) {
    if (loading) return <section className="flex-1" aria-busy="true" aria-label="Admin" />;
    return <NoAccess />;
  }
  if (section === null && !mobile) return <Navigate to={first.to} replace />;
  const back = section === "people" && detailId ? { to: paths.admin("people"), label: "People" } : section === "groups" && detailId ? { to: paths.admin("groups"), label: "Groups" } : undefined;
  const page = section === "risk" ? <PlanGate feature="risk"><RiskPage /></PlanGate>
    : section === "people" ? (detailId ? <MemberPage key={detailId} userId={detailId} folders={folders} /> : <PeoplePage pendingReady={pendingReady} onOpenMigrate={() => navigate(paths.admin("migrate"))} />)
    : section === "groups" ? (detailId ? <GroupPage key={detailId} groupId={detailId} folders={folders} /> : <SectionPage title="Groups"><GroupsSection /></SectionPage>)
    : section === "events" ? <EventLogPage />
    : section === "health" ? <SectionPage title="Password health" wide><TeamHealth /></SectionPage>
    : section === "migrate" ? <MigratePage folders={folders} records={records} vaultLoading={vaultLoading} />
    : section === "org/general" ? <SectionPage title="General" sub={org?.name}><OrgDetailsSection /></SectionPage>
    : section === "org/policies" ? <SectionPage title="Policies" sub={org?.name}><PlanGate feature="policyEdit"><OrgPoliciesSection /></PlanGate></SectionPage>
    : section === "org/sso" ? <SectionPage title="Single sign-on" sub={org?.name}>{demo ? <DemoUnavailable what="Single sign-on" /> : <SsoSettingsSection />}</SectionPage>
    : section === "org/recovery" ? <SectionPage title="Admin recovery" sub={org?.name}><PlanGate feature="adminRecovery"><AdminRecoverySection /></PlanGate></SectionPage>
    : section === "org/email" ? <SectionPage title="Email" sub={org?.name}>{demo ? <DemoUnavailable what="Email" /> : <EmailSettingsSection scope="org" />}</SectionPage>
    : section === "server/organisations" ? <SectionPage title="Customer organisations" sub="This server" wide><CustomerOrgsSection /></SectionPage>
    : section === "server/accounts" ? <SectionPage title="Accounts" sub="This server"><ResetAuthenticatorCard /></SectionPage>
    : section === "server/branding" ? <SectionPage title="Branding" sub="This server"><BrandingSection /></SectionPage>
    : section === "server/email" ? <SectionPage title="Email" sub="This server"><EmailSettingsSection scope="instance" /></SectionPage>
    : section === "org/storage" ? <SectionPage title="Storage" sub={org?.name} wide><OrgStorageSection records={records} folders={folders} /></SectionPage>
    : section === "server/storage" ? <SectionPage title="Storage" sub="This server" wide><ServerStorageSection /></SectionPage>
    : section === "server/backups" ? <BackupsPage /> : null;
  // The sub-navigation marks the list for its detail pages (a member is under People).
  return <SectionLayout title="Admin" base={org && orgAdmin ? paths.admin() : "/server"} groups={groups} active={section} mobile={mobile} back={back}>{orgAdmin && section && !isServerSection(section) && <TrialLine />}{page}</SectionLayout>;
}
