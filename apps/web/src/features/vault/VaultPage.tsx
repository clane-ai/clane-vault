import { useEffect, useMemo, useRef, useState } from "react";
import { Navigate, useLocation, useNavigate } from "react-router";
import { ApiError } from "@/lib/api";
import { ArrowDownUp, EllipsisVertical, FolderTree, List, ListFilter, Lock, LockKeyhole, Menu, Plus, Search, ShieldCheck, Trash2, Users } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Sheet, SheetContent, SheetTitle } from "@/components/ui/sheet";
import { Logo } from "@/components/brand/Logo";
import { MOBILE, useMediaQuery } from "@/lib/useMediaQuery";
import { Select, SelectContent, SelectGroup, SelectItem, SelectLabel, SelectSeparator, SelectTrigger, SelectValue } from "@/components/ui/select";
import { RECORD_TYPE_GROUPS, type RecordType } from "@clane-vault/crypto";
import { TYPE_ICON } from "./recordKinds";
import { useSession } from "@/lib/session";
import { cn } from "@/lib/utils";
import { LinksView } from "@/features/links/LinksView";
import { attentionReasons } from "./attention";
import { FolderDialog } from "./FolderDialog";
import { FolderOptionsMenu } from "./FolderOptionsMenu";
import type { NewKind } from "./NewMenu";
import type { VaultFolder, VaultRecord } from "./types";
import { filterRecords, groupByFolder, isSharedWithMe } from "./filter";
import { EmptyState, RecordList } from "./RecordList";
import { RecordPanel } from "./RecordPanel";
import { Sidebar, isCollapseShortcut, useSidebarCollapsed, type SidebarView } from "./Sidebar";
import { FolderPeopleSheet } from "./FolderPeopleSheet";
import { RecordActivity, WhoCanOpen } from "./RecordSharing";
import { ShareSheet } from "./ShareSheet";
import { HealthView } from "@/features/health/HealthPage";
import { useHealthReport } from "@/features/health/useHealthReport";
import { GroupAccessBanner } from "@/features/groups/GroupAccessBanner";
import { usePendingMembers } from "@/features/migrate/useMigration";
import { BackupBanner } from "@/features/admin/BackupBanner";
import { StorageBanner } from "@/features/admin/StoragePages";
import { SettingsArea } from "@/features/settings/SettingsPage";
import { AdminArea } from "@/features/admin/AdminArea";
import { parseAppPath, spacePrefix } from "@/lib/paths";
import { useSpacePaths } from "@/lib/space";
import { useRecoveryRequests } from "@/features/admin/RecoveryRequests";
import { KitBanner } from "@/features/recovery/KitBanner";
import { DemoBanner } from "@/features/demo/Demo";
import { AdminRecoveryNotice } from "@/features/recovery/AdminRecoveryNotice";
import { useMembershipSync, useSecurity } from "@/features/recovery/recovery";
import { ResetBanner } from "@/features/recovery/ResetBanner";
import { StatusBar } from "./StatusBar";
import { OfflineBanner, OfflineOnlyPanel } from "./OfflineBanner";
import { useVault } from "./useVault";
import { usePasswordScores } from "./usePasswordScores";
import { OrgSwitcher } from "@/features/orgs/OrgSwitcher";
import { useOrgLogoUrl } from "@/features/orgs/OrgLogo";
import { useOrgsInfo } from "@/features/orgs/orgs";
import { SsoRequiredPanel } from "@/features/auth/SsoRequired";
import { TotpStepUpPanel } from "@/features/auth/TotpStepUp";
import { FilesSection } from "@/features/attachments/AttachmentList";
import { useFileDrop } from "@/features/attachments/AttachmentDropZone";
import { useRecordDrop } from "@/features/attachments/useAttachments";

/** The phone top bar's brand: the active org's logo when it has one, else the product logo. */
function TopBarBrand({ org }: { org: { id: string; name: string; logoVersion?: string | null } | null }) {
  const url = useOrgLogoUrl(org?.id, org?.logoVersion);
  return url && org ? <img src={url} alt={org.name} className="h-8 max-w-[180px] object-contain object-left" /> : <Logo size="sm" onDark animated={false} />;
}

export default function VaultPage({ newButton, onEdit, onCreate, onNew, folderId: folderProp, onFolderChange }: {
  /** + New: the sidebar's (a round + in the icon rail: `compact`) and the phone top bar's. */
  newButton?: React.ReactNode | ((compact: boolean) => React.ReactNode); onEdit?: (id: string, opts?: { newPassword?: boolean }) => void; onCreate?: () => void;
  /** The folder Options' New Record / New Folder / New Shared Folder (with the folder they act on); no Options without it. */
  onNew?: (k: NewKind, folderId: string | null) => void;
  /** Controlled open folder (+ New → Record starts there); uncontrolled when absent. */ folderId?: string | null; onFolderChange?: (id: string | null) => void;
}) {
  const { user, lock, signOut, org, orgs, ssoBlocked, stepUpRequired, requestStepUp, offline } = useSession();
  // The space (Personal or an org) is in the URL; SpaceGate has already made it the session's (lib/paths, routes.tsx).
  const paths = useSpacePaths();
  const blocked = !!org && ssoBlocked === org.id;
  const v = useVault();
  // Every page and section has its own URL (lib/paths): the view, the open folder and the selected record come from it.
  const location = useLocation();
  const navigate = useNavigate();
  const loc = parseAppPath(location.pathname, paths.ctx);
  const listLoc = loc.area === "list" ? loc : null;
  const view: SidebarView = listLoc ? listLoc.view : loc.area === "settings" ? "settings" : loc.area === "admin" ? "admin" : null;
  // Offline (read-only copy): no admin pages.
  const isAdmin = user?.role === "admin" && !offline;
  const orgsInfo = useOrgsInfo();
  const isInstanceAdmin = !!orgsInfo.data?.instanceAdmin && !offline;
  // Admin from the account menu: this org's admin pages; from Personal, those of an org they administer; else the server's.
  const adminOrg = !org && !offline ? orgs.find((o) => o.role !== "member") ?? null : null;
  const adminHref = isAdmin ? paths.admin() : adminOrg ? `${spacePrefix(adminOrg)}/admin` : isInstanceAdmin ? "/server" : null;
  const pendingReady = usePendingMembers(isAdmin).ready.length;
  const recoveryPending = (useRecoveryRequests(isAdmin).data ?? []).filter((r) => r.status === "pending").length;
  const noKit = useSecurity().data?.recoveryKit === null;
  // Membership keys for the active org: created, rows moved, rotated, escrowed (per-org key pairs design).
  useMembershipSync(v.folders, !v.isLoading && !v.error);
  // Password health counts go to the org's admins as the vault changes (docs/password-health.md); the page shows the same report.
  // zxcvbn scores, worked out in a worker and kept: attention and health never score on the render path.
  const scores = usePasswordScores(v.records);
  const health = useHealthReport(v.records, v.isLoading, v.folders, scores);
  const [sharing, setSharing] = useState(false);
  const [managingId, setManagingId] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [sort, setSort] = useState<"name" | "recent">("name");
  // The list header's type filter (null: every type).
  const [typeFilter, setTypeFilter] = useState<RecordType | null>(null);
  const [mode, setMode] = useState<"folders" | "flat">("folders");
  const selectedId = listLoc?.recordId ?? null;
  const listView = listLoc?.view ?? "vault";
  // The open folder (Keeper's selected folder): the last folder row opened (/vault/folder/:id), or the selected record's folder.
  const [ownFolder, setOwnFolder] = useState<string | null>(listLoc?.folderId ?? null);
  const currentFolderId = folderProp !== undefined ? folderProp : ownFolder;
  const setCurrentFolder = (id: string | null) => { setOwnFolder(id); onFolderChange?.(id); };
  const openFolder = (id: string | null) => {
    setCurrentFolder(id);
    if (listView === "vault" && !selectedId && listLoc) navigate(paths.folder(id), { replace: true });
  };
  const urlFolder = listLoc?.folderId ?? null;
  useEffect(() => { if (urlFolder) setCurrentFolder(urlFolder); }, [urlFolder]); // eslint-disable-line react-hooks/exhaustive-deps
  // Opening a record pushes a history entry (Back closes it again); moving between records replaces it. Closing
  // replaces it with the list (never history.go(-1): that lands late and would undo a navigation made right after).
  const select = (id: string | null) => {
    if (!id) return closeRecord();
    const r = v.records.find((x) => x.id === id);
    if (r) setCurrentFolder(r.folderId);
    navigate(paths.record(listView, id), { replace: !!selectedId });
  };
  function closeRecord() {
    if (!selectedId) return;
    navigate(listView === "vault" && currentFolderId ? paths.folder(currentFolderId) : paths.list(listView), { replace: true });
  }
  const [renaming, setRenaming] = useState<VaultFolder | null>(null);
  const [deleting, setDeleting] = useState<VaultFolder | null>(null);
  const searchRef = useRef<HTMLInputElement>(null);
  // Phones: a top bar (menu, lock, + New) and the sidebar in a drawer.
  const mobile = useMediaQuery(MOBILE);
  const [navOpen, setNavOpen] = useState(false);
  // Navigating closes the phone drawer.
  const [navPath, setNavPath] = useState(location.pathname);
  if (navPath !== location.pathname) { setNavPath(location.pathname); setNavOpen(false); }
  // Desktop: the sidebar collapses to an icon rail (button or Ctrl/Cmd+B), remembered on this device.
  const [collapsed, toggleCollapsed] = useSidebarCollapsed();
  useEffect(() => {
    if (mobile) return;
    const onKey = (e: KeyboardEvent) => { if (isCollapseShortcut(e)) { e.preventDefault(); toggleCollapsed(); } };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [mobile, toggleCollapsed]);
  const busy = useRef(false);
  // The page now (for actions that finish later: only close the record if nobody navigated away meanwhile).
  const pathNow = useRef(location.pathname);
  pathNow.current = location.pathname;
  async function act(done: string, what: string, fn: () => Promise<unknown>, keepSelection = false) {
    if (busy.current) return;
    busy.current = true;
    const at = location.pathname;
    try { await fn(); if (!keepSelection && pathNow.current === at) closeRecord(); toast.success(done); }
    catch (e) {
      toast.error(e instanceof ApiError && e.code === "folder_has_others_records"
        ? "This folder has records other people own. Move them, or ask their owners to remove them first."
        : `Couldn't ${what}. Try again.`);
    }
    finally { busy.current = false; }
  }

  const escape = useRef(closeRecord);
  escape.current = closeRecord;
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "/" && document.activeElement?.tagName !== "INPUT" && document.activeElement?.tagName !== "TEXTAREA") { e.preventDefault(); searchRef.current?.focus(); }
      if (e.key === "Escape") escape.current();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  // Over every record I can open, shared ones included: a password reused across my records and shared ones counts.
  const reasons = useMemo(() => attentionReasons(v.records, Date.now(), scores.isWeak), [v.records, scores.isWeak]);
  const visible = useMemo(() => {
    const list = filterRecords(v.records, { view: listView, query, sort, type: typeFilter });
    return listView === "attention" ? list.filter((r) => reasons.has(r.id)) : list;
  }, [v.records, listView, query, sort, reasons, typeFilter]);
  // The filter offers the types this vault holds (and the one chosen, even if its last record went).
  const presentTypes = useMemo(() => new Set(v.records.flatMap((r) => (r.body ? [r.body.type] : []))), [v.records]);
  const groups = useMemo(() => groupByFolder(visible, v.folders), [visible, v.folders]);
  const selected = v.records.find((r) => r.id === selectedId) ?? null;
  // A record URL for something that isn't (or is no longer) in this vault: back to the list.
  const missing = !!selectedId && !v.isLoading && !v.error && !selected;
  useEffect(() => { if (missing) navigate(paths.list(listView), { replace: true }); }, [missing]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { if (selected) setCurrentFolder(selected.folderId); }, [selected?.id]); // eslint-disable-line react-hooks/exhaustive-deps
  const folderOf = (id: string | null) => v.folders.find((f) => f.id === id) ?? null;
  // Files dropped anywhere on the open record's panel attach to it (docs/attachments.md).
  const recordDrop = useRecordDrop(selected);
  const drop = useFileDrop({ canDrop: recordDrop.canDrop, title: selected?.body?.title, onFiles: recordDrop.onFiles, disabled: !selected || !recordDrop.enabled || offline || !selected.body });
  const folderName = (id: string | null) => folderOf(id)?.name ?? null;
  const managing = v.folders.find((f) => f.id === managingId) ?? null;
  const currentFolder = v.folders.find((f) => f.id === currentFolderId && !f.deleted) ?? null;
  // Move To moves the selected record (folders don't nest, so they can't be moved); re-wrapping its key as the editor does.
  const moveTo = (r: VaultRecord, folderId: string | null) => {
    void act(`Moved to ${folderName(folderId) ?? "No folder"}`, "move it", async () => { await v.moveRecord(r, folderId); setCurrentFolder(folderId); }, true);
  };
  const options = !offline && onNew ? (folder: VaultFolder | null, trigger: React.ReactNode, open?: boolean, onOpenChange?: (o: boolean) => void) => (
    <FolderOptionsMenu folder={folder} record={selected} folders={v.folders} team={!!org} trigger={trigger} open={open} onOpenChange={onOpenChange}
      onNew={onNew} onMove={moveTo} onDelete={setDeleting} onRename={setRenaming} onManage={(f) => setManagingId(f.id)} />
  ) : null;
  const showFlat = mode === "flat" || query !== "" || listView !== "vault" || typeFilter !== null;
  useEffect(() => { setSharing(false); }, [selectedId]);
  const spaceName = org ? org.name : "Personal";
  const HEAD: Record<typeof listView, [string, string]> = {
    vault: [org ? "Vault" : "Personal vault", org ? `${org.name}: its shared folders and records shared with you here.` : "Your private records. Nobody else sees them."],
    shared: ["Shared with me", `Records people shared with you directly in ${spaceName}.`],
    attention: ["Needs attention", "Weak, reused or old passwords. Change them on the website, then here."],
    links: ["Share links", "One-time links you created. Revoke any you no longer need."], trash: ["Trash", "Restore records you deleted by mistake."],
  };

  const plusButton = (compact: boolean) => (typeof newButton === "function" ? newButton(compact) : newButton)
    ?? <Button disabled aria-label="New" className={cn("w-full bg-orange-500 text-navy-900", compact && "size-10 rounded-full p-0")}><Plus className="size-4" />{!compact && "New"}</Button>;
  const rail = collapsed && !mobile;
  const sidebar = (drawer: boolean) => (
    <Sidebar drawer={drawer} view={view} user={{ name: user?.name ?? "", email: user?.email ?? "" }} adminHref={adminHref} paths={paths}
      org={org} collapsed={rail} onToggleCollapsed={toggleCollapsed}
      orgSwitcher={<OrgSwitcher compact={rail && !drawer} onSettings={() => navigate(isAdmin ? paths.admin("org/general") : "/settings/account")} />}
      badges={{ admin: isAdmin ? pendingReady + recoveryPending : 0, settings: noKit ? 1 : 0 }} onLock={lock} onSignOut={signOut}
      counts={{ vault: v.records.filter((r) => !r.deleted).length, shared: v.records.filter((r) => !r.deleted && isSharedWithMe(r)).length, attention: reasons.size, links: null,
        trash: v.records.filter((r) => r.deleted && r.permission === "owner").length }}
      newButton={plusButton(rail && !drawer)} />
  );
  const healthPage = <HealthView health={health} records={v.records} loading={v.isLoading} onOpen={(id) => navigate(paths.record("vault", id))} />;
  // Settings and Admin keep working while the session waits for a 2FA step-up or SSO; offline they're unavailable.
  const area = loc.area;
  const pageless = area === "settings" || area === "admin";

  return (
    // The shell is exactly the viewport's height and never scrolls: the sidebar stays put and each page scrolls inside
    // its own area. `relative` + `overflow-hidden` also keep absolutely positioned helpers (Radix's hidden native
    // inputs) from growing the document.
    <div className={cn("relative flex h-dvh overflow-hidden", mobile && "flex-col")} data-testid="app-shell">
      {mobile ? (<>
        <div className="flex h-14 shrink-0 items-center gap-1.5 bg-sidebar px-2">
          <button type="button" aria-label="Open menu" aria-expanded={navOpen} onClick={() => setNavOpen(true)} className="grid size-10 place-items-center rounded-[9px] text-[var(--text-on-dark)] hover:bg-white/[.06]"><Menu className="size-5" /></button>
          <span className="min-w-0 flex-1 pl-1"><TopBarBrand org={org} /></span>
          <button type="button" aria-label="Lock" onClick={lock} className="grid size-10 place-items-center rounded-[9px] text-[var(--text-dark-tertiary)] hover:bg-white/[.06] hover:text-[var(--text-on-dark)]"><Lock className="size-[18px]" /></button>
          {(typeof newButton === "function" ? newButton(false) : newButton) ?? <Button disabled aria-label="New" className="size-10 rounded-full bg-orange-500 p-0 text-navy-900"><Plus className="size-4" /></Button>}
        </div>
        <Sheet open={navOpen} onOpenChange={setNavOpen}>
          <SheetContent side="left" showCloseButton={false} aria-describedby={undefined} className="w-[288px] border-0 bg-sidebar p-0 data-[side=left]:w-[288px]">
            <SheetTitle className="sr-only">Menu</SheetTitle>
            {sidebar(true)}
          </SheetContent>
        </Sheet>
      </>) : sidebar(false)}
      <main className="relative flex min-h-0 min-w-0 flex-1 flex-col">
        {user?.demoExpiresAt && <DemoBanner expiresAt={user.demoExpiresAt} />}
        {offline && <OfflineBanner savedAt={v.savedAt} />}
        {isInstanceAdmin && location.pathname !== "/server/backups" && <BackupBanner onOpen={() => navigate("/server/backups")} />}
        {isInstanceAdmin && location.pathname !== "/server/storage" && <StorageBanner onOpen={() => navigate("/server/storage")} />}
        {/* A demo sandbox has no recovery kit to make: its password is random and it's deleted on schedule. */}
        {area !== "settings" && !offline && !user?.demoExpiresAt && <KitBanner />}
        {!offline && <ResetBanner onOpen={() => navigate("/settings/security")} />}
        {!offline && <GroupAccessBanner folders={v.folders} />}
        <AdminRecoveryNotice />
        {loc.area === "redirect" ? <Navigate to={loc.to} replace />
          : offline && (pageless || listView === "links") ? <OfflineOnlyPanel what={area === "settings" ? "Settings" : area === "admin" ? "Admin" : "Share links"} />
          : stepUpRequired && !pageless ? <TotpStepUpPanel /> : blocked && !pageless ? <SsoRequiredPanel org={org} />
          : loc.area === "settings" ? <SettingsArea section={loc.section} mobile={mobile} health={healthPage} />
          : loc.area === "admin" ? <AdminArea section={loc.section} detailId={loc.detailId} mobile={mobile} isAdmin={isAdmin} isInstanceAdmin={isInstanceAdmin} loading={orgsInfo.isPending && !offline}
              folders={v.folders} records={v.records} vaultLoading={v.isLoading} pendingReady={pendingReady} recoveryPending={recoveryPending} />
          : <div className={cn("grid min-h-0 flex-1", selected ? "min-[1100px]:grid-cols-[minmax(0,1fr)_440px]" : "grid-cols-1")}>
          <section className={cn("flex min-h-0 min-w-0 flex-col", selected && "max-[1099px]:hidden")}>
            <header className="flex h-[60px] shrink-0 items-center gap-3 border-b border-border-default bg-[var(--surface-overlay)] px-6 backdrop-blur-[8px] max-[760px]:px-3">
              <div className="relative w-full max-w-[520px]">
                <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-text-tertiary" />
                <Input ref={searchRef} type="search" aria-label="Search records" placeholder={`Search ${v.records.filter((r) => !r.deleted).length} records`} className="pr-10 pl-9" value={query} onChange={(e) => setQuery(e.target.value)} />
                <kbd aria-hidden="true" className="pointer-events-none absolute right-2.5 top-1/2 -translate-y-1/2 rounded-[5px] border border-border-default bg-app px-1.5 font-mono text-[11px] text-text-tertiary max-[760px]:hidden">/</kbd>
              </div>
            </header>
            <div className="flex items-center gap-4 px-6 pt-4 pb-3 max-[760px]:flex-col max-[760px]:items-stretch max-[760px]:gap-3 max-[760px]:px-3 max-[760px]:pt-4 max-[760px]:pb-3">
              <div className="min-w-0 flex-1">
                <h1 className="truncate text-[20px] leading-tight text-text-primary">{query && listView !== "links" ? `Results for "${query}"` : HEAD[listView][0]}</h1>
                <p className="mt-0.5 text-[12.5px] text-text-secondary">{HEAD[listView][1]}</p>
              </div>
              {listView !== "links" && (
                <div className="flex shrink-0 items-center gap-2 max-[760px]:w-full">
                  <Select value={typeFilter ?? "all"} onValueChange={(x) => setTypeFilter(x === "all" ? null : x as RecordType)}>
                    <SelectTrigger aria-label="Record type" className={cn("h-8 min-w-[148px] max-[760px]:min-w-0 max-[760px]:flex-1 data-[size=default]:h-8 data-[size=default]:rounded-[9px] text-[13px]", typeFilter && "border-blue-500/50 bg-blue-tint")}>
                      <span className="flex items-center gap-2"><ListFilter className="size-3.5 text-text-tertiary" /><SelectValue /></span>
                    </SelectTrigger>
                    <SelectContent align="end" className="max-h-[min(420px,var(--radix-select-content-available-height))]">
                      <SelectItem value="all">All types</SelectItem>
                      {RECORD_TYPE_GROUPS.map((g) => {
                        const types = g.types.filter((t) => presentTypes.has(t.id) || t.id === typeFilter);
                        return types.length > 0 && (
                          <SelectGroup key={g.group}>
                            <SelectSeparator />
                            <SelectLabel className="px-2 pt-1.5 pb-1 text-[11.5px] font-medium text-text-secondary">{g.label}</SelectLabel>
                            {types.map((t) => { const Icon = TYPE_ICON[t.id]; return <SelectItem key={t.id} value={t.id}><Icon className="text-text-tertiary" />{t.label}</SelectItem>; })}
                          </SelectGroup>
                        );
                      })}
                    </SelectContent>
                  </Select>
                  {listView === "vault" && !query && <>
                  <Select value={sort} onValueChange={(x) => setSort(x as "name" | "recent")}>
                    <SelectTrigger aria-label="Sort" className="h-8 min-w-[168px] max-[760px]:min-w-0 max-[760px]:flex-1 data-[size=default]:h-8 data-[size=default]:rounded-[9px] text-[13px]">
                      <span className="flex items-center gap-2"><ArrowDownUp className="size-3.5 text-text-tertiary" /><SelectValue /></span>
                    </SelectTrigger>
                    <SelectContent align="end">
                      <SelectItem value="name">Name</SelectItem>
                      <SelectItem value="recent">Recently changed</SelectItem>
                    </SelectContent>
                  </Select>
                  <div className="inline-flex h-8 shrink-0 items-center gap-0.5 rounded-[9px] border border-border-default bg-well p-[3px]" role="group" aria-label="View">
                    {([["folders", "Folders", FolderTree], ["flat", "List", List]] as const).map(([m, label, Icon]) => (
                      <button key={m} type="button" aria-pressed={mode === m} title={label} aria-label={label} onClick={() => setMode(m)}
                        className={cn("grid h-full w-7 place-items-center rounded-[6px] transition-colors duration-150",
                          mode === m ? "bg-card text-text-primary shadow-[var(--shadow-card)] ring-1 ring-border-default" : "text-text-tertiary hover:text-text-primary")}>
                        <Icon className="size-4" />
                      </button>
                    ))}
                  </div>
                  {options?.(currentFolder,
                    <button type="button" aria-label="Options" title="Options" className="grid size-8 shrink-0 place-items-center rounded-[9px] border border-border-default bg-card text-text-secondary shadow-[var(--shadow-card)] transition-colors duration-150 hover:text-text-primary aria-expanded:bg-well aria-expanded:text-text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500/40">
                      <EllipsisVertical className="size-4" />
                    </button>)}
                  </>}
                </div>
              )}
            </div>
            <div className="relative min-h-0 flex-1 overflow-y-auto px-6 pb-6 max-[760px]:px-3 max-[760px]:pb-4">
              {v.error && (
                <div role="alert" className="mb-3 flex items-center gap-3 rounded-[12px] border border-[var(--red-tint-border)] bg-red-tint px-4 py-3">
                  <p className="flex-1 text-[14px]">{offline ? "There's no offline copy of this vault on this device." : "Couldn't load your vault."}</p>
                  <Button type="button" variant="outline" onClick={() => void v.retry()}>Retry</Button>
                </div>
              )}
              {v.privateLocked && !offline && (listView === "vault" || listView === "trash") && (
                <button type="button" onClick={requestStepUp} data-testid="private-locked"
                  className="mb-3 flex w-full items-center gap-3 rounded-[12px] border border-dashed border-border-default bg-well px-4 py-3 text-left hover:border-border-strong">
                  <LockKeyhole aria-hidden="true" className="size-4 shrink-0 text-text-tertiary" />
                  <span className="min-w-0 flex-1 text-[13.5px] text-text-primary">Private items — verify with your authenticator to show</span>
                  <span className="text-[13px] font-medium text-blue-ink">Verify</span>
                </button>
              )}
              {listView === "links" ? <LinksView records={v.records} /> : v.isLoading ? <p className="py-16 text-center text-[14px] text-text-secondary">Decrypting your vault…</p>
                : v.error && v.records.length === 0 && v.folders.length === 0 ? null
                : <RecordList groups={groups} flat={visible} mode={showFlat ? "flat" : "folders"} selectedId={selectedId} onSelect={select}
                    currentFolderId={currentFolder?.id ?? null} onOpenFolder={openFolder} folderMenu={options ?? undefined}
                    onCreate={listView === "vault" && !query && !offline ? onCreate : undefined} reasons={reasons} view={listView} folderOf={folderOf} noFolderLabel={org ? "Shared directly" : "No folder"}
                    onNewRecord={onNew && !offline ? (id) => onNew("record", id) : undefined}
                    empty={listView === "trash" && !query ? <EmptyState icon={Trash2} title="Trash is empty" line="Records you move to the trash stay here until you delete them forever." />
                      : listView === "shared" && !query ? <EmptyState icon={Users} title="Nothing shared with you yet" line="When someone shares a record with you, it shows up here." />
                      : listView === "attention" && !query ? <EmptyState icon={ShieldCheck} title="Nothing needs attention" line="No weak, reused or old passwords. Nice work." /> : undefined} />}
            </div>
          </section>
          {selected && (
            <div className="relative min-h-0 border-l border-border-default max-[1099px]:border-l-0" {...drop.handlers}>
              {drop.overlay}
              <RecordPanel record={selected} files={selected.body ? <FilesSection record={selected} /> : undefined} folderName={folderName(selected.folderId)} teamFolder={folderOf(selected.folderId)?.kind === "team"} onClose={closeRecord} scoreOf={scores.scoreOf}
                onShare={() => setSharing(true)}
                onEdit={() => onEdit?.(selected.id)} reasons={reasons.get(selected.id)} onNewPassword={onEdit && !offline ? () => onEdit(selected.id, { newPassword: true }) : undefined}
                onTrash={() => act("Moved to trash", "move it to the trash", () => v.trashRecord(selected.id))}
                onRestore={() => act("Restored", "restore it", () => v.restoreRecord(selected.id))}
                onPurge={() => act("Deleted forever", "delete it", () => v.purgeRecord(selected.id))}>
                {!selected.deleted && !offline && <><WhoCanOpen record={selected} folder={folderOf(selected.folderId)} /><RecordActivity record={selected} /></>}
              </RecordPanel>
              {selected.permission === "owner" && (
                <ShareSheet record={selected} teamFolder={folderOf(selected.folderId)?.kind === "team" ? folderOf(selected.folderId) : null} open={sharing} onClose={() => setSharing(false)}
                  onShare={(p, perm) => v.shareRecord(selected, p, perm)} onShareIn={(o, p, perm) => v.shareRecordIn(selected, o, p, perm)} onUpdate={(uid, perm) => v.updateShare(selected.id, uid, perm)} onRemove={(uid) => v.unshare(selected.id, uid)} />
              )}
            </div>
          )}
        </div>}
        <StatusBar syncedAt={v.isLoading ? null : offline ? (v.savedAt ? new Date(v.savedAt) : null) : new Date()} offline={offline} />
      </main>
      <FolderPeopleSheet folder={managing} onClose={() => setManagingId(null)} onAdd={(f, p, perm) => v.addMember(f, p, perm)} onGiveAccess={(f, m) => v.giveAccessAgain(f, m)}
        onUpdate={(fid, uid, perm) => v.updateMember(fid, uid, perm)} onRemove={(fid, uid) => v.removeMember(fid, uid)} />
      {renaming && (
        <FolderDialog key={renaming.id} open mode="rename" initialName={renaming.name} onCancel={() => setRenaming(null)}
          onSave={async (name) => { await v.renameFolder(renaming.id, name); setRenaming(null); toast.success("Folder renamed"); }} />
      )}
      <Dialog open={!!deleting} onOpenChange={(o) => !o && setDeleting(null)}>
        <DialogContent>
          <DialogHeader><DialogTitle>Delete folder {deleting?.name}? Its records move to Trash.</DialogTitle></DialogHeader>
          <div className="flex justify-end gap-2">
            <Button type="button" variant="ghost" onClick={() => setDeleting(null)}>Cancel</Button>
            <Button type="button" onClick={() => { const f = deleting; setDeleting(null); if (f) void act("Folder deleted", "delete the folder", () => v.deleteFolder(f.id)); }}>Delete</Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
