import { useCallback, useState } from "react";
import { Link, useNavigate } from "react-router";
import { AlertTriangle, ChevronsLeft, ChevronsRight, ChevronsUpDown, Download, HeartPulse, Link2, Lock, LockKeyhole, LogOut, Puzzle, Settings, ShieldCheck, Trash2, Users, type LucideIcon } from "lucide-react";
import { Logo } from "@/components/brand/Logo";
import { VendorCredit } from "@/components/brand/VendorCredit";
import { DropdownMenu, DropdownMenuContent, DropdownMenuGroup, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { useOrgLogoUrl } from "@/features/orgs/OrgLogo";
import { useInstallPrompt } from "@/pwa/install";
import { cn } from "@/lib/utils";
import type { VaultView } from "./filter";

import { initials } from "./people";

/** What the sidebar marks as current: a vault list, Settings or Admin (both open from the account menu). */
export type SidebarView = VaultView | "settings" | "admin" | null;
/** Amber markers: Settings (no recovery kit yet) and Admin (people waiting: recovery requests, migration members). */
export interface SidebarBadges { settings?: number; admin?: number }

const COLLAPSED_KEY = "cv.sidebar.collapsed";
/** The sidebar's full / icon-rail choice, remembered on this device. */
export function useSidebarCollapsed(): [boolean, () => void] {
  const [collapsed, setCollapsed] = useState(() => { try { return localStorage.getItem(COLLAPSED_KEY) === "1"; } catch { return false; } });
  const toggle = useCallback(() => setCollapsed((c) => {
    try { localStorage.setItem(COLLAPSED_KEY, c ? "0" : "1"); } catch { /* private mode: not remembered */ }
    return !c;
  }), []);
  return [collapsed, toggle];
}
/** Ctrl+B (⌘B on a Mac) toggles the sidebar. */
export const isCollapseShortcut = (e: KeyboardEvent) => (e.ctrlKey || e.metaKey) && !e.altKey && !e.shiftKey && e.key.toLowerCase() === "b";
const SHORTCUT = typeof navigator !== "undefined" && /Mac|iPhone|iPad/.test(navigator.platform) ? "⌘B" : "Ctrl+B";

/** The signed-in person's initials in a circle (Clane style). */
export function UserAvatar({ name, size = 28, className }: { name: string; size?: number; className?: string }) {
  return (
    <span aria-hidden="true" style={{ width: size, height: size, fontSize: Math.round(size * 0.41) }}
      className={cn("grid shrink-0 place-items-center rounded-full bg-blue-500/20 font-display font-semibold text-[var(--text-on-dark)] ring-1 ring-[var(--border-dark-2)]", className)}>
      {initials(name) || "?"}
    </span>
  );
}

/** In the icon rail a control shows its name in a tooltip to the right. */
function RailTip({ on, label, children }: { on: boolean; label: React.ReactNode; children: React.ReactElement }) {
  if (!on) return children;
  return (
    <Tooltip>
      <TooltipTrigger asChild>{children}</TooltipTrigger>
      <TooltipContent side="right" sideOffset={10}>{label}</TooltipContent>
    </Tooltip>
  );
}

/**
 * Bottom of the sidebar: the signed-in person (avatar, name, email). It opens a menu upwards: Settings (everyone's own
 * sections), Password health, Admin (owners, admins and instance admins), installing the app and the extension, lock
 * and sign out. In the icon rail only the avatar shows.
 */
export function AccountMenu({ view, user, adminHref, badges, onLock, onSignOut, compact }: {
  view: SidebarView; user: { name: string; email: string };
  /** Where Admin goes (the active org's admin pages, an org they administer, or the server's); none: no Admin. */ adminHref?: string | null; badges?: SidebarBadges;
  onLock: () => void; onSignOut: () => void; compact?: boolean;
}) {
  const install = useInstallPrompt();
  const navigate = useNavigate();
  const attention = !!badges?.settings || !!badges?.admin;
  const item = (to: string, label: string, Icon: LucideIcon, active: boolean, marker?: React.ReactNode) => (
    <DropdownMenuItem onSelect={() => navigate(to)} aria-current={active ? "page" : undefined} className={cn(active && "bg-app font-medium")}>
      <Icon className={cn(active && "text-blue-500!")} /><span className="min-w-0 flex-1 truncate">{label}</span>{marker}
    </DropdownMenuItem>
  );
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button type="button" aria-label={`Account menu: ${user.name}${attention ? ", needs attention" : ""}`} title={`${user.name}\n${user.email}`} data-testid="account-menu"
          className={cn("group relative flex w-full items-center gap-2.5 rounded-[10px] py-2 text-left transition-colors duration-150 hover:bg-white/[.05] aria-expanded:bg-white/[.06]",
            compact ? "justify-center px-0" : "px-2")}>
          <span className="relative">
            <UserAvatar name={user.name} size={32} />
            {attention && <span aria-hidden="true" className="absolute -top-0.5 -right-0.5 size-2.5 rounded-full bg-amber-500 ring-2 ring-sidebar" />}
          </span>
          {!compact && (<>
            <span className="min-w-0 flex-1">
              <span className="block truncate text-[13.5px] font-medium text-[var(--text-on-dark)]">{user.name}</span>
              <span className="block truncate font-mono text-[11px] text-[var(--text-dark-tertiary)]">{user.email}</span>
            </span>
            <ChevronsUpDown aria-hidden="true" className="size-4 shrink-0 text-[var(--text-dark-tertiary)]" />
          </>)}
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent side={compact ? "right" : "top"} align={compact ? "end" : "start"} sideOffset={8} className={cn(compact ? "w-[260px]" : "w-(--radix-dropdown-menu-trigger-width) min-w-[240px]")}>
        <DropdownMenuLabel className="flex items-center gap-2.5 px-2.5 py-2 font-normal">
          <UserAvatar name={user.name} size={32} className="text-text-primary ring-border-default" />
          <span className="min-w-0">
            <span className="block truncate text-[13.5px] font-medium text-text-primary">{user.name}</span>
            <span className="block truncate font-mono text-[11px] text-text-tertiary">{user.email}</span>
          </span>
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuGroup>
          {item("/settings", "Settings", Settings, view === "settings", badges?.settings ? <span className="size-2 rounded-full bg-amber-500" aria-label="Needs attention" /> : undefined)}
          {item("/settings/health", "Password health", HeartPulse, false)}
          {adminHref && item(adminHref, "Admin", ShieldCheck, view === "admin",
            badges?.admin ? <span className="rounded-[6px] bg-amber-500/20 px-1.5 py-px font-mono text-[11px] text-orange-ink tabular-nums">{badges.admin}</span> : undefined)}
        </DropdownMenuGroup>
        <DropdownMenuSeparator />
        <DropdownMenuGroup>
          <DropdownMenuItem onSelect={() => (install ? void install() : navigate("/settings/device"))}><Download />Install app</DropdownMenuItem>
          {item("/settings/extension", "Browser extension", Puzzle, false)}
        </DropdownMenuGroup>
        <DropdownMenuSeparator />
        <DropdownMenuGroup>
          <DropdownMenuItem onSelect={onLock}><Lock />Lock</DropdownMenuItem>
          <DropdownMenuItem onSelect={onSignOut}><LogOut />Sign out</DropdownMenuItem>
        </DropdownMenuGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

/** Top of the sidebar: the active organisation's logo when it has one, else the product logo. */
function SidebarBrand({ org }: { org?: { id: string; name: string; logoVersion?: string | null } | null }) {
  const url = useOrgLogoUrl(org?.id, org?.logoVersion);
  if (url && org) return <img src={url} alt={org.name} data-testid="sidebar-org-logo" className="h-8 max-w-[176px] object-contain object-left" />;
  return <Logo size="sm" onDark animated={false} />;
}

export function Sidebar({ view, newButton, counts, badges, user, adminHref, paths, org, orgSwitcher, onLock, onSignOut, drawer, collapsed = false, onToggleCollapsed }: {
  view: SidebarView; newButton: React.ReactNode; counts: Record<VaultView, number | null>;
  /** Amber markers on Settings and Admin in the account menu. */ badges?: SidebarBadges;
  user: { name: string; email: string };
  /** Owners and admins (of the active org, or of some org from Personal), and instance admins: where Admin goes. */ adminHref?: string | null;
  /** The active space's lists and their URLs (lib/space): Personal has no "Shared with me". */ paths: { views: readonly VaultView[]; list: (v: VaultView) => string };
  /** The active organisation (its logo heads the sidebar). */ org?: { id: string; name: string; logoVersion?: string | null } | null;
  /** The organisation switcher, under the logo. */ orgSwitcher?: React.ReactNode;
  onLock: () => void; onSignOut: () => void;
  /** Rendered inside the phone drawer (full labels; + New lives in the top bar; never collapsed). */ drawer?: boolean;
  /** The icon rail: icons with tooltips, the org's logo or initials, a round +, the avatar. */ collapsed?: boolean; onToggleCollapsed?: () => void;
}) {
  const rail = collapsed && !drawer;
  const item = (id: VaultView, label: string, Icon: LucideIcon, tone?: "amber") => {
    const count = counts[id];
    const active = view === id;
    return (
      <RailTip key={id} on={rail} label={count != null ? `${label} · ${count}` : label}>
        <Link to={paths.list(id)} aria-current={active ? "page" : undefined} aria-label={rail ? label : undefined}
          className={cn("relative flex h-9 w-full items-center gap-3 rounded-[9px] text-left text-[13.5px] text-sidebar-foreground transition-colors duration-150 hover:bg-white/[.04] hover:text-[var(--text-on-dark)]",
            rail ? "justify-center px-0" : "px-3",
            active && "bg-white/[.06] font-medium text-[var(--text-on-dark)] before:absolute before:inset-y-2 before:left-0 before:w-[3px] before:rounded-r-full before:bg-blue-500")}>
          <Icon className={cn("size-4 shrink-0", active ? "text-blue-500" : "text-[var(--text-dark-tertiary)]")} />
          {!rail && <span>{label}</span>}
          {/* Zero is plain text; a pill only when there is something to count. */}
          {!rail && count != null && <span className={cn("ml-auto font-mono text-[11px] tabular-nums", count === 0 ? "px-1.5 text-[var(--text-dark-dim)]" : "rounded-[6px] px-1.5 py-px",
            count === 0 ? null : tone === "amber" ? "bg-amber-500/20 text-amber-500" : active ? "bg-white/[.08] text-[var(--text-dark-mono)]" : "bg-white/[.04] text-[var(--text-dark-tertiary)]")}>{count}</span>}
          {rail && tone === "amber" && !!count && <span aria-hidden="true" className="absolute top-1.5 right-2.5 size-2 rounded-full bg-amber-500" />}
        </Link>
      </RailTip>
    );
  };
  const toggle = onToggleCollapsed && !drawer && (
    <RailTip on label={<span className="flex items-center gap-2">{rail ? "Expand sidebar" : "Collapse sidebar"}<kbd className="font-mono text-[10.5px] opacity-70">{SHORTCUT}</kbd></span>}>
      <button type="button" onClick={onToggleCollapsed} aria-label={rail ? "Expand sidebar" : "Collapse sidebar"} aria-expanded={!rail} aria-keyshortcuts="Control+B Meta+B" data-testid="sidebar-toggle"
        className="absolute top-[26px] -right-3 z-30 grid size-6 place-items-center rounded-full border border-[var(--border-dark-2)] bg-sidebar text-[var(--text-dark-tertiary)] shadow-[var(--shadow-card)] transition-colors duration-150 hover:text-[var(--text-on-dark)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500/50">
        {rail ? <ChevronsRight className="size-3.5" /> : <ChevronsLeft className="size-3.5" />}
      </button>
    </RailTip>
  );
  return (
    <TooltipProvider delayDuration={0}>
      <nav className={cn("relative flex h-full shrink-0 flex-col bg-sidebar transition-[width] duration-150 ease-out motion-reduce:transition-none", rail ? "w-16" : "w-[248px]")}
        aria-label="Sections" data-drawer={drawer ? "" : undefined} data-collapsed={rail ? "" : undefined}>
        {/* On the sidebar's edge, so it never crowds the logo; Ctrl/Cmd+B does the same. */}
        {toggle}
        {/* The sections scroll on their own; the account stays at the bottom. */}
        <div className={cn("flex min-h-0 flex-1 flex-col overflow-x-hidden overflow-y-auto pt-4 pb-3", rail ? "items-center px-2" : "px-3")}>
          {!rail && <div className="flex h-9 items-center px-1.5"><SidebarBrand org={org} /></div>}
          {orgSwitcher && <div className={cn("w-full", rail ? "pt-0.5" : "pt-3")}>{orgSwitcher}</div>}
          {drawer ? <div className="pt-4" /> : <div className={cn("w-full pt-4 pb-4", rail && "flex justify-center")}>{newButton}</div>}
          <div className="flex w-full flex-col gap-px">
            {item("vault", "Vault", LockKeyhole)}
            {paths.views.includes("shared") && item("shared", "Shared with me", Users)}
            {item("attention", "Needs attention", AlertTriangle, "amber")}
            {item("links", "Share links", Link2)}
            {item("trash", "Trash", Trash2)}
          </div>
        </div>
        <div className={cn("shrink-0 border-t border-[var(--border-dark-1)] pt-2 pb-3", rail ? "px-2" : "px-3")}>
          <AccountMenu view={view} user={user} adminHref={adminHref} badges={badges} onLock={onLock} onSignOut={onSignOut} compact={rail} />
          {!rail && <VendorCredit className="block px-2 pt-1.5 font-mono text-[10px] tracking-[.04em] text-[var(--text-dark-tertiary)]/70 hover:text-[var(--text-dark-secondary)]" />}
        </div>
      </nav>
    </TooltipProvider>
  );
}
