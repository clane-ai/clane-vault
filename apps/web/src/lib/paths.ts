import type { VaultView } from "@/features/vault/filter";

/**
 * The app's URLs (every page and section can be bookmarked, reloaded and used with back/forward). The space (Personal or
 * one organisation) is part of the path and is the source of truth for what the app shows
 * (docs/design/2026-10-07-multi-org-design.md, section 11):
 *
 * Personal:      /p/vault, /p/vault/folder/:id, /p/vault/record/:id, /p/attention[/record/:id], /p/links, /p/trash[/record/:id]
 * Organisation:  /o/:org/vault[/folder/:id | /record/:id], /o/:org/shared[/record/:id], /o/:org/attention[/record/:id],
 *                /o/:org/links, /o/:org/trash[/record/:id]
 *                /o/:org/admin/{risk, people[/:userId], groups[/:groupId], events, health, migrate,
 *                               org/{general,policies,sso,recovery,email,storage}} (the org's owners and admins)
 * Server:        /server/{organisations,accounts,branding,email,backups,storage}  (instance admins; outside any org)
 * Settings:      /settings/{account,security,device,extension,health}            (the person's own; global)
 *
 * `:org` is the organisation's slug (unique), or its id. Older paths (/vault/..., /admin/..., /org/..., /health...)
 * redirect into the space used last on this device.
 */

/** A space as the URL names it: Personal, or an organisation by slug or id (not yet checked against the user's orgs). */
export type SpaceRef = { kind: "personal" } | { kind: "org"; ref: string };

export const PERSONAL = "/p";
/** How an org appears in URLs: its slug, else its id. */
export const orgRef = (o: { id: string; slug?: string | null }) => o.slug || o.id;
/** The path prefix of a space: /p, or /o/<slug>. */
export const spacePrefix = (o: { id: string; slug?: string | null } | null | undefined) => (o ? `/o/${encodeURIComponent(orgRef(o))}` : PERSONAL);
/** The org a URL reference names, among the user's own orgs only (so a URL never tells whether some other org exists). */
export const findOrg = <T extends { id: string; slug?: string | null }>(orgs: T[], ref: string): T | undefined =>
  orgs.find((o) => !!o.slug && o.slug === ref) ?? orgs.find((o) => o.id === ref.toLowerCase());

/** The vault lists of a space: Personal has no "Shared with me" (direct shares are made in an organisation). */
export const PERSONAL_VIEWS: readonly VaultView[] = ["vault", "attention", "links", "trash"];
export const ORG_VIEWS: readonly VaultView[] = ["vault", "shared", "attention", "links", "trash"];

export const listPath = (prefix: string, view: VaultView) => `${prefix}/${view}`;
export const recordPath = (prefix: string, view: VaultView, id: string) => `${prefix}/${view === "links" ? "vault" : view}/record/${id}`;
export const folderPath = (prefix: string, id: string | null) => (id ? `${prefix}/vault/folder/${id}` : `${prefix}/vault`);

export const SETTINGS_SECTIONS = ["account", "security", "device", "extension", "health"] as const;
export type SettingsSection = (typeof SETTINGS_SECTIONS)[number];

export const ORG_ADMIN_SECTIONS = ["risk", "people", "groups", "events", "health", "migrate",
  "org/general", "org/policies", "org/sso", "org/recovery", "org/email", "org/storage"] as const;
export const SERVER_SECTIONS = ["organisations", "accounts", "branding", "email", "backups", "storage"] as const;
export type ServerSection = (typeof SERVER_SECTIONS)[number];
/** Admin sections: the org's (under /o/:org/admin) and the server's ("server/…", under /server). */
export type AdminSection = (typeof ORG_ADMIN_SECTIONS)[number] | `server/${ServerSection}`;
export const ADMIN_SECTIONS: readonly AdminSection[] = [...ORG_ADMIN_SECTIONS, ...SERVER_SECTIONS.map((s) => `server/${s}` as const)];
/** Admin sections for the active org's owners and admins; the rest (server/*) for instance admins. */
export const isServerSection = (s: AdminSection) => s.startsWith("server/");

/** An org admin page (/o/:org/admin/...) or, for a server section, /server/.... `orgPrefix`: the org's space prefix. */
export function adminPath(orgPrefix: string | null, section?: AdminSection | null, detailId?: string | null): string {
  if (section && isServerSection(section)) return `/server/${section.slice("server/".length)}`;
  if (!orgPrefix) return "/server";
  return `${orgPrefix}/admin${section ? `/${section}` : ""}${detailId ? `/${detailId}` : ""}`;
}

export type AppLocation =
  | { area: "list"; space: SpaceRef; view: VaultView; folderId: string | null; recordId: string | null }
  | { area: "settings"; section: SettingsSection | null }
  /** `space`: the org of an org admin page; null for the server's pages (/server/*). */
  | { area: "admin"; space: SpaceRef | null; section: AdminSection | null; detailId: string | null }
  | { area: "redirect"; to: string };

/**
 * Where old and unknown paths go: `space`, the prefix of the space used last (/p or /o/<slug>); `adminOrg`, the prefix
 * of the org for old admin paths (the last org, else one the user administers), or null when there is none.
 */
export interface PathContext { space: string; adminOrg: string | null }

const LISTS = new Set<string>(["vault", "shared", "attention", "trash"]);
const ORG_ALIASES: Record<string, string> = { logo: "general", single_sign_on: "sso", "admin-recovery": "recovery" };
const isOrgSection = (s: string) => (ORG_ADMIN_SECTIONS as readonly string[]).includes(s);

/** A space's vault lists (`rest`: the path after the space prefix). */
function parseList(space: SpaceRef, prefix: string, rest: string[]): AppLocation {
  const [a, b, c] = rest;
  const views = space.kind === "personal" ? PERSONAL_VIEWS : ORG_VIEWS;
  if (!a) return { area: "redirect", to: `${prefix}/vault` };
  if (a === "links") return rest.length === 1 ? { area: "list", space, view: "links", folderId: null, recordId: null } : { area: "redirect", to: `${prefix}/links` };
  if (LISTS.has(a) && views.includes(a as VaultView)) {
    const view = a as VaultView;
    if (rest.length === 1) return { area: "list", space, view, folderId: null, recordId: null };
    if (rest.length === 3 && b === "record") return { area: "list", space, view, folderId: null, recordId: c! };
    if (rest.length === 3 && b === "folder" && view === "vault") return { area: "list", space, view, folderId: c!, recordId: null };
    return { area: "redirect", to: `${prefix}/${view}` };
  }
  return { area: "redirect", to: `${prefix}/vault` };
}

/** An org's admin pages (`rest`: the path after /o/:org/admin). */
function parseOrgAdmin(space: SpaceRef, prefix: string, rest: string[]): AppLocation {
  const [b, c] = rest;
  const base = `${prefix}/admin`;
  if (!b) return { area: "admin", space, section: null, detailId: null };
  if (b === "server" || b === "backups") return { area: "redirect", to: b === "backups" ? "/server/backups" : `/server${c ? `/${c}` : ""}` };
  if (b === "org" && rest.length === 1) return { area: "redirect", to: `${base}/org/general` };
  if (b === "org" && rest.length === 2) {
    const sec = `org/${ORG_ALIASES[c!] ?? c}`;
    return isOrgSection(sec) ? { area: "admin", space, section: sec as AdminSection, detailId: null } : { area: "redirect", to: base };
  }
  if ((b === "people" || b === "groups") && rest.length === 2) return { area: "admin", space, section: b, detailId: c! };
  if (rest.length === 1 && isOrgSection(b)) return { area: "admin", space, section: b as AdminSection, detailId: null };
  return { area: "redirect", to: base };
}

/** Where a pathname points; anything unknown or old becomes a redirect (into the space in `ctx`). */
export function parseAppPath(pathname: string, ctx: PathContext = { space: PERSONAL, adminOrg: null }): AppLocation {
  const s = pathname.split("/").filter(Boolean).map((x) => { try { return decodeURIComponent(x); } catch { return x; } });
  const [a, b, c] = s;
  const home = `${ctx.space}/vault`;
  if (!a) return { area: "redirect", to: home };
  if (a === "p") {
    if (b === "admin") return { area: "redirect", to: "/server" };
    return parseList({ kind: "personal" }, PERSONAL, s.slice(1));
  }
  if (a === "o") {
    if (!b) return { area: "redirect", to: home };
    const space: SpaceRef = { kind: "org", ref: b };
    const prefix = `/o/${encodeURIComponent(b)}`;
    if (c === "admin") return parseOrgAdmin(space, prefix, s.slice(3));
    if (c === "settings") return { area: "redirect", to: `/settings${s[3] ? `/${s[3]}` : ""}` };
    return parseList(space, prefix, s.slice(2));
  }
  if (a === "settings") {
    if (s.length === 1) return { area: "settings", section: null };
    if (s.length === 2 && (SETTINGS_SECTIONS as readonly string[]).includes(b!)) return { area: "settings", section: b as SettingsSection };
    // Old personal paths and admin sections people may have bookmarked under Settings.
    if (b === "org" || b === "organisation") return { area: "redirect", to: adminPath(ctx.adminOrg, `org/${ORG_ALIASES[c ?? ""] ?? c ?? "general"}` as AdminSection) };
    return { area: "redirect", to: "/settings" };
  }
  if (a === "server") {
    if (s.length === 1) return { area: "admin", space: null, section: null, detailId: null };
    if (s.length === 2 && (SERVER_SECTIONS as readonly string[]).includes(b!)) return { area: "admin", space: null, section: `server/${b as ServerSection}`, detailId: null };
    return { area: "redirect", to: "/server" };
  }
  // Older paths (before spaces were in the URL): into the space used last.
  if (LISTS.has(a) || a === "links") {
    const inSpace = parseList(ctx.space === PERSONAL ? { kind: "personal" } : { kind: "org", ref: "" }, ctx.space, s);
    if (inSpace.area !== "list") return { area: "redirect", to: inSpace.area === "redirect" ? inSpace.to : home };
    return { area: "redirect", to: inSpace.recordId ? recordPath(ctx.space, inSpace.view, inSpace.recordId) : inSpace.folderId ? folderPath(ctx.space, inSpace.folderId) : listPath(ctx.space, inSpace.view) };
  }
  if (a === "health" && s.length === 1) return { area: "redirect", to: "/settings/health" };
  if (a === "migrate" && s.length === 1) return { area: "redirect", to: adminPath(ctx.adminOrg, "migrate") };
  if (a === "org") return { area: "redirect", to: adminPath(ctx.adminOrg, `org/${ORG_ALIASES[c ?? ""] ?? c ?? "general"}` as AdminSection) };
  if (a === "admin") {
    if (b === "server" || b === "backups") return { area: "redirect", to: b === "backups" ? "/server/backups" : `/server${c ? `/${c}` : ""}` };
    if (!ctx.adminOrg) return { area: "redirect", to: "/server" };
    const inOrg = parseOrgAdmin({ kind: "org", ref: "" }, ctx.adminOrg, s.slice(1));
    return { area: "redirect", to: inOrg.area === "admin" ? adminPath(ctx.adminOrg, inOrg.section, inOrg.detailId) : inOrg.area === "redirect" ? inOrg.to : `${ctx.adminOrg}/admin` };
  }
  return { area: "redirect", to: home };
}

/** The space a pathname names (undefined: none, e.g. /settings or /server). */
export function spaceOf(pathname: string): SpaceRef | undefined {
  const s = pathname.split("/").filter(Boolean);
  if (s[0] === "p") return { kind: "personal" };
  if (s[0] === "o" && s[1]) { try { return { kind: "org", ref: decodeURIComponent(s[1]) }; } catch { return { kind: "org", ref: s[1] }; } }
  return undefined;
}
