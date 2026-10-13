import type { AdminSection } from "@/lib/paths";

/** GET /admin/risk (docs/risk-dashboard.md). */
export type Severity = "high" | "medium" | "low";
export type BenchmarkStatus = "critical" | "completed" | "ignored" | "not_applicable" | "unknown";
export interface Benchmark { key: string; title: string; severity: Severity; status: BenchmarkStatus; detail: string; passing: boolean | null }
export interface Alert { action: string; label: string; scope: "org" | "account"; current: number; previous: number; trend: number | null }
export interface RiskOverview {
  generatedAt: string; windowDays: number; instanceAdmin: boolean;
  score: { value: number; benchmarks: number; health: number | null; weights: { benchmarks: number; health: number }; counted: { earned: number; possible: number } };
  utilisation: {
    members: number; withRecords: number; active30d: number; invitations: { accepted: number; pending: number };
    twoFactor: { required: true; members: number; idpMfaSessions: number }; recoveryKit: number; healthReported30d: number;
    /** File storage (docs/attachments.md); absent from servers before 1.6. */
    storage?: { used: number; quota: number; files: number; alertRatio: number; enabled: boolean };
  };
  benchmarks: Benchmark[];
  alerts: Alert[];
  health: { members: number; reported: number; reported30d: number; averageScore: number | null; atRisk: number; atRiskBelow: number;
    passwords: number; weak: number; reused: number; old: number; breached: number | null; breachCheckMembers: number };
}

/** GET /admin/risk/members. */
export interface RiskMember {
  id: string; name: string; email: string; role: "owner" | "admin" | "member"; joinedAt: string;
  records: { owned: number; canOpen: number }; lastSeen: string | null; active30d: boolean; idpMfa: boolean; recoveryKit: boolean;
  health: { score: number; weak: number; reused: number; old: number; breached: number | null; reportedAt: string; recent: boolean } | null;
}
export interface RiskInvite { email: string; role: string; createdAt: string; expiresAt: string }
export interface RiskMembers { members: RiskMember[]; invites: RiskInvite[] }

/** GET /admin/risk/alerts/:action/members. */
export interface AlertPeople { action: string; label: string; scope: "org" | "account"; windowDays: number;
  people: { user: { id: string; name: string | null; email: string | null } | null; asActor: number; asTarget: number; lastAt: string }[] }

/** The utilisation tiles; each drills down to a member table (?view=<tile>). */
export const TILES = ["records", "active", "invites", "two_factor", "recovery_kit", "health", "storage"] as const;
export type Tile = (typeof TILES)[number];
export const isTile = (s: string | null): s is Tile => !!s && (TILES as readonly string[]).includes(s);

/** Whether a member "has" what a tile counts (the drill-down's With / Without filter). */
export function memberHas(tile: Tile, m: RiskMember): boolean {
  switch (tile) {
    case "records": return m.records.canOpen > 0;
    case "active": return m.active30d;
    case "two_factor": return m.idpMfa;
    case "recovery_kit": return m.recoveryKit;
    case "health": return !!m.health?.recent;
    case "invites": case "storage": return true;
  }
}
/** The CSV export's tile name (the API's). */
export const csvTile = (t: Tile) => (t === "two_factor" ? "idp_mfa" : t);

/** Where each benchmark is fixed: the exact settings page. backups is the server's (instance admins only). */
export const REMEDIATION: Record<string, { section: AdminSection; label: string }> = {
  backup_admin: { section: "people", label: "Add an admin" },
  admin_recovery: { section: "org/recovery", label: "Admin recovery" },
  auto_lock: { section: "org/policies", label: "Policies" },
  master_password: { section: "org/policies", label: "Policies" },
  share_links: { section: "org/policies", label: "Policies" },
  ip_allowlist: { section: "org/policies", label: "Policies" },
  sso: { section: "org/sso", label: "Single sign-on" },
  org_email: { section: "org/email", label: "Email" },
  backups: { section: "server/backups", label: "Backups" },
  password_health: { section: "health", label: "Password health" },
  inactive_admins: { section: "people", label: "People" },
  storage: { section: "org/storage", label: "Storage" },
};

export const SEVERITY_LABEL: Record<Severity, string> = { high: "High", medium: "Medium", low: "Low" };
export const scoreTone = (n: number) => (n >= 80 ? "text-green-600" : n >= 50 ? "text-orange-ink" : "text-red-500");
export const pct = (n: number, of: number) => (of ? Math.round((100 * n) / of) : 0);
export function trendLabel(a: Alert): string {
  if (a.trend === null) return "New";
  if (a.trend === 0) return a.current ? "0%" : "—";
  return `${a.trend > 0 ? "+" : "−"}${Math.abs(a.trend)}%`;
}

/** Saves text as a file (CSV exports). */
export function download(text: string, name: string) {
  const url = URL.createObjectURL(new Blob([text], { type: "text/csv" }));
  const a = document.createElement("a");
  a.href = url; a.download = name;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
