import type { Policies } from "./policies.js";

/**
 * The organisation risk dashboard (docs/risk-dashboard.md): security benchmarks, the score and the high-priority
 * alerts. Everything here is computed from configuration, metadata and counts; never from a secret or a vault item.
 */

export const DAY_MS = 24 * 3600e3;
/** Utilisation and alert windows. */
export const WINDOW_DAYS = 30;
/** An admin who hasn't been seen for this long counts as inactive. */
export const INACTIVE_ADMIN_DAYS = 90;
/** The last successful instance backup must be this recent. */
export const BACKUP_MAX_AGE_HOURS = 48;
/** File storage over this share of the org's quota is a critical benchmark (and the Storage tile turns red). */
export const STORAGE_ALERT_RATIO = 0.9;
/** A member's password health is "at risk" with any breached password or a score under this. */
export const HEALTH_AT_RISK_SCORE = 60;
/** How much the benchmarks and the members' password health weigh in the score (when there are health reports). */
export const SCORE_WEIGHTS = { benchmarks: 0.7, health: 0.3 } as const;

export type Severity = "high" | "medium" | "low";
export const SEVERITY_WEIGHT: Record<Severity, number> = { high: 3, medium: 2, low: 1 };

export const BENCHMARK_KEYS = ["backup_admin", "admin_recovery", "auto_lock", "master_password", "share_links", "ip_allowlist", "sso",
  "org_email", "backups", "password_health", "inactive_admins", "storage"] as const;
export type BenchmarkKey = (typeof BENCHMARK_KEYS)[number];
export const isBenchmarkKey = (k: string): k is BenchmarkKey => (BENCHMARK_KEYS as readonly string[]).includes(k);

/**
 * critical: needs action · completed · ignored: an admin chose to ignore it (still computed, shown with its real state)
 * · not_applicable: nothing to check here (no company domain, no health reports yet) · unknown: the viewer can't see
 * it (instance backups for someone who isn't an instance admin). Only critical and completed count in the score.
 */
export type BenchmarkStatus = "critical" | "completed" | "ignored" | "not_applicable" | "unknown";

export interface Benchmark {
  key: BenchmarkKey; title: string; severity: Severity; status: BenchmarkStatus;
  /** What the check found, in one sentence (counts and settings only). */ detail: string;
  /** For an ignored benchmark: whether it would pass. */ passing: boolean | null;
}

export interface BenchmarkInput {
  /** Active owners and admins (account active too). */ admins: number;
  adminRecoveryEnabled: boolean;
  policies: Policies;
  /** hasDomain: the org added an SSO domain, or two or more of its members share a company (non-public) domain. */
  sso: { hasDomain: boolean; configured: boolean; verifiedDomains: number };
  /** org: the org has its own email settings; any: email reaches members somehow (org, instance or environment). */
  email: { org: boolean; any: boolean;
    /** The org's Microsoft 365 delegated sign-in stopped working and needs an admin to sign in again. */ reconnect?: boolean };
  /** null: the viewer isn't an instance admin. */
  backups: { enabled: boolean; lastSuccessAt: Date | null;
    /** The last good dump's size and the file attachments in it (docs/attachments.md). */ bytes?: number; attachmentBytes?: number | null } | null;
  health: { reported: number; atRisk: number };
  inactiveAdmins: number;
  /** The org's file storage (docs/attachments.md): bytes used against its quota; null or absent: nothing to check. */
  storage?: { used: number; quota: number } | null;
  ignored: readonly string[];
  now: Date;
}

type Check = { title: string; severity: Severity; run: (i: BenchmarkInput) => { pass: boolean | null; detail: string } };
const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

const CHECKS: Record<BenchmarkKey, Check> = {
  backup_admin: { title: "At least two owners or admins", severity: "high", run: (i) => ({ pass: i.admins >= 2,
    detail: i.admins >= 2 ? `${plural(i.admins, "active owner or admin", "active owners and admins")}.` : "Only one active owner or admin: nobody can step in if they are away or locked out." }) },
  admin_recovery: { title: "Admin account recovery is on", severity: "medium", run: (i) => ({ pass: i.adminRecoveryEnabled,
    detail: i.adminRecoveryEnabled ? "Members who lose their master password and kit can ask an admin." : "Off: a member who loses both their master password and recovery kit loses their items." }) },
  auto_lock: { title: "Auto-lock after 15 minutes or less", severity: "medium", run: (i) => {
    const m = i.policies.autoLockMinutes;
    return { pass: m !== null && m <= 15, detail: m === null ? "Not set: each member chooses their own lock time." : `Vaults lock after ${plural(m, "idle minute")}.` };
  } },
  master_password: { title: "Minimum master password strength", severity: "high", run: (i) => {
    const s = i.policies.minPasswordScore;
    return { pass: s >= 3, detail: s >= 3 ? `Master passwords must reach strength ${s} of 4 and ${i.policies.minPasswordLength} characters.` : `Strength ${s} of 4 required (set 3 or more); length at least ${i.policies.minPasswordLength}.` };
  } },
  share_links: { title: "One-time links are restricted", severity: "medium", run: (i) => {
    const l = i.policies.links;
    if (!l.allowed) return { pass: true, detail: "One-time links are switched off." };
    const pass = l.requirePassword || l.maxExpiryHours <= 24;
    return { pass, detail: `${l.requirePassword ? "A password is required" : "No password required"}; links last at most ${l.maxExpiryHours === 168 ? "7 days" : plural(l.maxExpiryHours, "hour")}.` };
  } },
  ip_allowlist: { title: "IP allowlist (optional)", severity: "low", run: (i) => {
    const n = i.policies.ipAllowlist.length;
    return { pass: n > 0, detail: n ? `${plural(n, "network")} allowed.` : "The organisation can be reached from any network. Optional: ignore this if members work from anywhere." };
  } },
  sso: { title: "Single sign-on with a verified domain", severity: "medium", run: (i) => {
    if (!i.sso.hasDomain) return { pass: null, detail: "No company email domain: members use public addresses." };
    const pass = i.sso.configured && i.sso.verifiedDomains > 0;
    return { pass, detail: pass ? `Single sign-on is set up with ${plural(i.sso.verifiedDomains, "verified domain")}.` : !i.sso.configured ? "Single sign-on isn't set up." : "No domain is verified yet." };
  } },
  org_email: { title: "Organisation email is set up", severity: "medium", run: (i) => i.email.reconnect
    ? { pass: false, detail: "The Microsoft 365 sign-in for the organisation's email stopped working: reconnect it in Email." }
    : ({ pass: i.email.org,
    detail: i.email.org ? "Invitations and security notices go out from the organisation's own settings." : i.email.any ? "Using the server's email settings; set your own sender in Email." : "Email isn't set up: invitations, 2FA resets and recovery notices aren't emailed." }) },
  backups: { title: "Server backups ran in the last 48 hours", severity: "high", run: (i) => {
    const b = i.backups;
    if (!b) return { pass: null, detail: "Only the server's admins can see backups: ask your server admin." };
    if (!b.enabled) return { pass: false, detail: "Backups are switched off on this server." };
    if (!b.lastSuccessAt) return { pass: false, detail: "No backup has succeeded yet." };
    const h = Math.floor((i.now.getTime() - b.lastSuccessAt.getTime()) / 3600e3);
    const mb = (n: number) => `${Math.max(1, Math.round(n / (1024 * 1024)))} MB`;
    const size = b.bytes ? ` Dump size ${mb(b.bytes)}${b.attachmentBytes ? `, of which files ${mb(b.attachmentBytes)}` : ""}.` : "";
    return { pass: h <= BACKUP_MAX_AGE_HOURS, detail: `Last successful backup ${h < 1 ? "less than an hour" : plural(h, "hour")} ago.${size}` };
  } },
  password_health: { title: "No members with risky passwords", severity: "high", run: (i) => {
    if (!i.health.reported) return { pass: null, detail: "No password health reports yet: they arrive when members open their vault." };
    return { pass: i.health.atRisk === 0, detail: i.health.atRisk ? `${plural(i.health.atRisk, "member")} with a breached password or a health score under ${HEALTH_AT_RISK_SCORE}.`
      : i.health.reported === 1 ? `The 1 reporting member is above ${HEALTH_AT_RISK_SCORE} with no breached passwords.`
      : `All ${i.health.reported} reporting members are above ${HEALTH_AT_RISK_SCORE} with no breached passwords.` };
  } },
  inactive_admins: { title: `No admins inactive for ${INACTIVE_ADMIN_DAYS} days`, severity: "medium", run: (i) => ({ pass: i.inactiveAdmins === 0,
    detail: i.inactiveAdmins ? `${plural(i.inactiveAdmins, "owner or admin", "owners or admins")} not seen for ${INACTIVE_ADMIN_DAYS} days: remove the role if it isn't needed.` : "Every owner and admin signed in recently." }) },
  storage: { title: "File storage under 90 % of the quota", severity: "high", run: (i) => {
    const s = i.storage;
    if (!s || s.used === 0 || s.quota <= 0) return { pass: null, detail: "No files stored yet." };
    const pct = Math.round((100 * s.used) / s.quota);
    return { pass: s.used <= STORAGE_ALERT_RATIO * s.quota, detail: s.used > STORAGE_ALERT_RATIO * s.quota
      ? `Files use ${pct} % of the organisation's storage: uploads are refused once it is full. Remove files or ask the server admin for more.`
      : `Files use ${pct} % of the organisation's storage.` };
  } },
};

export function computeBenchmarks(i: BenchmarkInput): Benchmark[] {
  return BENCHMARK_KEYS.map((key) => {
    const c = CHECKS[key];
    const { pass, detail } = c.run(i);
    const base = { key, title: c.title, severity: c.severity, detail, passing: pass };
    if (i.ignored.includes(key)) return { ...base, status: "ignored" as const };
    if (pass === null) return { ...base, status: key === "backups" ? "unknown" as const : "not_applicable" as const };
    return { ...base, status: pass ? "completed" as const : "critical" as const };
  });
}

/**
 * The risk score, 0–100 (higher is better):
 *   benchmarks = 100 × Σ weight(completed) / Σ weight(completed or critical)   (weights: high 3, medium 2, low 1)
 *   health     = the average password health score of the members who reported
 *   score      = round(0.7 × benchmarks + 0.3 × health), or round(benchmarks) when nobody reported yet.
 * Ignored, not applicable and unknown benchmarks don't count either way.
 */
export function computeScore(benchmarks: Benchmark[], healthScores: number[]) {
  let got = 0, max = 0;
  for (const b of benchmarks) {
    if (b.status !== "completed" && b.status !== "critical") continue;
    max += SEVERITY_WEIGHT[b.severity];
    if (b.status === "completed") got += SEVERITY_WEIGHT[b.severity];
  }
  const bench = max ? (100 * got) / max : 100;
  const health = healthScores.length ? healthScores.reduce((a, b) => a + b, 0) / healthScores.length : null;
  const value = Math.round(health === null ? bench : SCORE_WEIGHTS.benchmarks * bench + SCORE_WEIGHTS.health * health);
  return { value: Math.max(0, Math.min(100, value)), benchmarks: Math.round(bench), health: health === null ? null : Math.round(health),
    weights: health === null ? { benchmarks: 1, health: 0 } : { ...SCORE_WEIGHTS }, counted: { earned: got, possible: max } };
}

/**
 * High-priority alerts: risky event actions (lib/events.ts call sites). "org" alerts are the org's own log entries;
 * "account" alerts are account-level events (no org) of the org's current members since they joined, plus the same
 * action logged in this org (e.g. a failed sign-in through its SSO).
 */
export interface AlertDef { action: string; label: string; scope: "org" | "account" }
/** Not an event action of its own: attachment.download events whose meta says the record is widely shared. */
export const WIDE_DOWNLOAD_ALERT = "attachment.download_wide";
export const ALERTS: readonly AlertDef[] = [
  { action: "auth.login_failed", label: "Failed sign-ins", scope: "account" },
  { action: "auth.refresh_reuse", label: "Refresh token reused (possible stolen session)", scope: "account" },
  { action: "auth.step_up_failed", label: "Failed 2FA step-ups", scope: "account" },
  { action: "auth.recovery_failed", label: "Failed recovery attempts", scope: "account" },
  { action: "auth.reauth_failed", label: "Failed re-authentications", scope: "account" },
  { action: "auth.recovery_kit_used", label: "Recovery kit used", scope: "account" },
  { action: "sso.callback_failed", label: "Failed single sign-ons", scope: "org" },
  { action: "email.m365_reconnect_needed", label: "Microsoft 365 email needs reconnecting", scope: "org" },
  { action: "admin.reset_2fa", label: "2FA resets", scope: "org" },
  { action: "recovery.request_created", label: "Admin recovery requested", scope: "org" },
  { action: "recovery.request_approved", label: "Admin recovery approved", scope: "org" },
  { action: "auth.admin_recovery_used", label: "Admin recovery used", scope: "org" },
  { action: "admin.recovery_policy_disabled", label: "Admin recovery switched off", scope: "org" },
  { action: "admin.role_change", label: "Role changes", scope: "org" },
  { action: "admin.remove_member", label: "Members removed", scope: "org" },
  { action: "admin.disable", label: "Members disabled", scope: "org" },
  { action: "org.transfer", label: "Ownership transferred", scope: "org" },
  { action: "org.policies_update", label: "Policy changes", scope: "org" },
  { action: "policy.ip_bypass_owner", label: "Owner bypassed the IP allowlist", scope: "org" },
  { action: "sso.bypass_owner", label: "Owner bypassed single sign-on", scope: "org" },
  { action: "sso.settings_updated", label: "Single sign-on settings changed", scope: "org" },
  { action: "sso.settings_removed", label: "Single sign-on removed", scope: "org" },
  { action: "link.create", label: "One-time links created", scope: "org" },
  { action: "admin.events_export", label: "Event log exported", scope: "org" },
  { action: "risk.benchmark_ignored", label: "Security benchmarks ignored", scope: "org" },
  { action: "attachment.quota_exceeded", label: "File uploads refused: storage full", scope: "org" },
  { action: "link.attachment_download", label: "Files downloaded through one-time links", scope: "org" },
  // attachment.download events with meta.wide (the record can be opened by WIDE_AUDIENCE people or more).
  { action: WIDE_DOWNLOAD_ALERT, label: "Files downloaded from widely shared records", scope: "org" },
];
export const alertDef = (action: string) => ALERTS.find((a) => a.action === action);

/** Change against the previous window, in percent (null: nothing before, so no meaningful percentage). */
export function trendPercent(current: number, previous: number): number | null {
  if (previous === 0) return current === 0 ? 0 : null;
  return Math.round(((current - previous) / previous) * 100);
}
