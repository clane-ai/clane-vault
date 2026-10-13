import { isWeakPassword } from "@/features/vault/attention";
import type { VaultRecord } from "@/features/vault/types";

/**
 * Password health (docs/password-health.md), computed in the browser over the records the user can open. Passwords
 * are compared in memory only; the server gets counts and a score, never a password, hash or record id.
 */
export type HealthIssue = "weak" | "reused" | "old" | "breached";
export const ISSUE_LABEL: Record<HealthIssue, string> = { weak: "Weak", reused: "Reused", old: "Old", breached: "Breached" };
export const OLD_DAYS = 365;

export interface HealthReport {
  /** Issues per record id (only records with at least one). */ issues: Map<string, HealthIssue[]>;
  total: number; weak: number; reused: number; old: number;
  /** Null when the breach check didn't run (not opted in, or the org doesn't allow it). */ breached: number | null;
  /** 0–100: the share of passwords without any issue. */ score: number;
}

/** When the password last changed: the editor's `passwordChangedAt`, else the record's last change. */
export const passwordAge = (r: VaultRecord) => r.body?.passwordChangedAt ?? r.updatedAt;

/** `isWeak`: see attentionReasons (the vault passes the worker-scored one). */
export function healthReport(records: VaultRecord[], opts: { now?: number; breached?: Set<string> | null; isWeak?: (pw: string) => boolean } = {}): HealthReport {
  const isWeak = opts.isWeak ?? isWeakPassword;
  const now = opts.now ?? Date.now();
  const live = records.filter((r) => !r.deleted && r.body?.password);
  const uses = new Map<string, number>();
  for (const r of live) uses.set(r.body!.password!, (uses.get(r.body!.password!) ?? 0) + 1);
  const weakCache = new Map<string, boolean>();
  const issues = new Map<string, HealthIssue[]>();
  const n = { weak: 0, reused: 0, old: 0, breached: 0 };
  for (const r of live) {
    const pw = r.body!.password!;
    const out: HealthIssue[] = [];
    if (!weakCache.has(pw)) weakCache.set(pw, isWeak(pw));
    if (weakCache.get(pw)) out.push("weak");
    if ((uses.get(pw) ?? 0) > 1) out.push("reused");
    const t = Date.parse(passwordAge(r));
    if (!Number.isNaN(t) && now - t > OLD_DAYS * 864e5) out.push("old");
    if (opts.breached?.has(r.id)) out.push("breached");
    for (const i of out) n[i]++;
    if (out.length) issues.set(r.id, out);
  }
  const total = live.length;
  return { issues, total, weak: n.weak, reused: n.reused, old: n.old, breached: opts.breached ? n.breached : null,
    score: total === 0 ? 100 : Math.round((100 * (total - issues.size)) / total) };
}

/** What is posted to the server: counts and the score, nothing else. */
export const reportPayload = (r: HealthReport) => ({ score: r.score, total: r.total, weak: r.weak, reused: r.reused, old: r.old, breached: r.breached });

/**
 * The part of a report that belongs to the organisation: records in its team folders and records shared with the user
 * in it. The user's own private records are in every org's vault view but are theirs, so the counts posted to an org's
 * admins leave them out (a reused password still counts when the other copy is private: the flag is about the org's record).
 */
export function orgScopedReport(r: HealthReport, records: VaultRecord[], teamFolderIds: Set<string>): HealthReport {
  const live = records.filter((x) => !x.deleted && x.body?.password && ((x.folderId != null && teamFolderIds.has(x.folderId)) || x.permission !== "owner"));
  const n = { weak: 0, reused: 0, old: 0, breached: 0 };
  const issues = new Map<string, HealthIssue[]>();
  for (const x of live) {
    const is = r.issues.get(x.id);
    if (!is) continue;
    issues.set(x.id, is);
    for (const i of is) n[i]++;
  }
  const total = live.length;
  return { issues, total, weak: n.weak, reused: n.reused, old: n.old, breached: r.breached === null ? null : n.breached,
    score: total === 0 ? 100 : Math.round((100 * (total - issues.size)) / total) };
}
