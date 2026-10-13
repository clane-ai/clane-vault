import { passwordStrength, strengthLabel, type StrengthScore } from "@/lib/strength";
import type { VaultRecord } from "./types";

export type AttentionReason = "weak" | "reused" | "old";
export const REASON_LABEL: Record<AttentionReason, string> = { weak: "Weak", reused: "Reused", old: "Old" };
const OLD_MS = 365 * 864e5;
/** Lowercase word followed by a few digits ("figma123", "summer2024"): the first thing people try. */
const COMMON = /^[a-z]+\d{1,4}$/i;

/** Weak without asking zxcvbn: short, or a word and a few digits. */
export const obviouslyWeak = (pw: string) => pw.length < 10 || COMMON.test(pw);
/** The weak rule given the password's zxcvbn score. */
export const weakForScore = (pw: string, score: StrengthScore) => obviouslyWeak(pw) || score <= 2;

export function isWeakPassword(pw: string): boolean {
  if (obviouslyWeak(pw)) return true;
  return passwordStrength(pw).score <= 2;
}

/** Strength for display from a zxcvbn score: never better than "Weak" when the weak rule says so. */
export function strengthForScore(pw: string, score: StrengthScore): { score: StrengthScore; label: string } {
  if (!weakForScore(pw, score) || score === 0) return { score, label: strengthLabel(score) };
  return { score: 1, label: "Weak" };
}
/** Strength for display (scores the password: one zxcvbn run). */
export const strengthOf = (pw: string) => strengthForScore(pw, passwordStrength(pw).score);

/**
 * Reasons per record id, over records the user can open and that are not in the trash. `isWeak` defaults to scoring
 * here and now; the vault passes usePasswordScores' (scored in a worker) so this stays cheap on every render.
 */
export function attentionReasons(records: VaultRecord[], now = Date.now(), isWeak: (pw: string) => boolean = isWeakPassword): Map<string, AttentionReason[]> {
  const live = records.filter((r) => !r.deleted && r.body?.password);
  const byPassword = new Map<string, number>();
  for (const r of live) byPassword.set(r.body!.password!, (byPassword.get(r.body!.password!) ?? 0) + 1);
  const weakCache = new Map<string, boolean>();
  const out = new Map<string, AttentionReason[]>();
  for (const r of live) {
    const pw = r.body!.password!;
    const reasons: AttentionReason[] = [];
    if (!weakCache.has(pw)) weakCache.set(pw, isWeak(pw));
    if (weakCache.get(pw)) reasons.push("weak");
    if ((byPassword.get(pw) ?? 0) >= 2) reasons.push("reused");
    if (now - new Date(r.updatedAt).getTime() > OLD_MS) reasons.push("old");
    if (reasons.length) out.set(r.id, reasons);
  }
  return out;
}

export function reasonLine(reasons: AttentionReason[]): string {
  const parts = reasons.map((r) => (r === "weak" ? "is weak" : r === "reused" ? "is used on another record too" : "hasn't changed in over a year"));
  return `This password ${parts.length > 1 ? parts.slice(0, -1).join(", ") + " and " + parts[parts.length - 1] : parts[0]}.`;
}
