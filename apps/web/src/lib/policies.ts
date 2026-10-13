import { useSession } from "./session";
import { passwordStrength } from "./strength";

/**
 * The active organisation's policies as every member's client reads them (docs/policies.md), from the org list
 * (`/me/orgs` and sign-in responses). The IP allowlist itself stays with admins; `ipRestricted` says one is on.
 */
export interface OrgPolicies {
  autoLockMinutes: number | null;
  minPasswordLength: number; minPasswordScore: number;
  links: { allowed: boolean; maxExpiryHours: 1 | 24 | 168; requirePassword: boolean; allowAttachments: boolean };
  /** File attachments (docs/attachments.md): new uploads allowed, a lower per-file limit (MiB), previews in the browser. */
  attachments: { allowed: boolean; maxFileMb: number | null; previews: boolean };
  offlineAllowed: boolean; extensionAllowed: boolean; breachCheckAllowed: boolean; ipRestricted: boolean;
}
/** A master password rule (an org's, or the app's own floor). */
export interface PasswordPolicy { minLength: number; minScore: number }

export const DEFAULT_POLICIES: OrgPolicies = {
  autoLockMinutes: null, minPasswordLength: 12, minPasswordScore: 0, links: { allowed: true, maxExpiryHours: 168, requirePassword: false, allowAttachments: true },
  attachments: { allowed: true, maxFileMb: null, previews: true },
  offlineAllowed: true, extensionAllowed: true, breachCheckAllowed: true, ipRestricted: false,
};
export const BASE_PASSWORD_POLICY: PasswordPolicy = { minLength: 12, minScore: 0 };

/** The active org's policies (defaults with no org, or from a server that doesn't send them). */
export function useOrgPolicies(): OrgPolicies {
  const p = useSession().org?.policies;
  return p ? { ...DEFAULT_POLICIES, ...p, links: { ...DEFAULT_POLICIES.links, ...p.links }, attachments: { ...DEFAULT_POLICIES.attachments, ...p.attachments } } : DEFAULT_POLICIES;
}

/**
 * Small helpers for features that must honour the org (offline copies, the browser extension, the breach check):
 * `allowed("offline")` is false when the active org switched it off.
 */
export function usePolicyFlags() {
  const p = useOrgPolicies();
  return { offlineAllowed: p.offlineAllowed, extensionAllowed: p.extensionAllowed, breachCheckAllowed: p.breachCheckAllowed, autoLockMinutes: p.autoLockMinutes };
}

/** The strictest of several rules (e.g. every org the account belongs to). */
export const strictest = (rules: PasswordPolicy[]): PasswordPolicy =>
  rules.reduce((a, b) => ({ minLength: Math.max(a.minLength, b.minLength), minScore: Math.max(a.minScore, b.minScore) }), BASE_PASSWORD_POLICY);

const SCORE_WORD = ["", "weak", "fair", "good", "strong"] as const;
/** The rule in words, for forms ("At least 16 characters, rated good or better."). */
export function passwordRuleText(p: PasswordPolicy): string {
  return `At least ${p.minLength} characters${p.minScore > 0 ? `, rated ${SCORE_WORD[p.minScore]} or better` : ""}.`;
}

/** Why a master password breaks the rule (a sentence to show), or null when it meets it. */
export function checkMasterPassword(pw: string, p: PasswordPolicy): string | null {
  if (pw.length < p.minLength) return `Use at least ${p.minLength} characters.`;
  if (p.minScore > 0 && passwordStrength(pw).score < p.minScore) return `Your organisation asks for a stronger master password (rated ${SCORE_WORD[p.minScore]} or better). Add words or length.`;
  return null;
}
