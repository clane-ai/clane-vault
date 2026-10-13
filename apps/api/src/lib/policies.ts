import { BlockList, isIPv4, isIPv6 } from "node:net";
import { z } from "zod";

/**
 * Organisation policies (docs/policies.md), stored as JSON on the organisation and validated here on every write and
 * read. Missing fields take their defaults, so `{}` is "nothing restricted".
 */

/** An IPv4 or IPv6 network in CIDR notation (a bare address counts as /32 or /128), normalised. */
export const cidr = z.string().trim().max(64).transform((s, ctx) => {
  const [addr, bits, ...rest] = s.split("/");
  const v4 = isIPv4(addr ?? ""), v6 = isIPv6(addr ?? "");
  const max = v4 ? 32 : 128;
  const prefix = bits === undefined ? max : /^\d{1,3}$/.test(bits) ? Number(bits) : NaN;
  if (rest.length || (!v4 && !v6) || !(prefix >= 0 && prefix <= max)) { ctx.addIssue({ code: "custom", message: "invalid_cidr" }); return z.NEVER; }
  return `${addr!.toLowerCase()}/${prefix}`;
});

export const policySchema = z.object({
  /** Lock the vault after this many idle minutes (null: the app's default). */
  autoLockMinutes: z.number().int().min(1).max(1440).nullable().default(null),
  /** Master password rules, checked by clients at sign-up, invitation acceptance and password change. */
  minPasswordLength: z.number().int().min(12).max(128).default(12),
  minPasswordScore: z.number().int().min(0).max(4).default(0),
  links: z.object({
    allowed: z.boolean().default(true),
    maxExpiryHours: z.union([z.literal(1), z.literal(24), z.literal(168)]).default(168),
    requirePassword: z.boolean().default(false),
    /** Links may carry files the creator picks (off: no files in links; live links with files are revoked). */
    allowAttachments: z.boolean().default(true),
  }).prefault({}),
  /** File attachments (docs/attachments.md). Off: no new files; existing ones stay listed and downloadable. */
  attachments: z.object({
    allowed: z.boolean().default(true),
    /** Per-file limit in MiB (null: the server's); it can only lower the server's limit. */
    maxFileMb: z.number().int().min(1).max(1024).nullable().default(null),
    /** Image, PDF and text previews in the browser (off: every file is download-only). */
    previews: z.boolean().default(true),
  }).prefault({}),
  offlineAllowed: z.boolean().default(true),
  extensionAllowed: z.boolean().default(true),
  /** Members may opt in to the Have I Been Pwned range check in the password health report. */
  breachCheckAllowed: z.boolean().default(true),
  /** Org-scoped requests only from these networks (empty: anywhere). */
  ipAllowlist: z.array(cidr).max(100).default([]),
  /** Break-glass: the owner reaches the org from anywhere even with an allowlist (logged). Only the owner changes it. */
  ownerBreakGlass: z.boolean().default(true),
}).strict();
export type Policies = z.infer<typeof policySchema>;

export const DEFAULT_POLICIES: Policies = policySchema.parse({});

/**
 * Risk dashboard (docs/risk-dashboard.md): the security benchmarks the org's admins chose to ignore. Kept in the same
 * JSON column beside the policies but outside policySchema, so the policies form never sends or replaces it.
 */
export const RISK_IGNORED = "riskIgnored";
export function readRiskIgnored(stored: unknown): string[] {
  const v = stored && typeof stored === "object" ? (stored as Record<string, unknown>)[RISK_IGNORED] : undefined;
  return Array.isArray(v) ? [...new Set(v.filter((x): x is string => typeof x === "string" && /^[a-z_]{1,40}$/.test(x)))].slice(0, 50) : [];
}
/** The stored JSON without what isn't a policy (so the strict schema reads it). */
function policyPart(stored: unknown): unknown {
  if (!stored || typeof stored !== "object" || Array.isArray(stored) || !(RISK_IGNORED in stored)) return stored;
  const { [RISK_IGNORED]: _ignored, ...rest } = stored as Record<string, unknown>;
  return rest;
}

/** Stored policies (validated on write); a row that somehow fails validation falls back field by field, never open. */
export function readPolicies(stored: unknown): Policies {
  const raw = policyPart(stored);
  const r = policySchema.safeParse(raw ?? {});
  if (r.success) return r.data;
  // Corrupt JSON: keep restrictions we can read and fail closed on the allowlist.
  const o = (raw && typeof raw === "object" ? raw : {}) as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const k of Object.keys(policySchema.shape) as (keyof Policies)[]) {
    const f = policySchema.shape[k].safeParse(o[k]);
    if (f.success) out[k] = f.data;
  }
  const p = { ...DEFAULT_POLICIES, ...out } as Policies;
  if (o.ipAllowlist !== undefined && !("ipAllowlist" in out)) p.ipAllowlist = ["0.0.0.0/32"];
  return p;
}

/** What every member's client reads with the org list (the allowlist itself stays with admins). */
export function clientPolicies(p: Policies) {
  return {
    autoLockMinutes: p.autoLockMinutes, minPasswordLength: p.minPasswordLength, minPasswordScore: p.minPasswordScore,
    links: p.links, attachments: p.attachments, offlineAllowed: p.offlineAllowed, extensionAllowed: p.extensionAllowed, breachCheckAllowed: p.breachCheckAllowed,
    ipRestricted: p.ipAllowlist.length > 0,
  };
}
export type ClientPolicies = ReturnType<typeof clientPolicies>;

/** "::ffff:10.0.0.1" → "10.0.0.1"; zone ids dropped. */
export function normalizeIp(ip: string): string {
  const s = ip.replace(/%.*$/, "").toLowerCase();
  const m = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(s);
  return m ? m[1]! : s;
}

const lists = new Map<string, BlockList>();
/** Whether `ip` is inside one of the networks. An empty list allows everything; an unparsable address nothing. */
export function ipAllowed(ip: string | undefined, allow: string[]): boolean {
  if (!allow.length) return true;
  if (!ip) return false;
  const key = allow.join(",");
  let bl = lists.get(key);
  if (!bl) {
    bl = new BlockList();
    for (const c of allow) {
      const [a, b] = c.split("/");
      bl.addSubnet(a!, Number(b), isIPv4(a!) ? "ipv4" : "ipv6");
    }
    if (lists.size > 1000) lists.clear();
    lists.set(key, bl);
  }
  const addr = normalizeIp(ip);
  if (isIPv4(addr)) return bl.check(addr, "ipv4");
  if (isIPv6(addr)) return bl.check(addr, "ipv6");
  return false;
}
