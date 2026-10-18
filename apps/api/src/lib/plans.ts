import type { Config } from "../config.js";
import type { Db } from "./access.js";

export type PlanId = "personal" | "team" | "business" | "unlimited";
export type Feature = "sso" | "domains" | "policyEdit" | "adminRecovery" | "risk" | "orgLogo" | "eventExport" | "agentApprovals" | "agentPathPolicy";
export interface Entitlements {
  plan: PlanId; features: Record<Feature, boolean>;
  seatsAllowed: number | null;          // null = unlimited
  storageBytesPerSeat: number | null;   // pooled per active member; personal: per user
  activeLinkLimit: number | null;
  eventLogDays: number | null;
  agentLimit: number | null;            // live agents (revokedAt null); null = unlimited; agents are not seats
}
export type OrgPlanFields = { plan: "team" | "business"; billingStatus: string; seatsPaid: number | null; trialEndsAt: Date | null };
export const PLAN_SELECT = { plan: true, billingStatus: true, seatsPaid: true, trialEndsAt: true } as const;

export const TRIAL_MS = 14 * 864e5;
const GIB = 1024 ** 3;
export const TEAM_FREE_SEATS = 10;
const FEATURES: Feature[] = ["sso", "domains", "policyEdit", "adminRecovery", "risk", "orgLogo", "eventExport", "agentApprovals", "agentPathPolicy"];
const all = (on: boolean) => Object.freeze(Object.fromEntries(FEATURES.map((f) => [f, on]))) as Record<Feature, boolean>;

const UNLIMITED: Entitlements = Object.freeze({ plan: "unlimited", features: all(true), seatsAllowed: null, storageBytesPerSeat: null, activeLinkLimit: null, eventLogDays: null, agentLimit: null });
const TEAM: Entitlements = Object.freeze({ plan: "team", features: all(false), seatsAllowed: TEAM_FREE_SEATS, storageBytesPerSeat: 2 * GIB, activeLinkLimit: null, eventLogDays: 30, agentLimit: 3 });
const BUSINESS: Entitlements = Object.freeze({ plan: "business", features: all(true), seatsAllowed: 0, storageBytesPerSeat: 10 * GIB, activeLinkLimit: null, eventLogDays: 365, agentLimit: 10 });

/** `trial` is true while a Team org without a subscription is inside its 14-day Business trial. */
export function getEntitlements(cfg: Pick<Config, "billingMode">, org: OrgPlanFields, now = new Date()): Entitlements & { trial: boolean } {
  if (cfg.billingMode !== "hosted") return { ...UNLIMITED, trial: false };
  const trial = org.plan === "team" && org.billingStatus === "free" && org.trialEndsAt != null && org.trialEndsAt > now;
  const base = trial || org.plan === "business" ? BUSINESS : TEAM;
  const seatsAllowed = org.seatsPaid ?? (org.plan === "team" ? TEAM_FREE_SEATS : 0);
  // Like seats, the Business trial keeps Team's agent limit.
  return { ...base, plan: org.plan, seatsAllowed, trial, ...(trial ? { agentLimit: TEAM.agentLimit } : {}) };
}

export function getPersonalEntitlements(cfg: Pick<Config, "billingMode">): Entitlements {
  if (cfg.billingMode !== "hosted") return UNLIMITED;
  return { plan: "personal", features: all(false), seatsAllowed: 1, storageBytesPerSeat: GIB, activeLinkLimit: 5, eventLogDays: null, agentLimit: 0 };
}

export async function orgEntitlements(db: Db, cfg: Pick<Config, "billingMode">, orgId: string): Promise<Entitlements> {
  if (cfg.billingMode !== "hosted") return UNLIMITED;
  return getEntitlements(cfg, await db.organization.findUniqueOrThrow({ where: { id: orgId }, select: PLAN_SELECT }));
}

export const planRequired = (feature: Feature) => ({ error: "plan_required" as const, feature, requiredPlan: "business" as const });
