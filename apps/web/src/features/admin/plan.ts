import { useQuery } from "@tanstack/react-query";
import { ApiError } from "@/lib/api";
import { useOrgApi, useScope } from "@/lib/scope";

export type PlanFeature = "sso" | "domains" | "policyEdit" | "adminRecovery" | "risk" | "orgLogo" | "eventExport";
export interface OrgPlan {
  plan: "team" | "business"; billingStatus: string; seatsPaid: number | null; currentPeriodEnd: string | null; trialEndsAt: string | null;
  entitlements: { plan: string; trial: boolean; features: Record<PlanFeature, boolean>; seatsAllowed: number | null; storageBytesPerSeat: number | null; activeLinkLimit: number | null; eventLogDays: number | null };
  seats: { used: number; allowed: number | null }; storage: { used: number; limit: number | null };
}

/** The org's plan for owners and admins. Null: billing is off (the route is absent), so nothing is locked. */
export function useOrgPlan(enabled = true) {
  const oapi = useOrgApi();
  return useQuery({
    queryKey: ["org-plan", useScope()], enabled, retry: false, staleTime: 60_000,
    queryFn: () => oapi.get<OrgPlan>("/org/plan").catch((e: unknown) => { if (e instanceof ApiError && e.status === 404) return null; throw e; }),
  });
}

/** True only when billing is on and the plan lacks the feature. While loading or on an error nothing is locked: the server still enforces. */
export function useLocked(feature: PlanFeature, enabled = true): boolean {
  const d = useOrgPlan(enabled).data;
  return !!d && d.entitlements.features[feature] === false;
}

export const UPGRADE = "Available on the Business plan.";

export const MEMBER_OVER_LIMIT = "Your organisation is over its plan's limit. Ask an admin.";

/** The line for a plan or limit refusal (402), or null for any other error. `member`: plain members never see seat counts or upgrade prompts. */
export function planMessage(e: unknown, member = false): string | null {
  if (!(e instanceof ApiError)) return null;
  if (member && (e.code === "seat_limit" || e.code === "plan_required" || e.code === "link_limit")) return MEMBER_OVER_LIMIT;
  const b = (e.body ?? {}) as { allowed?: number; limit?: number };
  if (e.code === "seat_limit") return b.allowed == null ? "All seats are in use. An owner can add seats." : `All ${b.allowed} seats are in use. An owner can add seats.`;
  if (e.code === "link_limit") return b.limit == null ? "You've reached the limit of active one-time links. Revoke one to make another." : `You can have ${b.limit} active one-time links. Revoke one to make another.`;
  if (e.code === "plan_required") return UPGRADE;
  return null;
}
