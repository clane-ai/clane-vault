import { Lock } from "lucide-react";
import { useOrgPlan, UPGRADE, type PlanFeature } from "./plan";

export function LockLine() {
  return <p className="flex items-center gap-2 text-[13.5px] text-text-secondary"><Lock className="size-4 shrink-0 text-text-tertiary" aria-hidden />{UPGRADE}</p>;
}

/** Shows the form, or one lock line when the org's plan lacks the feature. Waits for the plan so a locked form never flashes. */
export function PlanGate({ feature, children }: { feature: PlanFeature; children: React.ReactNode }) {
  const q = useOrgPlan();
  if (q.isPending) return null;
  return q.data && q.data.entitlements.features[feature] === false ? <LockLine /> : <>{children}</>;
}

/** Owners' and admins' header line while the Business trial runs. */
export function TrialLine() {
  const d = useOrgPlan().data;
  if (!d?.entitlements.trial) return null;
  const n = Math.max(1, Math.ceil((new Date(d.trialEndsAt ?? 0).getTime() - Date.now()) / 86_400_000));
  return <p className="border-b border-border-default bg-well px-4 py-1.5 text-[12.5px] text-text-secondary">Business trial: {n} {n === 1 ? "day" : "days"} left</p>;
}
