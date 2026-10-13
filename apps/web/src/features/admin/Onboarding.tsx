import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router";
import { ArrowRight, Check, X } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { useOrgApi, useScope } from "@/lib/scope";
import { useSpacePaths } from "@/lib/space";
import { cn } from "@/lib/utils";
import { ONBOARDING_KEY } from "./provisioning";

type StepId = "invite" | "group" | "policies" | "recovery" | "sso";
interface OnboardingView { show: boolean; dismissed: boolean; done: number; total: number; steps: { id: StepId; done: boolean }[] }

const STEPS: Record<StepId, { title: string; text: string; action: string }> = {
  invite: { title: "Invite your people", text: "Paste addresses or upload a CSV, with a role and groups.", action: "Invite people" },
  group: { title: "Create a group", text: "Share team folders with groups instead of one person at a time.", action: "Open Groups" },
  policies: { title: "Set policies", text: "Master password rules, auto-lock, sharing links and IP limits.", action: "Open Policies" },
  recovery: { title: "Turn on admin recovery", text: "So admins can restore access when someone forgets their master password.", action: "Open Admin recovery" },
  sso: { title: "Set up sign-in and email", text: "Single sign-on, email domain auto-join, or your own email delivery.", action: "Open Single sign-on" },
};

/**
 * The checklist a new organisation's admins see on People (docs/provisioning.md): what's done comes from the server
 * (real state, not clicks), each step links to its page, and it can be dismissed for the whole organisation.
 */
export function OnboardingChecklist({ onInvite }: { onInvite: () => void }) {
  const oapi = useOrgApi();
  const qc = useQueryClient();
  const paths = useSpacePaths();
  const KEY = [ONBOARDING_KEY, useScope()];
  const q = useQuery({ queryKey: KEY, queryFn: () => oapi.get<OnboardingView>("/admin/onboarding") });
  const dismiss = useMutation({ mutationFn: () => oapi.put("/admin/onboarding", { dismissed: true }),
    onSuccess: () => { qc.setQueryData<OnboardingView>(KEY, (v) => (v ? { ...v, dismissed: true, show: false } : v)); toast.success("Checklist dismissed"); },
    onError: () => toast.error("Couldn't dismiss. Try again.") });
  const d = q.data;
  if (!d?.show) return null;
  const to: Record<Exclude<StepId, "invite">, string> = { group: paths.admin("groups"), policies: paths.admin("org/policies"), recovery: paths.admin("org/recovery"), sso: paths.admin("org/sso") };

  return (
    <section aria-label="Set up your organisation" className="rounded-[14px] border border-border-default bg-card shadow-[var(--shadow-card)]">
      <div className="flex items-start gap-3 border-b border-border-default px-4 py-3">
        <div className="min-w-0 flex-1">
          <h2 className="font-display text-[15px] font-semibold tracking-[-0.01em] text-text-primary">Set up your organisation</h2>
          <p className="text-[12.5px] text-text-secondary"><span className="font-mono">{d.done}/{d.total}</span> done</p>
        </div>
        <div className="mt-1 h-1.5 w-24 overflow-hidden rounded-full bg-well max-[560px]:hidden" aria-hidden="true">
          <div className="h-full rounded-full bg-green-600" style={{ width: `${(d.done / d.total) * 100}%` }} />
        </div>
        <Button type="button" variant="ghost" size="icon-sm" aria-label="Dismiss checklist" onClick={() => dismiss.mutate()} disabled={dismiss.isPending}><X /></Button>
      </div>
      <ol className="flex flex-col">
        {d.steps.map((s) => {
          const step = STEPS[s.id];
          return (
            <li key={s.id} aria-label={step.title} className="flex items-center gap-3 border-b border-border-subtle px-4 py-2.5 last:border-b-0">
              <span aria-hidden="true" className={cn("grid size-5 shrink-0 place-items-center rounded-full border", s.done ? "border-green-600 bg-green-600 text-white" : "border-border-strong bg-card")}>
                {s.done && <Check className="size-3" strokeWidth={3} />}
              </span>
              <span className="min-w-0 flex-1">
                <span className={cn("block text-[13.5px] font-medium", s.done ? "text-text-secondary line-through decoration-text-tertiary" : "text-text-primary")}>{step.title}<span className="sr-only">{s.done ? " (done)" : " (to do)"}</span></span>
                <span className="block text-[12.5px] text-text-secondary">{step.text}</span>
              </span>
              {!s.done && (s.id === "invite"
                ? <Button type="button" variant="outline" size="sm" onClick={onInvite}>{step.action}</Button>
                : <Button asChild variant="ghost" size="sm"><Link to={to[s.id]}>{step.action}<ArrowRight className="size-3.5" /></Link></Button>)}
            </li>
          );
        })}
      </ol>
    </section>
  );
}
