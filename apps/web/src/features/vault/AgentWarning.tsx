import { AlertTriangle } from "lucide-react";

/** Exact copy (constraints: shown above the confirm button every time a human shares to an agent, never dismissable). */
export const AGENT_WARNING = "Give agents restricted credentials: a Stripe restricted key, a read-only database user, a scoped token. Never a root or owner credential. What you share here can be read by the gateway and used by whatever drives the agent.";
export const AGENT_DISCLOSURE = "Sharing with an agent makes those items readable by the gateway operator. Everything else stays end-to-end encrypted.";

/** No close button on purpose: it shows on every share to an agent. */
export function AgentWarning() {
  return (
    <div role="note" aria-label="Sharing with an agent" className="flex items-start gap-2 rounded-[10px] border border-[var(--orange-tint-border)] bg-orange-tint px-3 py-2 text-[12.5px] leading-snug text-text-secondary">
      <AlertTriangle className="mt-px size-3.5 shrink-0 text-orange-ink" />
      <span className="flex flex-col gap-1"><span className="text-text-primary">{AGENT_WARNING}</span><span>{AGENT_DISCLOSURE}</span></span>
    </div>
  );
}
