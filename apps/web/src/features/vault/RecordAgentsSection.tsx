import { useState } from "react";
import { Link } from "react-router";
import { ApiError } from "@/lib/api";
import { AgentAttestationError, KeyChangedError, type GatewayIdentity } from "@/lib/orgKeys";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { agentErrorText } from "@/features/admin/agents";
import { useMyAgents, type MyAgent } from "@/features/settings/myAgents";
import { AgentWarning } from "./AgentWarning";
import { PersonAvatar } from "./people";
import type { VaultRecord } from "./types";

const eyebrow = "font-mono text-[10.5px] font-normal tracking-[.12em] text-text-tertiary uppercase";
const GRANT_ERRORS: Record<string, string> = {
  agent_item_limit: "This agent already has 200 items. Take one away from it first.",
  team_record: "Items in a shared folder can't be given to a personal agent.",
  in_trash: "This item is in the trash.",
  user_not_active: "That agent isn't active any more. Check it in Settings → My agents.",
};
/** What went wrong giving an item to an agent: the attestation check's own words, else the server's refusal. */
export function grantErrorText(e: unknown): string {
  if (e instanceof AgentAttestationError && e.reason !== "gateway_changed") return e.message;
  if (e instanceof KeyChangedError) return "This agent's key changed since this device last gave it an item. Check the agent in Settings → My agents.";
  return (e instanceof ApiError ? GRANT_ERRORS[e.code] : undefined) ?? agentErrorText(e, { personal: true });
}
/** What giving an item resolves with: the gateway pin it made on the way, if any. */
export type GrantResult = { identity: GatewayIdentity; pinnedNow: boolean } | void;
/** My personal agents that can be given items: verified and live. */
export const liveAgents = (agents: MyAgent[] | undefined) => (agents ?? []).filter((a) => a.status === "active");

/**
 * Share sheet, Personal space, a record I own outside any team folder: which of my personal agents may use it. The warning
 * stands above the choices every time.
 */
export function RecordAgentsSection({ record, onGrant, onRevoke, onSetWrite }: {
  /** Resolves with the gateway pin it made, if any (`pinnedNow`: its fingerprint is shown). */
  record: VaultRecord; onGrant: (agent: MyAgent) => Promise<GrantResult>; onRevoke: (agentId: string) => Promise<unknown>;
  /** Agent can update this item (PATCH { write }). */ onSetWrite?: (agentId: string, write: boolean) => Promise<unknown>;
}) {
  const q = useMyAgents();
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [newGateway, setNewGateway] = useState<string | null>(null);
  // Loading, personal agents off (404), or a record whose key doesn't open here (nothing to seal).
  if (!q.data || !record.recordKey) return null;
  const agents = liveAgents(q.data.agents);
  const grants = new Map((record.agentGrants ?? []).filter((g) => g.use).map((g) => [g.agentId, g]));
  const run = async (fn: () => Promise<unknown>) => {
    setError(null); setBusy(true);
    try { await fn(); } catch (e) { setError(grantErrorText(e)); } finally { setBusy(false); }
  };
  const change = (a: MyAgent, v: string) => run(async () => {
    if (v !== "use") return onRevoke(a.id);
    const r = await onGrant(a);
    if (r?.pinnedNow) setNewGateway(r.identity.publicKey);
  });
  return (
    <section aria-label="Agents" className="flex flex-col gap-2.5">
      <h3 className={eyebrow}>Agents</h3>
      <AgentWarning newGateway={newGateway} />
      {agents.length === 0 ? (
        <p className="text-[13px] text-text-secondary">You have no agents yet. <Link to="/settings/agents" className="font-medium text-[var(--link)] hover:underline">Add one in My agents</Link>.</p>
      ) : <>
        {!record.body?.agentPolicy && <p className="text-[12.5px] text-text-secondary">This item has no Agent use settings yet, so the agent can't use it.</p>}
        <ul className="overflow-hidden rounded-[12px] border border-border-default bg-card">
          {agents.map((a) => (
            <li key={a.id} aria-label={a.name} className="flex flex-wrap items-center gap-3 border-b border-border-default px-4 py-3 last:border-b-0">
              <PersonAvatar id={a.id} name={a.name} agent />
              <span className="min-w-0 flex-1 truncate text-[14px] font-medium text-text-primary">{a.name}</span>
              <Select value={grants.has(a.id) ? "use" : "none"} onValueChange={(v) => void change(a, v)} disabled={busy}>
                <SelectTrigger aria-label={`Access for ${a.name}`} className="h-8 w-[118px] shrink-0 text-[13px]"><SelectValue /></SelectTrigger>
                <SelectContent align="end"><SelectItem value="none">None</SelectItem><SelectItem value="use">Can use</SelectItem></SelectContent>
              </Select>
              {/* Only where the owner's policies allow agent writes, and only for an agent that holds the item. */}
              {q.data.rules.write && grants.has(a.id) && onSetWrite && (
                <label className="flex min-h-6 w-full cursor-pointer items-center gap-2 pl-11 text-[13px] text-text-primary">
                  <input type="checkbox" checked={!!grants.get(a.id)!.write} disabled={busy} className="size-4 accent-blue-500"
                    onChange={(e) => void run(() => onSetWrite(a.id, e.target.checked))} />
                  Agent can update this item
                </label>
              )}
            </li>
          ))}
        </ul>
        {record.body?.type === "envFile" && <p className="text-[12.5px] text-text-secondary">The gateway can open this whole file. It will only send the entry you chose.</p>}
      </>}
      {error && <p role="alert" className="text-[13px] text-red-500">{error}</p>}
    </section>
  );
}
