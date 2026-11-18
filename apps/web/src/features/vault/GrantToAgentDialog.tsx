import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { ApiError } from "@/lib/api";
import type { MyAgent } from "@/features/settings/myAgents";
import { AgentWarning } from "./AgentWarning";
import { grantErrorText, type GrantResult } from "./RecordAgentsSection";
import type { VaultRecord } from "./types";

/** Refusals that mean "this one can't be given" rather than "stop": counted as skipped. */
const SKIP = new Set(["already_shared", "team_record", "in_trash", "not_found"]);

/**
 * The list's multi-select → Give to agent…: one agent, the warning, then the items one by one. Items already given to it,
 * or not mine to give, are skipped; any other refusal (an attestation that doesn't check out, the item limit) stops.
 */
export function GrantToAgentDialog({ records, agents, me, onGrant, onClose, onDone = onClose }: {
  records: VaultRecord[]; agents: MyAgent[]; me: string; onGrant: (r: VaultRecord, a: MyAgent) => Promise<GrantResult>; onClose: () => void;
  /** Closed after giving: the list's selection is cleared. */ onDone?: () => void;
}) {
  const [newGateway, setNewGateway] = useState<string | null>(null);
  const [agentId, setAgentId] = useState(agents.length === 1 ? agents[0].id : "");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ given: number; skipped: number } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const agent = agents.find((a) => a.id === agentId);
  const n = records.length;

  async function give() {
    if (!agent) return;
    setBusy(true); setError(null);
    let given = 0, skipped = 0;
    try {
      for (const r of records) {
        const mine = r.permission === "owner" && r.ownerId === me && !r.sharedBy && !r.deleted && !!r.recordKey;
        if (!mine || r.agentGrants?.some((g) => g.agentId === agent.id && g.use)) { skipped++; continue; }
        try { const g = await onGrant(r, agent); if (g?.pinnedNow) setNewGateway(g.identity.publicKey); given++; }
        catch (e) { if (e instanceof ApiError && SKIP.has(e.code)) skipped++; else throw e; }
      }
    } catch (e) { setError(grantErrorText(e)); }
    finally { setResult({ given, skipped }); setBusy(false); }
  }

  return (
    <Dialog open onOpenChange={(o) => !o && !busy && (result ? onDone() : onClose())}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Give {n} {n === 1 ? "item" : "items"} to an agent</DialogTitle>
          <DialogDescription>The agent can use them through the gateway without seeing them.</DialogDescription>
        </DialogHeader>
        <AgentWarning newGateway={newGateway} />
        <fieldset className="flex flex-col gap-2" disabled={busy || !!result}>
          <legend className="mb-1 text-[13px] font-medium text-text-primary">Agent</legend>
          {agents.map((a) => (
            <label key={a.id} className="flex cursor-pointer items-center gap-2 rounded-[10px] border border-border-default px-3 py-2 text-[14px]">
              <input type="radio" name="agent" value={a.id} checked={agentId === a.id} onChange={() => setAgentId(a.id)} />
              <span>{a.name}</span>
            </label>
          ))}
        </fieldset>
        {result && <p role="status" className="text-[13.5px] text-text-primary">{result.given} given, {result.skipped} skipped</p>}
        {error && <p role="alert" className="text-[13px] text-red-500">{error}</p>}
        <DialogFooter>
          {result ? <Button onClick={onDone}>Done</Button> : <>
            <Button variant="outline" disabled={busy} onClick={onClose}>Cancel</Button>
            <Button disabled={!agent || busy} onClick={() => void give()}>{busy ? "Giving…" : "Give"}</Button>
          </>}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
