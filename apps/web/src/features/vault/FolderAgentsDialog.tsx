import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { ApiError } from "@/lib/api";
import type { MyAgent } from "@/features/settings/myAgents";
import { AgentWarning } from "./AgentWarning";
import { SKIP } from "./GrantToAgentDialog";
import { PersonAvatar } from "./people";
import { grantErrorText, type GrantResult } from "./RecordAgentsSection";
import type { VaultFolder, VaultRecord } from "./types";

const holds = (r: VaultRecord, agentId: string) => !!r.agentGrants?.some((g) => g.agentId === agentId && g.use);

/**
 * A Personal folder's Give to agent…: Can use on every item in it, one grant per item as from the share sheet, then the
 * folder remembers the agent so items saved into it later get it too. None takes those grants away. Reading stays per item.
 */
export function FolderAgentsDialog({ folder, records, agents, me, onGrant, onRevoke, onSave, onClose }: {
  folder: VaultFolder; /** The folder's records. */ records: VaultRecord[]; agents: MyAgent[]; me: string;
  onGrant: (r: VaultRecord, a: MyAgent) => Promise<GrantResult>; onRevoke: (recordId: string, agentId: string) => Promise<unknown>;
  /** The agents the folder is given to, from now on. */ onSave: (agentIds: string[]) => Promise<unknown>; onClose: () => void;
}) {
  const [newGateway, setNewGateway] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const given = folder.agentIds ?? [];
  const items = (n: number) => `${n} ${n === 1 ? "item" : "items"}`;

  // Grants first, the folder's list last: if one fails, the folder isn't marked and choosing again picks up where it stopped.
  async function change(a: MyAgent, use: boolean) {
    setBusy(true); setError(null); setStatus(null);
    let n = 0, skipped = 0;
    try {
      if (use) {
        for (const r of records) {
          if (r.deleted || holds(r, a.id)) continue;
          if (r.permission !== "owner" || r.ownerId !== me || r.sharedBy || !r.recordKey) { skipped++; continue; }
          try { const g = await onGrant(r, a); if (g?.pinnedNow) setNewGateway(g.identity.publicKey); n++; }
          catch (e) { if (e instanceof ApiError && SKIP.has(e.code)) skipped++; else throw e; }
        }
        await onSave([...given, a.id]);
        setStatus(`${a.name} was given ${items(n)}${skipped ? `, ${skipped} skipped` : ""}. Items you add here later are given too.`);
      } else {
        for (const r of records) if (holds(r, a.id)) { await onRevoke(r.id, a.id); n++; }
        await onSave(given.filter((x) => x !== a.id));
        setStatus(`${a.name} no longer has ${items(n)} from this folder.`);
      }
    } catch (e) { setError(grantErrorText(e)); } finally { setBusy(false); }
  }

  return (
    <Dialog open onOpenChange={(o) => !o && !busy && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Give {folder.name} to an agent</DialogTitle>
          <DialogDescription>Can use: the agent can use every item in this folder through the gateway without seeing it, and items you add here later.</DialogDescription>
        </DialogHeader>
        <AgentWarning newGateway={newGateway} />
        <ul className="overflow-hidden rounded-[12px] border border-border-default bg-card">
          {agents.map((a) => (
            <li key={a.id} aria-label={a.name} className="flex items-center gap-3 border-b border-border-default px-4 py-3 last:border-b-0">
              <PersonAvatar id={a.id} name={a.name} agent />
              <span className="min-w-0 flex-1 truncate text-[14px] font-medium text-text-primary">{a.name}</span>
              <Select value={given.includes(a.id) ? "use" : "none"} onValueChange={(v) => void change(a, v === "use")} disabled={busy}>
                <SelectTrigger aria-label={`Access for ${a.name}`} className="h-8 w-[128px] shrink-0 text-[13px]"><SelectValue /></SelectTrigger>
                <SelectContent align="end"><SelectItem value="none">None</SelectItem><SelectItem value="use">Can use</SelectItem></SelectContent>
              </Select>
            </li>
          ))}
        </ul>
        {status && <p role="status" className="text-[13.5px] text-text-primary">{status}</p>}
        {error && <p role="alert" className="text-[13px] text-red-500">{error}</p>}
        <DialogFooter><Button disabled={busy} onClick={onClose}>Done</Button></DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
