import { useState } from "react";
import { Inbox, ShieldAlert } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { relativeTime } from "@/lib/time";
import { useMyAgents, type MyAgent } from "@/features/settings/myAgents";
import { DepositChangedError, useAgentInbox, useDeleteDeposit, useKeepDeposit, usePinPersonalGateway, type OpenedDeposit } from "./useAgentInbox";
import { grantErrorText, liveAgents } from "./RecordAgentsSection";
import { EmptyState } from "./RecordList";
import { Fingerprint } from "./people";
import type { VaultFolder } from "./types";

const DAY = 864e5;
const NO_FOLDER = "none";
const card = "flex flex-col gap-3 rounded-[12px] border border-border-default bg-card px-4 py-3.5";

/** "Deleted in n days unless you keep it." from day 60 of the 90 an unkept deposit lives. */
function expiryLine(d: OpenedDeposit, now = Date.now()) {
  if (now < new Date(d.createdAt).getTime() + 60 * DAY) return null;
  const n = Math.max(0, Math.ceil((new Date(d.expiresAt).getTime() - now) / DAY));
  return `Deleted in ${n} ${n === 1 ? "day" : "days"} unless you keep it.`;
}

function Meta({ d }: { d: OpenedDeposit }) {
  const expiry = expiryLine(d);
  return (<>
    <p className="text-[12.5px] text-text-secondary">From {d.agentName}{d.app && <> · via {d.app}</>} · <span title={new Date(d.createdAt).toLocaleString()}>{relativeTime(d.createdAt)}</span></p>
    {expiry && <p className="text-[12.5px] font-medium text-orange-ink">{expiry}</p>}
  </>);
}

/** A deposit that opened: read-only, with Keep (a folder, and whether the agent may keep using it) and Delete. */
function DepositCard({ d, folders, agent, onKept, onError }: {
  d: Extract<OpenedDeposit, { ok: true }>; folders: VaultFolder[]; agent?: MyAgent; onKept: (agentRow: boolean, agentName: string) => void; onError: (msg: string) => void;
}) {
  const [folderId, setFolderId] = useState(NO_FOLDER);
  const [grant, setGrant] = useState(true);
  const keep = useKeepDeposit();
  const del = useDeleteDeposit();
  const busy = keep.isPending || del.isPending;
  const b = d.body;
  const policy = b.agentPolicy;
  const doKeep = async () => {
    onError("");
    try {
      const r = await keep.mutateAsync({ d, folderId: folderId === NO_FOLDER ? null : folderId, agent: agent && grant ? agent : undefined });
      onKept(r.agentRow, d.agentName);
    } catch (e) { onError(e instanceof DepositChangedError ? e.message : grantErrorText(e)); }
  };
  return (
    <article aria-label={b.title} className={card}>
      <div>
        <h2 className="text-[15px] font-medium break-words text-text-primary">{b.title}</h2>
        {b.username && <p className="font-mono text-[13px] break-all text-text-primary">{b.username}</p>}
        {b.url && <p className="text-[13px] break-all text-text-secondary">{b.url}</p>}
      </div>
      <Meta d={d} />
      {policy && <p className="text-[12.5px] text-text-secondary">Agent use, <span className="italic">set by the agent</span>: {policy.hosts.join(", ")}</p>}
      <div className="flex flex-wrap items-center gap-3">
        <Select value={folderId} onValueChange={setFolderId} disabled={busy}>
          <SelectTrigger aria-label="Folder" className="h-8 min-w-[160px] text-[13px]"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value={NO_FOLDER}>No folder</SelectItem>
            {folders.filter((f) => f.kind === "private" && !f.deleted).map((f) => <SelectItem key={f.id} value={f.id}>{f.name}</SelectItem>)}
          </SelectContent>
        </Select>
        {agent && (
          <label className="flex min-h-6 cursor-pointer items-center gap-2 text-[13px] text-text-primary">
            <input type="checkbox" checked={grant} onChange={(e) => setGrant(e.target.checked)} disabled={busy} className="size-4 accent-blue-500" />
            {agent.name} can keep using this item
          </label>
        )}
      </div>
      <div className="flex gap-2">
        <Button size="sm" disabled={busy} onClick={() => void doKeep()}>{keep.isPending ? "Keeping…" : "Keep"}</Button>
        <Button size="sm" variant="ghost" disabled={busy} onClick={() => del.mutate(d.id)}>Delete</Button>
      </div>
    </article>
  );
}

/** A deposit that failed the gateway check: nothing of it was opened, and it can only be deleted. */
function RefusedCard({ d }: { d: OpenedDeposit }) {
  const del = useDeleteDeposit();
  return (
    <article aria-label={`From ${d.agentName}`} className={card}>
      <p className="flex items-center gap-2 text-[14px] font-medium text-red-500"><ShieldAlert className="size-4 shrink-0" />Not signed by the gateway — delete it</p>
      <Meta d={d} />
      <div><Button size="sm" variant="destructive" disabled={del.isPending} onClick={() => del.mutate(d.id)}>Delete</Button></div>
    </article>
  );
}

/** No personal gateway pinned on this device: nothing can be checked, so the owner pins it first (never shown as forged). */
function PinFirst({ onPinned }: { onPinned: (publicKey: string) => void }) {
  const pin = usePinPersonalGateway();
  return (
    <div className={card}>
      <p className="text-[14px] font-medium text-text-primary">Verify your gateway on this device first</p>
      <p className="text-[12.5px] text-text-secondary">This device hasn't checked your agent gateway yet, so it can't tell whether these items really come from your agents.</p>
      {pin.error && <p role="alert" className="text-[13px] text-red-500">{grantErrorText(pin.error)}</p>}
      <div><Button size="sm" disabled={pin.isPending} onClick={() => pin.mutate(undefined, { onSuccess: (g) => { if (g.pinnedNow) onPinned(g.identity.publicKey); } })}>Verify gateway</Button></div>
    </div>
  );
}

/**
 * From agents (Personal space): what my personal agents saved, waiting to be kept or deleted. Each is shown only after the
 * pinned gateway's signature over it checks out on this device.
 */
export function AgentInbox({ folders, enabled = true }: { folders: VaultFolder[]; enabled?: boolean }) {
  const q = useAgentInbox(enabled);
  const agents = liveAgents(useMyAgents(enabled).data?.agents);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  // The fingerprint of a gateway identity pinned from here (trust on first use), to compare with Settings → My agents.
  const [newGateway, setNewGateway] = useState<string | null>(null);
  const list = q.data ?? [];
  const unpinned = list.some((d) => !d.ok && d.reason === "unpinned");
  return (
    <div className="flex flex-col gap-3">
      {notice && <p role="status" className="text-[13px] text-text-primary">{notice}</p>}
      {error && <p role="alert" className="text-[13px] text-red-500">{error}</p>}
      {newGateway && <p aria-label="Gateway identity" className="text-[12.5px] text-text-secondary">This device now trusts the agent gateway with fingerprint <Fingerprint publicKey={newGateway} className="text-text-primary" />. Compare it with the one in Settings → My agents.</p>}
      {q.isLoading ? <p className="py-16 text-center text-[14px] text-text-secondary">Checking items from your agents…</p>
        : q.error ? <p role="alert" className="text-[14px] text-text-primary">Couldn't load the items from your agents.</p>
        : list.length === 0 ? <EmptyState icon={Inbox} title="Nothing from your agents" line="Items your agents save show up here until you keep or delete them." />
        : unpinned ? <PinFirst onPinned={setNewGateway} />
        : list.map((d) => d.ok
          ? <DepositCard key={`${d.id}:${d.revision}`} d={d} folders={folders} agent={agents.find((a) => a.id === d.agentId)}
              onError={(m) => { setError(m || null); if (m) setNotice(null); }}
              onKept={(agentRow, name) => setNotice(agentRow ? "Kept." : `Kept. ${name} already has 200 items, so it can't use this one. Take an item away from it, then give it this one.`)} />
          : <RefusedCard key={d.id} d={d} />)}
    </div>
  );
}
