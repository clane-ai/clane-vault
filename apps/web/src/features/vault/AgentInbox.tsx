import { useMemo, useState } from "react";
import { Navigate } from "react-router";
import { Download, Inbox, ShieldAlert } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { ApiError } from "@/lib/api";
import { useSpacePaths } from "@/lib/space";
import { relativeTime } from "@/lib/time";
import { useMyAgents, type MyAgent } from "@/features/settings/myAgents";
import { DepositChangedError, envReplaceTargets, useAgentInbox, useDeleteDeposit, useKeepDeposit, usePinPersonalGateway, useReplaceFromDeposit, type OpenedDeposit } from "./useAgentInbox";
import { downloadEnv, EnvDiff, EnvEntries } from "./EnvFile";
import { grantErrorText, liveAgents } from "./RecordAgentsSection";
import { EmptyState } from "./RecordList";
import { Fingerprint } from "./people";
import type { VaultFolder, VaultRecord } from "./types";
import { ConflictError } from "./useVault";

const DAY = 864e5;
const NO_FOLDER = "none";
const card = "flex flex-col gap-3 rounded-[12px] border border-border-default bg-card px-4 py-3.5";

/** "Deleted in n days unless you keep it." from day 60 of the 90 an unkept deposit lives. */
function expiryLine(d: OpenedDeposit, now = Date.now()) {
  if (now < new Date(d.createdAt).getTime() + 60 * DAY) return null;
  const n = Math.max(0, Math.ceil((new Date(d.expiresAt).getTime() - now) / DAY));
  return `Deleted in ${n} ${n === 1 ? "day" : "days"} unless you keep it.`;
}

/** `agentName`: from My agents for the signed agentId (the server's name for it isn't signed). */
function Meta({ d, agentName }: { d: OpenedDeposit; agentName: string }) {
  const expiry = expiryLine(d);
  return (<>
    <p className="text-[12.5px] text-text-secondary">From {agentName}{d.app && <> · via {d.app}</>} · <span title={new Date(d.createdAt).toLocaleString()}>{relativeTime(d.createdAt)}</span></p>
    {expiry && <p className="text-[12.5px] font-medium text-orange-ink">{expiry}</p>}
  </>);
}

/** A deposit that opened: read-only, with Keep (a folder, and whether the agent may keep using it) and Delete. */
/** Delete, per card: a genuine deposit asks first (it can't be undone); a failure says so here. */
function DeleteControl({ id, confirm, onBusy }: { id: string; confirm: boolean; onBusy?: boolean }) {
  const del = useDeleteDeposit();
  const [asking, setAsking] = useState(false);
  const run = () => { setAsking(false); del.mutate(id); };
  return (
    <div className="flex flex-col gap-2">
      {asking ? (
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-[13px] text-text-primary">Delete this item? It can't be undone.</span>
          <Button size="sm" variant="ghost" onClick={() => setAsking(false)}>Cancel</Button>
          <Button size="sm" variant="destructive" onClick={run}>Delete it</Button>
        </div>
      ) : (
        <div><Button size="sm" variant={confirm ? "ghost" : "destructive"} disabled={del.isPending || onBusy} onClick={() => (confirm ? setAsking(true) : run())}>Delete</Button></div>
      )}
      {del.isError && <p role="alert" className="text-[13px] text-red-500">Couldn't delete it. Try again.</p>}
    </div>
  );
}

function DepositCard({ d, folders, records, agent, agentName, onKept, onReplaced, onError }: {
  d: Extract<OpenedDeposit, { ok: true }>; folders: VaultFolder[]; records: VaultRecord[]; agent?: MyAgent; agentName: string; onKept: (agentRow: boolean, agentName: string) => void;
  onReplaced: (title: string) => void; onError: (msg: string) => void;
}) {
  const [folderId, setFolderId] = useState(NO_FOLDER);
  const [grant, setGrant] = useState(true);
  const keep = useKeepDeposit();
  const replace = useReplaceFromDeposit();
  const busy = keep.isPending || replace.isPending;
  const b = d.body;
  const policy = b.agentPolicy;
  // An env file can instead replace the contents of one of my env files (spec 10.5); the matching one is preselected.
  const { targets, match } = useMemo(() => envReplaceTargets(b, records), [b, records]);
  const [mode, setMode] = useState<"new" | "replace">(match ? "replace" : "new");
  const [targetId, setTargetId] = useState((match ?? targets[0])?.id ?? "");
  const target = targets.find((r) => r.id === targetId) ?? targets[0];
  const replacing = mode === "replace" && !!target;
  const doReplace = async () => {
    onError("");
    try { await replace.mutateAsync({ d, target: target! }); onReplaced(target!.body?.title ?? ""); }
    catch (e) { onError(e instanceof ConflictError || (e instanceof Error && e.message.startsWith("Agent policy:")) ? e.message : grantErrorText(e)); }
  };
  const doKeep = async () => {
    onError("");
    try {
      const r = await keep.mutateAsync({ d, folderId: folderId === NO_FOLDER ? null : folderId, agent: agent && grant ? agent : undefined });
      onKept(r.agentRow, agentName);
    } catch (e) { onError(e instanceof DepositChangedError ? e.message : grantErrorText(e)); }
  };
  return (
    <article aria-label={b.title} className={card}>
      <div>
        <h2 className="text-[15px] font-medium break-words text-text-primary">{b.title}</h2>
        {b.username && <p className="font-mono text-[13px] break-all text-text-primary">{b.username}</p>}
        {b.url && <p className="text-[13px] break-all text-text-secondary">{b.url}</p>}
      </div>
      <Meta d={d} agentName={agentName} />
      {b.type === "envFile" && <EnvEntries content={b.data?.content ?? ""} />}
      {policy && <p className="text-[12.5px] text-text-secondary">Agent use, <span className="italic">set by the agent</span>: {policy.hosts.join(", ")}</p>}
      {target && (
        <div role="radiogroup" aria-label="Keep how" className="flex flex-col gap-2">
          <label className="flex min-h-6 cursor-pointer items-center gap-2 text-[13px] text-text-primary">
            <input type="radio" name={`keep-${d.id}`} checked={!replacing} onChange={() => setMode("new")} disabled={busy} className="size-4 accent-blue-500" />Keep as a new item
          </label>
          <div className="flex flex-wrap items-center gap-2">
            <label className="flex min-h-6 cursor-pointer items-center gap-2 text-[13px] text-text-primary">
              <input type="radio" name={`keep-${d.id}`} checked={replacing} onChange={() => setMode("replace")} disabled={busy} className="size-4 accent-blue-500" />Replace the contents of
            </label>
            <Select value={target.id} onValueChange={(id) => { setTargetId(id); setMode("replace"); }} disabled={busy}>
              <SelectTrigger aria-label="Item to replace" className="h-8 min-w-[160px] text-[13px]"><SelectValue /></SelectTrigger>
              <SelectContent>{targets.map((r) => <SelectItem key={r.id} value={r.id}>{r.body?.title}</SelectItem>)}</SelectContent>
            </Select>
          </div>
          {replacing && (
            <div className="flex flex-col gap-1.5 pl-6">
              <EnvDiff before={target.body?.data?.content ?? ""} after={b.data?.content ?? ""} />
              <p className="text-[12.5px] text-text-primary">The current contents will be replaced.</p>
              <div><Button variant="outline" size="sm" onClick={() => downloadEnv(target.body?.data?.content ?? "", target.body?.data?.fileName, target.body?.title)}><Download className="size-3.5" />Download current</Button></div>
              <p className="text-[12.5px] text-text-secondary">The existing item keeps its own agent settings.</p>
            </div>
          )}
        </div>
      )}
      {!replacing && <div className="flex flex-wrap items-center gap-3">
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
      </div>}
      <div className="flex flex-wrap items-start gap-2">
        {replacing ? <Button size="sm" disabled={busy} onClick={() => void doReplace()}>{replace.isPending ? "Replacing…" : "Replace"}</Button>
          : <Button size="sm" disabled={busy} onClick={() => void doKeep()}>{keep.isPending ? "Keeping…" : "Keep"}</Button>}
        <DeleteControl id={d.id} confirm onBusy={busy} />
      </div>
    </article>
  );
}

/** A deposit that failed the gateway check: nothing of it was opened, and it can only be deleted. */
function RefusedCard({ d, agentName }: { d: OpenedDeposit; agentName: string }) {
  return (
    <article aria-label={`From ${agentName}`} className={card}>
      <p className="flex items-center gap-2 text-[14px] font-medium text-red-500"><ShieldAlert className="size-4 shrink-0" />Not signed by the gateway — delete it</p>
      <Meta d={d} agentName={agentName} />
      <DeleteControl id={d.id} confirm={false} />
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
export function AgentInbox({ folders, records = [], enabled = true }: { folders: VaultFolder[]; /** The Personal vault's records (env files a deposit can replace). */ records?: VaultRecord[]; enabled?: boolean }) {
  const q = useAgentInbox(enabled);
  const paths = useSpacePaths();
  const mine = useMyAgents(enabled).data?.agents;
  const agents = liveAgents(mine);
  const nameOf = (id: string) => mine?.find((a) => a.id === id)?.name ?? "an agent";
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  // The fingerprint of a gateway identity pinned from here (trust on first use), to compare with Settings → My agents.
  const [newGateway, setNewGateway] = useState<string | null>(null);
  const list = q.data ?? [];
  const unpinned = list.some((d) => !d.ok && d.reason === "unpinned");
  // Personal agents off on this server: there is no inbox.
  if (q.error instanceof ApiError && q.error.status === 404) return <Navigate to={paths.list("vault")} replace />;
  return (
    <div className="flex flex-col gap-3">
      {notice && <p role="status" className="text-[13px] text-text-primary">{notice}</p>}
      {error && <p role="alert" className="text-[13px] text-red-500">{error}</p>}
      {newGateway && <p aria-label="Gateway identity" className="text-[12.5px] text-text-secondary">This device now trusts the agent gateway with fingerprint <Fingerprint publicKey={newGateway} className="text-text-primary" />. Compare it with the one in Settings → My agents.</p>}
      {q.isPending ? <p role="status" className="py-16 text-center text-[14px] text-text-secondary">Checking items from your agents…</p>
        : q.error ? <p role="alert" className="text-[14px] text-text-primary">Couldn't load the items from your agents.</p>
        : list.length === 0 ? <EmptyState icon={Inbox} title="Nothing from your agents" line="Items your agents save show up here until you keep or delete them." />
        : unpinned ? <PinFirst onPinned={setNewGateway} />
        : list.map((d) => d.ok
          ? <DepositCard key={`${d.id}:${d.revision}`} d={d} folders={folders} records={records} agent={agents.find((a) => a.id === d.agentId)} agentName={nameOf(d.agentId)}
              onError={(m) => { setError(m || null); if (m) setNotice(null); }}
              onReplaced={(title) => setNotice(`Replaced the contents of ${title}.`)}
              onKept={(agentRow, name) => setNotice(agentRow ? "Kept." : `Kept. ${name} already has 200 items, so it can't use this one. Take an item away from it, then give it this one.`)} />
          : <RefusedCard key={d.id} d={d} agentName={nameOf(d.agentId)} />)}
    </div>
  );
}
