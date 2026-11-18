import { useState, type FormEvent } from "react";
import { Link } from "react-router";
import type { RecordBody } from "@clane-vault/crypto";
import { Button } from "@/components/ui/button";
import { Sheet, SheetBody, SheetCloseButton, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Switch } from "@/components/ui/switch";
import { isAgent } from "@/lib/orgKeys";
import { cn } from "@/lib/utils";
import { useMyAgents, type MyAgent } from "@/features/settings/myAgents";
import { AgentPolicyEditor, agentPolicyError } from "./AgentPolicyEditor";
import { AgentWarning } from "./AgentWarning";
import { Chip, PersonAvatar } from "./people";
import { defaultRevealFields, liveAgents, revealErrorText, revealOffered, RevealFieldPicker, type GrantResult } from "./RecordAgentsSection";
import { RecordAvatar } from "./RecordAvatar";
import { revealFieldLabel } from "./reveals";
import type { Person, VaultFolder, VaultRecord } from "./types";

const eyebrow = "font-mono text-[10.5px] font-normal tracking-[.12em] text-text-tertiary uppercase";
const alertBox = "rounded-[9px] border border-[var(--red-tint-border)] bg-red-tint px-3 py-2 text-[13px] text-red-500";

/** What the header button shows: Use is a policy on the item, See is an agent that may read some of its fields. */
export type AgentUseStatus = "Off" | "Use" | "See" | "Use + See";
export function agentUseStatus(record: Pick<VaultRecord, "body" | "agentGrants">): AgentUseStatus {
  const use = !!record.body?.agentPolicy;
  const see = !!record.agentGrants?.some((g) => g.reveal?.length) || !!record.body?.agentReveal?.agents.length;
  return use ? (see ? "Use + See" : "Use") : see ? "See" : "Off";
}
/** The dot beside the status: green while values stay sealed, orange once an AI model may read one. */
export const statusDot = (s: AgentUseStatus) => (s === "Off" ? "bg-border-strong" : s === "Use" ? "bg-green-600" : "bg-orange-500");

/** One agent that holds the item, and how. */
export interface AgentAccess { id: string; name: string; use: boolean; /** Labels of the fields it may read. */ see: string[]; standing?: boolean; write?: boolean; via?: string }
/**
 * Who the summary lists, from what the vault already knows: in Personal my agents' grants on the item; in an organisation
 * the agents among its direct shares (`people` tells them from persons) and its team folder's members.
 */
export function agentAccess(record: VaultRecord, o: { myAgents: MyAgent[]; people?: Person[]; teamFolder: VaultFolder | null }): AgentAccess[] {
  const body = record.body;
  const mine = (record.agentGrants ?? []).filter((g) => g.use || g.reveal?.length).map((g) => ({
    id: g.agentId, name: o.myAgents.find((a) => a.id === g.agentId)?.name ?? "An agent", use: g.use, write: g.write,
    see: (g.reveal ?? []).map((f) => (body ? revealFieldLabel(body, f) : f)), standing: !!body?.agentReveal?.agents.includes(g.agentId) }));
  const direct = (record.sharedWith ?? []).filter((s) => { const p = o.people?.find((x) => x.id === s.userId); return !!p && isAgent(p); })
    .map((s) => ({ id: s.userId, name: s.name, use: true, see: [], via: "Shared directly" }));
  const folder = (o.teamFolder?.members ?? []).filter((m) => isAgent(m) && !direct.some((d) => d.id === m.userId))
    .map((m) => ({ id: m.userId, name: m.name, use: true, see: [], via: `via ${o.teamFolder!.name}` }));
  return [...mine, ...direct, ...folder];
}

/** The top of the sheet: is it on, and which agents hold the item in which modes. */
function Summary({ status, access, onManageAccess }: { status: AgentUseStatus; access: AgentAccess[]; onManageAccess?: () => void }) {
  const users = access.filter((a) => a.use).length;
  const line = status === "Off" ? "Off. No agent can use this item."
    : !status.startsWith("Use") ? "Agents can't use this item in requests. Reading is on for the fields below."
    : users === 0 ? "Ready, but no agent has this item yet." : `${users === 1 ? "1 agent" : `${users} agents`} can use this item.`;
  return (
    <section aria-label="Status" className="overflow-hidden rounded-[12px] border border-border-default bg-app">
      <p className="flex items-center gap-2.5 px-4 py-3 text-[13.5px] font-medium text-text-primary">
        <span aria-hidden="true" className={cn("size-2 shrink-0 rounded-full", statusDot(status))} />
        <span className="min-w-0 flex-1">{line}</span>
        {onManageAccess && <button type="button" className="shrink-0 text-[13px] font-medium text-[var(--link)] hover:underline" onClick={onManageAccess}>Manage in Share</button>}
      </p>
      {access.length > 0 && (
        <ul aria-label="Agents with this item" className="border-t border-border-default bg-card">
          {access.map((a) => (
            <li key={a.id} aria-label={a.name} className="flex flex-wrap items-center gap-x-2.5 gap-y-1.5 border-b border-border-default px-4 py-2.5 last:border-b-0">
              <PersonAvatar id={a.id} name={a.name} size={24} agent />
              <span className="min-w-0 flex-1 truncate text-[13.5px] text-text-primary">{a.name}{a.via && <span className="text-text-secondary"> · {a.via}</span>}</span>
              <span className="flex flex-wrap items-center justify-end gap-1">
                {a.use && <Chip tone="green">Use</Chip>}
                {a.write && <Chip>Update</Chip>}
                {a.see.length > 0 && <Chip tone="orange">See: {a.see.join(", ")}</Chip>}
                {a.standing && <Chip tone="orange">Reads without approval</Chip>}
              </span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

/**
 * "Let the AI see this value" (the Agent use sheet, Personal items I own): per agent a switch, off for every item until
 * turned on, and the *Can reveal* field picker. Each change is sent at once through the share sheet's own calls (a stub
 * sealed to the agent), not with the sheet's Save. Shown only where reading values is offered (my policies and the gateway).
 */
export function AgentSeeSection({ record, onSetReveal, onUnreveal }: {
  record: VaultRecord; onSetReveal: (agent: MyAgent, fields: string[]) => Promise<GrantResult>; onUnreveal: (agentId: string) => Promise<unknown>;
}) {
  const q = useMyAgents();
  const [picking, setPicking] = useState<{ agentId: string; fields: string[] } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [newGateway, setNewGateway] = useState<string | null>(null);
  const body = record.body;
  if (!q.data || !body || !record.recordKey) return null;
  const shown = new Map((record.agentGrants ?? []).filter((g) => g.reveal?.length).map((g) => [g.agentId, g.reveal!]));
  const offered = revealOffered(q.data);
  // Where it is no longer offered, what is on can still be turned off.
  const agents = liveAgents(q.data.agents).filter((a) => offered || shown.has(a.id));
  if (!offered && agents.length === 0) return null;
  const run = async (fn: () => Promise<unknown>) => {
    setError(null); setBusy(true);
    try { await fn(); setPicking(null); } catch (e) { setError(revealErrorText(e)); } finally { setBusy(false); }
  };
  return (
    <section aria-label="Let the AI see this value" className="flex flex-col gap-2.5">
      <h3 className={eyebrow}>Let the AI see this value</h3>
      <p className="text-[12.5px] leading-snug text-text-secondary">
        Off unless you turn it on, for values an agent has to read itself, like a username or a one-time code.
        Each read still needs your approval in the web app, unless your server's operator has turned on reading without approval.
      </p>
      {agents.length === 0 ? (
        <p className="text-[13px] text-text-secondary">You have no agents yet. <Link to="/settings/agents" className="font-medium text-[var(--link)] hover:underline">Add one in My agents</Link>.</p>
      ) : (
        <ul className="overflow-hidden rounded-[12px] border border-border-default bg-card">
          {agents.map((a) => {
            const on = shown.has(a.id);
            const p = picking?.agentId === a.id ? picking : null;
            return (
              <li key={a.id} aria-label={a.name} className="flex flex-col gap-2.5 border-b border-border-default px-4 py-3 last:border-b-0">
                <div className="flex items-center gap-3">
                  <PersonAvatar id={a.id} name={a.name} agent />
                  <span className="min-w-0 flex-1 truncate text-[14px] font-medium text-text-primary">{a.name}</span>
                  <Switch aria-label={`Let ${a.name} see values from this item`} checked={on || !!p} disabled={busy || (!on && !offered)}
                    onCheckedChange={(v) => (v ? setPicking({ agentId: a.id, fields: defaultRevealFields(body) }) : on ? void run(() => onUnreveal(a.id)) : setPicking(null))} />
                </div>
                {on && !p && (
                  <p className="pl-11 text-[12.5px] text-text-secondary">
                    Can read: {shown.get(a.id)!.map((f) => revealFieldLabel(body, f)).join(", ")}
                    {offered && <> · <button type="button" className="font-medium text-[var(--link)] hover:underline" disabled={busy}
                      onClick={() => setPicking({ agentId: a.id, fields: shown.get(a.id)! })}>Change fields</button></>}
                  </p>
                )}
                {p && <>
                  <AgentWarning />
                  <RevealFieldPicker body={body} fields={p.fields} onChange={(fields) => setPicking({ ...p, fields })} busy={busy} onCancel={() => setPicking(null)}
                    onSave={() => void run(async () => { const r = await onSetReveal(a, p.fields); if (r?.pinnedNow) setNewGateway(r.identity.publicKey); })}
                    note="Prefer use in requests. Let it see only what can't be sent in an HTTP call and is easy to change." />
                </>}
              </li>
            );
          })}
        </ul>
      )}
      {newGateway && <AgentWarning newGateway={newGateway} />}
      {error && <p role="alert" className="text-[13px] text-red-500">{error}</p>}
    </section>
  );
}

function Form({ record, body, access, pathsLocked, onSave, onClose, onManageAccess, see }: {
  record: VaultRecord; body: RecordBody; access: AgentAccess[]; pathsLocked: boolean; onSave: (body: RecordBody) => Promise<void>; onClose: () => void;
  onManageAccess?: () => void; see?: React.ReactNode;
}) {
  // As it was when the sheet opened: a refetch decrypts the body into new objects, which is not an edit.
  const [stored] = useState(body.agentPolicy);
  const [policy, setPolicy] = useState(stored);
  const [busy, setBusy] = useState(false);
  const [removing, setRemoving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // The editor's own check (agentPolicyError), against the item as stored.
  const policyError = agentPolicyError(policy, body);
  const dirty = policy !== stored;
  const save = async (next: RecordBody) => {
    setBusy(true); setError(null);
    try { await onSave(next); } catch (e) { setError((e as Error).message); setRemoving(false); } finally { setBusy(false); }
  };
  const submit = (e: FormEvent) => { e.preventDefault(); if (policy && !policyError && dirty) void save({ ...body, agentPolicy: policy }); };
  const remove = () => { const { agentPolicy: _dropped, ...rest } = body; void save(rest); };
  return (
    <form onSubmit={submit} className="flex h-full min-h-0 flex-col" noValidate>
      <SheetHeader className="items-start gap-3 py-5">
        <div className="flex min-w-0 items-center gap-3">
          <RecordAvatar title={body.title} kind={body.type} size={36} />
          <div className="min-w-0">
            <SheetTitle className="truncate text-[17px] leading-tight">Agent use: {body.title}</SheetTitle>
            <SheetDescription className="mt-0.5 text-[12.5px] leading-snug text-text-secondary">Agents send this credential only to these hosts. They never see it.</SheetDescription>
          </div>
        </div>
        <SheetCloseButton className="-mt-1" />
      </SheetHeader>
      <SheetBody className="gap-6">
        <Summary status={agentUseStatus(record)} access={access} onManageAccess={onManageAccess} />
        <section aria-label="Use in requests" className="flex flex-col gap-3">
          <h3 className={eyebrow}>Use in requests</h3>
          <AgentPolicyEditor body={body} value={stored} onChange={setPolicy} pathsLocked={pathsLocked} />
          {policyError && <p role="alert" className={alertBox}>{policyError}</p>}
          {dirty && !policy && <p className="text-[12.5px] text-text-secondary">Add at least one host{stored ? ", or choose Remove agent use" : ""}.</p>}
        </section>
        {see}
        {error && <p role="alert" className={alertBox}>{error}</p>}
      </SheetBody>
      <SheetFooter>
        {removing ? <>
          <span className="mr-auto min-w-0 text-[13px] text-text-primary">Remove agent use? Agents can no longer use this item.</span>
          <Button type="button" variant="ghost" disabled={busy} onClick={() => setRemoving(false)}>Keep</Button>
          <Button type="button" variant="destructive" disabled={busy} onClick={remove}>{busy ? "Removing…" : "Remove"}</Button>
        </> : <>
          {stored && <Button type="button" variant="ghost" className="mr-auto -ml-2 text-red-500 hover:bg-red-tint hover:text-red-500" disabled={busy} onClick={() => setRemoving(true)}>Remove agent use</Button>}
          <Button type="button" variant="ghost" onClick={onClose}>Cancel</Button>
          <Button type="submit" disabled={busy || !dirty || !policy || !!policyError} className="min-w-20">{busy ? "Saving…" : "Save"}</Button>
        </>}
      </SheetFooter>
    </form>
  );
}

/**
 * Agent use, from the record panel's header: who holds the item, the usage policy (hosts, how the secret is sent, which
 * field) and, for my own Personal items, what an AI model may read (`see`). Save writes the policy into the record's
 * encrypted body through `onSave` (the editor's own save); the server never gets it in plain text.
 */
export function AgentUseSheet({ record, open, onClose, onSave, access, pathsLocked = false, onManageAccess, see }: {
  record: VaultRecord; open: boolean; onClose: () => void;
  /** The whole body with the policy set or removed. Rejects with the message to show. */ onSave: (body: RecordBody) => Promise<void>;
  access: AgentAccess[]; /** Methods and paths need the Business plan. */ pathsLocked?: boolean;
  /** Opens the share sheet, where agents are given the item (owners). */ onManageAccess?: () => void;
  /** The "Let the AI see this value" section, where it applies. */ see?: React.ReactNode;
}) {
  return (
    <Sheet open={open} onOpenChange={(o) => !o && onClose()}>
      <SheetContent side="right" showCloseButton={false} className="data-[side=right]:w-full data-[side=right]:sm:max-w-[480px]">
        {/* A new revision is a new form: what was typed never lands on another version of the item. */}
        {record.body && <Form key={`${record.id}-${record.revision}`} record={record} body={record.body} access={access} pathsLocked={pathsLocked}
          onSave={onSave} onClose={onClose} onManageAccess={onManageAccess} see={see} />}
      </SheetContent>
    </Sheet>
  );
}
