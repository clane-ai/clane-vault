import { useState, type FormEvent } from "react";
import type { RecordBody } from "@clane-vault/crypto";
import { Button } from "@/components/ui/button";
import { Sheet, SheetBody, SheetCloseButton, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { isAgent } from "@/lib/orgKeys";
import { cn } from "@/lib/utils";
import type { MyAgent } from "@/features/settings/myAgents";
import { AgentPolicyEditor, agentPolicyError } from "./AgentPolicyEditor";
import { Chip, PersonAvatar } from "./people";
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
/** See is on, and every agent that may read asks first (*Ask me each time*): none reads without asking. The header marks it. */
export const agentAsksFirst = (record: Pick<VaultRecord, "body" | "agentGrants">) =>
  !!record.agentGrants?.some((g) => g.reveal?.length) && !record.body?.agentReveal?.agents.length;
/** The dot beside the status: green while values stay sealed, orange once an AI model may read one. */
export const statusDot = (s: AgentUseStatus) => (s === "Off" ? "bg-border-strong" : s === "Use" ? "bg-green-600" : "bg-orange-500");

/** One agent that holds the item, and how. */
export interface AgentAccess { id: string; name: string; use: boolean; /** Labels of the fields it may read. */ see: string[]; /** It reads them without asking (the item's `agentReveal`); else each read is approved. */ standing?: boolean; write?: boolean; via?: string }
/**
 * Who the summary lists, from what the vault already knows: in Personal my agents' grants on the item; in an organisation
 * the agents among its direct shares (`people` tells them from persons) and its team folder's members.
 */
export function agentAccess(record: VaultRecord, o: { myAgents: MyAgent[]; people?: Person[]; teamFolder: VaultFolder | null }): AgentAccess[] {
  const body = record.body;
  const mine = (record.agentGrants ?? []).filter((g) => g.use || g.reveal?.length).map((g) => {
    const standing = !!body?.agentReveal?.agents.includes(g.agentId);
    return { id: g.agentId, name: o.myAgents.find((a) => a.id === g.agentId)?.name ?? "An agent", use: g.use, write: g.write, standing,
      see: (standing ? body!.agentReveal!.fields : g.reveal ?? []).map((f) => (body ? revealFieldLabel(body, f) : f)) };
  });
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
    <section aria-label="Status" className="shrink-0 overflow-hidden rounded-[12px] border border-border-default bg-app">
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
                {a.see.length > 0 && <Chip>{a.standing ? "Without asking" : "Asks first"}</Chip>}
              </span>
            </li>
          ))}
        </ul>
      )}
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
        {/* A changed stored policy is a new form (what was typed never lands on another version of it); a See change, which also saves the body, is not. */}
        {record.body && <Form key={`${record.id}:${JSON.stringify(record.body.agentPolicy ?? null)}`} record={record} body={record.body} access={access} pathsLocked={pathsLocked}
          onSave={onSave} onClose={onClose} onManageAccess={onManageAccess} see={see} />}
      </SheetContent>
    </Sheet>
  );
}
