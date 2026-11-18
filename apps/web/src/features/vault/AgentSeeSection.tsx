import { useState } from "react";
import { Link } from "react-router";
import { RadioGroup } from "radix-ui";
import { validateAgentReveal, validateRevealFields, type AgentReveal, type RecordBody } from "@clane-vault/crypto";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Switch } from "@/components/ui/switch";
import { cn } from "@/lib/utils";
import { useMyAgents, type MyAgent, type MyAgents } from "@/features/settings/myAgents";
import { AgentWarning } from "./AgentWarning";
import { PersonAvatar } from "./people";
import { defaultRevealFields, liveAgents, revealErrorText, revealOffered, RevealFieldPicker, type GrantResult } from "./RecordAgentsSection";
import { revealFieldLabel } from "./reveals";
import type { VaultRecord } from "./types";

const eyebrow = "font-mono text-[10.5px] font-normal tracking-[.12em] text-text-tertiary uppercase";

/** Reading without asking works only when every policy (rules.reveal) and the gateway (GATEWAY_REVEAL) say standing. */
// eslint-disable-next-line react-refresh/only-export-components
export const standingOn = (d: MyAgents | undefined) => d?.rules.reveal === "standing" && d.gateway?.reveal === "standing";

/** The validator's message for the record editor (an edit that takes away a field the item lets agents read), or null. */
// eslint-disable-next-line react-refresh/only-export-components
export function agentRevealError(r: AgentReveal | undefined, body: Pick<RecordBody, "type" | "fields" | "totpSecret" | "data">): string | null {
  if (!r) return null;
  try { validateAgentReveal(r, body); return null; } catch (e) { return (e as Error).message.replace(/^agent reveal:/, "Reading without asking:").replace(/^reveal fields:/, "Reading without asking:"); }
}

/** After a save: each agent listed in `agentReveal` that holds no key for the item yet is given one (the attestation checked as for Can use). */
// eslint-disable-next-line react-refresh/only-export-components
export async function grantStandingAgents(record: VaultRecord, body: RecordBody, agents: MyAgent[], grant: (r: VaultRecord, a: MyAgent) => Promise<unknown>): Promise<void> {
  for (const id of body.agentReveal?.agents ?? []) {
    const a = agents.find((x) => x.id === id);
    if (a && !record.agentGrants?.some((g) => g.agentId === id && g.use)) await grant(record, a);
  }
}

/** Why an agent can't read without asking here, or at all: an organisation's policy, the server's setting, or neither (null). */
// eslint-disable-next-line react-refresh/only-export-components
export function readingLimit(d: MyAgents): string | null {
  if (d.rules.reveal === "off") return "Your organisation has turned reading values off.";
  if (!d.gateway) return "The agent gateway can't be reached right now, so this can't be changed.";
  if (!d.gateway.reveal || d.gateway.reveal === "off") return "Reading values is off on this server.";
  if (d.rules.reveal === "approval") return "Your organisation requires approval for each read.";
  if (d.gateway.reveal === "approval") return "This server requires approval for each read.";
  return null;
}

type Mode = "standing" | "ask";
class SaveFailed extends Error {}
const MODES: { mode: Mode; label: string; line: string }[] = [
  { mode: "standing", label: "Without asking", line: "It reads these fields whenever it needs them." },
  { mode: "ask", label: "Ask me each time", line: "You approve each read in the web app." },
];
const WARNING = "The AI model reads these fields. Clane Vault can't take back what it has read.";
const list = (items: string[]) => new Intl.ListFormat("en", { style: "long", type: "conjunction" }).format(items);

/**
 * "Let the AI see this value" (the Agent use sheet, my own Personal items). Turning it on for an agent is the consent: by
 * default the agent then reads the chosen fields without asking (the item's encrypted `agentReveal`, and the item's key, as
 * *Can use*); *Ask me each time* is the approval way (a stub sealed to the agent, no key). An organisation's policy or the
 * server's setting can require approval or switch reading off, and the section says so. Each change is saved at once, not
 * with the sheet's Save. The first time for an item, one dialog asks.
 */
export function AgentSeeSection({ record, onSaveBody, onGrant, onRevoke, onSetReveal, onUnreveal }: {
  record: VaultRecord;
  /** The record editor's save: the whole body, re-encrypted in the browser. */ onSaveBody: (body: RecordBody) => Promise<void>;
  /** Without asking needs the item's key at the gateway, as Can use does. */ onGrant: (agent: MyAgent) => Promise<GrantResult>; onRevoke: (agentId: string) => Promise<unknown>;
  /** Ask me each time: the fields, as a stub sealed to the agent. */ onSetReveal: (agent: MyAgent, fields: string[]) => Promise<GrantResult>; onUnreveal: (agentId: string) => Promise<unknown>;
}) {
  const q = useMyAgents();
  const [picking, setPicking] = useState<{ agentId: string; mode: Mode; fields: string[] } | null>(null);
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [newGateway, setNewGateway] = useState<string | null>(null);
  const body = record.body;
  if (!q.data || !body || !record.recordKey) return null;
  const offered = revealOffered(q.data);
  const standingOk = standingOn(q.data);
  const limit = readingLimit(q.data);
  const stored = body.agentReveal;
  const asks = new Map((record.agentGrants ?? []).filter((g) => g.reveal?.length).map((g) => [g.agentId, g.reveal!]));
  const modeOf = (id: string): Mode | null => (stored?.agents.includes(id) ? "standing" : asks.has(id) ? "ask" : null);
  const fieldsOf = (id: string) => (modeOf(id) === "standing" ? stored!.fields : asks.get(id) ?? []);
  const anyOn = !!stored?.agents.length || asks.size > 0;
  // Where it is no longer offered, what is on can still be turned off.
  const agents = liveAgents(q.data.agents).filter((a) => offered || modeOf(a.id));
  const labels = (fields: string[]) => fields.map((f) => revealFieldLabel(body, f));
  const pinned = (r: GrantResult) => { if (r?.pinnedNow) setNewGateway(r.identity.publicKey); };
  /** The body with `agents` reading `fields` without asking; nobody left takes the setting away. */
  const withStanding = (ids: string[], fields: string[]): RecordBody => {
    const { agentReveal: _dropped, ...rest } = body;
    return ids.length ? { ...rest, agentReveal: { v: 1, agents: ids, fields: [...fields].sort() } } : rest;
  };
  const run = async (fn: () => Promise<unknown>) => {
    setError(null); setBusy(true);
    try { await fn(); setPicking(null); }
    catch (e) { setError(e instanceof SaveFailed ? e.message : revealErrorText(e)); }
    finally { setBusy(false); setConfirming(false); }
  };
  // The editor's save rejects with the words to show.
  const saveBody = (next: RecordBody) => onSaveBody(next).catch((e: unknown) => { throw new SaveFailed(e instanceof Error ? e.message : "Couldn't save. Try again."); });
  const apply = (a: MyAgent, mode: Mode, fields: string[]) => run(async () => {
    validateRevealFields(fields, body);
    const was = modeOf(a.id);
    if (mode === "standing") {
      const next = withStanding([...new Set([...(stored?.agents ?? []), a.id])], fields);
      await saveBody(next);
      await grantStandingAgents(record, next, [a], (_r, x) => onGrant(x).then(pinned));
      // The same fields as an approval stub too: where an organisation or the server requires approval, the agent asks
      // for them instead of reading nothing.
      pinned(await onSetReveal(a, fields));
    } else {
      pinned(await onSetReveal(a, fields));
      if (was === "standing") await saveBody(withStanding(stored!.agents.filter((x) => x !== a.id), stored!.fields));
    }
  });
  const turnOff = (a: MyAgent) => run(async () => {
    if (modeOf(a.id) === "standing") {
      await saveBody(withStanding(stored!.agents.filter((x) => x !== a.id), stored!.fields));
      // The key was only there for reading: an item with no Agent use settings can't be used in requests anyway.
      const g = record.agentGrants?.find((x) => x.agentId === a.id);
      if (g?.use && !g.write && !body.agentPolicy) await onRevoke(a.id);
    }
    if (asks.has(a.id)) await onUnreveal(a.id);
  });
  const open = (a: MyAgent) => {
    const was = modeOf(a.id);
    const mode: Mode = was ?? (standingOk ? "standing" : "ask");
    // Agents that read without asking share one list of fields.
    setPicking({ agentId: a.id, mode, fields: was ? fieldsOf(a.id) : mode === "standing" && stored ? stored.fields : defaultRevealFields(body) });
  };
  const picked = picking ? agents.find((a) => a.id === picking.agentId) : undefined;
  return (
    <section aria-label="Let the AI see this value" className="flex flex-col gap-2.5">
      <h3 className={eyebrow}>Let the AI see this value</h3>
      <p className="text-[12.5px] leading-snug text-text-secondary">
        For values an agent has to read itself, like a username or a one-time code. Off until you turn it on. Turning it on is your consent:
        the agent then reads the fields you choose whenever it needs them, unless you pick <span className="text-text-primary">Ask me each time</span>.
      </p>
      {limit && <p role="note" aria-label="Reading values here" className="rounded-[10px] border border-[var(--orange-tint-border)] bg-orange-tint px-3 py-2 text-[12.5px] leading-snug text-text-primary">{limit}</p>}
      {!offered && agents.length === 0 ? null : agents.length === 0 ? (
        <p className="text-[13px] text-text-secondary">You have no agents yet. <Link to="/settings/agents" className="font-medium text-[var(--link)] hover:underline">Add one in My agents</Link>.</p>
      ) : (
        <ul className="overflow-hidden rounded-[12px] border border-border-default bg-card">
          {agents.map((a) => {
            const mode = modeOf(a.id);
            const p = picking?.agentId === a.id ? picking : null;
            return (
              <li key={a.id} aria-label={a.name} className="flex flex-col gap-2.5 border-b border-border-default px-4 py-3 last:border-b-0">
                <div className="flex items-center gap-3">
                  <PersonAvatar id={a.id} name={a.name} agent />
                  <span className="min-w-0 flex-1 truncate text-[14px] font-medium text-text-primary">{a.name}</span>
                  <Switch aria-label={`Let ${a.name} see values from this item`} checked={!!mode || !!p} disabled={busy || (!mode && !offered)}
                    onCheckedChange={(v) => (v ? open(a) : mode ? void turnOff(a) : setPicking(null))} />
                </div>
                {mode && !p && (
                  <p className="pl-11 text-[12.5px] text-text-secondary">
                    <span className="font-medium text-text-primary">{mode === "standing" ? "Reads without asking" : "Asks first"}</span>: {labels(fieldsOf(a.id)).join(", ")}
                    {/* Approval required here: it asks for the fields its approval stub names, or reads nothing without one. */}
                    {mode === "standing" && !standingOk && <span className="text-orange-ink"> ({offered && asks.has(a.id) ? "asks first for now" : "paused"})</span>}
                    {offered && <> · <button type="button" className="font-medium text-[var(--link)] hover:underline" disabled={busy} onClick={() => open(a)}>Change</button></>}
                  </p>
                )}
                {p && <>
                  <RadioGroup.Root aria-label={`How ${a.name} reads`} value={p.mode} disabled={busy} className="flex flex-col gap-1.5"
                    onValueChange={(m) => setPicking({ ...p, mode: m as Mode, fields: m === "standing" && stored ? stored.fields : p.fields })}>
                    {MODES.map((m) => (
                      <RadioGroup.Item key={m.mode} value={m.mode} disabled={m.mode === "standing" && !standingOk}
                        className={cn("flex items-start gap-2.5 rounded-[10px] border border-border-default px-3 py-2 text-left outline-none transition-[border-color,background-color] duration-150",
                          "hover:border-border-strong focus-visible:ring-3 focus-visible:ring-ring/25 disabled:pointer-events-none disabled:opacity-55",
                          "data-[state=checked]:border-[var(--blue-selected-border)] data-[state=checked]:bg-blue-tint")}>
                        <span aria-hidden="true" className={cn("mt-[3px] grid size-3.5 shrink-0 place-items-center rounded-full border", p.mode === m.mode ? "border-blue-500" : "border-border-strong")}>
                          {p.mode === m.mode && <span className="size-1.5 rounded-full bg-blue-500" />}
                        </span>
                        <span className="min-w-0">
                          <span className="block text-[13px] font-medium text-text-primary">{m.label}</span>
                          <span className="block text-[12.5px] leading-snug text-text-secondary">{m.mode === "standing" && !standingOk ? limit : m.line}</span>
                        </span>
                      </RadioGroup.Item>
                    ))}
                  </RadioGroup.Root>
                  {p.mode === "standing" && (stored?.agents.some((x) => x !== a.id) ?? false) && <p className="text-[12.5px] text-text-secondary">Agents that read without asking share one list of fields.</p>}
                  <AgentWarning />
                  <RevealFieldPicker body={body} fields={p.fields} onChange={(fields) => setPicking({ ...p, fields })} busy={busy} onCancel={() => setPicking(null)}
                    // The first time for this item, one dialog asks; after that the choice here is the answer.
                    onSave={() => (anyOn ? void apply(a, p.mode, p.fields) : setConfirming(true))} warning={WARNING}
                    note={p.mode === "standing" && !body.agentPolicy ? "The agent gateway gets this item's key to read it, as it does for an item an agent can use."
                      : "Prefer use in requests. Let it see only what can't be sent in an HTTP call and is easy to change."} />
                </>}
              </li>
            );
          })}
        </ul>
      )}
      {newGateway && <AgentWarning newGateway={newGateway} />}
      {error && <p role="alert" className="text-[13px] text-red-500">{error}</p>}
      <Dialog open={confirming && !!picking && !!picked} onOpenChange={(o) => !o && !busy && setConfirming(false)}>
        {picking && picked && (
          <DialogContent showCloseButton={false}>
            <DialogHeader>
              <DialogTitle>Let {picked.name} see this?</DialogTitle>
              <DialogDescription className="text-[14px] leading-relaxed text-text-primary">
                {picking.mode === "standing"
                  ? `${picked.name} will be able to read ${list(labels(picking.fields))} of ${body.title} whenever it needs them, without asking you.`
                  : `${picked.name} will be able to read ${list(labels(picking.fields))} of ${body.title} after you approve each read.`}
                {" "}Clane Vault can't take back what it has read.
              </DialogDescription>
            </DialogHeader>
            <div className="flex justify-end gap-2">
              <Button type="button" variant="ghost" disabled={busy} onClick={() => setConfirming(false)}>Cancel</Button>
              <Button type="button" disabled={busy} onClick={() => void apply(picked, picking.mode, picking.fields)}>{busy ? "Allowing…" : "Allow"}</Button>
            </div>
          </DialogContent>
        )}
      </Dialog>
    </section>
  );
}
