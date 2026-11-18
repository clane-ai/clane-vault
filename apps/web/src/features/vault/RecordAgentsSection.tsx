import { useState } from "react";
import { Link } from "react-router";
import { coreKeysOf, dataKeysOf, envKeys, validateRevealFields, type RecordBody } from "@clane-vault/crypto";
import { Button } from "@/components/ui/button";
import { ApiError } from "@/lib/api";
import { AgentAttestationError, KeyChangedError, type GatewayIdentity } from "@/lib/orgKeys";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { agentErrorText } from "@/features/admin/agents";
import { useMyAgents, type MyAgent } from "@/features/settings/myAgents";
import { AgentWarning } from "./AgentWarning";
import { PersonAvatar } from "./people";
import { revealFieldLabel } from "./reveals";
import type { VaultRecord } from "./types";

const eyebrow = "font-mono text-[10.5px] font-normal tracking-[.12em] text-text-tertiary uppercase";
const GRANT_ERRORS: Record<string, string> = {
  agent_item_limit: "This agent already has 200 items. Take one away from it first.",
  team_record: "Items in a shared folder can't be given to a personal agent.",
  in_trash: "This item is in the trash.",
  user_not_active: "That agent isn't active any more. Check it in Settings → My agents.",
  reveal_disabled: "Your organisation's policy doesn't let agents read values.",
};
/** What went wrong giving an item to an agent: the attestation check's own words, else the server's refusal. */
export function grantErrorText(e: unknown): string {
  if (e instanceof AgentAttestationError && e.reason !== "gateway_changed") return e.message;
  if (e instanceof KeyChangedError) return "This agent's key changed since this device last gave it an item. Check the agent in Settings → My agents.";
  return (e instanceof ApiError ? GRANT_ERRORS[e.code] : undefined) ?? agentErrorText(e, { personal: true });
}
/** What giving an item resolves with: the gateway pin it made on the way, if any. */
export type GrantResult = { identity: GatewayIdentity; pinnedNow: boolean } | void;
/**
 * What *Can reveal* may name on this record: its own fields that have a value (never the one-time-code seed: `totp` is the
 * current code; never a TOTP custom field; for a .env file, its keys and never the whole file).
 */
export function revealOptions(body: RecordBody): string[] {
  if (body.type === "envFile") return envKeys(body.data?.content ?? "").map((k) => `env:${k}`);
  const core = (coreKeysOf(body.type) as string[]).filter((k) => k !== "totpSecret" && body[k as "username"]);
  return [...core, ...(body.totpSecret ? ["totp"] : []), ...dataKeysOf(body.type).filter((k) => body.data?.[k]).map((k) => `data.${k}`),
    ...(body.fields ?? []).filter((f) => f.kind !== "totp").map((f) => `field:${f.id}`), ...(body.notes ? ["notes"] : [])];
}
type Mode = "none" | "use" | "reveal" | "both";
const usesKey = (m: Mode) => m === "use" || m === "both";
const reveals = (m: Mode) => m === "reveal" || m === "both";

/** My personal agents that can be given items: verified and live. */
export const liveAgents = (agents: MyAgent[] | undefined) => (agents ?? []).filter((a) => a.status === "active");

/**
 * Share sheet, Personal space, a record I own outside any team folder: which of my personal agents may use it. The warning
 * stands above the choices every time.
 */
export function RecordAgentsSection({ record, onGrant, onRevoke, onSetWrite, onSetReveal, onUnreveal }: {
  /** Resolves with the gateway pin it made, if any (`pinnedNow`: its fingerprint is shown). */
  record: VaultRecord; onGrant: (agent: MyAgent) => Promise<GrantResult>; onRevoke: (agentId: string) => Promise<unknown>;
  /** Agent can update this item (PATCH { write }). */ onSetWrite?: (agentId: string, write: boolean) => Promise<unknown>;
  /** *Can reveal*: a stub { title, type, fields } sealed to the agent; no record key. */
  onSetReveal?: (agent: MyAgent, fields: string[]) => Promise<GrantResult>; onUnreveal?: (agentId: string) => Promise<unknown>;
}) {
  const q = useMyAgents();
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [newGateway, setNewGateway] = useState<string | null>(null);
  /** The field picker open for one agent: the mode it will save and the ticked fields. */
  const [picking, setPicking] = useState<{ agentId: string; mode: Mode; fields: string[] } | null>(null);
  // Loading, personal agents off (404), or a record whose key doesn't open here (nothing to seal).
  if (!q.data || !record.recordKey) return null;
  const agents = liveAgents(q.data.agents);
  const grants = new Map((record.agentGrants ?? []).filter((g) => g.use).map((g) => [g.agentId, g]));
  const shown = new Map((record.agentGrants ?? []).filter((g) => g.reveal?.length).map((g) => [g.agentId, g.reveal!]));
  // Only where the owner's policies, the gateway (GATEWAY_REVEAL) and the caller all allow it.
  const revealOn = q.data.rules.reveal !== "off" && !!q.data.gateway?.reveal && q.data.gateway.reveal !== "off" && !!onSetReveal && !!onUnreveal && !!record.body;
  const modeOf = (id: string): Mode => (grants.has(id) ? (shown.has(id) ? "both" : "use") : shown.has(id) ? "reveal" : "none");
  const run = async (fn: () => Promise<unknown>) => {
    setError(null); setBusy(true);
    try { await fn(); } catch (e) { setError(e instanceof Error && e.message.startsWith("reveal fields:") ? "Choose fields this item has." : grantErrorText(e)); } finally { setBusy(false); }
  };
  /** Moves the agent to `mode`: the use grant first, then the stub (fields given) or its removal. */
  const apply = (a: MyAgent, mode: Mode, fields?: string[]) => run(async () => {
    const was = modeOf(a.id);
    if (fields) validateRevealFields(fields, record.body!);
    if (usesKey(mode) && !usesKey(was)) { const r = await onGrant(a); if (r?.pinnedNow) setNewGateway(r.identity.publicKey); }
    if (!usesKey(mode) && usesKey(was)) await onRevoke(a.id);
    if (reveals(mode) && fields) { const r = await onSetReveal!(a, fields); if (r?.pinnedNow) setNewGateway(r.identity.publicKey); }
    if (!reveals(mode) && reveals(was)) await onUnreveal!(a.id);
    setPicking(null);
  });
  const change = (a: MyAgent, v: string) => {
    const mode = v as Mode;
    if (reveals(mode) && !reveals(modeOf(a.id))) {
      const opts = revealOptions(record.body!);
      return setPicking({ agentId: a.id, mode, fields: record.body!.type !== "envFile" && opts.includes("username") ? ["username"] : [] });
    }
    setPicking(null);
    return apply(a, mode);
  };
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
              <Select value={picking?.agentId === a.id ? picking.mode : modeOf(a.id)} onValueChange={(v) => void change(a, v)} disabled={busy}>
                <SelectTrigger aria-label={`Access for ${a.name}`} className="h-8 w-[168px] shrink-0 text-[13px]"><SelectValue /></SelectTrigger>
                <SelectContent align="end">
                  <SelectItem value="none">None</SelectItem><SelectItem value="use">Can use</SelectItem>
                  {(revealOn || shown.has(a.id)) && <><SelectItem value="reveal">Can reveal</SelectItem><SelectItem value="both">Can use and reveal</SelectItem></>}
                </SelectContent>
              </Select>
              {record.body?.agentReveal?.agents.includes(a.id) && <span className="w-full pl-11 text-[12.5px] font-medium text-orange-ink">Reads without approval</span>}
              {shown.has(a.id) && picking?.agentId !== a.id && (
                <p className="w-full pl-11 text-[12.5px] text-text-secondary">
                  Can read: {shown.get(a.id)!.map((f) => revealFieldLabel(record.body!, f)).join(", ")}
                  {revealOn && <> · <button type="button" className="font-medium text-[var(--link)] hover:underline" disabled={busy}
                    onClick={() => setPicking({ agentId: a.id, mode: modeOf(a.id), fields: shown.get(a.id)! })}>Change fields</button></>}
                </p>
              )}
              {picking?.agentId === a.id && (
                <fieldset className="flex w-full flex-col gap-2 pl-11" disabled={busy}>
                  <legend className="mb-1 text-[13px] font-medium text-text-primary">Fields the agent may read</legend>
                  {revealOptions(record.body!).map((f) => (
                    <label key={f} className="flex min-h-6 cursor-pointer items-center gap-2 text-[13px] text-text-primary">
                      <input type="checkbox" className="size-4 accent-blue-500" checked={picking.fields.includes(f)}
                        onChange={(e) => setPicking({ ...picking, fields: e.target.checked ? [...picking.fields, f] : picking.fields.filter((x) => x !== f) })} />
                      {revealFieldLabel(record.body!, f)}
                    </label>
                  ))}
                  <p className="text-[12.5px] font-medium text-text-primary">Can reveal lets the AI model read these fields. Clane Vault cannot take them back afterwards.</p>
                  <p className="text-[12.5px] text-text-secondary">Prefer Can use. Reveal only what can't be sent in an HTTP call and is easy to change.</p>
                  <div className="flex gap-2">
                    <Button size="sm" disabled={busy || picking.fields.length === 0} onClick={() => void apply(a, picking.mode, picking.fields)}>Save</Button>
                    <Button size="sm" variant="outline" disabled={busy} onClick={() => setPicking(null)}>Cancel</Button>
                  </div>
                </fieldset>
              )}
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
