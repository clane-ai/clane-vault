import { useState } from "react";
import { validateAgentReveal, type AgentReveal, type RecordBody } from "@clane-vault/crypto";
import { Input } from "@/components/ui/input";
import type { MyAgent, MyAgents } from "@/features/settings/myAgents";
import { revealOptions } from "./RecordAgentsSection";
import { revealFieldLabel } from "./reveals";
import type { VaultRecord } from "./types";

const eyebrow = "font-mono text-[10.5px] font-normal tracking-[.12em] text-text-tertiary uppercase";

/** Reading without approval is offered only when every policy (rules.reveal) and the gateway (GATEWAY_REVEAL) say standing. */
export const standingOn = (d: MyAgents | undefined) => d?.rules.reveal === "standing" && d.gateway?.reveal === "standing";

/** The validator's message for the editor, or null. */
export function agentRevealError(r: AgentReveal | undefined, body: Pick<RecordBody, "type" | "fields" | "totpSecret" | "data">): string | null {
  if (!r) return null;
  try { validateAgentReveal(r, body); return null; } catch (e) { return (e as Error).message.replace(/^agent reveal:/, "Reading without approval:").replace(/^reveal fields:/, "Reading without approval:"); }
}

/** After a save: each agent listed in `agentReveal` that holds no key for the item yet is given one (the attestation checked as for Can use). */
export async function grantStandingAgents(record: VaultRecord, body: RecordBody, agents: MyAgent[], grant: (r: VaultRecord, a: MyAgent) => Promise<unknown>): Promise<void> {
  for (const id of body.agentReveal?.agents ?? []) {
    const a = agents.find((x) => x.id === id);
    if (a && !record.agentGrants?.some((g) => g.agentId === id && g.use)) await grant(record, a);
  }
}

/**
 * Reading without approval (spec §5.6), a section of the record editor: per verified personal agent, a switch and the
 * fields it may read whenever it asks. Turning one on needs the item's title typed exactly. Shown only for the owner's
 * Personal items when the gateway and every policy say standing. Untouched, `value` is the stored object as it was.
 */
export function AgentRevealEditor({ body, title, agents, value, onChange }: {
  body: RecordBody; title: string; agents: MyAgent[]; value: AgentReveal | undefined; onChange: (v: AgentReveal | undefined) => void;
}) {
  const [confirming, setConfirming] = useState<{ agentId: string; typed: string } | null>(null);
  const options = revealOptions(body);
  const listed = value?.agents ?? [];
  const [picked, setPicked] = useState<string[]>(() => value?.fields ?? (options.includes("username") ? ["username"] : []));
  const fields = value?.fields ?? picked;
  const set = (agentIds: string[], f: string[]) => onChange(agentIds.length ? { v: 1, agents: agentIds, fields: [...f].sort() } : undefined);
  return (
    <section aria-label="Reading without approval" className="flex flex-col gap-2.5">
      <h3 className={eyebrow}>Reading without approval</h3>
      <p className="text-[12.5px] font-medium text-text-primary">Can reveal lets the AI model read these fields. Clane Vault cannot take them back afterwards.</p>
      <p className="text-[12.5px] text-text-secondary">The AI model can read these fields whenever it asks. Nobody is asked first.</p>
      <ul className="flex flex-col gap-2">
        {agents.map((a) => {
          const on = listed.includes(a.id);
          const c = confirming?.agentId === a.id ? confirming : null;
          return (
            <li key={a.id} className="flex flex-col gap-1.5 rounded-[10px] border border-border-default px-3 py-2">
              <label className="flex cursor-pointer items-center gap-2 text-[13.5px] text-text-primary">
                <input type="checkbox" role="switch" aria-checked={on} checked={on} className="size-4 accent-blue-500"
                  disabled={!on && (!c || c.typed !== title || !title || fields.length === 0)}
                  onChange={(e) => { setConfirming(null); set(e.target.checked ? [...listed, a.id] : listed.filter((x) => x !== a.id), fields); }} />
                {a.name} reads without approval
              </label>
              {!on && !c && <button type="button" className="self-start text-[12.5px] font-medium text-[var(--link)] hover:underline" onClick={() => setConfirming({ agentId: a.id, typed: "" })}>Turn on…</button>}
              {!on && c && (
                <Input aria-label={`Type the item's title to let ${a.name} read without approval`} placeholder={title} value={c.typed}
                  onChange={(e) => setConfirming({ agentId: a.id, typed: e.target.value })} className="h-8 text-[13px]" />
              )}
            </li>
          );
        })}
      </ul>
      {(listed.length > 0 || confirming) && (
        <fieldset className="flex flex-col gap-1.5">
          <legend className="mb-1 text-[13px] font-medium text-text-primary">Fields</legend>
          {options.map((f) => (
            <label key={f} className="flex min-h-6 cursor-pointer items-center gap-2 text-[13px] text-text-primary">
              <input type="checkbox" className="size-4 accent-blue-500" checked={fields.includes(f)}
                onChange={(e) => { const next = e.target.checked ? [...fields, f] : fields.filter((x) => x !== f); setPicked(next); if (listed.length) set(listed, next); }} />
              {revealFieldLabel(body, f)}
            </label>
          ))}
        </fieldset>
      )}
    </section>
  );
}
