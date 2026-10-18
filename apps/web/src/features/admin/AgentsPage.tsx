import { useState, type FormEvent } from "react";
import { useQuery } from "@tanstack/react-query";
import { Bot } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { SectionPage } from "@/components/SectionLayout";
import { AgentAttestationError, fingerprintOf, gatewayPinStatus, pinnedGateway, verifyAgentKey } from "@/lib/orgKeys";
import { useSession } from "@/lib/session";
import { relativeTime } from "@/lib/time";
import { Chip } from "@/features/vault/people";
import type { VaultFolder } from "@/features/vault/types";
import { AgentConnectSheet } from "./AgentConnectSheet";
import { AgentVerifyDialog } from "./AgentVerifyDialog";
import { LockLine } from "./PlanLock";
import { agentLimitLine, useOrgPlan } from "./plan";
import { AGENTS_OFF, agentErrorText, agentsOff, gatewayIdentity, PIN_LABEL, STATUS_LABEL, useAgents, useCreateAgent, useGateway, useRevokeAgent, useUpdateAgent, type Agent, type Gateway, type Rotation } from "./agents";

const card = "rounded-[14px] border border-border-default bg-card shadow-[var(--shadow-card)]";
const mono = "font-mono text-[11.5px] tracking-[.02em] text-text-tertiary";
type ToVerify = { id: string; name: string; publicKey: string; attestation: string };

const useFingerprint = (key: string | undefined) =>
  useQuery({ queryKey: ["fingerprint", key], enabled: !!key, staleTime: Infinity, queryFn: () => fingerprintOf(key!).catch(() => "—") }).data;
/** The expiry's day in local time (as `expiryOf` builds it), so an edit round trip never moves it. */
const pad = (n: number) => String(n).padStart(2, "0");
const dateInput = (iso: string | null) => { if (!iso) return ""; const d = new Date(iso); return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`; };
/** The end of the chosen day, local time. */
const expiryOf = (day: string) => (day ? new Date(`${day}T23:59:59`).toISOString() : null);

/** Name and optional expiry: a new agent (then the verify dialog) or an edit. */
function AgentForm({ agent, onDone, onClose }: { agent?: Agent; onDone: (created?: ToVerify) => void; onClose: () => void }) {
  const [name, setName] = useState(agent?.name ?? "");
  const [expiry, setExpiry] = useState(dateInput(agent?.expiresAt ?? null));
  const [error, setError] = useState<string | null>(null);
  const create = useCreateAgent(), update = useUpdateAgent();
  const busy = create.isPending || update.isPending;
  const submit = async (e: FormEvent) => {
    e.preventDefault(); setError(null);
    try {
      if (agent) {
        const changed = { ...(name.trim() !== agent.name ? { name: name.trim() } : {}), ...(expiry !== dateInput(agent.expiresAt) ? { expiresAt: expiryOf(expiry) } : {}) };
        if (Object.keys(changed).length) await update.mutateAsync({ id: agent.id, ...changed });
        onDone();
      }
      else { const c = await create.mutateAsync({ name: name.trim(), expiresAt: expiryOf(expiry) }); onDone({ id: c.id, name: c.name, publicKey: c.publicKey, attestation: c.attestation }); }
    } catch (err) { setError(agentErrorText(err)); }
  };
  return (
    <Dialog open onOpenChange={(o) => { if (!o && !busy) onClose(); }}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{agent ? `Edit ${agent.name}` : "New agent"}</DialogTitle>
          <DialogDescription>{agent ? "An expired agent can't use anything until you set a later date." : "The gateway creates the agent's key. You'll check its fingerprint next."}</DialogDescription>
        </DialogHeader>
        <form className="flex flex-col gap-3" onSubmit={(e) => void submit(e)}>
          <div className="flex flex-col gap-1"><Label htmlFor="agent-name">Name</Label><Input id="agent-name" value={name} maxLength={60} onChange={(e) => setName(e.target.value)} required /></div>
          <div className="flex flex-col gap-1"><Label htmlFor="agent-expiry">Expires (optional)</Label><Input id="agent-expiry" type="date" value={expiry} onChange={(e) => setExpiry(e.target.value)} /></div>
          {error && <p role="alert" className="text-[13px] text-red-500">{error}</p>}
          <div className="flex justify-end gap-2">
            <Button type="button" variant="outline" onClick={onClose} disabled={busy}>Cancel</Button>
            <Button type="submit" disabled={busy || !name.trim()}>{agent ? "Save" : "Create"}</Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

/** Revoke: a confirmation, then the folders the gateway could open for it (names from this vault). */
function RevokeDialog({ agent, folders, onClose }: { agent: Agent; folders: VaultFolder[]; onClose: () => void }) {
  const revoke = useRevokeAgent();
  const [rotate, setRotate] = useState<Rotation | null>(null);
  const [error, setError] = useState<string | null>(null);
  const go = async () => { setError(null); try { setRotate((await revoke.mutateAsync({ id: agent.id })).rotate); } catch (e) { setError(agentErrorText(e)); } };
  const nameOf = (id: string) => folders.find((f) => f.id === id)?.name ?? "A folder you can't open";
  return (
    <Dialog open onOpenChange={(o) => { if (!o && !revoke.isPending) onClose(); }}>
      <DialogContent className="sm:max-w-[460px]">
        <DialogHeader>
          <DialogTitle>Revoke {agent.name}?</DialogTitle>
          <DialogDescription>{rotate ? `${agent.name} is revoked. Its tokens and connected apps stopped working.` : "Its key, tokens and connected apps stop working at once. This can't be undone."}</DialogDescription>
        </DialogHeader>
        {rotate ? (
          <div className="flex flex-col gap-2 text-[13px]">
            {rotate.folders.length > 0 ? (<>
              <p className="text-text-primary">The gateway could open these folders for this agent. Rotate the credentials in them.</p>
              <ul className="list-disc pl-5">{rotate.folders.map((f) => <li key={f.id}>{nameOf(f.id)}</li>)}</ul>
            </>) : null}
            {rotate.records > 0 && <p className="text-text-secondary">{rotate.records === 1 ? "1 item" : `${rotate.records} items`} in all could be opened, including items shared with it directly.</p>}
            {!rotate.folders.length && !rotate.records && <p className="text-text-secondary">It couldn't open anything, so there's nothing to rotate.</p>}
            <div className="flex justify-end"><Button onClick={onClose}>Done</Button></div>
          </div>
        ) : (<>
          {error && <p role="alert" className="text-[13px] text-red-500">{error}</p>}
          <div className="flex justify-end gap-2">
            <Button variant="outline" onClick={onClose} disabled={revoke.isPending}>Cancel</Button>
            <Button variant="destructive" onClick={() => void go()} disabled={revoke.isPending}>Revoke</Button>
          </div>
        </>)}
      </DialogContent>
    </Dialog>
  );
}

function AgentRow({ agent, gateway, onVerify, onConnect, onEdit, onRevoke }: { agent: Agent; gateway: Gateway | undefined } & Record<"onVerify" | "onConnect" | "onEdit" | "onRevoke", () => void>) {
  const { user, org } = useSession();
  const pinned = user && org ? pinnedGateway(user.id, org.id) : null;
  // A gateway identity change invalidates every attestation by the old one: those agents must be enrolled again.
  const attest = useQuery({
    queryKey: ["agent-attestation", org?.id, user?.id, agent.id, agent.publicKey, agent.attestation, pinned?.keyId, pinned?.publicKey],
    enabled: !!user && !!org && !!pinned && agent.status !== "revoked",
    queryFn: () => verifyAgentKey(user!.id, org!.id, { id: agent.id, kind: "agent", publicKey: agent.publicKey, attestation: agent.attestation })
      .then(() => null, (e: unknown) => (e instanceof AgentAttestationError ? e.reason : "invalid")),
  });
  const reEnrol = (agent.status === "active" || agent.status === "expired") && !!attest.data && attest.data !== "unpinned";
  const agentFp = useFingerprint(agent.publicKey);
  const gatewayFp = useFingerprint(gateway?.identityPublicKey);
  const signedBy = agent.attestation.split(".")[1];
  const pin = gateway && user && org ? gatewayPinStatus(user.id, org.id, gatewayIdentity(gateway)) : null;
  const tone = reEnrol ? "orange" : agent.status === "active" ? "green" : agent.status === "awaiting_verification" ? "blue" : "neutral";
  const facts = [
    agent.expiresAt ? `${agent.status === "expired" ? "Expired" : "Expires"} ${relativeTime(agent.expiresAt)}` : "No expiry",
    agent.lastUsedAt ? `Last used ${relativeTime(agent.lastUsedAt)}` : "Never used",
    `${agent.folders.length} ${agent.folders.length === 1 ? "folder" : "folders"}`,
    `${agent.groups.length} ${agent.groups.length === 1 ? "group" : "groups"}`,
  ];
  return (
    <li aria-label={agent.name} className="flex flex-wrap items-start gap-3 border-b border-border-subtle px-4 py-3 last:border-b-0">
      <span className="grid size-8 shrink-0 place-items-center rounded-full bg-well text-text-secondary"><Bot className="size-4" /></span>
      <div className="flex min-w-0 flex-1 flex-col gap-1">
        <div className="flex flex-wrap items-center gap-2">
          <span className="truncate text-[14px] font-medium text-text-primary">{agent.name}</span>
          <Chip tone={tone}>{reEnrol ? "Needs re-enrolment" : STATUS_LABEL[agent.status]}</Chip>
        </div>
        <span className={mono} title="Agent key fingerprint">Agent {agentFp ?? "…"}</span>
        <span className={mono} title="Gateway identity fingerprint">
          Gateway {gateway && signedBy === gateway.identityKeyId ? `${gatewayFp ?? "…"} · ${pin ? PIN_LABEL[pin.status] : ""}` : "an earlier gateway identity"}
        </span>
        <span className="text-[12.5px] text-text-secondary">{facts.join(" · ")}</span>
      </div>
      {agent.status !== "revoked" && (
        <div className="flex flex-wrap gap-1.5">
          {agent.status === "awaiting_verification" && <Button size="sm" aria-label={`Verify ${agent.name}`} onClick={onVerify}>Verify</Button>}
          {agent.status === "active" && !reEnrol && <Button size="sm" variant="outline" aria-label={`Connect ${agent.name}`} onClick={onConnect}>Connect</Button>}
          <Button size="sm" variant="ghost" aria-label={`Edit ${agent.name}`} onClick={onEdit}>Edit</Button>
          <Button size="sm" variant="ghost" aria-label={`Revoke ${agent.name}`} onClick={onRevoke}>Revoke</Button>
        </div>
      )}
    </li>
  );
}

/**
 * Admin → Agents (docs/design/2026-10-17-agent-access.md §4.7): agents that use credentials through the gateway without
 * seeing them. Create, verify both fingerprints, connect, revoke with the folders to rotate.
 */
export default function AgentsPage({ folders }: { folders: VaultFolder[] }) {
  const { org } = useSession();
  const q = useAgents();
  const gw = useGateway();
  const plan = useOrgPlan().data;
  const [form, setForm] = useState<{ agent?: Agent } | null>(null);
  const [verifying, setVerifying] = useState<ToVerify | null>(null);
  const [connecting, setConnecting] = useState<string | null>(null);
  const [revoking, setRevoking] = useState<Agent | null>(null);
  const limit = plan?.agents;
  const atLimit = !!limit && limit.allowed !== null && limit.used >= limit.allowed;
  const connectAgent = q.data?.find((a) => a.id === connecting);

  const action = atLimit ? (plan.plan === "team" ? <LockLine /> : <p className="text-[13.5px] text-text-secondary">{agentLimitLine(limit.allowed)}</p>)
    : <Button onClick={() => setForm({})}>New agent</Button>;
  return (
    <SectionPage title="Agents" sub={org?.name}>
      <div className="flex flex-col gap-4">
        <p className="text-[13.5px] leading-relaxed text-text-secondary">
          Agents use credentials you share with them through the gateway, without ever seeing them. Share only restricted credentials.
        </p>
        {agentsOff(q.error) ? <p className="text-[13.5px] text-text-secondary">{AGENTS_OFF}</p> : <div>{action}</div>}
        {agentsOff(q.error) ? null : q.isError ? <p role="alert" className="text-[13px] text-red-500">{agentErrorText(q.error)}</p>
          : q.data && q.data.length === 0 ? <p className="text-[13.5px] text-text-secondary">No agents yet.</p>
          : q.data && (
            <ul className={card} aria-label="Agents">
              {q.data.map((a) => (
                <AgentRow key={a.id} agent={a} gateway={gw.data}
                  onVerify={() => setVerifying({ id: a.id, name: a.name, publicKey: a.publicKey, attestation: a.attestation })}
                  onConnect={() => setConnecting(a.id)} onEdit={() => setForm({ agent: a })} onRevoke={() => setRevoking(a)} />
              ))}
            </ul>
          )}
      </div>
      {form && <AgentForm agent={form.agent} onClose={() => setForm(null)} onDone={(created) => { setForm(null); if (created) setVerifying(created); else toast.success("Saved"); }} />}
      {verifying && <AgentVerifyDialog agent={verifying} onClose={() => setVerifying(null)} />}
      {connectAgent && gw.data && <AgentConnectSheet agent={connectAgent} url={gw.data.url} onClose={() => setConnecting(null)} />}
      {revoking && <RevokeDialog agent={revoking} folders={folders} onClose={() => setRevoking(null)} />}
    </SectionPage>
  );
}
