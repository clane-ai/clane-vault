import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Bot } from "lucide-react";
import { toast } from "sonner";
import { verifyPersonalAgentAttestation } from "@clane-vault/crypto";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { SectionPage } from "@/components/SectionLayout";
import { ApiError } from "@/lib/api";
import { accountPublicKeyOf, fingerprintOf, PERSONAL_SLOT, pinnedGateway } from "@/lib/orgKeys";
import { TotpStepUpPanel } from "@/features/auth/TotpStepUp";
import { useSession } from "@/lib/session";
import { relativeTime } from "@/lib/time";
import { Chip } from "@/features/vault/people";
import type { VaultRecord } from "@/features/vault/types";
import { AgentConnectSheet } from "@/features/admin/AgentConnectSheet";
import { AgentVerifyDialog } from "@/features/admin/AgentVerifyDialog";
import { AgentForm, type ToVerify } from "@/features/admin/AgentsPage";
import { AGENTS_OFF, agentErrorText, agentsOff, personalAgentsOffLine, STATUS_LABEL } from "@/features/admin/agents";
import { useMyAgentActivity, useMyAgents, useRevealEmail, useRevokeMyAgent, type MyAgent, type Rotation } from "./myAgents";

const card = "rounded-[14px] border border-border-default bg-card shadow-[var(--shadow-card)]";
const mono = "font-mono text-[11.5px] tracking-[.02em] text-text-tertiary";
type Titles = (id: string | null) => string;

/** Revoke: a confirmation, then the items the gateway could open for it (titles from this vault), to rotate. */
function RevokeDialog({ agent, titleOf, onClose }: { agent: MyAgent; titleOf: Titles; onClose: () => void }) {
  const revoke = useRevokeMyAgent();
  const [rotate, setRotate] = useState<Rotation | null>(null);
  const [error, setError] = useState<string | null>(null);
  const go = async () => { setError(null); try { setRotate((await revoke.mutateAsync({ id: agent.id })).rotate); } catch (e) { setError(agentErrorText(e, { personal: true })); } };
  return (
    <Dialog open onOpenChange={(o) => { if (!o && !revoke.isPending) onClose(); }}>
      <DialogContent className="sm:max-w-[460px]">
        <DialogHeader>
          <DialogTitle>Revoke {agent.name}?</DialogTitle>
          <DialogDescription>{rotate ? `${agent.name} is revoked. Its tokens and connected apps stopped working.` : "Its key, tokens and connected apps stop working at once. This can't be undone."}</DialogDescription>
        </DialogHeader>
        {rotate ? (
          <div className="flex flex-col gap-2 text-[13px]">
            {rotate.records.length > 0 ? (<>
              <p className="text-text-primary">The gateway could open these items. Change the credentials in them.</p>
              <ul className="list-disc pl-5">{rotate.records.map((r) => <li key={r.id}>{titleOf(r.id)}</li>)}</ul>
            </>) : <p className="text-text-secondary">It couldn't open anything, so there's nothing to rotate.</p>}
            {rotate.revealed.length > 0 && (<>
              <p className="text-text-primary">These fields were shown to the AI model. Change them.</p>
              <ul className="list-disc pl-5">{rotate.revealed.map((r) => <li key={r.id}>{titleOf(r.id)}: {r.fields.join(", ")}</li>)}</ul>
            </>)}
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

/** The agent's own events (owner-visible, newest first). */
function ActivityDialog({ agent, titleOf, onClose }: { agent: MyAgent; titleOf: Titles; onClose: () => void }) {
  const q = useMyAgentActivity(agent.id);
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose(); }}>
      <DialogContent className="sm:max-w-[520px]">
        <DialogHeader><DialogTitle>{agent.name}: activity</DialogTitle><DialogDescription>What this agent did with your items, newest first.</DialogDescription></DialogHeader>
        {q.isError ? <p role="alert" className="text-[13px] text-red-500">{agentErrorText(q.error, { personal: true })}</p>
          : !q.data ? <p className="text-[13px] text-text-secondary">Loading…</p>
          : q.data.events.length === 0 ? <p className="text-[13px] text-text-secondary">Nothing yet.</p>
          : (
            <ul className="flex max-h-[60vh] flex-col divide-y divide-border-subtle overflow-y-auto text-[13px]">
              {q.data.events.map((e) => (
                <li key={e.id} className="flex items-center gap-2 py-2">
                  <span className="font-mono text-[12px] text-text-primary">{e.action}</span>
                  {e.recordId && <span className="min-w-0 flex-1 truncate text-text-secondary">{titleOf(e.recordId)}</span>}
                  <span className="ml-auto text-[12px] text-text-tertiary">{relativeTime(e.at)}</span>
                </li>
              ))}
            </ul>
          )}
      </DialogContent>
    </Dialog>
  );
}

function MyAgentRow({ agent, canConnect, on }: { agent: MyAgent; canConnect: boolean; on: Record<"verify" | "connect" | "activity" | "edit" | "revoke", () => void> }) {
  const { user, keys } = useSession();
  const pinned = user ? pinnedGateway(user.id, PERSONAL_SLOT) : null;
  // As on Admin → Agents: an attestation the personal pin didn't make, or over the owner's earlier account key, needs enrolling again.
  // The owner key is derived from the unlocked private key, so a server listing a stale one can't hide that (locked: no check).
  const attest = useQuery({
    queryKey: ["my-agent-attestation", user?.id, agent.id, agent.publicKey, agent.attestation, pinned?.keyId, pinned?.publicKey, !!keys],
    enabled: !!pinned && !!keys && (agent.status === "active" || agent.status === "suspended"),
    queryFn: async () => verifyPersonalAgentAttestation(agent.attestation,
      { ownerUserId: user!.id, ownerPublicKey: await accountPublicKeyOf(keys!.privateKey), agentId: agent.id, publicKey: agent.publicKey }, pinned!).catch(() => false),
  });
  const reEnrol = attest.data === false && (agent.status === "active" || agent.status === "suspended");
  const agentFp = useQuery({ queryKey: ["fingerprint", agent.publicKey], enabled: !!agent.publicKey, staleTime: Infinity, queryFn: () => fingerprintOf(agent.publicKey).catch(() => "—") }).data;
  const tone = reEnrol ? "orange" : agent.status === "active" ? "green" : agent.status === "awaiting_verification" ? "blue" : agent.status === "suspended" ? "orange" : "neutral";
  const facts = [
    agent.expiresAt ? `${agent.status === "expired" ? "Expired" : "Expires"} ${relativeTime(agent.expiresAt)}` : "No expiry",
    agent.lastUsedAt ? `Last used ${relativeTime(agent.lastUsedAt)}` : "Never used",
    `${agent.items} ${agent.items === 1 ? "item" : "items"}`,
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
        <span className="text-[12.5px] text-text-secondary">{facts.join(" · ")}</span>
      </div>
      {agent.status !== "revoked" && (
        <div className="flex flex-wrap gap-1.5">
          {agent.status === "awaiting_verification" && <Button size="sm" aria-label={`Verify ${agent.name}`} onClick={on.verify}>Verify</Button>}
          {agent.status === "active" && !reEnrol && canConnect && <Button size="sm" variant="outline" aria-label={`Connect ${agent.name}`} onClick={on.connect}>Connect</Button>}
          <Button size="sm" variant="ghost" aria-label={`Activity of ${agent.name}`} onClick={on.activity}>Activity</Button>
          <Button size="sm" variant="ghost" aria-label={`Edit ${agent.name}`} onClick={on.edit}>Edit</Button>
          <Button size="sm" variant="ghost" aria-label={`Revoke ${agent.name}`} onClick={on.revoke}>Revoke</Button>
        </div>
      )}
    </li>
  );
}

/**
 * Settings → My agents (docs/design/2026-11-15-personal-agents.md): the user's own agents, which use items they give them
 * through the gateway. Create, verify both fingerprints, connect, see activity, revoke with the items to rotate.
 */
export function MyAgentsSection({ records, privateLocked = false }: { records: VaultRecord[]; privateLocked?: boolean }) {
  const { orgs } = useSession();
  const q = useMyAgents(!privateLocked);
  const revealEmail = useRevealEmail();
  const [form, setForm] = useState<{ agent?: MyAgent } | null>(null);
  const [verifying, setVerifying] = useState<ToVerify | null>(null);
  const [open, setOpen] = useState<{ kind: "connect" | "activity" | "revoke"; id: string } | null>(null);
  const d = q.data;
  const opened = d?.agents.find((a) => a.id === open?.id);
  const titleOf: Titles = (id) => records.find((r) => r.id === id)?.body?.title || "An item you can't open";
  const atLimit = !!d && d.allowance.used >= d.allowance.allowed;
  const toVerify = (a: MyAgent): ToVerify => ({ id: a.id, name: a.name, publicKey: a.publicKey, attestation: a.attestation, personal: { ownerUserId: a.owner.userId, ownerPublicKey: a.owner.publicKey } });

  // A session confined to one organisation (SSO without the authenticator code): personal agents wait for the step-up.
  if (privateLocked || (q.error instanceof ApiError && q.error.code === "totp_step_up_required")) return <SectionPage title="My agents"><TotpStepUpPanel /></SectionPage>;
  return (
    <SectionPage title="My agents">
      <div className="flex flex-col gap-4">
        <p className="text-[13.5px] leading-relaxed text-text-secondary">
          Your agents use the items you give them through the gateway, without ever seeing the credentials. Give them only restricted credentials.
        </p>
        {agentsOff(q.error) ? <p className="text-[13.5px] text-text-secondary">{AGENTS_OFF}</p>
          : q.isError ? <p role="alert" className="text-[13px] text-red-500">{agentErrorText(q.error, { orgs, personal: true })}</p>
          : d && (<>
            {!d.rules.allowed ? <p role="note" className="text-[13.5px] text-text-secondary">{personalAgentsOffLine(d.rules.blockedByOrgId, orgs)}</p> : (
              <div className="flex flex-wrap items-center gap-3">
                <Button onClick={() => setForm({})} disabled={atLimit}>New agent</Button>
                <span className="text-[13px] text-text-secondary">{d.allowance.used} of {d.allowance.allowed} agents</span>
              </div>
            )}
            {d.rules.reveal !== "off" && d.gateway?.reveal && d.gateway.reveal !== "off" && (
              <label className="flex min-h-6 cursor-pointer items-center gap-2 text-[13.5px] text-text-primary">
                <input type="checkbox" className="size-4 accent-blue-500" checked={d.revealEmail} disabled={revealEmail.isPending}
                  onChange={(e) => revealEmail.mutate(e.target.checked, { onError: () => toast.error("Couldn't save that change. Try again.") })} />
                Email me when an agent asks for a secret
              </label>
            )}
            {d.agents.length === 0 ? <p className="text-[13.5px] text-text-secondary">No agents yet.</p> : (
              <ul className={card} aria-label="My agents">
                {d.agents.map((a) => (
                  <MyAgentRow key={a.id} agent={a} canConnect={!!d.gateway} on={{
                    verify: () => setVerifying(toVerify(a)), edit: () => setForm({ agent: a }),
                    connect: () => setOpen({ kind: "connect", id: a.id }), activity: () => setOpen({ kind: "activity", id: a.id }), revoke: () => setOpen({ kind: "revoke", id: a.id }),
                  }} />
                ))}
              </ul>
            )}
          </>)}
      </div>
      {form && <AgentForm personal agent={form.agent} onClose={() => setForm(null)} onDone={(created) => { setForm(null); if (created) setVerifying(created); else toast.success("Saved"); }} />}
      {verifying && <AgentVerifyDialog agent={verifying} personal={verifying.personal} onClose={() => setVerifying(null)} />}
      {opened && open?.kind === "connect" && d?.gateway && <AgentConnectSheet personal agent={opened} url={d.gateway.url} onClose={() => setOpen(null)} />}
      {opened && open?.kind === "activity" && <ActivityDialog agent={opened} titleOf={titleOf} onClose={() => setOpen(null)} />}
      {opened && open?.kind === "revoke" && <RevokeDialog agent={opened} titleOf={titleOf} onClose={() => setOpen(null)} />}
    </SectionPage>
  );
}
