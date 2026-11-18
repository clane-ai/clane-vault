import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ShieldAlert } from "lucide-react";
import { toast } from "sonner";
import { verifyAgentAttestation, verifyPersonalAgentAttestation } from "@clane-vault/crypto";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { AgentAttestationError, fingerprintOf, gatewayConsistent, gatewayPinStatus, ownedByMe, personalGatewayPinStatus } from "@/lib/orgKeys";
import { useSession } from "@/lib/session";
import { SELF_HOST_URL } from "@/features/demo/Demo";
import { useMyGateway, useRevokeMyAgent, useVerifyMyAgent } from "@/features/settings/myAgents";
import { agentErrorText, gatewayIdentity, PIN_LABEL, useGateway, useRevokeAgent, useVerifyAgent } from "./agents";

const PUBLISHED_FINGERPRINT = `${SELF_HOST_URL}/blob/main/docs/agents.md#enrolment-and-the-gateway-fingerprint`;

/**
 * Verify a new agent (spec §4.2 step 4): the gateway must have signed the agent's key, and the admin compares the agent
 * and gateway fingerprints with what the gateway operator publishes. **Matches** marks the agent verified and pins both
 * on this device. A changed gateway identity is repinned only here, after the admin ticks that they compared it.
 * `personal`: the owner's own agent (Settings → My agents): its attestation binds the owner's account key, which must be
 * the one this unlocked session holds, and its gateway pin is "changed" when it differs from ANY pin on this device.
 */
export function AgentVerifyDialog({ agent, personal, onClose, onVerified }: {
  agent: { id: string; name: string; publicKey: string; attestation: string }; personal?: { ownerUserId: string; ownerPublicKey: string }; onClose: () => void;
  /** After Matches succeeds (My agents opens Connect next). */ onVerified?: () => void;
}) {
  const { user, org, keys } = useSession();
  const orgGw = useGateway(!personal), myGw = useMyGateway(!!personal);
  const gw = personal ? myGw : orgGw;
  const orgVerify = useVerifyAgent(), myVerify = useVerifyMyAgent();
  const verify = personal ? myVerify : orgVerify;
  const orgRevoke = useRevokeAgent(), myRevoke = useRevokeMyAgent();
  const revoke = personal ? myRevoke : orgRevoke;
  const [compared, setCompared] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const identity = gw.data ? gatewayIdentity(gw.data) : null;
  const check = useQuery({
    queryKey: ["agent-verify-check", personal ? `personal:${personal.ownerUserId}:${personal.ownerPublicKey}` : org?.id, agent.id, agent.publicKey, agent.attestation, identity?.keyId, identity?.publicKey],
    enabled: !!identity && (personal ? !!keys && !!user : !!org),
    gcTime: 0,
    queryFn: async () => ({
      signed: await gatewayConsistent(identity!) && await (personal
        ? verifyPersonalAgentAttestation(agent.attestation, { ownerUserId: personal.ownerUserId, ownerPublicKey: personal.ownerPublicKey, agentId: agent.id, publicKey: agent.publicKey }, identity!)
        : verifyAgentAttestation(agent.attestation, { orgId: org!.id, agentId: agent.id, publicKey: agent.publicKey }, identity!)),
      // The owner check verifyPersonalAgentKey makes before sealing (not that call itself: the personal pin may not exist yet here).
      ownerOk: !personal || await ownedByMe(user!.id, { userId: personal.ownerUserId, publicKey: personal.ownerPublicKey }, keys!.privateKey),
      agentFp: await fingerprintOf(agent.publicKey).catch(() => "—"),
      gatewayFp: await fingerprintOf(identity!.publicKey).catch(() => "—"),
    }),
  });
  // The tick is for the identity on screen: any refetch that serves another one unticks it.
  const idKey = identity ? `${identity.keyId}.${identity.publicKey}` : null;
  const [ticked, setTicked] = useState(idKey);
  if (ticked !== idKey) { setTicked(idKey); setCompared(false); }
  const pin = !identity || !user ? null : personal ? personalGatewayPinStatus(user.id, identity) : org ? gatewayPinStatus(user.id, org.id, identity) : null;
  const previousFp = useQuery({ queryKey: ["fingerprint", pin?.previous?.publicKey], enabled: !!personal && !!pin?.previous, staleTime: Infinity,
    queryFn: () => fingerprintOf(pin!.previous!.publicKey).catch(() => "—") }).data;
  const busy = verify.isPending || revoke.isPending;

  const matches = async () => {
    setError(null);
    try { await verify.mutateAsync({ agent, gateway: identity!, repin: pin?.status === "changed" }); toast.success(`${agent.name} is verified`); onClose(); onVerified?.(); }
    catch (e) { setError(agentErrorText(e, { personal: !!personal })); }
  };
  const revokeIt = async () => {
    setError(null);
    try { await (personal ? myRevoke.mutateAsync({ id: agent.id }) : orgRevoke.mutateAsync({ id: agent.id, reason: "attestation_failed" })); toast.success(`${agent.name} was revoked`); onClose(); }
    catch (e) { setError(agentErrorText(e, { personal: !!personal })); }
  };

  const fp = "font-mono text-[12.5px] tracking-[.02em] text-text-primary break-all";
  return (
    <Dialog open onOpenChange={(o) => { if (!o && !busy) onClose(); }}>
      <DialogContent className="sm:max-w-[480px]">
        <DialogHeader>
          <DialogTitle>Verify {agent.name}</DialogTitle>
          <DialogDescription>Compare both fingerprints with the ones the gateway operator publishes before anyone shares with this agent.</DialogDescription>
        </DialogHeader>
        {gw.isError ? <p role="alert" className="text-[13px] text-red-500">{agentErrorText(gw.error, { personal: !!personal })}</p>
          : !check.data ? <p className="text-[13px] text-text-secondary">Checking the gateway's signature…</p>
          : !check.data.ownerOk ? (
            <div className="flex flex-col gap-3">
              <p role="alert" className="flex items-start gap-2 rounded-[10px] border border-[var(--orange-tint-border)] bg-orange-tint px-3 py-2.5 text-[13px] text-orange-ink">
                <ShieldAlert className="mt-0.5 size-4 shrink-0" /><span>{new AgentAttestationError("owner").message}</span>
              </p>
              <div className="flex justify-end gap-2">
                <Button variant="outline" onClick={onClose} disabled={busy}>Close</Button>
                <Button variant="destructive" onClick={() => void revokeIt()} disabled={busy}>Revoke</Button>
              </div>
            </div>
          ) : !check.data.signed ? (
            <div className="flex flex-col gap-3">
              <p role="alert" className="flex items-start gap-2 rounded-[10px] border border-[var(--orange-tint-border)] bg-orange-tint px-3 py-2.5 text-[13px] text-orange-ink">
                <ShieldAlert className="mt-0.5 size-4 shrink-0" /><span><strong>The gateway did not sign this key</strong><br />Don't use this agent. Revoke it and tell whoever runs the server.</span>
              </p>
              <div className="flex justify-end gap-2">
                <Button variant="outline" onClick={onClose} disabled={busy}>Close</Button>
                <Button variant="destructive" onClick={() => void revokeIt()} disabled={busy}>Revoke</Button>
              </div>
            </div>
          ) : (
            <div className="flex flex-col gap-3">
              <dl className="grid gap-2 text-[13px]">
                <dt className="text-text-secondary">Agent fingerprint</dt><dd className={fp}>{check.data.agentFp}</dd>
                <dt className="text-text-secondary">Gateway fingerprint</dt>
                <dd><span className={fp}>{check.data.gatewayFp}</span> <span className={pin?.status === "changed" ? "text-orange-ink" : "text-text-secondary"}>{pin && PIN_LABEL[pin.status]}</span></dd>
                {personal && pin?.status === "changed" && (<>
                  <dt className="text-text-secondary">Gateway this device trusted before</dt><dd className={fp}>{previousFp ?? "…"}</dd>
                </>)}
              </dl>
              <p className="text-[12.5px] text-text-secondary">
                Check that the gateway fingerprint matches <a href={PUBLISHED_FINGERPRINT} target="_blank" rel="noreferrer" className="font-medium text-[var(--link)] underline-offset-2 hover:underline">the published fingerprint</a> (vault.clane.ai's is listed there; on your own server, ask whoever runs it). If it matches, click <b>Matches</b>. A wrong gateway could read everything you give this agent.
              </p>
              {pin?.status === "changed" && (
                <label className="flex items-start gap-2 text-[13px] text-text-primary">
                  <input type="checkbox" className="mt-0.5 size-4" checked={compared} onChange={(e) => setCompared(e.target.checked)} />
                  I compared the gateway fingerprint with the published one
                </label>
              )}
              <div className="flex justify-end gap-2">
                <Button variant="outline" onClick={onClose} disabled={busy}>Not now</Button>
                <Button onClick={() => void matches()} disabled={busy || (pin?.status === "changed" && !compared)}>Matches</Button>
              </div>
            </div>
          )}
        {error && <p role="alert" className="text-[13px] text-red-500">{error}</p>}
      </DialogContent>
    </Dialog>
  );
}
