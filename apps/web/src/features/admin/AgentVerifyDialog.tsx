import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ShieldAlert } from "lucide-react";
import { toast } from "sonner";
import { verifyAgentAttestation } from "@clane-vault/crypto";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { fingerprintOf, gatewayConsistent, gatewayPinStatus } from "@/lib/orgKeys";
import { useSession } from "@/lib/session";
import { agentErrorText, gatewayIdentity, PIN_LABEL, useGateway, useRevokeAgent, useVerifyAgent } from "./agents";

/**
 * Verify a new agent (spec §4.2 step 4): the gateway must have signed the agent's key, and the admin compares the agent
 * and gateway fingerprints with what the gateway operator publishes. **Matches** marks the agent verified and pins both
 * on this device. A changed gateway identity is repinned only here, after the admin ticks that they compared it.
 */
export function AgentVerifyDialog({ agent, onClose }: { agent: { id: string; name: string; publicKey: string; attestation: string }; onClose: () => void }) {
  const { user, org } = useSession();
  const gw = useGateway();
  const verify = useVerifyAgent();
  const revoke = useRevokeAgent();
  const [compared, setCompared] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const identity = gw.data ? gatewayIdentity(gw.data) : null;
  const check = useQuery({
    queryKey: ["agent-verify-check", org?.id, agent.id, agent.publicKey, agent.attestation, identity?.keyId, identity?.publicKey],
    enabled: !!identity && !!org,
    gcTime: 0,
    queryFn: async () => ({
      signed: await gatewayConsistent(identity!) && await verifyAgentAttestation(agent.attestation, { orgId: org!.id, agentId: agent.id, publicKey: agent.publicKey }, identity!),
      agentFp: await fingerprintOf(agent.publicKey).catch(() => "—"),
      gatewayFp: await fingerprintOf(identity!.publicKey).catch(() => "—"),
    }),
  });
  const pin = identity && user && org ? gatewayPinStatus(user.id, org.id, identity) : null;
  const busy = verify.isPending || revoke.isPending;

  const matches = async () => {
    setError(null);
    try { await verify.mutateAsync({ agent, gateway: identity!, repin: pin?.status === "changed" }); toast.success(`${agent.name} is verified`); onClose(); }
    catch (e) { setError(agentErrorText(e)); }
  };
  const revokeIt = async () => {
    setError(null);
    try { await revoke.mutateAsync({ id: agent.id, reason: "attestation_failed" }); toast.success(`${agent.name} was revoked`); onClose(); }
    catch (e) { setError(agentErrorText(e)); }
  };

  const fp = "font-mono text-[12.5px] tracking-[.02em] text-text-primary break-all";
  return (
    <Dialog open onOpenChange={(o) => { if (!o && !busy) onClose(); }}>
      <DialogContent className="sm:max-w-[480px]">
        <DialogHeader>
          <DialogTitle>Verify {agent.name}</DialogTitle>
          <DialogDescription>Compare both fingerprints with the ones the gateway operator publishes before anyone shares with this agent.</DialogDescription>
        </DialogHeader>
        {gw.isError ? <p role="alert" className="text-[13px] text-red-500">{agentErrorText(gw.error)}</p>
          : !check.data ? <p className="text-[13px] text-text-secondary">Checking the gateway's signature…</p>
          : !check.data.signed ? (
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
              </dl>
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
