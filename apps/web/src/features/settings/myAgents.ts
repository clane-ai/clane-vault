import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "@/lib/api";
import { PERSONAL_SLOT, pinGateway, pinKey, type GatewayIdentity } from "@/lib/orgKeys";
import { useSession } from "@/lib/session";
import { type AgentGrant, type AgentStatus, type AgentToken, type Gateway } from "@/features/admin/agents";

/** Settings → My agents: the owner's personal agents on /me/agents (docs/design/2026-11-15-personal-agents.md). No organisation context. */

/** `owner`: the owner's CURRENT account key; an attestation over an earlier one needs the agent enrolled again. */
export interface MyAgent {
  id: string; name: string; status: AgentStatus; publicKey: string; attestation: string; expiresAt: string | null; lastUsedAt: string | null;
  createdAt: string; verifiedAt: string | null; items: number; owner: { userId: string; publicKey: string }; tokens: AgentToken[]; grants: AgentGrant[];
}
export interface MyAgents {
  agents: MyAgent[]; allowance: { used: number; allowed: number };
  rules: { allowed: boolean; blockedByOrgId: string | null; write: boolean; reveal: string };
  /** null: the gateway is unreachable or its identity changed. */
  gateway: Gateway | null; revealEmail: boolean;
}
/** `POST /me/agents`: the page recomputes both fingerprints and checks the attestation itself. */
export interface CreatedMyAgent {
  id: string; name: string; publicKey: string; attestation: string; owner: { userId: string; publicKey: string }; gateway: { keyId: string; publicKey: string };
}
export interface Rotation { records: { id: string }[]; revealed: unknown[] }
export interface AgentEvent { id: string; at: string; action: string; recordId: string | null; meta: unknown }

const KEY = "my-agents";
/** One retry for a network or server error; a refusal (404 off, 403 step-up) is final. */
const notOff = (n: number, e: unknown) => !(e instanceof ApiError && e.status < 500) && n < 1;
/** A 404 (agent access or personal agents off) is final and hides the section. */
/** `enabled` false while the session is confined to one organisation: a 403 there would raise the app-wide step-up prompt. */
export function useMyAgents(enabled = true) {
  const { user } = useSession();
  return useQuery({ queryKey: [KEY, user?.id], enabled: enabled && !!user, retry: notOff, queryFn: () => api.get<MyAgents>("/me/agents") });
}
export function useMyGateway(enabled = true) {
  const { user } = useSession();
  return useQuery({ queryKey: ["my-agent-gateway", user?.id], enabled, retry: notOff, queryFn: () => api.get<Gateway>("/me/agents/gateway") });
}
export function useMyAgentActivity(id: string) {
  return useQuery({ queryKey: ["my-agent-activity", id], queryFn: () => api.get<{ events: AgentEvent[]; nextBefore: string | null }>(`/me/agents/${id}/activity`) });
}

function useMyMutation<V, R>(fn: (v: V) => Promise<R>) {
  const qc = useQueryClient();
  return useMutation({ mutationFn: fn, onSettled: () => qc.invalidateQueries({ queryKey: [KEY] }) });
}
export function useCreateMyAgent() {
  return useMyMutation((v: { name: string; expiresAt?: string | null }) => api.post<CreatedMyAgent>("/me/agents", v));
}
/**
 * The owner compared both fingerprints: the server marks the agent verified, then this device pins the gateway identity
 * and the agent key in the personal slot. `repin`: only after the owner confirmed a Changed gateway.
 */
export function useVerifyMyAgent() {
  const { user } = useSession();
  return useMyMutation(async (v: { agent: { id: string; publicKey: string }; gateway: GatewayIdentity; repin: boolean }) => {
    await api.post(`/me/agents/${v.agent.id}/verify`, { publicKey: v.agent.publicKey });
    await pinGateway(user!.id, PERSONAL_SLOT, v.gateway, { repin: v.repin });
    pinKey(user!.id, PERSONAL_SLOT, v.agent.id, v.agent.publicKey);
  });
}
export function useUpdateMyAgent() {
  return useMyMutation(({ id, ...changed }: { id: string; name?: string; expiresAt?: string | null }) => api.patch(`/me/agents/${id}`, changed));
}
export function useRevokeMyAgent() {
  return useMyMutation((v: { id: string }) => api.del(`/me/agents/${v.id}`) as unknown as Promise<{ rotate: Rotation }>);
}
