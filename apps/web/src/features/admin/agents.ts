import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ApiError } from "@/lib/api";
import { AgentAttestationError, pinGateway, pinKey, type GatewayIdentity } from "@/lib/orgKeys";
import { useOrgApi, useScope } from "@/lib/scope";
import { useSession } from "@/lib/session";
import { planMessage } from "./plan";

/** Admin → Agents (docs/design/2026-10-17-agent-access.md §4.2, §4.5, §4.7, §7). */

export type AgentStatus = "awaiting_verification" | "active" | "expired" | "revoked";
export const STATUS_LABEL: Record<AgentStatus, string> = { awaiting_verification: "Awaiting verification", active: "Active", expired: "Expired", revoked: "Revoked" };
export interface AgentToken { id: string; label: string; createdAt: string; expiresAt: string | null; lastUsedAt: string | null; revokedAt: string | null }
/** An OAuth grant (a client an admin allowed on the consent page). */
export interface AgentGrant { id: string; clientName: string; grantedBy: { id: string; name: string } | null; createdAt: string; revokedAt?: string | null }
export interface Agent {
  id: string; name: string; status: AgentStatus; publicKey: string; attestation: string; expiresAt: string | null; lastUsedAt: string | null;
  createdAt: string; verifiedAt: string | null; folders: { id: string }[]; groups: { id: string; name: string }[]; tokens: AgentToken[]; grants: AgentGrant[];
}
/** `POST /admin/agents`: the server's fingerprints are a convenience; the page recomputes both. */
export interface CreatedAgent { id: string; name: string; publicKey: string; attestation: string }
export interface Gateway { url: string; identityKeyId: string; identityPublicKey: string }
export interface Rotation { folders: { id: string }[]; records: number }

export const PIN_LABEL = { same: "Pinned", new: "New", changed: "Changed — compare it with the published fingerprint" } as const;
export const gatewayIdentity = (g: Gateway): GatewayIdentity => ({ keyId: g.identityKeyId, publicKey: g.identityPublicKey });

/** Agent features off on this server: every agent route is 404. */
export const AGENTS_OFF = "Agent access isn't turned on for this server.";
export const agentsOff = (e: unknown) => e instanceof ApiError && e.status === 404;
export function useAgents() {
  const oapi = useOrgApi();
  return useQuery({ queryKey: ["admin-agents", useScope()], queryFn: () => oapi.get<{ agents: Agent[] }>("/admin/agents").then((r) => r.agents) });
}
export function useGateway(enabled = true) {
  const oapi = useOrgApi();
  return useQuery({ queryKey: ["agent-gateway", useScope()], enabled, queryFn: () => oapi.get<Gateway>("/org/agents/gateway") });
}

function useAgentMutation<V, R>(fn: (v: V) => Promise<R>, opts: { gcTime?: number } = {}) {
  const qc = useQueryClient();
  return useMutation({ ...opts, mutationFn: fn, onSettled: () => Promise.all([qc.invalidateQueries({ queryKey: ["admin-agents"] }), qc.invalidateQueries({ queryKey: ["org-plan"] })]) });
}

export function useCreateAgent() {
  const oapi = useOrgApi();
  return useAgentMutation((v: { name: string; expiresAt?: string | null }) => oapi.post<CreatedAgent>("/admin/agents", v));
}
/**
 * The admin compared both fingerprints: the server marks the agent verified, then this device pins the gateway identity
 * and the agent key. `repin`: the gateway identity differs from the pinned one and the admin confirmed the comparison;
 * the only place a changed gateway identity is ever repinned.
 */
export function useVerifyAgent() {
  const oapi = useOrgApi();
  const { user, org } = useSession();
  return useAgentMutation(async (v: { agent: { id: string; publicKey: string }; gateway: GatewayIdentity; repin: boolean }) => {
    await oapi.post(`/admin/agents/${v.agent.id}/verify`, { publicKey: v.agent.publicKey });
    await pinGateway(user!.id, org!.id, v.gateway, { repin: v.repin });
    pinKey(user!.id, org!.id, v.agent.id, v.agent.publicKey);
  });
}
export function useUpdateAgent() {
  const oapi = useOrgApi();
  // Only the fields given: a rename never re-sends (and so never moves or refuses) the expiry.
  return useAgentMutation(({ id, ...changed }: { id: string; name?: string; expiresAt?: string | null }) => oapi.patch(`/admin/agents/${id}`, changed));
}
export function useRevokeAgent() {
  const oapi = useOrgApi();
  return useAgentMutation((v: { id: string; reason?: string }) =>
    oapi.delReq(`/admin/agents/${v.id}`, v.reason ? { reason: v.reason } : {}) as unknown as Promise<{ rotate: Rotation }>);
}
export function useCreateToken() {
  const oapi = useOrgApi();
  return useAgentMutation((v: { agentId: string; label: string; expiresAt?: string | null }) =>
    oapi.post<{ id: string; token: string }>(`/admin/agents/${v.agentId}/tokens`, { label: v.label, ...(v.expiresAt ? { expiresAt: v.expiresAt } : {}) }),
  // The answer holds the token: never kept in the mutation cache once the sheet lets go of it.
  { gcTime: 0 });
}
export function useRevokeToken() {
  const oapi = useOrgApi();
  return useAgentMutation((v: { agentId: string; tokenId: string }) => oapi.del(`/admin/agents/${v.agentId}/tokens/${v.tokenId}`));
}
export function useRevokeGrant() {
  const oapi = useOrgApi();
  return useAgentMutation((v: { agentId: string; grantId: string }) => oapi.del(`/admin/agents/${v.agentId}/grants/${v.grantId}`));
}

const ERRORS: Record<string, string> = {
  agent_revoked: "This agent has already been revoked.",
  stale_key: "The agent's key changed since this page loaded. Close this and check it again.",
  gateway_unavailable: "The agent gateway isn't reachable, so nothing was changed. Try again in a moment.",
  gateway_identity_changed: "The agent gateway's identity changed, so the server refused. Ask whoever runs the server to confirm the new gateway fingerprint.",
  invalid_request: "Use a plain name (up to 60 characters) and an expiry in the future.",
  not_found: "That agent no longer exists. Reload the page.",
};
export function agentErrorText(e: unknown): string {
  if (e instanceof AgentAttestationError && e.reason === "gateway_changed") return "The agent was verified, but this device's pinned gateway identity changed meanwhile, so it can't be used from here. Revoke the agent and create it again.";
  return planMessage(e) ?? (e instanceof ApiError ? ERRORS[e.code] : undefined) ?? "Couldn't do that. Try again.";
}

/** What to tell the model, the same for every client (spec §7). */
export const AGENT_PROMPT = "Use `list_secrets` to see what you may call, then `http_request` with the item handle. You will never see a credential.";
export const ANTHROPIC_BETA = "anthropic-beta: mcp-client-2025-11-20";

export type SnippetId = "claude-ai" | "chatgpt" | "claude-code" | "claude-code-token" | "claude-api" | "openai";
/** Per-client setup (spec §7) for this gateway `url`; `token` (shown once after creating it) replaces the `cvat_…` placeholder. */
export function connectSnippets(url: string, token?: string): { id: SnippetId; label: string; text: string }[] {
  const t = token ?? "cvat_…";
  const claudeApi = JSON.stringify({
    model: "claude-opus-5-5", max_tokens: 16000,
    mcp_servers: [{ type: "url", url, name: "clane-vault", authorization_token: t }],
    tools: [{ type: "mcp_toolset", mcp_server_name: "clane-vault" }],
    messages: [{ role: "user", content: "Create a Stripe test customer for ACME." }],
  }, null, 2);
  const openai = JSON.stringify({
    model: "<model>",
    tools: [{ type: "mcp", server_label: "clane_vault", server_url: url, authorization: t, require_approval: "never" }],
    input: "Create a Stripe test customer for ACME.",
  }, null, 2);
  return [
    { id: "claude-ai", label: "Claude.ai (web and desktop)", text: `Customize → Connectors → + Add → Add custom connector → name, URL ${url} → Continue → OAuth client: Register automatically → Add → Connect → sign in to Clane Vault, pick the agent, Allow. (Team and Enterprise: an owner adds it in Organization settings → Connectors.)` },
    { id: "chatgpt", label: "ChatGPT", text: `Plugins (chatgpt.com/plugins) → + → Add custom MCP server → name, description, MCP server URL ${url}, authentication OAuth → I understand and want to continue → Create as a plugin → sign in to Clane Vault, pick the agent, Allow.` },
    { id: "claude-code", label: "Claude Code (OAuth)", text: `claude mcp add --transport http clane-vault ${url}\n# then run /mcp in Claude Code to sign in` },
    { id: "claude-code-token", label: "Claude Code (API token)", text: `claude mcp add --transport http clane-vault ${url} --header "Authorization: Bearer ${t}"` },
    { id: "claude-api", label: "Claude API (MCP connector)", text: `${claudeApi}\n\nHeader: ${ANTHROPIC_BETA}` },
    { id: "openai", label: "OpenAI Responses API", text: openai },
  ];
}
