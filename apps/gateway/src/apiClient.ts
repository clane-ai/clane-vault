import type { AgentMethod } from "@clane-vault/crypto";
import type { GatewayConfig } from "./config.js";

/** GET /agent/sync: the agent's `/sync?space=org` body plus its wrapped key (plan Task 5). Only the fields the gateway reads. */
export interface AgentSync {
  orgId: string; wrappedPrivateKey: string; kekId: string; membershipKeys: { publicKey: string }[]; expiresAt: string | null;
  folders: { id: string; kind: "team" | "private"; encName: string; wrappedFolderKey?: string; sealedTo?: string | null }[];
  records: { id: string; folderId: string | null; encBody: string; holderType: "user" | "folder"; keyFolderId: string | null; wrappedRecordKey: string; deletedAt: string | null }[];
  entitlements: { approvals: boolean };
}
export interface UseEvent { at: string; recordId?: string; action: "use" | "refused" | "reflected"; host: string; method: AgentMethod; reason?: string; truncated?: boolean }

export class ApiRefused extends Error {
  constructor(public status: 401 | 403, public code: string) {
    super(`API refused the agent: ${code}`);
    this.name = "ApiRefused";
  }
}

export interface ApiClient {
  sync(accessToken: string): Promise<AgentSync>;
  events(accessToken: string, events: UseEvent[]): Promise<void>;
  exchangeStatic(cvat: string): Promise<{ accessToken: string; expiresIn: number }>;
  jwksUrl: URL;
}

const TIMEOUT_MS = 15_000;
// The code comes from the API's body; anything unexpected is reported as plain "unauthorized".
const codeOf = (j: unknown) => {
  const e = (j as { error?: unknown } | null)?.error;
  return typeof e === "string" && /^[a-z_]{1,64}$/.test(e) ? e : "unauthorized";
};

export function apiClient(cfg: Pick<GatewayConfig, "apiUrl" | "apiToken">, fetchImpl: typeof fetch = fetch): ApiClient {
  const base = `${cfg.apiUrl.replace(/\/+$/, "")}/api/v1`;
  /** `grantRefusals`: a 400 (OAuth invalid_grant and friends) means the token is no good, as a 401 does. */
  async function call(path: string, init: { method?: string; headers?: Record<string, string>; body?: string }, grantRefusals = false): Promise<Response> {
    const r = await fetchImpl(`${base}${path}`, { ...init, headers: { "x-gateway-token": cfg.apiToken, ...init.headers }, signal: AbortSignal.timeout(TIMEOUT_MS) });
    if (r.ok) return r;
    if (r.status === 401 || r.status === 403 || (grantRefusals && r.status === 400))
      throw new ApiRefused(r.status === 403 ? 403 : 401, codeOf(await r.json().catch(() => null)));
    throw new Error(`API ${path} failed (${r.status})`);
  }
  const bearer = (t: string) => ({ authorization: `Bearer ${t}` });
  return {
    jwksUrl: new URL(`${base}/.well-known/jwks.json`),
    async sync(accessToken) {
      return await (await call("/agent/sync", { headers: bearer(accessToken) })).json() as AgentSync;
    },
    async events(accessToken, events) {
      await call("/agent/events", { method: "POST", headers: { ...bearer(accessToken), "content-type": "application/json" }, body: JSON.stringify({ events }) });
    },
    async exchangeStatic(cvat) {
      const r = await call("/oauth/token", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ grant_type: "urn:clane:agent-token", token: cvat }).toString() }, true);
      const j = await r.json() as { access_token: string; expires_in: number };
      return { accessToken: j.access_token, expiresIn: j.expires_in };
    },
  };
}
