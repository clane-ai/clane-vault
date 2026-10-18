import { createHash } from "node:crypto";
import { createRemoteJWKSet, errors, jwtVerify, type JWTVerifyGetKey } from "jose";
import { ApiRefused, type ApiClient } from "./apiClient.js";
import type { GatewayConfig } from "./config.js";
import { HttpError } from "./http.js";

export interface AgentPrincipal { agentId: string; orgId: string; accessToken: string; exp: number }

export type BearerAuth = ((authorization: string | undefined, onExchange?: () => void) => Promise<AgentPrincipal | null>) & {
  /** Evicts the agent's cached exchanges (revoked or refused), so its static token is checked at the API again. */
  drop(agentId: string): void;
};

const BEARER = /^Bearer\s+(\S+)$/i;
const CVAT = /^cvat_([^_]+)_./;
const MARGIN_MS = 30_000;

/** RFC 9728 metadata URL for PUBLIC_URL; every 401 names it (MCP authorization). */
export const resourceMetadataUrl = (cfg: Pick<GatewayConfig, "publicUrl">) => `${cfg.publicUrl.replace(/\/+$/, "")}/.well-known/oauth-protected-resource`;
/** `invalid`: a bearer was sent but is bad, expired or revoked (RFC 6750 §3.1); without a token the challenge names no error. */
export const challenge = (cfg: Pick<GatewayConfig, "publicUrl">, invalid = false) =>
  ({ "www-authenticate": `Bearer ${invalid ? 'error="invalid_token", ' : ""}resource_metadata="${resourceMetadataUrl(cfg)}"` });

/** The API (metadata, JWKS or exchange) can't be reached: 503, never a 401 that would send the client to re-authorise. */
export class ApiUnavailable extends HttpError {
  constructor(public reason: "issuer" | "jwks" | "exchange") { super(503, "api_unavailable", { "retry-after": "5" }); }
}

/**
 * "cvat_…": exchanged at the API, cached by SHA-256 of the token until exp − 30 s. Otherwise an ES256 JWT (an OAuth AgentGrant's)
 * verified against the API's JWKS (aud = cfg.publicUrl, iss = the API metadata's issuer). The principal always comes from a
 * verified token's claims, never from the client. A bad token is null; an unreachable API throws a 503 HttpError.
 */
export function bearerAuth(cfg: GatewayConfig, api: ApiClient, now: () => number = Date.now): BearerAuth {
  const remote = createRemoteJWKSet(api.jwksUrl);
  // Only "no such key" is the token's fault; any other failure to get a key is the JWKS being unreachable or broken.
  const jwks: JWTVerifyGetKey = async (h, t) => {
    try { return await remote(h, t); } catch (e) {
      if (e instanceof errors.JWKSNoMatchingKey || e instanceof errors.JWKSMultipleMatchingKeys) throw e;
      throw new ApiUnavailable("jwks");
    }
  };
  // A pending exchange is shared, so concurrent connects with one token make one exchange.
  const statics = new Map<string, { p: Promise<AgentPrincipal | null>; until: number; agentId?: string }>();

  /** `grant`: an exchanged token must name the static token it came from (an OAuth grant's JWT has no cvat_ id to match). */
  async function verify(jwt: string, grant?: string): Promise<AgentPrincipal | null> {
    let issuer: string;
    try { issuer = await api.issuer(); } catch { throw new ApiUnavailable("issuer"); }
    try {
      const { payload: c } = await jwtVerify(jwt, jwks, { audience: cfg.publicUrl, issuer, algorithms: ["ES256"] });
      if (c.scope !== "agent" || typeof c.sub !== "string" || typeof c.org !== "string" || typeof c.exp !== "number" || typeof c.grant !== "string") return null;
      if (grant !== undefined && c.grant !== grant) return null;
      return { agentId: c.sub, orgId: c.org, accessToken: jwt, exp: c.exp };
    } catch (e) {
      if (e instanceof HttpError) throw e;
      return null;
    }
  }

  async function exchange(cvat: string, id: string): Promise<AgentPrincipal | null> {
    try {
      return await verify((await api.exchangeStatic(cvat)).accessToken, id);
    } catch (e) {
      if (e instanceof ApiRefused) return null; // an unknown or revoked token
      if (e instanceof HttpError) throw e;
      throw new ApiUnavailable("exchange"); // the API is down, slow or answering 5xx
    }
  }

  /** `onExchange` runs before an exchange on a cache miss (a rate limit); it may throw. */
  const auth = async (authorization: string | undefined, onExchange?: () => void) => {
    const token = BEARER.exec(authorization ?? "")?.[1];
    if (!token) return null;
    if (!token.startsWith("cvat_")) return verify(token);
    const id = CVAT.exec(token)?.[1];
    if (!id) return null;
    const t = now();
    for (const [k, e] of statics) if (t >= e.until) statics.delete(k);
    const key = createHash("sha256").update(token).digest("base64url");
    const hit = statics.get(key);
    if (hit) return hit.p;
    onExchange?.();
    const entry: { p: Promise<AgentPrincipal | null>; until: number; agentId?: string } = { p: exchange(token, id), until: Infinity };
    statics.set(key, entry);
    try {
      const p = await entry.p;
      if (p) { entry.until = p.exp * 1000 - MARGIN_MS; entry.agentId = p.agentId; } else statics.delete(key);
      return p;
    } catch (e) {
      statics.delete(key);
      throw e;
    }
  };
  return Object.assign(auth, { drop(agentId: string) { for (const [k, e] of statics) if (e.agentId === agentId) statics.delete(k); } });
}
