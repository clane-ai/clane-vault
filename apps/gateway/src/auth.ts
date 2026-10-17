import { createHash } from "node:crypto";
import { createRemoteJWKSet, jwtVerify } from "jose";
import { ApiRefused, type ApiClient } from "./apiClient.js";
import type { GatewayConfig } from "./config.js";

export interface AgentPrincipal { agentId: string; orgId: string; accessToken: string; exp: number }

const BEARER = /^Bearer\s+(\S+)$/i;
const MARGIN_MS = 30_000;

/**
 * "cvat_…": exchanged at the API, cached by SHA-256 of the token until exp − 30 s. Otherwise an ES256 JWT verified against
 * the API's JWKS (aud = cfg.publicUrl). The principal always comes from a verified token's claims, never from the client.
 */
export function bearerAuth(cfg: GatewayConfig, api: ApiClient, now: () => number = Date.now): (authorization: string | undefined) => Promise<AgentPrincipal | null> {
  const jwks = createRemoteJWKSet(api.jwksUrl);
  // A pending exchange is shared, so concurrent connects with one token make one exchange.
  const statics = new Map<string, { p: Promise<AgentPrincipal | null>; until: number }>();

  // shortcut: a JWKS fetch failure also reads as "invalid" (401), and iss is not checked yet (Task 12b adds it).
  async function verify(jwt: string): Promise<AgentPrincipal | null> {
    try {
      const { payload: c } = await jwtVerify(jwt, jwks, { audience: cfg.publicUrl, algorithms: ["ES256"] });
      if (c.scope !== "agent" || typeof c.sub !== "string" || typeof c.org !== "string" || typeof c.exp !== "number") return null;
      return { agentId: c.sub, orgId: c.org, accessToken: jwt, exp: c.exp };
    } catch {
      return null;
    }
  }

  async function exchange(cvat: string): Promise<AgentPrincipal | null> {
    try {
      return await verify((await api.exchangeStatic(cvat)).accessToken);
    } catch (e) {
      if (e instanceof ApiRefused) return null; // an unknown or revoked token
      throw e;
    }
  }

  return async (authorization) => {
    const token = BEARER.exec(authorization ?? "")?.[1];
    if (!token) return null;
    if (!token.startsWith("cvat_")) return verify(token);
    const t = now();
    for (const [k, e] of statics) if (t >= e.until) statics.delete(k);
    const key = createHash("sha256").update(token).digest("base64url");
    const hit = statics.get(key);
    if (hit) return hit.p;
    const entry = { p: exchange(token), until: Infinity };
    statics.set(key, entry);
    try {
      const p = await entry.p;
      if (p) entry.until = p.exp * 1000 - MARGIN_MS; else statics.delete(key);
      return p;
    } catch (e) {
      statics.delete(key);
      throw e;
    }
  };
}
