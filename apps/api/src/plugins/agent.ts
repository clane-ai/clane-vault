import { createHash, timingSafeEqual } from "node:crypto";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { decodeJwt } from "jose";
import { verifyAgentAccess } from "../lib/tokens.js";
import { logEvent } from "../lib/events.js";

declare module "fastify" {
  interface FastifyRequest { agent: { userId: string; orgId: string; grantId: string; via: "token" | "grant" } }
  interface FastifyInstance {
    /** The gateway's X-Gateway-Token plus an ES256 agent access token (docs/agents.md). Registered only when agents are on. */
    requireAgent: (req: FastifyRequest, reply: FastifyReply) => Promise<void>;
  }
}

const sha = (s: string) => createHash("sha256").update(s).digest();
const bearer = (req: FastifyRequest) => req.headers.authorization?.replace(/^Bearer /, "") ?? "";

/** The caller is the gateway: X-Gateway-Token equals GATEWAY_API_TOKEN (constant time). */
export function fromGateway(app: FastifyInstance, req: FastifyRequest): boolean {
  const h = req.headers["x-gateway-token"];
  return typeof h === "string" && timingSafeEqual(sha(h), sha(app.config.agents!.gatewayApiToken));
}

/**
 * Rate-limit key: everything the gateway sends comes from one address, so its calls are counted per agent (the
 * token's `sub`, read unverified: the gateway is already authenticated and requireAgent verifies it next).
 */
export const agentRateKey = (app: FastifyInstance) => (req: FastifyRequest): string => {
  if (!fromGateway(app, req)) return req.ip;
  try { const sub = decodeJwt(bearer(req)).sub; if (sub) return `agent:${sub}`; } catch { /* not a JWT */ }
  return req.ip;
};

export function registerAgent(app: FastifyInstance) {
  app.decorateRequest("agent", null as never);
  app.decorate("requireAgent", async (req: FastifyRequest, reply: FastifyReply) => {
    const deny = async () => { await reply.code(401).send({ error: "unauthorized" }); };
    if (!fromGateway(app, req)) return deny();
    let t: Awaited<ReturnType<typeof verifyAgentAccess>>;
    try { t = await verifyAgentAccess(app.config, bearer(req)); } catch { return deny(); }
    const now = new Date();
    const a = await app.prisma.agent.findFirst({ where: { userId: t.sub, orgId: t.org, revokedAt: null, user: { status: "active" } },
      select: { expiresAt: true, verifiedAt: true } });
    if (!a) return deny();
    const live = { id: t.grant, agentId: t.sub, revokedAt: null };
    const token = await app.prisma.agentToken.findFirst({ where: { ...live, OR: [{ expiresAt: null }, { expiresAt: { gt: now } }] }, select: { id: true } });
    const grant = token ? null : await app.prisma.agentGrant.findFirst({ where: { ...live, expiresAt: { gt: now } }, select: { id: true } });
    if (!token && !grant) return deny();
    if (a.expiresAt && a.expiresAt <= now) {
      if (!(await app.prisma.event.findFirst({ where: { action: "agent.expired", actorId: t.sub }, select: { id: true } }))) {
        await logEvent(app.prisma, { orgId: t.org, actorId: t.sub, action: "agent.expired" });
        // The gateway drops its cached keys at once (best effort; it treats agent_expired like revocation anyway).
        app.gateway.dropAgent(t.sub).catch(() => undefined);
      }
      await reply.code(403).send({ error: "agent_expired" });
      return;
    }
    const m = await app.prisma.membership.findUnique({ where: { orgId_userId: { orgId: t.org, userId: t.sub } }, select: { status: true } });
    if (!a.verifiedAt || m?.status !== "active") { await reply.code(403).send({ error: "agent_unverified" }); return; }
    req.agent = { userId: t.sub, orgId: t.org, grantId: t.grant, via: token ? "token" : "grant" };
  });
}
