import { createHash, timingSafeEqual } from "node:crypto";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { decodeJwt } from "jose";
import { verifyAgentAccess } from "../lib/tokens.js";
import { logEvent } from "../lib/events.js";
import { personalAgentRules } from "../lib/personalAgents.js";

declare module "fastify" {
  /** Exactly one of orgId (an organisation agent) and ownerUserId (a personal agent). */
  interface FastifyRequest { agent: { userId: string; orgId: string | null; ownerUserId: string | null; grantId: string; via: "token" | "grant" } }
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
    // Explicit on both sides: an undefined filter would be dropped by Prisma, matching an agent of the other kind.
    const kind = t.org ? { orgId: t.org } : { ownerUserId: t.owner!, orgId: null };
    const a = await app.prisma.agent.findFirst({ where: { userId: t.sub, ...kind, revokedAt: null, user: { status: "active" } },
      select: { expiresAt: true, verifiedAt: true } });
    if (!a) return deny();
    const live = { id: t.grant, agentId: t.sub, revokedAt: null };
    const token = await app.prisma.agentToken.findFirst({ where: { ...live, OR: [{ expiresAt: null }, { expiresAt: { gt: now } }] }, select: { id: true } });
    const grant = token ? null : await app.prisma.agentGrant.findFirst({ where: { ...live, expiresAt: { gt: now } }, select: { id: true } });
    if (!token && !grant) return deny();
    if (a.expiresAt && a.expiresAt <= now) {
      if (!(await app.prisma.event.findFirst({ where: { action: "agent.expired", actorId: t.sub }, select: { id: true } }))) {
        await logEvent(app.prisma, { orgId: t.org ?? undefined, actorId: t.sub, action: "agent.expired" });
        // The gateway drops its cached keys at once (best effort; it treats agent_expired like revocation anyway).
        app.gateway.dropAgent(t.sub).catch(() => undefined);
      }
      await reply.code(403).send({ error: "agent_expired" });
      return;
    }
    if (t.org) {
      const m = await app.prisma.membership.findUnique({ where: { orgId_userId: { orgId: t.org, userId: t.sub } }, select: { status: true } });
      if (!a.verifiedAt || m?.status !== "active") { await reply.code(403).send({ error: "agent_unverified" }); return; }
    } else {
      if (!a.verifiedAt) { await reply.code(403).send({ error: "agent_unverified" }); return; }
      const owner = await app.prisma.user.findUnique({ where: { id: t.owner! }, select: { status: true } });
      if (owner?.status !== "active") { await reply.code(403).send({ error: "owner_inactive" }); return; }
      const rules = await personalAgentRules(app.prisma, app.config, t.owner!);
      if (!rules.allowed) { await reply.code(403).send({ error: "personal_agents_disabled", orgId: rules.blockedByOrgId ?? undefined }); return; }
    }
    req.agent = { userId: t.sub, orgId: t.org, ownerUserId: t.owner, grantId: t.grant, via: token ? "token" : "grant" };
  });
}
