import type { FastifyPluginAsync } from "fastify";
import { z } from "zod";
import { syncFor } from "../lib/sync.js";
import { accessFor } from "../lib/access.js";
import { orgEntitlements } from "../lib/plans.js";
import { logEvent } from "../lib/events.js";
import { agentRateKey } from "../plugins/agent.js";

const HOUR = 3600e3;

// AgentMethod from @clane-vault/crypto, inlined: the API can't load the crypto package at runtime.
const events = z.object({ events: z.array(z.object({
  at: z.string().datetime({ offset: true }),
  recordId: z.string().uuid().optional(),
  action: z.enum(["use", "refused", "reflected"]),
  host: z.string().max(255),
  method: z.enum(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]),
  reason: z.string().max(64).optional(),
  truncated: z.boolean().optional(),
})).min(1).max(200) });

/** What the gateway calls for an agent (docs/agents.md). Registered only when agents are on. */
export const agentApiRoutes: FastifyPluginAsync = async (app) => {
  const opts = { preHandler: app.requireAgent, config: { rateLimit: { keyGenerator: agentRateKey(app) } } };

  app.get("/agent/sync", opts, async (req) => {
    const { userId, orgId } = req.agent;
    const [body, a, ent] = await Promise.all([
      syncFor(app.prisma, app.config, { userId, orgId, orgOnly: true }),
      app.prisma.agent.findUniqueOrThrow({ where: { userId }, select: { wrappedPrivateKey: true, kekId: true, expiresAt: true } }),
      orgEntitlements(app.prisma, app.config, orgId),
    ]);
    // At most hourly: the claim on lastSyncLoggedAt is atomic, so concurrent syncs log once.
    const now = new Date();
    const claimed = await app.prisma.agent.updateMany({ where: { userId, OR: [{ lastSyncLoggedAt: null }, { lastSyncLoggedAt: { lt: new Date(now.getTime() - HOUR) } }] }, data: { lastSyncLoggedAt: now } });
    if (claimed.count) await logEvent(app.prisma, { orgId, actorId: userId, action: "agent.sync", meta: { records: body.records.length } });
    return { ...body, wrappedPrivateKey: a.wrappedPrivateKey, kekId: a.kekId, expiresAt: a.expiresAt?.toISOString() ?? null,
      entitlements: { approvals: ent.features.agentApprovals } };
  });

  app.post("/agent/events", opts, async (req) => {
    const b = events.parse(req.body);
    const { userId, orgId } = req.agent;
    // Only a record the agent can open is linked; anything else the gateway names stays unlinked. One lookup per record.
    const ids = [...new Set(b.events.flatMap((e) => (e.recordId ? [e.recordId] : [])))];
    const open = new Map(await Promise.all(ids.map(async (id) => [id, !!(await accessFor(app.prisma, userId, id, orgId))] as const)));
    // The gateway's clock is trusted only to within the last hour.
    const now = Date.now();
    const rows = b.events.map((e) => ({
      at: new Date(Math.min(now, Math.max(now - HOUR, Date.parse(e.at)))), orgId, actorId: userId, action: `agent.${e.action}`,
      recordId: e.recordId && open.get(e.recordId) ? e.recordId : null,
      meta: { host: e.host, method: e.method, ...(e.reason !== undefined ? { reason: e.reason } : {}), ...(e.truncated !== undefined ? { truncated: e.truncated } : {}) },
    }));
    await app.prisma.event.createMany({ data: rows });
    if (b.events.some((e) => e.action === "use")) await app.prisma.agent.update({ where: { userId }, data: { lastUsedAt: new Date() } });
    return { ok: true };
  });
};
