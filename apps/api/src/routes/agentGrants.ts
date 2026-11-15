import type { FastifyPluginAsync } from "fastify";
import { z } from "zod";
import { logEvent } from "../lib/events.js";
import { lockUser } from "../lib/orgs.js";
import { isPrivateLocked } from "../lib/privateLock.js";
import { reqMeta } from "../lib/agentAdmin.js";
import { AGENT_ITEM_LIMIT, assertGrantable } from "../lib/personalAgents.js";

const idParam = z.object({ id: z.string().uuid() });
const grantParam = z.object({ id: z.string().uuid(), agentId: z.string().uuid() });

/** Per-item grants of a person's private records to their own personal agents. Registered only with agent access and PERSONAL_AGENTS on. */
export const agentGrantRoutes: FastifyPluginAsync = async (app) => {
  app.addHook("preHandler", app.requireAuth);
  app.addHook("preHandler", async (req, reply) => { if (isPrivateLocked(req)) return reply.code(403).send({ error: "totp_step_up_required" }); });

  /** `wrappedRecordKey`: the record key sealed to the agent (AAD personal-agent-record:<owner>:<agent>:<record>), made in the owner's browser. */
  app.post("/records/:id/agent-grants", async (req, reply) => {
    const { id } = idParam.parse(req.params);
    const b = z.object({ agentId: z.string().uuid(), wrappedRecordKey: z.string().startsWith("s1.").max(4096) }).parse(req.body);
    const me = req.auth.userId;
    const r = await app.prisma.$transaction(async (tx) => {
      await lockUser(tx, b.agentId); // serialised with revocation and with other grants to this agent (the item limit)
      const g = await assertGrantable(tx, me, id, b.agentId);
      if ("error" in g) return g;
      if (await tx.recordAccess.count({ where: { holderType: "user", holderId: b.agentId } }) >= AGENT_ITEM_LIMIT) return { code: 409, error: "agent_item_limit" };
      if (await tx.recordAccess.findUnique({ where: { recordId_holderType_holderId: { recordId: id, holderType: "user", holderId: b.agentId } }, select: { id: true } }))
        return { code: 409, error: "already_shared" };
      await tx.recordAccess.create({ data: { recordId: id, holderType: "user", holderId: b.agentId, permission: "use", orgId: null, sealedTo: g.publicKey, wrappedRecordKey: b.wrappedRecordKey } });
      await logEvent(tx, { actorId: me, action: "agent.item_grant", recordId: id, targetUserId: b.agentId, ...reqMeta(req) });
      return null;
    });
    return r ? reply.code(r.code).send({ error: r.error }) : reply.code(201).send({ ok: true });
  });

  app.delete("/records/:id/agent-grants/:agentId", async (req, reply) => {
    const { id, agentId } = grantParam.parse(req.params);
    const me = req.auth.userId;
    if (!(await app.prisma.agent.findFirst({ where: { userId: agentId, ownerUserId: me }, select: { userId: true } }))) return reply.code(404).send({ error: "not_found" });
    const n = await app.prisma.$transaction(async (tx) => {
      const d = await tx.recordAccess.deleteMany({ where: { recordId: id, holderType: "user", holderId: agentId, permission: { not: "owner" } } });
      if (d.count) await logEvent(tx, { actorId: me, action: "agent.item_revoke", recordId: id, targetUserId: agentId, ...reqMeta(req) });
      return d.count;
    });
    if (!n) return reply.code(404).send({ error: "not_found" });
    app.gateway.dropAgent(agentId).catch(() => undefined); // best effort: it forgets the cached key now
    return reply.code(204).send();
  });
};
