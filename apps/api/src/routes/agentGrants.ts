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
  const ownedRecord = (me: string, id: string) =>
    app.prisma.record.findFirst({ where: { id, ownerId: me, access: { some: { holderType: "user", holderId: me, permission: "owner" } } }, select: { id: true } });

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

  /** Agent can update: the only route that sets RecordAccess.agentWrite. */
  app.patch("/records/:id/agent-grants/:agentId", async (req, reply) => {
    const { id, agentId } = grantParam.parse(req.params);
    const b = z.object({ write: z.boolean() }).parse(req.body);
    const me = req.auth.userId;
    if (!(await app.prisma.agent.findFirst({ where: { userId: agentId, ownerUserId: me }, select: { userId: true } }))) return reply.code(404).send({ error: "not_found" });
    const r = await app.prisma.$transaction(async (tx) => {
      await lockUser(tx, agentId); // the agent's lock first, as revocation and the agent's writes
      // Turning write on gets a grant's checks (the owner's own live private record, the agent live and verified); turning it off is never refused.
      if (b.write) { const g = await assertGrantable(tx, me, id, agentId); if ("error" in g) return g; }
      const u = await tx.recordAccess.updateMany({ where: { recordId: id, holderType: "user", holderId: agentId, permission: { not: "owner" }, orgId: null, state: "active", record: { ownerId: me } }, data: { agentWrite: b.write } });
      if (!u.count) return { code: 404 as const, error: "not_found" as const };
      await logEvent(tx, { actorId: me, action: "agent.item_write", recordId: id, targetUserId: agentId, meta: { write: b.write }, ...reqMeta(req) });
      return null;
    });
    if (r) return reply.code(r.code).send({ error: r.error });
    if (!b.write) app.gateway?.dropAgent(agentId).catch(() => undefined); // best effort: it forgets that it may write
    return { ok: true };
  });

  /** The record's kept overwrites, newest first (owner only). Restoring one is the client's ordinary PUT /records/:id. */
  app.get("/records/:id/agent-overwrites", async (req, reply) => {
    const { id } = idParam.parse(req.params);
    if (!(await ownedRecord(req.auth.userId, id))) return reply.code(404).send({ error: "not_found" });
    const rows = await app.prisma.recordAgentOverwrite.findMany({ where: { recordId: id }, orderBy: { newRevision: "desc" } });
    const names = new Map((await app.prisma.user.findMany({ where: { id: { in: [...new Set(rows.map((o) => o.agentId))] } }, select: { id: true, name: true } })).map((u) => [u.id, u.name]));
    return { overwrites: rows.map((o) => ({ id: o.id, agentId: o.agentId, agentName: names.get(o.agentId) ?? "", prevEncBody: o.prevEncBody, newRevision: o.newRevision,
      signature: o.signature, createdAt: o.createdAt.toISOString() })) };
  });

  /** The owner has seen them: *Changed by agent* goes. */
  app.post("/records/:id/agent-overwrites/ack", async (req, reply) => {
    const { id } = idParam.parse(req.params);
    if (!(await ownedRecord(req.auth.userId, id))) return reply.code(404).send({ error: "not_found" });
    await app.prisma.recordAgentOverwrite.updateMany({ where: { recordId: id, ackedAt: null }, data: { ackedAt: new Date() } });
    return { ok: true };
  });
};
