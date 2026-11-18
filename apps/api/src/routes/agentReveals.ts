import type { FastifyPluginAsync } from "fastify";
import { z } from "zod";
import { logEvent } from "../lib/events.js";
import { lockUser } from "../lib/orgs.js";
import { isPrivateLocked } from "../lib/privateLock.js";
import { reqMeta } from "../lib/agentAdmin.js";
import { AGENT_ITEM_LIMIT, assertGrantable, personalAgentRules } from "../lib/personalAgents.js";

/** REVEAL_REF of @clane-vault/crypto (the API can't load it at runtime; a test pins the two together). */
export const REVEAL_FIELD = /^(username|password|url|notes|totp|data\.[A-Za-z0-9_]{1,40}|field:[A-Za-z0-9_-]{1,64}|env:[A-Za-z0-9_.-]{1,128})$/;
export const revealFields = z.array(z.string().regex(REVEAL_FIELD)).min(1).max(20).refine((f) => new Set(f).size === f.length, "fields must be unique");

const grantParam = z.object({ id: z.string().uuid(), agentId: z.string().uuid() });

/** *Can reveal* on one item: the owner's routes. Registered only with agent access and PERSONAL_AGENTS on. */
export const agentRevealOwnerRoutes: FastifyPluginAsync = async (app) => {
  app.addHook("preHandler", app.requireAuth);
  app.addHook("preHandler", async (req, reply) => { if (isPrivateLocked(req)) return reply.code(403).send({ error: "totp_step_up_required" }); });

  /** `sealedStub`: { title, type, fields } sealed to the agent (AAD personal-agent-stub:<owner>:<agent>:<record>) in the owner's browser. */
  app.put("/records/:id/agent-reveal/:agentId", async (req, reply) => {
    const { id, agentId } = grantParam.parse(req.params);
    const b = z.object({ sealedStub: z.string().startsWith("s1.").max(8192), fields: revealFields }).parse(req.body);
    const me = req.auth.userId;
    const r = await app.prisma.$transaction(async (tx) => {
      await lockUser(tx, agentId); // the agent's lock first, as grants and revocation
      const g = await assertGrantable(tx, me, id, agentId);
      if ("error" in g) return g;
      if ((await personalAgentRules(tx, app.config, me)).reveal === "off") return { code: 403, error: "reveal_disabled" };
      const held = await tx.agentRevealGrant.findUnique({ where: { recordId_agentId: { recordId: id, agentId } }, select: { id: true } });
      if (!held && await tx.agentRevealGrant.count({ where: { agentId } }) >= AGENT_ITEM_LIMIT) return { code: 409, error: "agent_item_limit" };
      await tx.agentRevealGrant.upsert({ where: { recordId_agentId: { recordId: id, agentId } },
        create: { recordId: id, agentId, sealedStub: b.sealedStub, fields: b.fields }, update: { sealedStub: b.sealedStub, fields: b.fields } });
      await logEvent(tx, { actorId: me, action: "agent.item_reveal_on", recordId: id, targetUserId: agentId, meta: { fields: b.fields }, ...reqMeta(req) });
      return null;
    });
    if (r) return reply.code(r.code).send({ error: r.error });
    app.gateway?.dropAgent(agentId).catch(() => undefined); // best effort: it sees the new fields on its next call
    return { ok: true };
  });

  app.delete("/records/:id/agent-reveal/:agentId", async (req, reply) => {
    const { id, agentId } = grantParam.parse(req.params);
    const me = req.auth.userId;
    if (!(await app.prisma.agent.findFirst({ where: { userId: agentId, ownerUserId: me }, select: { userId: true } }))) return reply.code(404).send({ error: "not_found" });
    const n = await app.prisma.$transaction(async (tx) => {
      const d = await tx.agentRevealGrant.deleteMany({ where: { recordId: id, agentId, record: { ownerId: me } } });
      if (d.count) await logEvent(tx, { actorId: me, action: "agent.item_reveal_off", recordId: id, targetUserId: agentId, ...reqMeta(req) });
      return d.count;
    });
    if (!n) return reply.code(404).send({ error: "not_found" });
    app.gateway?.dropAgent(agentId).catch(() => undefined); // F3: best effort, after the commit
    return reply.code(204).send();
  });
};
