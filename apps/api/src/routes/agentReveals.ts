import type { FastifyInstance, FastifyPluginAsync, FastifyReply } from "fastify";
import { z } from "zod";
import { logEvent } from "../lib/events.js";
import { lockUser } from "../lib/orgs.js";
import { isPrivateLocked } from "../lib/privateLock.js";
import { ensureIdentity, reqMeta } from "../lib/agentAdmin.js";
import { gatewaySigned, revealRequestMessage } from "../lib/agents.js";
import { recordOrgOf } from "../lib/access.js";
import { agentRevealEmail, sendEmail } from "../lib/email.js";
import { isPublicKeyB64 } from "../lib/membershipKeys.js";
import { agentRateKey } from "../plugins/agent.js";
import { AGENT_ITEM_LIMIT, assertGrantable, connectedApp, expireReveal, personalAgentRules } from "../lib/personalAgents.js";

/** REVEAL_REF of @clane-vault/crypto (the API can't load it at runtime; a test pins the two together). */
export const REVEAL_FIELD = /^(username|password|url|notes|totp|data\.[A-Za-z0-9_]{1,40}|field:[A-Za-z0-9_-]{1,64}|env:[A-Za-z0-9_.-]{1,128})$/;
export const revealFields = z.array(z.string().regex(REVEAL_FIELD)).min(1).max(20).refine((f) => new Set(f).size === f.length, "fields must be unique");

const grantParam = z.object({ id: z.string().uuid(), agentId: z.string().uuid() });
const idParam = z.object({ id: z.string().uuid() });
/** A request lives 5 minutes; the gateway's clock may run a little ahead. */
export const REVEAL_TTL_MS = 5 * 60e3;
const CLOCK_SLACK_MS = 30e3;
const DENIALS = 3, DENIAL_WINDOW_MS = 10 * 60e3, PAUSE_MS = 3600e3, EMAIL_EVERY_MS = 10 * 60e3;

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

  /** Pending, unexpired requests to the caller, and their agents that are paused after three denials. */
  app.get("/me/agent-reveals", async (req) => {
    const me = req.auth.userId, now = new Date();
    const [rows, paused] = await Promise.all([
      app.prisma.agentRevealRequest.findMany({ where: { ownerUserId: me, status: "pending", expiresAt: { gt: now }, agent: { revokedAt: null } }, orderBy: { createdAt: "asc" },
        include: { agent: { select: { user: { select: { name: true } } } } } }),
      app.prisma.agent.findMany({ where: { ownerUserId: me, revokedAt: null, revealPausedUntil: { gt: now } }, select: { userId: true, revealPausedUntil: true, user: { select: { name: true } } } }),
    ]);
    return {
      requests: rows.map((r) => ({ id: r.id, agentId: r.agentId, agentName: r.agent.user.name, app: r.connectedApp, recordId: r.recordId, fields: r.fields, reason: r.reason,
        requestPublicKey: r.requestPublicKey, signature: r.signature, expiresAt: r.expiresAt.toISOString(), createdAt: r.createdAt.toISOString() })),
      paused: paused.map((p) => ({ agentId: p.userId, agentName: p.user.name, until: p.revealPausedUntil!.toISOString() })),
    };
  });

  /** `sealed`: only the approved fields, sealed to the request's one-time key (AAD agent-reveal:<request>:<record>:<agent>:<owner tag>) in the owner's browser. */
  app.post("/me/agent-reveals/:id/approve", async (req, reply) => {
    const { id } = idParam.parse(req.params);
    const b = z.object({ sealed: z.string().startsWith("s1.").max(65536) }).parse(req.body);
    const me = req.auth.userId;
    if (!(await app.prisma.agentRevealRequest.findFirst({ where: { id, ownerUserId: me }, select: { id: true } }))) return reply.code(404).send({ error: "not_found" });
    if ((await personalAgentRules(app.prisma, app.config, me)).reveal === "off") return reply.code(403).send({ error: "reveal_disabled" });
    const n = await app.prisma.agentRevealRequest.updateMany({ where: { id, ownerUserId: me, status: "pending", expiresAt: { gt: new Date() }, agent: { revokedAt: null } },
      data: { status: "approved", sealed: b.sealed } });
    return n.count ? { ok: true } : reply.code(409).send({ error: "expired" });
  });

  app.post("/me/agent-reveals/:id/deny", async (req, reply) => {
    const { id } = idParam.parse(req.params);
    const me = req.auth.userId;
    const row = await app.prisma.agentRevealRequest.findFirst({ where: { id, ownerUserId: me }, select: { agentId: true, recordId: true } });
    if (!row) return reply.code(404).send({ error: "not_found" });
    const ok = await app.prisma.$transaction(async (tx) => {
      await lockUser(tx, row.agentId);
      if (!(await tx.agentRevealRequest.updateMany({ where: { id, status: "pending", expiresAt: { gt: new Date() } }, data: { status: "denied" } })).count) return false;
      await logEvent(tx, { actorId: me, action: "agent.reveal_denied", recordId: row.recordId, targetUserId: row.agentId, meta: { requestId: id }, ...reqMeta(req) });
      const recent = await tx.event.count({ where: { action: "agent.reveal_denied", targetUserId: row.agentId, at: { gt: new Date(Date.now() - DENIAL_WINDOW_MS) } } });
      if (recent >= DENIALS) await tx.agent.update({ where: { userId: row.agentId }, data: { revealPausedUntil: new Date(Date.now() + PAUSE_MS) } });
      return true;
    });
    return ok ? { ok: true } : reply.code(409).send({ error: "expired" });
  });
};

/**
 * get_secret with approval (spec §5.3): the gateway's /agent/reveals*. Every business refusal is 409 { error } (the
 * gateway reads 401/403 as "agent ended"). Registered only with agent access and PERSONAL_AGENTS on.
 */
export const agentRevealAgentRoutes: FastifyPluginAsync = async (app) => {
  const agentOpts = { preHandler: app.requireAgent, config: { rateLimit: { keyGenerator: agentRateKey(app) } } };
  const refuse = (reply: FastifyReply, error: "reveal_off" | "busy" | "denied") => reply.code(409).send({ error });
  /** The owner's policies allow reveal, and *Can reveal* covers these fields of a Personal, untrashed item the owner holds. */
  const revealable = async (owner: string, agentId: string, recordId: string, fields: string[]) => {
    if ((await personalAgentRules(app.prisma, app.config, owner)).reveal === "off") return false;
    const stub = await app.prisma.agentRevealGrant.findUnique({ where: { recordId_agentId: { recordId, agentId } },
      select: { fields: true, record: { select: { ownerId: true, deletedAt: true, folder: { select: { kind: true, orgId: true } } } } } });
    return !!stub && stub.record.ownerId === owner && !stub.record.deletedAt && recordOrgOf(stub.record) === null && fields.every((f) => stub.fields.includes(f));
  };

  app.post("/agent/reveals", agentOpts, async (req, reply) => {
    const b = z.object({ id: z.string().uuid(), recordId: z.string().uuid(), fields: revealFields, reason: z.string().min(1).max(300),
      requestPublicKey: z.string().refine(isPublicKeyB64), signature: z.string().regex(/^q1\.[^.]+\.[^.]+$/).max(512),
      expiresAt: z.string().datetime().refine((s) => new Date(s).toISOString() === s, "expiresAt must be canonical") }).parse(req.body);
    const a = req.agent;
    if (!a.ownerUserId) return refuse(reply, "reveal_off"); // organisation agents never read values
    const owner = a.ownerUserId;
    if (!await revealable(owner, a.userId, b.recordId, b.fields)) return refuse(reply, "reveal_off");
    const now = Date.now(), exp = new Date(b.expiresAt).getTime();
    const via = await connectedApp(app.prisma, a);
    const r = await app.prisma.$transaction(async (tx) => {
      await lockUser(tx, a.userId); // one open request per agent; serialised with revocation
      const ag = await tx.agent.findFirst({ where: { userId: a.userId, revokedAt: null }, select: { revealPausedUntil: true } });
      if (!ag) return "reveal_off" as const;
      if (ag.revealPausedUntil && ag.revealPausedUntil.getTime() > now) return "denied" as const;
      if (await tx.agentRevealRequest.count({ where: { agentId: a.userId, status: "pending", expiresAt: { gt: new Date(now) } } })) return "busy" as const;
      if (!(exp > now && exp <= now + REVEAL_TTL_MS + CLOCK_SLACK_MS)) return "reveal_off" as const;
      const identity = await tx.gatewayIdentity.findUnique({ where: { id: "gateway" } }) ?? await ensureIdentity(app);
      if (!gatewaySigned(b.signature, "q1", revealRequestMessage({ requestId: b.id, ownerUserId: owner, agentId: a.userId, recordId: b.recordId, fields: b.fields,
        requestPublicKey: b.requestPublicKey, expiresAt: b.expiresAt }), identity)) return "reveal_off" as const;
      if (await tx.agentRevealRequest.findUnique({ where: { id: b.id }, select: { id: true } })) return "busy" as const;
      await tx.agentRevealRequest.create({ data: { id: b.id, agentId: a.userId, ownerUserId: owner, recordId: b.recordId, fields: b.fields, reason: b.reason,
        requestPublicKey: b.requestPublicKey, signature: b.signature, connectedApp: via, expiresAt: new Date(exp) } });
      await logEvent(tx, { actorId: a.userId, action: "agent.reveal_request", recordId: b.recordId, meta: { requestId: b.id, fields: b.fields, app: via } });
      return null;
    });
    if (r) return refuse(reply, r);
    notifyOwner(app, owner).catch((e: unknown) => req.log.warn({ err: e }, "agent reveal email failed")); // never awaited
    return reply.code(201).send({ id: b.id, expiresAt: b.expiresAt });
  });

  /**
   * Standing reveal (Phase D, spec §5.6): the gateway read fields the owner listed in the item's encrypted body. The API
   * can't see that list; it only refuses unless every policy says standing and the agent holds the item's key, and logs.
   * The gateway releases nothing before this 201.
   */
  app.post("/agent/reveals/standing", agentOpts, async (req, reply) => {
    const b = z.object({ recordId: z.string().uuid(), fields: revealFields }).parse(req.body);
    const a = req.agent;
    if (!a.ownerUserId || (await personalAgentRules(app.prisma, app.config, a.ownerUserId)).reveal !== "standing") return refuse(reply, "reveal_off");
    const row = await app.prisma.recordAccess.findFirst({ where: { recordId: b.recordId, holderType: "user", holderId: a.userId, orgId: null, state: "active",
      record: { ownerId: a.ownerUserId, deletedAt: null } }, select: { record: { select: { folder: { select: { kind: true, orgId: true } } } } } });
    if (!row || recordOrgOf(row.record) !== null) return refuse(reply, "reveal_off");
    const via = await connectedApp(app.prisma, a);
    await logEvent(app.prisma, { actorId: a.userId, action: "agent.reveal", recordId: b.recordId, meta: { fields: b.fields, app: via, standing: true } });
    return reply.code(201).send({ ok: true });
  });

  app.get("/agent/reveals/:id", agentOpts, async (req, reply) => {
    const { id } = idParam.parse(req.params);
    const a = req.agent;
    const row = await app.prisma.agentRevealRequest.findFirst({ where: { id, agentId: a.userId } });
    if (!row) return reply.code(404).send({ error: "not_found" });
    const now = new Date();
    if ((row.status === "pending" || row.status === "approved") && row.expiresAt <= now) { await expireReveal(app.prisma, id, now); return { status: "expired" }; }
    if (row.status === "pending") return { status: "pending" };
    if (row.status === "denied") return { status: "denied" };
    if (row.status !== "approved") return { status: "expired" };
    // M2: Can reveal turned off, the item moved, trashed or the policy changed after Allow: nothing is handed over.
    if (!await revealable(row.ownerUserId, a.userId, row.recordId, row.fields)) { await expireReveal(app.prisma, id, now, true); return { status: "expired" }; }
    // Delivered exactly once: the reply leaves the database as it is handed over.
    const sealed = await app.prisma.$transaction(async (tx) => {
      const r = await tx.agentRevealRequest.findFirst({ where: { id, status: "approved", expiresAt: { gt: now } }, select: { sealed: true } });
      if (!r?.sealed || !(await tx.agentRevealRequest.updateMany({ where: { id, status: "approved" }, data: { status: "delivered", sealed: null } })).count) return null;
      await logEvent(tx, { actorId: a.userId, action: "agent.reveal", recordId: row.recordId, meta: { requestId: id, fields: row.fields, app: row.connectedApp } });
      return r.sealed;
    });
    return sealed ? { status: "approved", sealed } : { status: "expired" };
  });
};

/** One email per owner per 10 minutes, when they want it (claimed with updateMany so two requests send one). */
async function notifyOwner(app: FastifyInstance, ownerUserId: string): Promise<void> {
  const since = new Date(Date.now() - EMAIL_EVERY_MS);
  const claimed = await app.prisma.user.updateMany({ where: { id: ownerUserId, agentRevealEmail: true, OR: [{ agentRevealEmailedAt: null }, { agentRevealEmailedAt: { lt: since } }] },
    data: { agentRevealEmailedAt: new Date() } });
  if (!claimed.count) return;
  const u = await app.prisma.user.findUniqueOrThrow({ where: { id: ownerUserId }, select: { email: true } });
  await sendEmail(app.mail, u.email, agentRevealEmail(await app.brand.productName(), `${app.config.publicUrl}/`), app.log);
}
