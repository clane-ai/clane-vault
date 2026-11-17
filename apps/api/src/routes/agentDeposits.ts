import type { FastifyPluginAsync, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import { depositMessage, gatewaySigned, sha256B64 } from "../lib/agents.js";
import { ensureIdentity, reqMeta } from "../lib/agentAdmin.js";
import { logEvent } from "../lib/events.js";
import { lockUser } from "../lib/orgs.js";
import { isPrivateLocked } from "../lib/privateLock.js";
import { agentRateKey } from "../plugins/agent.js";
import { AGENT_ITEM_LIMIT, DEPOSIT_INBOX_LIMIT, DEPOSIT_TTL_MS, connectedApp, personalAgentRules } from "../lib/personalAgents.js";

const envelope = z.string().startsWith("v1.").max(65536);
const sealed = z.string().startsWith("s1.").max(4096);
const signature = z.string().regex(/^d1\.[^.]+\.[^.]+$/).max(512);
const idParam = z.object({ id: z.string().uuid() });

/**
 * Agent writes (spec §4): the gateway's /agent/deposits*, and the owner's /me/agent-deposits* inbox. Registered only with
 * agent access and PERSONAL_AGENTS on. Every business refusal to the gateway is 409 { error }: it reads 401/403 as "agent ended".
 */
export const agentDepositRoutes: FastifyPluginAsync = async (app) => {
  const agentOpts = { preHandler: app.requireAgent, config: { rateLimit: { keyGenerator: agentRateKey(app) } } };
  const ownerOpts = { preHandler: [app.requireAuth, async (req: FastifyRequest, reply: FastifyReply) => {
    if (isPrivateLocked(req)) return reply.code(403).send({ error: "totp_step_up_required" });
  }] };
  const refuse = (reply: FastifyReply, error: "not_writable" | "conflict" | "inbox_full") => reply.code(409).send({ error });

  /** The owner's current key and whether the pinned gateway identity signed this body at `revision` for them. */
  async function signedByGateway(a: FastifyRequest["agent"], b: { id: string; encBody: string; signature: string }, revision: number) {
    const owner = await app.prisma.user.findUniqueOrThrow({ where: { id: a.ownerUserId! }, select: { publicKey: true } });
    const identity = await app.prisma.gatewayIdentity.findUnique({ where: { id: "gateway" } }) ?? await ensureIdentity(app);
    return gatewaySigned(b.signature, "d1", depositMessage({ ownerUserId: a.ownerUserId!, ownerPublicKey: owner.publicKey, agentId: a.userId, id: b.id, revision,
      encBodyHash: sha256B64(b.encBody) }), identity);
  }
  /** An organisation agent, or the owner's policies forbid writes. */
  const writable = async (a: FastifyRequest["agent"]) => !!a.ownerUserId && (await personalAgentRules(app.prisma, app.config, a.ownerUserId)).write;

  app.post("/agent/deposits", agentOpts, async (req, reply) => {
    const b = z.object({ id: z.string().uuid(), type: z.enum(["login", "item"]), encBody: envelope, ownerSealedKey: sealed, agentSealedKey: sealed, signature }).parse(req.body);
    const a = req.agent;
    if (!(await writable(a))) return refuse(reply, "not_writable");
    if (!(await signedByGateway(a, b, 1))) return refuse(reply, "conflict");
    const via = await connectedApp(app.prisma, a);
    const r = await app.prisma.$transaction(async (tx) => {
      await lockUser(tx, a.ownerUserId!); // serialises the owner's inbox count
      if (await tx.agentDeposit.count({ where: { ownerUserId: a.ownerUserId! } }) >= DEPOSIT_INBOX_LIMIT) return "inbox_full" as const;
      if (await tx.record.findUnique({ where: { id: b.id }, select: { id: true } }) || await tx.agentDeposit.findUnique({ where: { id: b.id }, select: { id: true } })) return "conflict" as const;
      await tx.agentDeposit.create({ data: { ...b, ownerUserId: a.ownerUserId!, agentId: a.userId, connectedApp: via } });
      await logEvent(tx, { actorId: a.userId, action: "agent.deposit", recordId: b.id, meta: { app: via } });
      return null;
    });
    return r ? refuse(reply, r) : reply.code(201).send({ id: b.id, revision: 1 });
  });

  /** update_secret on the agent's own unkept deposit: same record key, the signature covers revision + 1. */
  app.put("/agent/deposits/:id", agentOpts, async (req, reply) => {
    const { id } = idParam.parse(req.params);
    const b = z.object({ encBody: envelope, revision: z.number().int().min(1), signature }).parse(req.body);
    const a = req.agent;
    if (!(await writable(a))) return refuse(reply, "not_writable");
    const d = await app.prisma.agentDeposit.findFirst({ where: { id, agentId: a.userId }, select: { revision: true } });
    if (!d) return refuse(reply, "not_writable");
    if (d.revision !== b.revision || !(await signedByGateway(a, { id, ...b }, b.revision + 1))) return refuse(reply, "conflict");
    const n = await app.prisma.agentDeposit.updateMany({ where: { id, agentId: a.userId, revision: b.revision },
      data: { encBody: b.encBody, signature: b.signature, revision: b.revision + 1 } });
    return n.count ? { id, revision: b.revision + 1 } : refuse(reply, "conflict");
  });

  app.get("/me/agent-deposits", ownerOpts, async (req) => {
    const rows = await app.prisma.agentDeposit.findMany({ where: { ownerUserId: req.auth.userId }, orderBy: { createdAt: "asc" },
      include: { agent: { select: { user: { select: { name: true } } } } } });
    return { deposits: rows.map((d) => ({ id: d.id, agentId: d.agentId, agentName: d.agent.user.name, app: d.connectedApp, type: d.type, encBody: d.encBody, revision: d.revision,
      ownerSealedKey: d.ownerSealedKey, signature: d.signature, createdAt: d.createdAt.toISOString(), updatedAt: d.updatedAt.toISOString(),
      expiresAt: new Date(d.createdAt.getTime() + DEPOSIT_TTL_MS).toISOString() })) };
  });

  /** Keep: the browser re-wrapped the record key under the user key (v1.); optionally sealed it to the agent again (s1.). */
  app.post("/me/agent-deposits/:id/keep", ownerOpts, async (req, reply) => {
    const { id } = idParam.parse(req.params);
    const b = z.object({ revision: z.number().int().min(1), wrappedRecordKey: z.string().startsWith("v1.").max(4096), folderId: z.string().uuid().nullable(),
      agentWrappedRecordKey: sealed.optional() }).parse(req.body);
    const me = req.auth.userId;
    const r = await app.prisma.$transaction(async (tx) => {
      const d = await tx.agentDeposit.findFirst({ where: { id, ownerUserId: me } });
      if (!d) return { code: 404, error: "not_found" } as const;
      if (d.revision !== b.revision) return { code: 409, error: "conflict" } as const;
      if (b.folderId && !(await tx.folder.findFirst({ where: { id: b.folderId, ownerId: me, kind: "private", deletedAt: null }, select: { id: true } })))
        return { code: 404, error: "folder_not_found" } as const;
      // The claim: a concurrent agent update or a second Keep loses here.
      if ((await tx.agentDeposit.deleteMany({ where: { id, ownerUserId: me, revision: b.revision } })).count !== 1) return { code: 409, error: "conflict" } as const;
      await tx.record.create({ data: { id, folderId: b.folderId, ownerId: me, type: d.type, encBody: d.encBody, createdByAgentId: d.agentId,
        access: { create: { holderType: "user", holderId: me, permission: "owner", wrappedRecordKey: b.wrappedRecordKey } } } });
      let agentRow: boolean | undefined;
      if (b.agentWrappedRecordKey) {
        await lockUser(tx, d.agentId); // as a grant: serialised with revocation and the item limit
        const a = await tx.agent.findFirst({ where: { userId: d.agentId, ownerUserId: me, revokedAt: null, verifiedAt: { not: null },
          OR: [{ expiresAt: null }, { expiresAt: { gt: new Date() } }], user: { status: "active" } }, select: { publicKey: true } });
        agentRow = !!a && await tx.recordAccess.count({ where: { holderType: "user", holderId: d.agentId } }) < AGENT_ITEM_LIMIT;
        if (agentRow) await tx.recordAccess.create({ data: { recordId: id, holderType: "user", holderId: d.agentId, permission: "use", orgId: null, sealedTo: a!.publicKey,
          wrappedRecordKey: b.agentWrappedRecordKey } });
      }
      await logEvent(tx, { actorId: me, action: "agent.deposit_keep", recordId: id, targetUserId: d.agentId, ...reqMeta(req) });
      return { code: 201, agentRow } as const;
    });
    if (r.code !== 201) return reply.code(r.code).send({ error: r.error });
    return reply.code(201).send({ id, revision: 1, ...(r.agentRow === false ? { agentRow: false } : {}) });
  });

  app.delete("/me/agent-deposits/:id", ownerOpts, async (req, reply) => {
    const { id } = idParam.parse(req.params);
    const me = req.auth.userId;
    const n = await app.prisma.$transaction(async (tx) => {
      const d = await tx.agentDeposit.deleteMany({ where: { id, ownerUserId: me } });
      if (d.count) await logEvent(tx, { actorId: me, action: "agent.deposit_delete", recordId: id, ...reqMeta(req) });
      return d.count;
    });
    return n ? reply.code(204).send() : reply.code(404).send({ error: "not_found" });
  });
};
