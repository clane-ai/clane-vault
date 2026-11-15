import type { FastifyPluginAsync, FastifyReply, FastifyRequest } from "fastify";
import { randomUUID } from "node:crypto";
import { z } from "zod";
import { displayName } from "../lib/names.js";
import { createAgentToken, ensureIdentity, expiry, gatewayInfo, grantView, patchAgent, revokeAgentGrant, revokeAgentToken, tokenView, verifyAgent } from "../lib/agentAdmin.js";
import { agentEmail, fingerprintOf, personalAttestationOk } from "../lib/agents.js";
import { GatewayUnavailable } from "../lib/gateway.js";
import { isPrivateLocked } from "../lib/privateLock.js";
import { assertPersonalAgentSlot, logLifecycle, personalAgentRules } from "../lib/personalAgents.js";

const idParam = z.object({ id: z.string().uuid() });

/** /me/agents: the owner-scoped twins of /admin/agents, for personal agents. Registered only with agent access and PERSONAL_AGENTS on. No organisation context is read. */
export const myAgentRoutes: FastifyPluginAsync = async (app) => {
  app.addHook("preHandler", app.requireAuth);
  app.addHook("preHandler", async (req, reply) => { if (isPrivateLocked(req)) return reply.code(403).send({ error: "totp_step_up_required" }); });
  const me = (req: FastifyRequest) => req.auth.userId;

  /** The caller's own agent; 404 otherwise. */
  async function mine(req: FastifyRequest, reply: FastifyReply) {
    const { id } = idParam.parse(req.params);
    const a = await app.prisma.agent.findFirst({ where: { userId: id, ownerUserId: me(req) } });
    if (!a) { await reply.code(404).send({ error: "not_found" }); return null; }
    return a;
  }
  app.post("/", async (req, reply) => {
    const b = z.object({ name: displayName, expiresAt: expiry.optional() }).parse(req.body);
    const owner = me(req);
    const rules = await personalAgentRules(app.prisma, app.config, owner);
    if (!rules.allowed) return reply.code(403).send({ error: "personal_agents_disabled", orgId: rules.blockedByOrgId ?? undefined });
    await app.prisma.$transaction((tx) => assertPersonalAgentSlot(tx, app.config, owner)); // fast refusal before asking the gateway
    const ownerPublicKey = (await app.prisma.user.findUniqueOrThrow({ where: { id: owner }, select: { publicKey: true } })).publicKey;
    const gateway = await ensureIdentity(app);
    const id = randomUUID();
    const key = await app.gateway.createPersonalAgentKey({ agentId: id, ownerUserId: owner, ownerPublicKey });
    // Defence in depth (the browser checks it too): never store a key the pinned gateway identity didn't sign for this owner.
    if (!personalAttestationOk(key.attestation, { ownerUserId: owner, ownerPublicKey, agentId: id, publicKey: key.publicKey }, gateway))
      throw new GatewayUnavailable("the agent gateway's attestation does not verify");
    const blocked = await app.prisma.$transaction(async (tx) => {
      await assertPersonalAgentSlot(tx, app.config, owner); // takes the owner's lock; the rules are re-read under it
      const now = await personalAgentRules(tx, app.config, owner);
      if (!now.allowed) return { orgId: now.blockedByOrgId };
      await tx.user.create({ data: { id, kind: "agent", email: agentEmail(id), name: b.name, status: "active",
        authHash: "", kdfSalt: "", kdfParams: {}, wrappedUserKey: "", publicKey: key.publicKey, wrappedPrivateKey: "" } });
      await tx.agent.create({ data: { userId: id, ownerUserId: owner, createdById: owner, publicKey: key.publicKey, wrappedPrivateKey: key.wrappedPrivateKey,
        kekId: key.kekId, attestation: key.attestation, expiresAt: b.expiresAt ?? null } });
      await logLifecycle(tx, owner, "create", id);
      return null;
    });
    if (blocked) return reply.code(403).send({ error: "personal_agents_disabled", orgId: blocked.orgId ?? undefined });
    return reply.code(201).send({ id, name: b.name, publicKey: key.publicKey, fingerprint: fingerprintOf(key.publicKey), attestation: key.attestation,
      owner: { userId: owner, publicKey: ownerPublicKey }, gateway: { keyId: gateway.keyId, publicKey: gateway.publicKey, fingerprint: fingerprintOf(gateway.publicKey) } });
  });

  app.get("/", async (req) => {
    const owner = me(req);
    const [rows, rules, ownerRow, gw] = await Promise.all([
      app.prisma.agent.findMany({ where: { ownerUserId: owner }, orderBy: { createdAt: "asc" }, include: { user: { select: { name: true } },
        tokens: { orderBy: { createdAt: "asc" }, select: { id: true, label: true, createdAt: true, expiresAt: true, lastUsedAt: true, revokedAt: true } },
        grants: { where: { revokedAt: null, expiresAt: { gt: new Date() } }, orderBy: { createdAt: "asc" }, select: { id: true, clientId: true, createdAt: true } } } }),
      personalAgentRules(app.prisma, app.config, owner),
      app.prisma.user.findUniqueOrThrow({ where: { id: owner }, select: { publicKey: true } }),
      gatewayInfo(app).catch(() => null), // by design an unreachable gateway, or a changed identity (GatewayIdentityChanged), shows as no gateway here instead of failing the list
    ]);
    const [items, clients] = await Promise.all([
      app.prisma.recordAccess.groupBy({ by: ["holderId"], where: { holderType: "user", holderId: { in: rows.map((r) => r.userId) }, state: "active" }, _count: true }),
      app.prisma.agentOAuthClient.findMany({ where: { id: { in: rows.flatMap((r) => r.grants.map((g) => g.clientId)) } }, select: { id: true, name: true } }),
    ]);
    const now = Date.now(), ownerKey = { userId: owner, publicKey: ownerRow.publicKey };
    return {
      agents: rows.map((a) => ({
        id: a.userId, name: a.user.name,
        status: a.revokedAt ? "revoked" : a.expiresAt && a.expiresAt.getTime() <= now ? "expired" : !a.verifiedAt ? "awaiting_verification" : rules.allowed ? "active" : "suspended",
        publicKey: a.publicKey, attestation: a.attestation, expiresAt: a.expiresAt?.toISOString() ?? null, lastUsedAt: a.lastUsedAt?.toISOString() ?? null,
        createdAt: a.createdAt.toISOString(), verifiedAt: a.verifiedAt?.toISOString() ?? null,
        items: items.find((i) => i.holderId === a.userId)?._count ?? 0, owner: ownerKey,
        tokens: a.tokens.map(tokenView),
        grants: a.grants.map((g) => grantView(g, clients)),
      })),
      allowance: { used: rows.filter((r) => !r.revokedAt).length, allowed: rules.max },
      rules: { allowed: rules.allowed, blockedByOrgId: rules.blockedByOrgId, write: rules.write, reveal: rules.reveal },
      gateway: gw, revealEmail: true,
    };
  });

  app.get("/gateway", async () => gatewayInfo(app));

  /** The owner's browser checked the attestation and the fingerprints; `publicKey` is the key it checked. */
  app.post("/:id/verify", async (req, reply) => verifyAgent(app, req, reply, () => mine(req, reply),
    async (a, publicKey) => a.publicKey === publicKey,
    (tx, a) => logLifecycle(tx, me(req), "verify", a.userId)));

  app.patch("/:id", async (req, reply) => patchAgent(app, req, reply, () => mine(req, reply), undefined));

  app.post("/:id/tokens", async (req, reply) => createAgentToken(app, req, reply, () => mine(req, reply), undefined, (tx) => logLifecycle(tx, me(req), "connect", idParam.parse(req.params).id)));

  app.delete("/:id/tokens/:tokenId", async (req, reply) => revokeAgentToken(app, req, reply, () => mine(req, reply), undefined));

  app.delete("/:id/grants/:grantId", async (req, reply) => revokeAgentGrant(app, req, reply, () => mine(req, reply)));
};
