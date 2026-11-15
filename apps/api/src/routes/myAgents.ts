import type { FastifyPluginAsync, FastifyReply, FastifyRequest } from "fastify";
import { randomUUID } from "node:crypto";
import { z } from "zod";
import { displayName } from "../lib/names.js";
import { logEvent } from "../lib/events.js";
import { agentEmail, fingerprintOf, personalAttestationOk } from "../lib/agents.js";
import { GatewayUnavailable } from "../lib/gateway.js";
import { isPublicKeyB64 } from "../lib/membershipKeys.js";
import { isPrivateLocked } from "../lib/privateLock.js";
import { assertPersonalAgentSlot, logLifecycle, personalAgentRules } from "../lib/personalAgents.js";
import { newAgentToken } from "../lib/tokens.js";
import { revokeGrant } from "./oauth.js";
import { ensureIdentity, expiry, stillLive } from "./agents.js";

const idParam = z.object({ id: z.string().uuid() });
const tokenParam = z.object({ tokenId: z.string().uuid() }).passthrough();
const grantParam = z.object({ grantId: z.string().uuid() }).passthrough();

/** /me/agents: the owner-scoped twins of /admin/agents, for personal agents. Registered only with agent access and PERSONAL_AGENTS on. No organisation context is read. */
export const myAgentRoutes: FastifyPluginAsync = async (app) => {
  app.addHook("preHandler", app.requireAuth);
  app.addHook("preHandler", async (req, reply) => { if (isPrivateLocked(req)) return reply.code(403).send({ error: "totp_step_up_required" }); });
  const me = (req: FastifyRequest) => req.auth.userId;
  const meta = (req: FastifyRequest) => ({ ip: req.ip, userAgent: String(req.headers["user-agent"] ?? "").slice(0, 300) });

  /** The caller's own agent; 404 otherwise. */
  async function mine(req: FastifyRequest, reply: FastifyReply) {
    const { id } = idParam.parse(req.params);
    const a = await app.prisma.agent.findFirst({ where: { userId: id, ownerUserId: me(req) } });
    if (!a) { await reply.code(404).send({ error: "not_found" }); return null; }
    return a;
  }
  const gatewayInfo = async () => {
    const row = await app.prisma.gatewayIdentity.findUnique({ where: { id: "gateway" } }) ?? await ensureIdentity(app);
    return { url: app.config.agents!.gatewayPublicUrl, identityKeyId: row.keyId, identityPublicKey: row.publicKey };
  };

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
    await app.prisma.$transaction(async (tx) => {
      await assertPersonalAgentSlot(tx, app.config, owner);
      await tx.user.create({ data: { id, kind: "agent", email: agentEmail(id), name: b.name, status: "active",
        authHash: "", kdfSalt: "", kdfParams: {}, wrappedUserKey: "", publicKey: key.publicKey, wrappedPrivateKey: "" } });
      await tx.agent.create({ data: { userId: id, ownerUserId: owner, createdById: owner, publicKey: key.publicKey, wrappedPrivateKey: key.wrappedPrivateKey,
        kekId: key.kekId, attestation: key.attestation, expiresAt: b.expiresAt ?? null } });
      await logLifecycle(tx, owner, "create", id);
    });
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
      gatewayInfo().catch(() => null), // an unreachable gateway still lets people see their agents
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
        // Never the token or its hash.
        tokens: a.tokens.map((k) => ({ id: k.id, label: k.label, createdAt: k.createdAt.toISOString(), expiresAt: k.expiresAt?.toISOString() ?? null,
          lastUsedAt: k.lastUsedAt?.toISOString() ?? null, revokedAt: k.revokedAt?.toISOString() ?? null })),
        grants: a.grants.map((g) => ({ id: g.id, clientName: clients.find((c) => c.id === g.clientId)?.name ?? "", createdAt: g.createdAt.toISOString() })),
      })),
      allowance: { used: rows.filter((r) => !r.revokedAt).length, allowed: rules.max },
      rules: { allowed: rules.allowed, blockedByOrgId: rules.blockedByOrgId, write: rules.write, reveal: rules.reveal },
      gateway: gw, revealEmail: true,
    };
  });

  app.get("/gateway", async () => gatewayInfo());

  /** The owner's browser checked the attestation and the fingerprints; `publicKey` is the key it checked. */
  app.post("/:id/verify", async (req, reply) => {
    const b = z.object({ publicKey: z.string().refine(isPublicKeyB64) }).parse(req.body);
    const a = await mine(req, reply);
    if (!a) return reply;
    if (a.revokedAt) return reply.code(409).send({ error: "agent_revoked" });
    if (a.publicKey !== b.publicKey) return reply.code(409).send({ error: "stale_key" });
    const ok = await app.prisma.$transaction(async (tx) => {
      if (!(await stillLive(tx, a.userId))) return false;
      await tx.agent.update({ where: { userId: a.userId }, data: { verifiedById: me(req), verifiedAt: new Date() } });
      await logLifecycle(tx, me(req), "verify", a.userId);
      return true;
    });
    return ok ? { ok: true } : reply.code(409).send({ error: "agent_revoked" });
  });

  app.patch("/:id", async (req, reply) => {
    const b = z.object({ name: displayName.optional(), expiresAt: expiry.optional() }).parse(req.body);
    const a = await mine(req, reply);
    if (!a) return reply;
    await app.prisma.$transaction([
      ...(b.name !== undefined ? [app.prisma.user.update({ where: { id: a.userId }, data: { name: b.name } })] : []),
      ...(b.expiresAt !== undefined ? [app.prisma.agent.update({ where: { userId: a.userId }, data: { expiresAt: b.expiresAt } })] : []),
    ]);
    return { ok: true };
  });

  /** A static token for an API/SDK client: returned once, only its hash is kept. */
  app.post("/:id/tokens", async (req, reply) => {
    const b = z.object({ label: z.string().min(1).max(60), expiresAt: expiry.optional() }).parse(req.body);
    const a = await mine(req, reply);
    if (!a) return reply;
    if (a.revokedAt) return reply.code(409).send({ error: "agent_revoked" });
    const id = randomUUID();
    const { token, hash } = newAgentToken(id);
    const ok = await app.prisma.$transaction(async (tx) => {
      if (!(await stillLive(tx, a.userId))) return false;
      await tx.agentToken.create({ data: { id, agentId: a.userId, label: b.label, tokenHash: hash, createdById: me(req), expiresAt: b.expiresAt ?? null } });
      await logEvent(tx, { actorId: me(req), action: "agent.token_create", targetUserId: a.userId, meta: { tokenId: id }, ...meta(req) });
      await logLifecycle(tx, me(req), "connect", a.userId);
      return true;
    });
    return ok ? reply.code(201).send({ id, token }) : reply.code(409).send({ error: "agent_revoked" });
  });

  app.delete("/:id/tokens/:tokenId", async (req, reply) => {
    const { tokenId } = tokenParam.parse(req.params);
    const a = await mine(req, reply);
    if (!a) return reply;
    if (!(await app.prisma.agentToken.findFirst({ where: { id: tokenId, agentId: a.userId }, select: { id: true } }))) return reply.code(404).send({ error: "not_found" });
    // The claim is atomic: of two concurrent revokes only one logs.
    const claimed = await app.prisma.$transaction(async (tx) => {
      const r = await tx.agentToken.updateMany({ where: { id: tokenId, agentId: a.userId, revokedAt: null }, data: { revokedAt: new Date() } });
      if (r.count === 1) await logEvent(tx, { actorId: me(req), action: "agent.token_revoke", targetUserId: a.userId, meta: { tokenId }, ...meta(req) });
      return r.count === 1;
    });
    if (claimed) app.gateway.dropAgent(a.userId).catch(() => undefined); // the gateway forgets its cached keys now rather than in 60 s
    return reply.code(204).send();
  });

  app.delete("/:id/grants/:grantId", async (req, reply) => {
    const { grantId } = grantParam.parse(req.params);
    const a = await mine(req, reply);
    if (!a) return reply;
    if (!(await app.prisma.agentGrant.findFirst({ where: { id: grantId, agentId: a.userId }, select: { id: true } }))) return reply.code(404).send({ error: "not_found" });
    await revokeGrant(app, { id: grantId, agentId: a.userId }, { actorId: me(req), req });
    return reply.code(204).send();
  });
};
