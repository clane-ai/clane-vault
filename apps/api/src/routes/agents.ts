import type { FastifyInstance, FastifyPluginAsync, FastifyReply, FastifyRequest } from "fastify";
import { randomUUID } from "node:crypto";
import { z } from "zod";
import { displayName } from "../lib/names.js";
import { logEvent } from "../lib/events.js";
import { agentEmail, assertAgentSlot, fingerprintOf } from "../lib/agents.js";
import { pinGatewayIdentity, type GatewayIdentityInfo } from "../lib/gateway.js";
import { isPublicKeyB64 } from "../lib/membershipKeys.js";

const idParam = z.object({ id: z.string().uuid() });
const expiry = z.string().datetime({ offset: true }).transform((s) => new Date(s)).refine((d) => d.getTime() > Date.now(), { message: "past" }).nullable();

/** health → pin: what every caller that needs the gateway identity goes through. Throws GatewayUnavailable / GatewayIdentityChanged. */
async function ensureIdentity(app: FastifyInstance): Promise<GatewayIdentityInfo> {
  const seen = await app.gateway.health();
  await pinGatewayIdentity(app.prisma, seen, { accept: app.config.agents!.acceptNewGatewayIdentity });
  return seen;
}

/** /admin/agents (org owner or admin). Registered only when agent features are on. */
export const agentAdminRoutes: FastifyPluginAsync = async (app) => {
  app.addHook("preHandler", app.requireAuth);
  app.addHook("preHandler", app.orgAdmin);
  const orgId = (req: FastifyRequest) => req.org!.id;
  const meta = (req: FastifyRequest) => ({ ip: req.ip, userAgent: String(req.headers["user-agent"] ?? "").slice(0, 300) });

  /** The agent, within the active org; 404 otherwise. */
  async function agentIn(req: FastifyRequest, reply: FastifyReply) {
    const { id } = idParam.parse(req.params);
    const a = await app.prisma.agent.findFirst({ where: { userId: id, orgId: orgId(req) } });
    if (!a) await reply.code(404).send({ error: "not_found" });
    return a;
  }

  app.post("/", async (req, reply) => {
    const b = z.object({ name: displayName, expiresAt: expiry.optional() }).parse(req.body);
    const org = orgId(req);
    await assertAgentSlot(app.prisma, app.config, org); // fast refusal before asking the gateway
    const gateway = await ensureIdentity(app);
    const id = randomUUID();
    const key = await app.gateway.createAgentKey({ agentId: id, orgId: org });
    await app.prisma.$transaction(async (tx) => {
      await assertAgentSlot(tx, app.config, org);
      await tx.user.create({ data: { id, kind: "agent", email: agentEmail(id), name: b.name, status: "active",
        authHash: "", kdfSalt: "", kdfParams: {}, wrappedUserKey: "", publicKey: key.publicKey, wrappedPrivateKey: "" } });
      await tx.membership.create({ data: { orgId: org, userId: id, role: "member", status: "invited", invitedById: req.auth.userId } });
      await tx.membershipKey.create({ data: { orgId: org, userId: id, publicKey: key.publicKey, wrappedPrivateKey: "", userKeyGen: 1, state: "current" } });
      await tx.agent.create({ data: { userId: id, orgId: org, createdById: req.auth.userId, publicKey: key.publicKey, wrappedPrivateKey: key.wrappedPrivateKey,
        kekId: key.kekId, attestation: key.attestation, expiresAt: b.expiresAt ?? null } });
      await logEvent(tx, { orgId: org, actorId: req.auth.userId, action: "agent.create", targetUserId: id, meta: { gatewayKeyId: gateway.keyId }, ...meta(req) });
    });
    // The fingerprints are a convenience: the browser recomputes both and never trusts these.
    return reply.code(201).send({ id, name: b.name, publicKey: key.publicKey, fingerprint: fingerprintOf(key.publicKey), attestation: key.attestation,
      gateway: { keyId: gateway.keyId, publicKey: gateway.publicKey, fingerprint: fingerprintOf(gateway.publicKey) } });
  });

  app.get("/", async (req) => {
    const org = orgId(req);
    const rows = await app.prisma.agent.findMany({ where: { orgId: org }, orderBy: { createdAt: "asc" }, include: { user: { select: { name: true } } } });
    const ids = rows.map((r) => r.userId);
    const [folders, groups] = await Promise.all([
      app.prisma.folderMember.findMany({ where: { userId: { in: ids }, folder: { kind: "team", orgId: org, deletedAt: null } }, select: { userId: true, folderId: true } }),
      app.prisma.groupMember.findMany({ where: { userId: { in: ids }, group: { orgId: org } }, select: { userId: true, group: { select: { id: true, name: true } } } }),
    ]);
    const now = Date.now();
    return { agents: rows.map((a) => ({
      id: a.userId, name: a.user.name,
      status: a.revokedAt ? "revoked" : a.expiresAt && a.expiresAt.getTime() <= now ? "expired" : a.verifiedAt ? "active" : "awaiting_verification",
      publicKey: a.publicKey, attestation: a.attestation, expiresAt: a.expiresAt?.toISOString() ?? null, lastUsedAt: a.lastUsedAt?.toISOString() ?? null,
      createdAt: a.createdAt.toISOString(), verifiedAt: a.verifiedAt?.toISOString() ?? null,
      folders: folders.filter((f) => f.userId === a.userId).map((f) => ({ id: f.folderId })),
      groups: groups.filter((g) => g.userId === a.userId).map((g) => g.group),
      tokens: [], grants: [], // Tasks 5 and 12
    })) };
  });

  /** The admin's browser checked the attestation and the fingerprints; `publicKey` is the key it checked. */
  app.post("/:id/verify", async (req, reply) => {
    const b = z.object({ publicKey: z.string().refine(isPublicKeyB64) }).parse(req.body);
    const a = await agentIn(req, reply);
    if (!a) return reply;
    if (a.revokedAt) return reply.code(409).send({ error: "agent_revoked" });
    const key = await app.prisma.membershipKey.findFirst({ where: { orgId: a.orgId, userId: a.userId, state: "current" }, select: { publicKey: true } });
    if (key?.publicKey !== b.publicKey) return reply.code(409).send({ error: "stale_key" });
    const now = new Date();
    await app.prisma.$transaction([
      app.prisma.agent.update({ where: { userId: a.userId }, data: { verifiedById: req.auth.userId, verifiedAt: now } }),
      app.prisma.membership.update({ where: { orgId_userId: { orgId: a.orgId, userId: a.userId } }, data: { status: "active", joinedAt: now } }),
      app.prisma.event.create({ data: { orgId: a.orgId, actorId: req.auth.userId, action: "agent.verify", targetUserId: a.userId, ...meta(req) } }),
    ]);
    return { ok: true };
  });

  app.patch("/:id", async (req, reply) => {
    const b = z.object({ name: displayName.optional(), expiresAt: expiry.optional() }).parse(req.body);
    const a = await agentIn(req, reply);
    if (!a) return reply;
    await app.prisma.$transaction([
      ...(b.name !== undefined ? [app.prisma.user.update({ where: { id: a.userId }, data: { name: b.name } })] : []),
      ...(b.expiresAt !== undefined ? [app.prisma.agent.update({ where: { userId: a.userId }, data: { expiresAt: b.expiresAt } })] : []),
      app.prisma.event.create({ data: { orgId: a.orgId, actorId: req.auth.userId, action: "agent.update", targetUserId: a.userId,
        meta: { fields: Object.keys(b).filter((k) => b[k as keyof typeof b] !== undefined) }, ...meta(req) } }),
    ]);
    return { ok: true };
  });
};

/** Any member of the active org: where the gateway is and the identity the API pinned (browsers pin it themselves too). */
export const orgAgentRoutes: FastifyPluginAsync = async (app) => {
  app.get("/org/agents/gateway", { preHandler: [app.requireAuth, app.orgRequired] }, async () => {
    const row = await app.prisma.gatewayIdentity.findUnique({ where: { id: "gateway" } }) ?? await ensureIdentity(app);
    return { url: app.config.agents!.gatewayPublicUrl, identityKeyId: row.keyId, identityPublicKey: row.publicKey };
  });
};
