import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import type { Prisma } from "@prisma/client";
import { randomUUID } from "node:crypto";
import { z } from "zod";
import { displayName } from "./names.js";
import { logEvent } from "./events.js";
import { lockUser } from "./orgs.js";
import { pinGatewayIdentity, type GatewayIdentityInfo } from "./gateway.js";
import { isPublicKeyB64 } from "./membershipKeys.js";
import { newAgentToken } from "./tokens.js";

/** What /admin/agents and /me/agents share: each handler body is written once, `org` is the organisation for events (undefined: an owner-visible row). */
type Target = { userId: string; revokedAt: Date | null };
/** Looks the agent up (answering 404 itself) after the request body is parsed, as the routes always ordered it. */
type Find<T extends Target> = () => Promise<T | null>;

export const expiry = z.string().datetime({ offset: true }).transform((s) => new Date(s)).refine((d) => d.getTime() > Date.now(), { message: "past" }).nullable();

export const reqMeta = (req: FastifyRequest) => ({ ip: req.ip, userAgent: String(req.headers["user-agent"] ?? "").slice(0, 300) });

/** Serialised with revoke (which locks the user first): true when the agent is still live inside this transaction. */
export async function stillLive(tx: Prisma.TransactionClient, userId: string): Promise<boolean> {
  await lockUser(tx, userId);
  return !!(await tx.agent.findFirst({ where: { userId, revokedAt: null }, select: { userId: true } }));
}

/** health → pin: what every caller that needs the gateway identity goes through. Throws GatewayUnavailable / GatewayIdentityChanged. */
export async function ensureIdentity(app: FastifyInstance): Promise<GatewayIdentityInfo> {
  const seen = await app.gateway.health();
  await pinGatewayIdentity(app.prisma, seen, { accept: app.config.agents!.acceptNewGatewayIdentity, log: app.log });
  return seen;
}

/** Where the gateway is and the identity the API pinned (browsers pin it themselves too). */
export async function gatewayInfo(app: FastifyInstance) {
  const row = await app.prisma.gatewayIdentity.findUnique({ where: { id: "gateway" } }) ?? await ensureIdentity(app);
  return { url: app.config.agents!.gatewayPublicUrl, identityKeyId: row.keyId, identityPublicKey: row.publicKey };
}

/** Never the token or its hash. */
export const tokenView = (k: { id: string; label: string; createdAt: Date; expiresAt: Date | null; lastUsedAt: Date | null; revokedAt: Date | null }) =>
  ({ id: k.id, label: k.label, createdAt: k.createdAt.toISOString(), expiresAt: k.expiresAt?.toISOString() ?? null,
    lastUsedAt: k.lastUsedAt?.toISOString() ?? null, revokedAt: k.revokedAt?.toISOString() ?? null });

export const grantView = (g: { id: string; clientId: string; createdAt: Date }, clients: { id: string; name: string }[]) =>
  ({ id: g.id, clientName: clients.find((c) => c.id === g.clientId)?.name ?? "", createdAt: g.createdAt.toISOString() });

/** Ends a live grant once (the claim logs and drops the gateway's cache); a second call does nothing. */
export async function revokeGrant(app: FastifyInstance, where: Prisma.AgentGrantWhereInput, ev: { actorId?: string; reason?: string; req: FastifyRequest }): Promise<boolean> {
  const g = await app.prisma.agentGrant.findFirst({ where: { ...where, revokedAt: null }, select: { id: true, agentId: true, agent: { select: { orgId: true } } } });
  if (!g) return false;
  const done = await app.prisma.$transaction(async (tx) => {
    if ((await tx.agentGrant.updateMany({ where: { id: g.id, revokedAt: null }, data: { revokedAt: new Date() } })).count !== 1) return false;
    await logEvent(tx, { orgId: g.agent.orgId ?? undefined, actorId: ev.actorId, action: "agent.grant_revoke", targetUserId: g.agentId,
      meta: { grantId: g.id, ...(ev.reason ? { reason: ev.reason } : {}) }, ...reqMeta(ev.req) });
    return true;
  });
  // Preflight #11: the gateway forgets its cached keys now rather than in 60 s (best effort).
  if (done) app.gateway.dropAgent(g.agentId).catch(() => undefined);
  return done;
}

/** `check`: is the key the browser verified still the agent's current one. `inTx`: what else verifying does (membership, events). */
export async function verifyAgent<T extends Target>(app: FastifyInstance, req: FastifyRequest, reply: FastifyReply, find: Find<T>,
  check: (a: T, publicKey: string) => Promise<boolean>, inTx: (tx: Prisma.TransactionClient, a: T, now: Date) => Promise<void>) {
  const b = z.object({ publicKey: z.string().refine(isPublicKeyB64) }).parse(req.body);
  const a = await find();
  if (!a) return reply;
  if (a.revokedAt) return reply.code(409).send({ error: "agent_revoked" });
  if (!(await check(a, b.publicKey))) return reply.code(409).send({ error: "stale_key" });
  const now = new Date();
  const ok = await app.prisma.$transaction(async (tx) => {
    if (!(await stillLive(tx, a.userId))) return false;
    await tx.agent.update({ where: { userId: a.userId }, data: { verifiedById: req.auth.userId, verifiedAt: now } });
    await inTx(tx, a, now);
    return true;
  });
  return ok ? { ok: true } : reply.code(409).send({ error: "agent_revoked" });
}

/** A static token for an API/SDK client: returned once, only its hash is kept. */
export async function createAgentToken(app: FastifyInstance, req: FastifyRequest, reply: FastifyReply, find: Find<Target>, org: string | undefined,
  after?: (tx: Prisma.TransactionClient) => Promise<void>) {
  const b = z.object({ label: z.string().min(1).max(60), expiresAt: expiry.optional() }).parse(req.body);
  const a = await find();
  if (!a) return reply;
  if (a.revokedAt) return reply.code(409).send({ error: "agent_revoked" });
  const id = randomUUID();
  const { token, hash } = newAgentToken(id);
  const ok = await app.prisma.$transaction(async (tx) => {
    if (!(await stillLive(tx, a.userId))) return false;
    await tx.agentToken.create({ data: { id, agentId: a.userId, label: b.label, tokenHash: hash, createdById: req.auth.userId, expiresAt: b.expiresAt ?? null } });
    await logEvent(tx, { orgId: org, actorId: req.auth.userId, action: "agent.token_create", targetUserId: a.userId, meta: { tokenId: id }, ...reqMeta(req) });
    await after?.(tx);
    return true;
  });
  return ok ? reply.code(201).send({ id, token }) : reply.code(409).send({ error: "agent_revoked" });
}

export async function revokeAgentToken(app: FastifyInstance, req: FastifyRequest, reply: FastifyReply, find: Find<Target>, org: string | undefined) {
  const { tokenId } = z.object({ tokenId: z.string().uuid() }).passthrough().parse(req.params);
  const a = await find();
  if (!a) return reply;
  const k = await app.prisma.agentToken.findFirst({ where: { id: tokenId, agentId: a.userId }, select: { id: true } });
  if (!k) return reply.code(404).send({ error: "not_found" });
  // The claim is atomic: of two concurrent revokes only one logs.
  const claimed = await app.prisma.$transaction(async (tx) => {
    const r = await tx.agentToken.updateMany({ where: { id: tokenId, agentId: a.userId, revokedAt: null }, data: { revokedAt: new Date() } });
    if (r.count === 1) await logEvent(tx, { orgId: org, actorId: req.auth.userId, action: "agent.token_revoke", targetUserId: a.userId, meta: { tokenId }, ...reqMeta(req) });
    return r.count === 1;
  });
  // Preflight #11: the gateway forgets its cached keys now rather than in 60 s (best effort).
  if (claimed) app.gateway.dropAgent(a.userId).catch(() => undefined);
  return reply.code(204).send();
}

/** Ends one OAuth grant (a client the person allowed on the consent page). */
export async function revokeAgentGrant(app: FastifyInstance, req: FastifyRequest, reply: FastifyReply, find: Find<Target>) {
  const { grantId } = z.object({ grantId: z.string().uuid() }).passthrough().parse(req.params);
  const a = await find();
  if (!a) return reply;
  if (!(await app.prisma.agentGrant.findFirst({ where: { id: grantId, agentId: a.userId }, select: { id: true } }))) return reply.code(404).send({ error: "not_found" });
  await revokeGrant(app, { id: grantId, agentId: a.userId }, { actorId: req.auth.userId, req });
  return reply.code(204).send();
}

export async function patchAgent(app: FastifyInstance, req: FastifyRequest, reply: FastifyReply, find: Find<Target>, org: string | undefined) {
  const b = z.object({ name: displayName.optional(), expiresAt: expiry.optional() }).parse(req.body);
  const a = await find();
  if (!a) return reply;
  await app.prisma.$transaction([
    ...(b.name !== undefined ? [app.prisma.user.update({ where: { id: a.userId }, data: { name: b.name } })] : []),
    ...(b.expiresAt !== undefined ? [app.prisma.agent.update({ where: { userId: a.userId }, data: { expiresAt: b.expiresAt } })] : []),
    app.prisma.event.create({ data: { orgId: org, actorId: req.auth.userId, action: "agent.update", targetUserId: a.userId,
      meta: { fields: Object.keys(b).filter((k) => b[k as keyof typeof b] !== undefined) }, ...reqMeta(req) } }),
  ]);
  return { ok: true };
}
