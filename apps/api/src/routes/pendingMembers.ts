import type { FastifyPluginAsync, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import { capForAgent, isUniqueViolation } from "../lib/access.js";
import { logEvent } from "../lib/events.js";
import { currentKeys, isPublicKeyB64, recipientKeyOk } from "../lib/membershipKeys.js";

const sealed = z.string().startsWith("s1.").max(4096);
const idParam = z.object({ id: z.string().uuid() });
const pendingParam = z.object({ id: z.string().uuid(), pendingId: z.string().uuid() });
const email = z.string().trim().toLowerCase().email().max(254);
const grantable = z.enum(["edit", "view", "use"]);

/**
 * Pending team-folder members (bulk migration): people who should join a team folder but have no active account yet,
 * so nobody can seal the folder key to them. The folder's owner records them by email and completes each one once
 * that person is active, by sealing the folder key to their public key (the server never holds a folder key).
 * Only the folder's owner sees, adds, completes or cancels them. Rows go when completed, when the person is added
 * as a member some other way, and when the folder is deleted.
 */
export const pendingMemberRoutes: FastifyPluginAsync = async (app) => {
  app.addHook("preHandler", app.requireAuth);
  app.addHook("preHandler", app.orgRequired);

  /** The caller's own live team folder in the active org; sends 404 otherwise. */
  async function ownTeamFolder(req: FastifyRequest, reply: FastifyReply, folderId: string) {
    const f = await app.prisma.folder.findFirst({ where: { id: folderId, kind: "team", deletedAt: null, ownerId: req.auth.userId, orgId: req.org!.id,
      members: { some: { userId: req.auth.userId, permission: "owner" } } }, select: { id: true } });
    if (!f) { await reply.code(404).send({ error: "not_found" }); return null; }
    return f;
  }

  app.post("/folders/:id/pending-members", async (req, reply) => {
    const { id } = idParam.parse(req.params);
    const b = z.object({ email, permission: grantable }).parse(req.body);
    if (!(await ownTeamFolder(req, reply, id))) return reply;
    const user = await app.prisma.user.findUnique({ where: { email: b.email }, select: { id: true, kind: true } });
    // Agents hold Use only (docs/agents.md); their emails are under the reserved .invalid TLD.
    if (b.permission !== "use" && (user?.kind === "agent" || b.email.endsWith("@agents.invalid"))) return reply.code(400).send({ error: "agent_use_only" });
    // (Someone who isn't in the org yet can still be listed: they are added once they join and are active.)
    if (user && (await app.prisma.folderMember.findUnique({ where: { folderId_userId: { folderId: id, userId: user.id } } }))) return reply.code(409).send({ error: "already_member" });
    try {
      const p = await app.prisma.pendingFolderMember.create({ data: { folderId: id, email: b.email, permission: b.permission, createdBy: req.auth.userId } });
      await logEvent(app.prisma, { orgId: req.org!.id, actorId: req.auth.userId, action: "folder.pending_add", folderId: id });
      return reply.code(201).send({ id: p.id });
    } catch (e) {
      if (isUniqueViolation(e)) return reply.code(409).send({ error: "exists" });
      throw e;
    }
  });

  /** Pending members of the caller's live team folders in the active org; `user` is set once that email belongs to an active member of it. */
  app.get("/pending-members", async (req) => {
    const rows = await app.prisma.pendingFolderMember.findMany({
      where: { folder: { ownerId: req.auth.userId, kind: "team", deletedAt: null, orgId: req.org!.id } }, orderBy: { createdAt: "asc" },
      select: { id: true, folderId: true, email: true, permission: true, createdAt: true },
    });
    const users = rows.length
      ? await app.prisma.user.findMany({ where: { email: { in: [...new Set(rows.map((r) => r.email))] }, status: "active", memberships: { some: { orgId: req.org!.id, status: "active" } } }, select: { id: true, name: true, email: true, publicKey: true } })
      : [];
    const byEmail = new Map(users.map((u) => [u.email, u]));
    const mkeys = await currentKeys(app.prisma, req.org!.id, users.map((u) => u.id));
    return { pending: rows.map((r) => {
      const u = byEmail.get(r.email);
      return { ...r, createdAt: r.createdAt.toISOString(), user: u ? { id: u.id, name: u.name, publicKey: u.publicKey, membershipKey: mkeys.get(u.id) ?? null } : null };
    }) };
  });

  /** Completes one: the owner seals the folder key to the now-active user; the membership replaces the pending row. */
  app.post("/folders/:id/pending-members/:pendingId/complete", async (req, reply) => {
    const { id, pendingId } = pendingParam.parse(req.params);
    const b = z.object({ userId: z.string().uuid(), wrappedFolderKey: sealed, sealedTo: z.string().refine(isPublicKeyB64).nullable().default(null) }).parse(req.body);
    if (!(await ownTeamFolder(req, reply, id))) return reply;
    const p = await app.prisma.pendingFolderMember.findFirst({ where: { id: pendingId, folderId: id } });
    if (!p) return reply.code(404).send({ error: "not_found" });
    const user = await app.prisma.user.findFirst({ where: { id: b.userId, email: p.email }, select: { id: true, status: true, memberships: { where: { orgId: req.org!.id, status: "active" }, select: { id: true } } } });
    if (!user) return reply.code(400).send({ error: "user_mismatch" });
    if (user.status !== "active" || !user.memberships.length) return reply.code(400).send({ error: "user_not_active" });
    if (!(await recipientKeyOk(app.prisma, req.org!.id, user.id, b.sealedTo))) return reply.code(409).send({ error: "stale_recipient_key" });
    let added: false | typeof p.permission;
    try {
      added = await app.prisma.$transaction(async (tx) => {
        await tx.pendingFolderMember.delete({ where: { id: p.id } });
        if (await tx.folderMember.findUnique({ where: { folderId_userId: { folderId: id, userId: user.id } } })) return false;
        const perm = await capForAgent(tx, user.id, p.permission);
        await tx.folderMember.create({ data: { folderId: id, userId: user.id, permission: perm, directPermission: perm, wrappedFolderKey: b.wrappedFolderKey, sealedTo: b.sealedTo } });
        return perm;
      });
    } catch (e) {
      if (!isUniqueViolation(e)) throw e;
      added = false;
    }
    if (!added) {
      // Already a member (added some other way): the pending entry is done either way.
      await app.prisma.pendingFolderMember.deleteMany({ where: { id: p.id } });
      return reply.code(409).send({ error: "already_member" });
    }
    await logEvent(app.prisma, { orgId: req.org!.id, actorId: req.auth.userId, action: "folder.member_add", folderId: id, targetUserId: user.id });
    return reply.code(201).send({ ok: true, permission: added });
  });

  app.delete("/folders/:id/pending-members/:pendingId", async (req, reply) => {
    const { id, pendingId } = pendingParam.parse(req.params);
    if (!(await ownTeamFolder(req, reply, id))) return reply;
    const n = await app.prisma.pendingFolderMember.deleteMany({ where: { id: pendingId, folderId: id } });
    if (n.count === 0) return reply.code(404).send({ error: "not_found" });
    await logEvent(app.prisma, { orgId: req.org!.id, actorId: req.auth.userId, action: "folder.pending_remove", folderId: id });
    return reply.code(204).send();
  });
};
