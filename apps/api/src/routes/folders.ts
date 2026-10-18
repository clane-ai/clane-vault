import type { FastifyPluginAsync, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import { activeMember, capForAgent, isUniqueViolation, maxPermission, permissionRank } from "../lib/access.js";
import { isAgentUser } from "../lib/agents.js";
import { logEvent } from "../lib/events.js";
import { privateLockGuard } from "../lib/privateLock.js";
import { removeFolderMember, trashFolder } from "../lib/folderMembers.js";
import { revokeLinksOfLostAccess } from "../lib/links.js";
import { isAdminRole } from "../lib/orgs.js";
import { groupPermission, lockFolder, recomputeMember } from "../lib/groups.js";
import { isPublicKeyB64, recipientKeyOk } from "../lib/membershipKeys.js";

const envelope = z.string().startsWith("v1.").max(4096);
const sealed = z.string().startsWith("s1.").max(4096);
const idParam = z.object({ id: z.string().uuid() });
/** The recipient key a folder key was sealed to: their current membership key, or null (their account key, before they have one). */
const sealedTo = z.string().refine(isPublicKeyB64).nullable().default(null);
const memberParam = z.object({ id: z.string().uuid(), userId: z.string().uuid() });
/** "owner" belongs to the folder's creator only; it is never granted. */
const grantable = z.enum(["edit", "view", "use"]);

/**
 * Folders. Private folders belong to their owner and work in any org (or none); team folders belong to the active org
 * (X-Org-Id) and are only reachable from it (docs/design/2026-10-07-multi-org-design.md).
 */
export const folderRoutes: FastifyPluginAsync = async (app) => {
  app.addHook("preHandler", app.requireAuth);
  app.addHook("preHandler", app.orgOptional);
  app.addHook("preHandler", privateLockGuard(app));

  /** Folders the caller may rename or delete: their private ones, and team folders they own in the active org. */
  const ownedWhere = (req: FastifyRequest, id: string) => ({ id, ownerId: req.auth.userId, deletedAt: null,
    OR: [{ kind: "private" as const }, ...(req.org ? [{ kind: "team" as const, orgId: req.org.id }] : [])] });

  app.post("/folders", async (req, reply) => {
    const b = z.union([
      z.object({ id: z.string().uuid(), kind: z.literal("private").optional(), encName: envelope }),
      z.object({ id: z.string().uuid(), kind: z.literal("team"), encName: envelope, wrappedFolderKey: sealed, sealedTo }),
    ]).parse(req.body);
    if (b.kind === "team" && !req.org) return reply.code(403).send({ error: "org_required" });
    if (await app.prisma.folder.findUnique({ where: { id: b.id } })) return reply.code(409).send({ error: "exists" });
    const userId = req.auth.userId;
    if (b.kind === "team" && !(await recipientKeyOk(app.prisma, req.org!.id, userId, b.sealedTo))) return reply.code(409).send({ error: "stale_recipient_key" });
    if (b.kind === "team") {
      await app.prisma.folder.create({ data: { id: b.id, encName: b.encName, kind: "team", ownerId: userId, orgId: req.org!.id,
        members: { create: { userId, permission: "owner", directPermission: "owner", wrappedFolderKey: b.wrappedFolderKey, sealedTo: b.sealedTo } } } });
    } else {
      await app.prisma.folder.create({ data: { id: b.id, encName: b.encName, kind: "private", ownerId: userId } });
    }
    await logEvent(app.prisma, { orgId: b.kind === "team" ? req.org!.id : undefined, actorId: userId, action: "folder.create", folderId: b.id });
    return reply.code(201).send({ id: b.id });
  });

  app.patch("/folders/:id", async (req, reply) => {
    const { id } = idParam.parse(req.params);
    const b = z.object({ encName: envelope }).parse(req.body);
    const folder = await app.prisma.folder.findFirst({ where: ownedWhere(req, id), select: { kind: true } });
    const n = folder ? await app.prisma.folder.updateMany({ where: ownedWhere(req, id), data: { encName: b.encName } }) : { count: 0 };
    if (n.count === 0) return reply.code(404).send({ error: "not_found" });
    // A private folder is nobody's business in the org: its events carry no org (they'd show in the admin event log).
    await logEvent(app.prisma, { orgId: folder!.kind === "team" ? req.org?.id : undefined, actorId: req.auth.userId, action: "folder.rename", folderId: id });
    return { ok: true };
  });

  app.delete("/folders/:id", async (req, reply) => {
    const { id } = idParam.parse(req.params);
    const now = new Date();
    const folder = await app.prisma.folder.findFirst({ where: ownedWhere(req, id), select: { id: true, kind: true } });
    if (!folder) return reply.code(404).send({ error: "not_found" });
    // A team folder can't be deleted from under other people's live records: they'd lose them to the trash.
    const others = await app.prisma.record.count({ where: { folderId: id, deletedAt: null, ownerId: { not: req.auth.userId }, folder: { kind: "team" } } });
    if (others > 0) return reply.code(409).send({ error: "folder_has_others_records" });
    const done = await app.prisma.$transaction((tx) => trashFolder(tx, id, now));
    if (!done) return reply.code(404).send({ error: "not_found" });
    await logEvent(app.prisma, { orgId: folder.kind === "team" ? req.org?.id : undefined, actorId: req.auth.userId, action: "folder.delete", folderId: id });
    return reply.code(204).send();
  });

  /**
   * Loads a live team folder of the active org the caller may manage: its owner (who holds the folder key), or with
   * `admin` an admin of that org, who may only downgrade and remove members. Sends the error itself on failure.
   */
  async function manageable(req: FastifyRequest, reply: FastifyReply, folderId: string, opts: { admin: boolean }) {
    const folder = req.org ? await app.prisma.folder.findFirst({ where: { id: folderId, kind: "team", deletedAt: null, orgId: req.org.id }, select: { id: true, ownerId: true } }) : null;
    const mine = folder && (await app.prisma.folderMember.findFirst({ where: { folderId, userId: req.auth.userId }, select: { permission: true } }));
    if (mine?.permission === "owner") return { ...folder!, asAdmin: false };
    if (folder && opts.admin && isAdminRole(req.org!.role)) return { ...folder, asAdmin: true };
    if (!folder || !mine) { await reply.code(404).send({ error: "not_found" }); return null; }
    await reply.code(403).send({ error: "forbidden" }); return null;
  }

  app.post("/folders/:id/members", async (req, reply) => {
    const { id } = idParam.parse(req.params);
    const b = z.object({ userId: z.string().uuid(), permission: grantable, wrappedFolderKey: sealed, sealedTo }).parse(req.body);
    // Only the folder owner adds people: an admin outside the folder must not be able to seal a key to themselves.
    const folder = await manageable(req, reply, id, { admin: false });
    if (!folder) return reply;
    // Only active members of the folder's organisation can join it.
    if (!(await activeMember(app.prisma, b.userId, req.org!.id))) return reply.code(400).send({ error: "user_not_active" });
    if (b.permission !== "use" && (await isAgentUser(app.prisma, b.userId))) return reply.code(400).send({ error: "agent_use_only" });
    let r: "added" | "exists" | "stale";
    try {
      r = await app.prisma.$transaction(async (tx) => {
        await lockFolder(tx, id);
        if (!(await recipientKeyOk(tx, req.org!.id, b.userId, b.sealedTo))) return "stale";
        const cur = await tx.folderMember.findUnique({ where: { folderId_userId: { folderId: id, userId: b.userId } }, select: { directPermission: true } });
        // Someone with access only through a group gets a direct grant on top (their key is already sealed).
        if (cur && cur.directPermission !== null) return "exists";
        if (cur) await tx.folderMember.update({ where: { folderId_userId: { folderId: id, userId: b.userId } }, data: { directPermission: b.permission } });
        else await tx.folderMember.create({ data: { folderId: id, userId: b.userId, permission: await capForAgent(tx, b.userId, maxPermission(b.permission, await groupPermission(tx, id, b.userId))!), directPermission: b.permission, wrappedFolderKey: b.wrappedFolderKey, sealedTo: b.sealedTo } });
        await recomputeMember(tx, folder, b.userId);
        // Added directly: a pending entry for the same person (bulk migration) is done.
        const u = await tx.user.findUnique({ where: { id: b.userId }, select: { email: true } });
        if (u) await tx.pendingFolderMember.deleteMany({ where: { folderId: id, email: u.email } });
        return "added";
      });
    } catch (e) { if (isUniqueViolation(e)) return reply.code(409).send({ error: "exists" }); throw e; }
    if (r === "exists") return reply.code(409).send({ error: "already_member" });
    if (r === "stale") return reply.code(409).send({ error: "stale_recipient_key" });
    await logEvent(app.prisma, { orgId: req.org!.id, actorId: req.auth.userId, action: "folder.member_add", folderId: id, targetUserId: b.userId });
    return reply.code(201).send({ ok: true });
  });

  app.patch("/folders/:id/members/:userId", async (req, reply) => {
    const { id, userId } = memberParam.parse(req.params);
    const b = z.object({ permission: grantable }).parse(req.body);
    const folder = await manageable(req, reply, id, { admin: true });
    if (!folder) return reply;
    if (userId === folder.ownerId) return reply.code(400).send({ error: "folder_owner" });
    if (b.permission !== "use" && (await isAgentUser(app.prisma, userId))) return reply.code(400).send({ error: "agent_use_only" });
    // Changes the direct grant; the effective permission stays the highest of it and the person's group grants.
    const n = await app.prisma.$transaction(async (tx) => {
      await lockFolder(tx, id);
      const cur = await tx.folderMember.findUnique({ where: { folderId_userId: { folderId: id, userId } }, select: { directPermission: true } });
      if (!cur) return "not_member" as const;
      if (cur.directPermission === null) return "group_only" as const;
      if (folder.asAdmin && permissionRank(b.permission) > permissionRank(cur.directPermission)) return "forbidden" as const;
      const g = await groupPermission(tx, id, userId);
      await tx.folderMember.update({ where: { folderId_userId: { folderId: id, userId } }, data: { directPermission: b.permission, permission: await capForAgent(tx, userId, maxPermission(b.permission, g)!) } });
      // Down to view/use: links they made on the folder's records go (unless a direct share or a group still gives them edit).
      if (b.permission !== "edit" && g !== "edit") {
        const ids = (await tx.record.findMany({ where: { folderId: id }, select: { id: true } })).map((r) => r.id);
        await revokeLinksOfLostAccess(tx, userId, ids);
      }
      return "ok" as const;
    });
    if (n === "not_member") return reply.code(404).send({ error: "not_member" });
    if (n === "group_only") return reply.code(409).send({ error: "group_access" });
    if (n === "forbidden") return reply.code(403).send({ error: "forbidden" });
    await logEvent(app.prisma, { orgId: req.org!.id, actorId: req.auth.userId, action: "folder.member_update", folderId: id, targetUserId: userId });
    return { ok: true };
  });

  app.delete("/folders/:id/members/:userId", async (req, reply) => {
    const { id, userId } = memberParam.parse(req.params);
    const leaving = userId === req.auth.userId;
    const folder = leaving
      ? req.org ? await app.prisma.folder.findFirst({ where: { id, kind: "team", orgId: req.org.id, members: { some: { userId } } }, select: { id: true, ownerId: true } }) : null
      : await manageable(req, reply, id, { admin: true });
    if (!folder) return leaving ? reply.code(404).send({ error: "not_found" }) : reply;
    if (userId === folder.ownerId) return reply.code(400).send({ error: "folder_owner" });
    // Removes the direct grant. Access through a group stays (remove them from the group, or the group from the folder).
    const n = await app.prisma.$transaction(async (tx) => {
      await lockFolder(tx, id);
      const cur = await tx.folderMember.findUnique({ where: { folderId_userId: { folderId: id, userId } }, select: { directPermission: true } });
      if (!cur) return "not_member" as const;
      if (cur.directPermission === null) return "group_only" as const;
      if (!(await groupPermission(tx, id, userId))) return (await removeFolderMember(tx, id, folder.ownerId, userId)) ? "removed" as const : "not_member" as const;
      await tx.folderMember.update({ where: { folderId_userId: { folderId: id, userId } }, data: { directPermission: null } });
      await recomputeMember(tx, folder, userId);
      return "group_kept" as const;
    });
    if (n === "not_member") return reply.code(404).send({ error: "not_member" });
    if (n === "group_only") return reply.code(409).send({ error: "group_access" });
    await logEvent(app.prisma, { orgId: req.org?.id, actorId: req.auth.userId, action: "folder.member_remove", folderId: id, targetUserId: userId });
    return reply.code(204).send();
  });
};
