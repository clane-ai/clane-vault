import type { FastifyPluginAsync, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import { activeMember, capForAgent, isUniqueViolation, permissionRank, type Db } from "../lib/access.js";
import { logEvent } from "../lib/events.js";
import { groupPermission, lockFolder, lockGroup, pendingGroupAccess, recomputeFolder, recomputeGroupFolders } from "../lib/groups.js";
import { displayName } from "../lib/names.js";
import { isAdminRole } from "../lib/orgs.js";
import { currentKeys, isPublicKeyB64, recipientKeyOk } from "../lib/membershipKeys.js";
import { agentAttestations } from "../lib/agents.js";

const sealed = z.string().startsWith("s1.").max(4096);
const grantable = z.enum(["edit", "view", "use"]);
const idParam = z.object({ id: z.string().uuid() });
const folderGroupParam = z.object({ id: z.string().uuid(), groupId: z.string().uuid() });
const memberParam = z.object({ id: z.string().uuid(), userId: z.string().uuid() });
/** Each wrap names the key it is sealed to: the person's current membership key, or null (account key, none yet). */
const wraps = z.array(z.object({ userId: z.string().uuid(), wrappedFolderKey: sealed, sealedTo: z.string().refine(isPublicKeyB64).nullable().default(null) })).max(500);
/** Group names follow the rules for people and org names (no links or addresses). */
const groupName = displayName;

/**
 * Groups for members and folder owners (docs/groups.md): the org's groups (for the folder people sheet), sharing a team
 * folder with a group, and sealing the folder key to group members who don't have it yet.
 */
export const groupRoutes: FastifyPluginAsync = async (app) => {
  app.addHook("preHandler", app.requireAuth);
  app.addHook("preHandler", app.orgRequired);
  const orgId = (req: FastifyRequest) => req.org!.id;

  /** The active org's groups with their active members' public keys (any member: sharing a folder seals to them). */
  app.get("/groups", async (req) => {
    const groups = await app.prisma.group.findMany({ where: { orgId: orgId(req) }, orderBy: { name: "asc" },
      select: { id: true, name: true, members: { where: { user: { status: "active", memberships: { some: { orgId: orgId(req), status: "active" } } } },
        select: { user: { select: { id: true, name: true, email: true, publicKey: true, kind: true } } } } } });
    const keys = await currentKeys(app.prisma, orgId(req), groups.flatMap((g) => g.members.map((m) => m.user.id)));
    const att = await agentAttestations(app.prisma, groups.flatMap((g) => g.members.filter((m) => m.user.kind === "agent").map((m) => m.user.id)));
    return { groups: groups.map((g) => ({ id: g.id, name: g.name, members: g.members.map((m) => ({ ...m.user, membershipKey: keys.get(m.user.id) ?? null, ...att.get(m.user.id) })) })) };
  });

  /**
   * A live team folder of the active org and the caller's place in it. `need`: "owner" (holds the key and shares),
   * "manage" (the owner, or an org admin who may only downgrade and remove), "seal" (owner or editor: holds the key).
   */
  async function folderFor(req: FastifyRequest, reply: FastifyReply, folderId: string, need: "owner" | "manage" | "seal") {
    const folder = await app.prisma.folder.findFirst({ where: { id: folderId, kind: "team", deletedAt: null, orgId: orgId(req) }, select: { id: true, ownerId: true } });
    const mine = folder && (await app.prisma.folderMember.findUnique({ where: { folderId_userId: { folderId, userId: req.auth.userId } }, select: { permission: true } }));
    const ok = mine?.permission === "owner" || (need === "seal" && mine?.permission === "edit");
    if (folder && ok) return { ...folder, asAdmin: false };
    if (folder && need === "manage" && isAdminRole(req.org!.role)) return { ...folder, asAdmin: true };
    if (!folder || !mine) { await reply.code(404).send({ error: "not_found" }); return null; }
    await reply.code(403).send({ error: "forbidden" }); return null;
  }

  /**
   * Users who may get group access to the folder from these wraps: in a group shared with it, active here, not yet in
   * it, and sealed to their current key. A decline for them ends: a key holder approved them after all.
   */
  async function addViaGroups(tx: Db, folderId: string, list: z.infer<typeof wraps>, org: string): Promise<string[]> {
    const added: string[] = [];
    for (const w of list) {
      const perm = await groupPermission(tx, folderId, w.userId);
      if (!perm) continue;
      if (!(await activeMember(tx, w.userId, org))) continue;
      if (await tx.folderMember.findUnique({ where: { folderId_userId: { folderId, userId: w.userId } }, select: { id: true } })) continue;
      if (!(await recipientKeyOk(tx, org, w.userId, w.sealedTo))) continue;
      // Group grants to an agent are capped to use silently.
      await tx.folderMember.create({ data: { folderId, userId: w.userId, permission: await capForAgent(tx, w.userId, perm), directPermission: null, wrappedFolderKey: w.wrappedFolderKey, sealedTo: w.sealedTo } });
      await tx.groupAccessDecline.deleteMany({ where: { folderId, userId: w.userId } });
      added.push(w.userId);
    }
    return added;
  }

  /** Shares a team folder with a group (the folder owner, who holds the key): wraps for the members the client could seal to. */
  app.post("/folders/:id/groups", async (req, reply) => {
    const { id } = idParam.parse(req.params);
    const b = z.object({ groupId: z.string().uuid(), permission: grantable, wraps: wraps.default([]) }).parse(req.body);
    const folder = await folderFor(req, reply, id, "owner");
    if (!folder) return reply;
    const group = await app.prisma.group.findFirst({ where: { id: b.groupId, orgId: orgId(req) }, select: { id: true } });
    if (!group) return reply.code(404).send({ error: "group_not_found" });
    let added: string[];
    try {
      added = await app.prisma.$transaction(async (tx) => {
        // Group first, then folder: the order every group change uses.
        await lockGroup(tx, b.groupId);
        await lockFolder(tx, id);
        await tx.folderGroup.create({ data: { folderId: id, groupId: b.groupId, permission: b.permission, createdBy: req.auth.userId } });
        const a = await addViaGroups(tx, id, b.wraps, orgId(req));
        // Members who already had access may now get more through the group.
        const members = (await tx.groupMember.findMany({ where: { groupId: b.groupId }, select: { userId: true } })).map((m) => m.userId);
        await recomputeFolder(tx, id, members);
        return a;
      });
    } catch (e) { if (isUniqueViolation(e)) return reply.code(409).send({ error: "exists" }); throw e; }
    await logEvent(app.prisma, { orgId: orgId(req), actorId: req.auth.userId, action: "folder.group_add", folderId: id, meta: { groupId: b.groupId, permission: b.permission } });
    for (const u of added) await logEvent(app.prisma, { orgId: orgId(req), actorId: req.auth.userId, action: "folder.member_add", folderId: id, targetUserId: u, meta: { via: "group" } });
    const pending = (await pendingGroupAccess(app.prisma, orgId(req), req.auth.userId)).filter((p) => p.folderId === id).length;
    return reply.code(201).send({ ok: true, added: added.length, pending });
  });

  /** Changes a group's permission on the folder: the owner, or an org admin (downgrade only). */
  app.patch("/folders/:id/groups/:groupId", async (req, reply) => {
    const { id, groupId } = folderGroupParam.parse(req.params);
    const b = z.object({ permission: grantable }).parse(req.body);
    const folder = await folderFor(req, reply, id, "manage");
    if (!folder) return reply;
    const done = await app.prisma.$transaction(async (tx) => {
      await lockFolder(tx, id);
      const cur = await tx.folderGroup.findUnique({ where: { folderId_groupId: { folderId: id, groupId } }, select: { permission: true } });
      if (!cur) return "not_found" as const;
      if (folder.asAdmin && permissionRank(b.permission) > permissionRank(cur.permission)) return "forbidden" as const;
      await tx.folderGroup.update({ where: { folderId_groupId: { folderId: id, groupId } }, data: { permission: b.permission } });
      const members = (await tx.groupMember.findMany({ where: { groupId }, select: { userId: true } })).map((m) => m.userId);
      await recomputeFolder(tx, id, members);
      return "ok" as const;
    });
    if (done === "not_found") return reply.code(404).send({ error: "not_found" });
    if (done === "forbidden") return reply.code(403).send({ error: "forbidden" });
    await logEvent(app.prisma, { orgId: orgId(req), actorId: req.auth.userId, action: "folder.group_update", folderId: id, meta: { groupId, permission: b.permission } });
    return { ok: true };
  });

  /** Stops sharing the folder with a group: access that came only through it ends (direct grants stay). */
  app.delete("/folders/:id/groups/:groupId", async (req, reply) => {
    const { id, groupId } = folderGroupParam.parse(req.params);
    const folder = await folderFor(req, reply, id, "manage");
    if (!folder) return reply;
    const removed = await app.prisma.$transaction(async (tx) => {
      await lockFolder(tx, id);
      const n = await tx.folderGroup.deleteMany({ where: { folderId: id, groupId } });
      if (!n.count) return null;
      const members = (await tx.groupMember.findMany({ where: { groupId }, select: { userId: true } })).map((m) => m.userId);
      return recomputeFolder(tx, id, members);
    });
    if (!removed) return reply.code(404).send({ error: "not_found" });
    await logEvent(app.prisma, { orgId: orgId(req), actorId: req.auth.userId, action: "folder.group_remove", folderId: id, meta: { groupId } });
    for (const u of removed) await logEvent(app.prisma, { orgId: orgId(req), actorId: req.auth.userId, action: "folder.member_remove", folderId: id, targetUserId: u, meta: { via: "group" } });
    return reply.code(204).send();
  });

  /** Group members waiting for the key of folders the caller can seal (owner or editor), for explicit approval. */
  app.get("/group-access/pending", async (req) => ({ pending: await pendingGroupAccess(app.prisma, orgId(req), req.auth.userId) }));

  /**
   * Approves waiting group members: a key holder (owner or editor) who chose them by name and email seals the folder
   * key to them. The server decides the permission; wraps for anyone not waiting, or sealed to a stale key, are skipped.
   */
  app.post("/folders/:id/group-access", async (req, reply) => {
    const { id } = idParam.parse(req.params);
    const b = z.object({ wraps: wraps.min(1) }).parse(req.body);
    const folder = await folderFor(req, reply, id, "seal");
    if (!folder) return reply;
    const added = await app.prisma.$transaction(async (tx) => { await lockFolder(tx, id); return addViaGroups(tx, id, b.wraps, orgId(req)); });
    for (const u of added) await logEvent(app.prisma, { orgId: orgId(req), actorId: req.auth.userId, action: "folder.member_add", folderId: id, targetUserId: u, meta: { via: "group" } });
    return { added, skipped: b.wraps.length - added.length };
  });

  /** Declines waiting group members for this folder: hidden from the prompt until they are added to a group again. */
  app.post("/folders/:id/group-access/decline", async (req, reply) => {
    const { id } = idParam.parse(req.params);
    const { userIds } = z.object({ userIds: z.array(z.string().uuid()).min(1).max(500) }).parse(req.body);
    const folder = await folderFor(req, reply, id, "seal");
    if (!folder) return reply;
    const waiting = new Set((await pendingGroupAccess(app.prisma, orgId(req), req.auth.userId)).filter((p) => p.folderId === id).map((p) => p.userId));
    const ids = [...new Set(userIds)].filter((u) => waiting.has(u));
    await app.prisma.groupAccessDecline.createMany({ data: ids.map((userId) => ({ folderId: id, userId, declinedBy: req.auth.userId })), skipDuplicates: true });
    for (const u of ids) await logEvent(app.prisma, { orgId: orgId(req), actorId: req.auth.userId, action: "folder.group_access_declined", folderId: id, targetUserId: u });
    return { declined: ids.length };
  });
};

/** /admin/groups: owners and admins of the active org create, rename and delete groups and manage their members. */
export const groupAdminRoutes: FastifyPluginAsync = async (app) => {
  const orgId = (req: FastifyRequest) => req.org!.id;
  const groupIn = (req: FastifyRequest, id: string) => app.prisma.group.findFirst({ where: { id, orgId: orgId(req) }, select: { id: true, name: true } });

  app.get("/", async (req) => {
    const groups = await app.prisma.group.findMany({ where: { orgId: orgId(req) }, orderBy: { name: "asc" },
      select: { id: true, name: true, createdAt: true, _count: { select: { folders: { where: { folder: { deletedAt: null } } } } },
        members: { orderBy: { createdAt: "asc" }, select: { user: { select: { id: true, name: true, email: true } } } } } });
    return { groups: groups.map((g) => ({ id: g.id, name: g.name, createdAt: g.createdAt.toISOString(), folderCount: g._count.folders, members: g.members.map((m) => m.user) })) };
  });

  /**
   * One group for the admin's group page: its members, the live team folders shared with it (ids and permissions;
   * names are encrypted) and who is still waiting for a folder's key (`declined`: a key holder said no).
   */
  app.get("/:id", async (req, reply) => {
    const { id } = idParam.parse(req.params);
    const g = await app.prisma.group.findFirst({ where: { id, orgId: orgId(req) },
      select: { id: true, name: true, createdAt: true,
        members: { orderBy: { createdAt: "asc" }, select: { createdAt: true, user: { select: { id: true, name: true, email: true } } } },
        folders: { where: { folder: { deletedAt: null } }, orderBy: { createdAt: "asc" }, select: { folderId: true, permission: true, createdAt: true } } } });
    if (!g) return reply.code(404).send({ error: "not_found" });
    const folderIds = g.folders.map((f) => f.folderId), userIds = g.members.map((m) => m.user.id);
    const [have, declined] = await Promise.all([
      app.prisma.folderMember.findMany({ where: { folderId: { in: folderIds }, userId: { in: userIds } }, select: { folderId: true, userId: true } }),
      app.prisma.groupAccessDecline.findMany({ where: { folderId: { in: folderIds }, userId: { in: userIds } }, select: { folderId: true, userId: true } }),
    ]);
    const key = (f: string, u: string) => `${f}:${u}`;
    const has = new Set(have.map((x) => key(x.folderId, x.userId))), no = new Set(declined.map((x) => key(x.folderId, x.userId)));
    return {
      group: { id: g.id, name: g.name, createdAt: g.createdAt.toISOString() },
      members: g.members.map((m) => ({ ...m.user, addedAt: m.createdAt.toISOString() })),
      folders: g.folders.map((f) => ({ id: f.folderId, permission: f.permission, sharedAt: f.createdAt.toISOString() })),
      pending: g.folders.flatMap((f) => g.members.filter((m) => !has.has(key(f.folderId, m.user.id)))
        .map((m) => ({ folderId: f.folderId, userId: m.user.id, name: m.user.name, email: m.user.email, declined: no.has(key(f.folderId, m.user.id)) }))),
    };
  });

  app.post("/", async (req, reply) => {
    const { name } = z.object({ name: groupName }).parse(req.body);
    if ((await app.prisma.group.count({ where: { orgId: orgId(req) } })) >= 500) return reply.code(409).send({ error: "group_limit" });
    try {
      const g = await app.prisma.group.create({ data: { orgId: orgId(req), name } });
      await logEvent(app.prisma, { orgId: orgId(req), actorId: req.auth.userId, action: "group.create", meta: { groupId: g.id, name } });
      return reply.code(201).send({ id: g.id, name: g.name });
    } catch (e) { if (isUniqueViolation(e)) return reply.code(409).send({ error: "exists" }); throw e; }
  });

  app.patch("/:id", async (req, reply) => {
    const { id } = idParam.parse(req.params);
    const { name } = z.object({ name: groupName }).parse(req.body);
    const g = await groupIn(req, id);
    if (!g) return reply.code(404).send({ error: "not_found" });
    try { await app.prisma.group.update({ where: { id }, data: { name } }); }
    catch (e) { if (isUniqueViolation(e)) return reply.code(409).send({ error: "exists" }); throw e; }
    await logEvent(app.prisma, { orgId: orgId(req), actorId: req.auth.userId, action: "group.rename", meta: { groupId: id, name } });
    return { ok: true, name };
  });

  /** Deletes the group: folder access that came only through it ends. */
  app.delete("/:id", async (req, reply) => {
    const { id } = idParam.parse(req.params);
    const g = await groupIn(req, id);
    if (!g) return reply.code(404).send({ error: "not_found" });
    const removed = await app.prisma.$transaction(async (tx) => {
      await lockGroup(tx, id);
      const folders = (await tx.folderGroup.findMany({ where: { groupId: id }, select: { folderId: true } })).map((f) => f.folderId);
      const members = (await tx.groupMember.findMany({ where: { groupId: id }, select: { userId: true } })).map((m) => m.userId);
      await tx.group.delete({ where: { id } }); // grants and members cascade
      return recomputeGroupFolders(tx, folders, members);
    }, { timeout: 60_000 });
    await logEvent(app.prisma, { orgId: orgId(req), actorId: req.auth.userId, action: "group.delete", meta: { groupId: id, name: g.name } });
    for (const [folderId, users] of removed) for (const u of users) await logEvent(app.prisma, { orgId: orgId(req), actorId: req.auth.userId, action: "folder.member_remove", folderId, targetUserId: u, meta: { via: "group" } });
    return reply.code(204).send();
  });

  /** Adds members (people of this org). Folders shared with the group reach them once a key holder seals the key. */
  app.post("/:id/members", async (req, reply) => {
    const { id } = idParam.parse(req.params);
    const { userIds } = z.object({ userIds: z.array(z.string().uuid()).min(1).max(100) }).parse(req.body);
    const g = await groupIn(req, id);
    if (!g) return reply.code(404).send({ error: "not_found" });
    const ids = [...new Set(userIds)];
    const ok = await app.prisma.membership.count({ where: { orgId: orgId(req), userId: { in: ids }, status: { in: ["active", "disabled"] } } });
    if (ok !== ids.length) return reply.code(400).send({ error: "user_not_member" });
    const added = await app.prisma.$transaction(async (tx) => {
      await lockGroup(tx, id);
      const before = new Set((await tx.groupMember.findMany({ where: { groupId: id, userId: { in: ids } }, select: { userId: true } })).map((m) => m.userId));
      const fresh = ids.filter((u) => !before.has(u));
      await tx.groupMember.createMany({ data: fresh.map((userId) => ({ groupId: id, userId, addedBy: req.auth.userId })), skipDuplicates: true });
      // People already in a shared folder may get more through the group.
      const folders = (await tx.folderGroup.findMany({ where: { groupId: id }, select: { folderId: true } })).map((f) => f.folderId);
      // Added to a group again: earlier declines for its folders are asked again.
      if (fresh.length) await tx.groupAccessDecline.deleteMany({ where: { folderId: { in: folders }, userId: { in: fresh } } });
      await recomputeGroupFolders(tx, folders, fresh);
      return fresh;
    });
    for (const u of added) await logEvent(app.prisma, { orgId: orgId(req), actorId: req.auth.userId, action: "group.member_add", targetUserId: u, meta: { groupId: id } });
    return reply.code(201).send({ added: added.length });
  });

  /** Removes a member: folder access that came only through this group ends (direct grants and other groups stay). */
  app.delete("/:id/members/:userId", async (req, reply) => {
    const { id, userId } = memberParam.parse(req.params);
    const g = await groupIn(req, id);
    if (!g) return reply.code(404).send({ error: "not_found" });
    const removed = await app.prisma.$transaction(async (tx) => {
      await lockGroup(tx, id);
      const n = await tx.groupMember.deleteMany({ where: { groupId: id, userId } });
      if (!n.count) return null;
      const folders = (await tx.folderGroup.findMany({ where: { groupId: id }, select: { folderId: true } })).map((f) => f.folderId);
      return recomputeGroupFolders(tx, folders, [userId]);
    });
    if (!removed) return reply.code(404).send({ error: "not_member" });
    await logEvent(app.prisma, { orgId: orgId(req), actorId: req.auth.userId, action: "group.member_remove", targetUserId: userId, meta: { groupId: id } });
    for (const [folderId, users] of removed) for (const u of users) await logEvent(app.prisma, { orgId: orgId(req), actorId: req.auth.userId, action: "folder.member_remove", folderId, targetUserId: u, meta: { via: "group" } });
    return reply.code(204).send();
  });
};

