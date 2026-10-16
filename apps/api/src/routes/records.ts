import type { FastifyPluginAsync, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import { accessFor, activeMember, canEdit, isUniqueViolation, teamMembership } from "../lib/access.js";
import { logEvent } from "../lib/events.js";
import { privateLockGuard } from "../lib/privateLock.js";
import { revokeLinksForRecords, revokeLinksOfLostAccess } from "../lib/links.js";
import { isPublicKeyB64, liveKeys, needsAccess, recipientKeyOk } from "../lib/membershipKeys.js";
import { seatOverage } from "../lib/seats.js";
import { attachmentConfig, checkQuota, lockQuota, recordUsage, type Charge, type QuotaRefusal } from "../lib/attachments/quota.js";
import { tombstoneAttachments } from "../lib/attachments/sweep.js";

const envelope = z.string().startsWith("v1.").max(65536);
const keyEnvelope = z.string().startsWith("v1.").max(4096);
const sealed = z.string().startsWith("s1.").max(4096);
const idParam = z.object({ id: z.string().uuid() });
const shareParam = z.object({ id: z.string().uuid(), userId: z.string().uuid() });
/**
 * The coarse type the server keeps (docs/record-types.md): "login" (the extension may fill it) or "item" (everything
 * else; the real type is inside the encrypted body). "note" from clients before record types is stored as "item".
 */
export const recordType = z.enum(["login", "item", "note"]).transform((t) => (t === "note" ? "item" as const : t));
const type = recordType;
/** "owner" is the creator's alone; shares grant edit, view or use. */
const grantable = z.enum(["edit", "view", "use"]);

/**
 * Records. A record in a team folder is reachable only from that folder's org (X-Org-Id); a private record from any
 * org; a direct share only in the org it was made in (docs/design/2026-10-07-multi-org-design.md).
 */
export const recordRoutes: FastifyPluginAsync = async (app) => {
  app.addHook("preHandler", app.requireAuth);
  app.addHook("preHandler", app.orgOptional);
  app.addHook("preHandler", privateLockGuard(app));
  const ctx = (req: FastifyRequest) => req.org?.id ?? null;

  const ownFolder = async (folderId: string | null | undefined, userId: string) =>
    folderId == null || !!(await app.prisma.folder.findFirst({ where: { id: folderId, ownerId: userId, kind: "private", deletedAt: null } }));

  /** Loads the caller's access to a record they own; sends 404/403 itself otherwise. */
  async function owned(req: FastifyRequest, reply: FastifyReply, id: string) {
    const access = await accessFor(app.prisma, req.auth.userId, id, ctx(req));
    if (!access) { await reply.code(404).send({ error: "not_found" }); return null; }
    if (!access.isOwner) { await reply.code(403).send({ error: "forbidden" }); return null; }
    return access;
  }

  app.post("/records", async (req, reply) => {
    const b = z.object({ id: z.string().uuid(), folderId: z.string().uuid().nullable(), type, encBody: envelope, wrappedRecordKey: keyEnvelope, ownerWrappedRecordKey: keyEnvelope.optional() }).parse(req.body);
    const userId = req.auth.userId;
    // A team-folder record carries two wraps: the folder's (wrappedRecordKey) and the owner's own (ownerWrappedRecordKey).
    const team = b.folderId ? await teamMembership(app.prisma, userId, b.folderId, ctx(req)) : null;
    if (team) {
      if (!canEdit(team.permission)) return reply.code(403).send({ error: "forbidden" });
      if (!b.ownerWrappedRecordKey) return reply.code(400).send({ error: "invalid_request", issues: ["ownerWrappedRecordKey"] });
      const over = ctx(req) ? await seatOverage(app.prisma, app.config, ctx(req)!) : null;
      if (over) return reply.code(402).send({ error: "seat_limit", ...over });
    } else if (!(await ownFolder(b.folderId, userId))) return reply.code(404).send({ error: "folder_not_found" });
    if (await app.prisma.record.findUnique({ where: { id: b.id } })) return reply.code(409).send({ error: "exists" });
    const access = team
      ? [{ holderType: "user" as const, holderId: userId, permission: "owner" as const, wrappedRecordKey: b.ownerWrappedRecordKey! },
         { holderType: "folder" as const, holderId: b.folderId!, permission: "edit" as const, wrappedRecordKey: b.wrappedRecordKey }]
      : [{ holderType: "user" as const, holderId: userId, permission: "owner" as const, wrappedRecordKey: b.wrappedRecordKey }];
    await app.prisma.record.create({ data: { id: b.id, folderId: b.folderId, ownerId: userId, type: b.type, encBody: b.encBody, access: { create: access } } });
    await logEvent(app.prisma, { orgId: team ? ctx(req) ?? undefined : undefined, actorId: userId, action: "record.create", recordId: b.id });
    return reply.code(201).send({ id: b.id, revision: 1 });
  });

  app.put("/records/:id", async (req, reply) => {
    const { id } = idParam.parse(req.params);
    const b = z.object({ encBody: envelope, revision: z.number().int().min(1), folderId: z.string().uuid().nullable().optional(), type: type.optional() }).parse(req.body);
    const access = await accessFor(app.prisma, req.auth.userId, id, ctx(req));
    if (!access) return reply.code(404).send({ error: "not_found" });
    if (!canEdit(access.permission)) return reply.code(403).send({ error: "forbidden" });
    const existing = await app.prisma.record.findUnique({ where: { id }, select: { deletedAt: true, folderId: true, folder: { select: { kind: true } } } });
    if (b.folderId !== undefined && b.folderId !== existing?.folderId) {
      // Moves between private folders only; team-folder moves need key re-wrapping via PUT /records/:id/folder.
      if (!access.isOwner || !(await ownFolder(b.folderId, req.auth.userId))) return reply.code(404).send({ error: "folder_not_found" });
      if (existing?.folder?.kind === "team") return reply.code(409).send({ error: "use_folder_move" });
    }
    if (existing?.deletedAt) return reply.code(409).send({ error: "in_trash" });
    const n = await app.prisma.record.updateMany({
      where: { id, revision: b.revision, deletedAt: null },
      data: { encBody: b.encBody, revision: { increment: 1 }, ...(b.folderId !== undefined ? { folderId: b.folderId } : {}), ...(b.type ? { type: b.type } : {}) },
    });
    if (n.count === 0) {
      const cur = await app.prisma.record.findUniqueOrThrow({ where: { id } });
      return reply.code(409).send({ error: "conflict", current: { revision: cur.revision, encBody: cur.encBody, updatedAt: cur.updatedAt } });
    }
    await logEvent(app.prisma, { orgId: access.orgId ?? undefined, actorId: req.auth.userId, action: "record.update", recordId: id });
    return { revision: b.revision + 1 };
  });

  app.delete("/records/:id", async (req, reply) => {
    const { id } = idParam.parse(req.params);
    const acc = await owned(req, reply, id);
    if (!acc) return reply;
    const now = new Date();
    await app.prisma.$transaction(async (tx) => {
      await tx.record.updateMany({ where: { id, deletedAt: null }, data: { deletedAt: now } });
      await revokeLinksForRecords(tx, [id], now); // one-time links die with the record
    });
    await logEvent(app.prisma, { orgId: acc.orgId ?? undefined, actorId: req.auth.userId, action: "record.trash", recordId: id });
    return reply.code(204).send();
  });

  app.post("/records/:id/restore", async (req, reply) => {
    const { id } = idParam.parse(req.params);
    const acc = await owned(req, reply, id);
    if (!acc) return reply;
    const rec = await app.prisma.record.findUniqueOrThrow({ where: { id }, include: { folder: true } });
    const folderGone = rec.folder?.deletedAt != null;
    await app.prisma.$transaction([
      app.prisma.record.update({ where: { id }, data: { deletedAt: null, ...(folderGone ? { folderId: null } : {}) } }),
      // Restored out of a deleted team folder: the folder's members lose access with the folder.
      ...(folderGone ? [app.prisma.recordAccess.deleteMany({ where: { recordId: id, holderType: "folder" } })] : []),
    ]);
    await logEvent(app.prisma, { orgId: acc.orgId ?? undefined, actorId: req.auth.userId, action: "record.restore", recordId: id });
    return { ok: true };
  });

  app.delete("/records/:id/purge", async (req, reply) => {
    const { id } = idParam.parse(req.params);
    const acc = await owned(req, reply, id);
    if (!acc) return reply;
    const rec = await app.prisma.record.findUniqueOrThrow({ where: { id } });
    if (!rec.deletedAt) return reply.code(409).send({ error: "not_in_trash" });
    await app.prisma.$transaction(async (tx) => {
      // Its files go with it (FK cascade); S3 objects are written down for the sweep.
      await tombstoneAttachments(tx, [id]);
      await tx.record.delete({ where: { id } });
    });
    await logEvent(app.prisma, { orgId: acc.orgId ?? undefined, actorId: req.auth.userId, action: "record.purge", recordId: id });
    return reply.code(204).send();
  });

  // Move a record between folders. Into a team folder the client supplies the record key wrapped under that folder's key.
  app.put("/records/:id/folder", async (req, reply) => {
    const { id } = idParam.parse(req.params);
    const b = z.object({ folderId: z.string().uuid().nullable(), folderWrappedRecordKey: keyEnvelope.optional(), ownerWrappedRecordKey: keyEnvelope.optional() }).parse(req.body);
    const access = await owned(req, reply, id);
    if (!access) return reply;
    const rec = await app.prisma.record.findUniqueOrThrow({ where: { id }, select: { deletedAt: true, ownerId: true, folder: { select: { kind: true, orgId: true } } } });
    if (rec.deletedAt) return reply.code(409).send({ error: "in_trash" });
    // A record in an organisation's team folder stays in that organisation: moved out to private it would escape the
    // org's rules (one-time link policy, event log) although the folder's members already know its key.
    const fromOrg = rec.folder?.kind === "team" ? rec.folder.orgId : null;
    const userId = req.auth.userId;
    // A folder owner acting on someone else's record reaches its key only through the folder: moving it takes
    // ownership, so the caller must supply their own wrap (otherwise the record could end up with no key holder).
    const takeOver = !access.ownerRow;
    if (takeOver && !b.ownerWrappedRecordKey) return reply.code(400).send({ error: "invalid_request", issues: ["ownerWrappedRecordKey"] });
    const team = b.folderId ? await teamMembership(app.prisma, userId, b.folderId, ctx(req)) : null;
    if (team) {
      if (!canEdit(team.permission)) return reply.code(403).send({ error: "forbidden" });
      if (!b.folderWrappedRecordKey) return reply.code(400).send({ error: "invalid_request", issues: ["folderWrappedRecordKey"] });
    } else if (!(await ownFolder(b.folderId, userId))) return reply.code(404).send({ error: "folder_not_found" });
    if (fromOrg && !team) return reply.code(409).send({ error: "org_record" });
    // Into a team folder from outside one adds a record to the org's shared space.
    const seatOver = team && !fromOrg ? await seatOverage(app.prisma, app.config, ctx(req)!) : null;
    if (seatOver) return reply.code(402).send({ error: "seat_limit", ...seatOver });
    // Into a team folder the record joins that org: direct shares made in other orgs (or none) end.
    const foreign = team ? { recordId: id, holderType: "user" as const, permission: { not: "owner" as const }, OR: [{ orgId: null }, { orgId: { not: ctx(req)! } }] } : null;
    // Files are charged to the record's org (team folder) or its owner: a move re-charges them, and is refused when the
    // new payer's quota can't take them (docs/design/2026-10-12-attachments.md §3.5).
    const nextCharge: Charge = team ? { kind: "org", orgId: ctx(req)! } : { kind: "user", userId: takeOver ? userId : rec.ownerId };
    const prevCharge: Charge = rec.folder?.kind === "team" && rec.folder.orgId ? { kind: "org", orgId: rec.folder.orgId } : { kind: "user", userId: rec.ownerId };
    const recharge = JSON.stringify(nextCharge) !== JSON.stringify(prevCharge);
    let over: QuotaRefusal | null = null;
    await app.prisma.$transaction(async (tx) => {
      if (recharge) {
        const usage = await recordUsage(tx, id);
        if (usage.bytes > 0) {
          await lockQuota(tx, nextCharge);
          over = await checkQuota(tx, attachmentConfig(app.config), nextCharge, usage.bytes, { instance: false });
          if (over) return;
        }
      }
      // All in one transaction, the cross-org share cleanup and the link revocation included.
      const dropped = foreign ? (await tx.recordAccess.findMany({ where: foreign, select: { holderId: true } })).map((r) => r.holderId) : [];
      if (foreign) await tx.recordAccess.deleteMany({ where: foreign });
      await tx.recordAccess.deleteMany({ where: { recordId: id, holderType: "folder" } });
      if (team) await tx.recordAccess.create({ data: { recordId: id, holderType: "folder", holderId: b.folderId!, permission: "edit", wrappedRecordKey: b.folderWrappedRecordKey! } });
      if (takeOver) {
        // The previous owner keeps edit access through their existing row, now a share made in this org.
        await tx.recordAccess.updateMany({ where: { recordId: id, holderType: "user", permission: "owner" }, data: { permission: "edit", orgId: ctx(req) } });
        await tx.recordAccess.upsert({ where: { recordId_holderType_holderId: { recordId: id, holderType: "user", holderId: userId } },
          create: { recordId: id, holderType: "user", holderId: userId, permission: "owner", wrappedRecordKey: b.ownerWrappedRecordKey! },
          update: { permission: "owner", wrappedRecordKey: b.ownerWrappedRecordKey! } });
      }
      await tx.record.update({ where: { id }, data: { folderId: b.folderId, ...(takeOver ? { ownerId: userId } : {}) } });
      for (const h of dropped) await revokeLinksOfLostAccess(tx, h, [id]);
    }, { timeout: 30_000, maxWait: 15_000 });
    const refused = over as QuotaRefusal | null;
    if (refused) {
      await logEvent(app.prisma, { orgId: (team ? ctx(req) : access.orgId) ?? undefined, actorId: userId, action: "attachment.quota_exceeded", recordId: id, meta: { ...refused, move: true } });
      return reply.code(409).send({ error: "quota_exceeded", ...refused });
    }
    await logEvent(app.prisma, { orgId: (team ? ctx(req) : access.orgId) ?? undefined, actorId: userId, action: "record.move", recordId: id });
    return { ok: true };
  });

  app.post("/records/:id/shares", async (req, reply) => {
    const { id } = idParam.parse(req.params);
    const b = z.object({ userId: z.string().uuid(), permission: grantable, sealedRecordKey: sealed, sealedTo: z.string().refine(isPublicKeyB64).nullable().default(null) }).parse(req.body);
    // A direct share is made in the active org, to an active member of it.
    if (!req.org) return reply.code(403).send({ error: "org_required" });
    if (!(await owned(req, reply, id))) return reply;
    if (b.userId === req.auth.userId) return reply.code(400).send({ error: "self_share" });
    if ((await app.prisma.record.findUniqueOrThrow({ where: { id }, select: { deletedAt: true } })).deletedAt) return reply.code(409).send({ error: "in_trash" });
    if (!(await activeMember(app.prisma, b.userId, req.org.id))) return reply.code(400).send({ error: "user_not_active" });
    if (!(await recipientKeyOk(app.prisma, req.org.id, b.userId, b.sealedTo))) return reply.code(409).send({ error: "stale_recipient_key" });
    const exists = await app.prisma.recordAccess.findUnique({ where: { recordId_holderType_holderId: { recordId: id, holderType: "user", holderId: b.userId } } });
    if (exists) {
      // Shared before, but the person can no longer open it (their key changed: a scoped reset): share it again.
      if (exists.permission === "owner" || exists.orgId !== req.org.id || !needsAccess(exists.sealedTo, await liveKeys(app.prisma, req.org.id, [b.userId]))) return reply.code(409).send({ error: "already_shared" });
      await app.prisma.recordAccess.update({ where: { id: exists.id }, data: { wrappedRecordKey: b.sealedRecordKey, sealedTo: b.sealedTo, permission: b.permission } });
      await logEvent(app.prisma, { orgId: req.org.id, actorId: req.auth.userId, action: "record.reshare", recordId: id, targetUserId: b.userId });
      return reply.code(200).send({ ok: true });
    }
    try {
      await app.prisma.recordAccess.create({ data: { recordId: id, holderType: "user", holderId: b.userId, permission: b.permission, wrappedRecordKey: b.sealedRecordKey, orgId: req.org.id, sealedTo: b.sealedTo } });
    } catch (e) { if (isUniqueViolation(e)) return reply.code(409).send({ error: "exists" }); throw e; }
    await logEvent(app.prisma, { orgId: req.org?.id, actorId: req.auth.userId, action: "record.share", recordId: id, targetUserId: b.userId });
    return reply.code(201).send({ ok: true });
  });

  app.patch("/records/:id/shares/:userId", async (req, reply) => {
    const { id, userId } = shareParam.parse(req.params);
    const b = z.object({ permission: grantable }).parse(req.body);
    if (!(await owned(req, reply, id))) return reply;
    const n = await app.prisma.$transaction(async (tx) => {
      const u = await tx.recordAccess.updateMany({ where: { recordId: id, holderType: "user", holderId: userId, permission: { not: "owner" }, orgId: ctx(req) }, data: { permission: b.permission } });
      if (u.count) await revokeLinksOfLostAccess(tx, userId, [id]); // down to view/use: their links go
      return u;
    });
    if (n.count === 0) return reply.code(404).send({ error: "not_shared" });
    await logEvent(app.prisma, { orgId: req.org?.id, actorId: req.auth.userId, action: "record.permission", recordId: id, targetUserId: userId });
    return { ok: true };
  });

  app.delete("/records/:id/shares/:userId", async (req, reply) => {
    const { id, userId } = shareParam.parse(req.params);
    if (!(await owned(req, reply, id))) return reply;
    const n = await app.prisma.$transaction(async (tx) => {
      const d = await tx.recordAccess.deleteMany({ where: { recordId: id, holderType: "user", holderId: userId, permission: { not: "owner" }, orgId: ctx(req) } });
      // Their live one-time links on this record go too, unless a team folder still gives them edit.
      if (d.count) await revokeLinksOfLostAccess(tx, userId, [id]);
      return d;
    });
    if (n.count === 0) return reply.code(404).send({ error: "not_shared" });
    await logEvent(app.prisma, { orgId: req.org?.id, actorId: req.auth.userId, action: "record.unshare", recordId: id, targetUserId: userId });
    return reply.code(204).send();
  });

  app.get("/records/:id/activity", async (req, reply) => {
    const { id } = idParam.parse(req.params);
    const access = await accessFor(app.prisma, req.auth.userId, id, ctx(req));
    if (!access) return reply.code(404).send({ error: "not_found" });
    // Only what happened in the active org, plus the record's own private context: its owner sees their org-less events,
    // others see the owner's org-less events (create, edits) but nothing from shares in other orgs.
    const org = ctx(req);
    const rec = await app.prisma.record.findUniqueOrThrow({ where: { id }, select: { ownerId: true } });
    const scope = [...(org ? [{ orgId: org }] : []), access.isOwner ? { orgId: null } : { orgId: null, actorId: rec.ownerId }];
    const events = await app.prisma.event.findMany({ where: { recordId: id, OR: scope }, orderBy: { id: "desc" }, take: 50, select: { action: true, at: true, actorId: true, targetUserId: true } });
    const ids = [...new Set(events.flatMap((e) => [e.actorId, e.targetUserId]).filter((x): x is string => !!x))];
    const names = new Map((await app.prisma.user.findMany({ where: { id: { in: ids } }, select: { id: true, name: true } })).map((u) => [u.id, u.name]));
    const name = (x: string | null) => (x ? names.get(x) ?? "Removed user" : null);
    return { events: events.map((e) => ({ action: e.action, at: e.at.toISOString(), actor: name(e.actorId), target: name(e.targetUserId) })) };
  });
};
