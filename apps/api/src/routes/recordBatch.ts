import type { FastifyPluginAsync } from "fastify";
import { privateLockGuard } from "../lib/privateLock.js";
import { z } from "zod";
import { canEdit } from "../lib/access.js";
import { isUniqueViolation } from "../lib/links.js";
import { seatOverage } from "../lib/seats.js";
import { recordType } from "./records.js";

const envelope = z.string().startsWith("v1.").max(65536);
const keyEnvelope = z.string().startsWith("v1.").max(4096);
const item = z.object({
  id: z.string().uuid(), folderId: z.string().uuid().nullable(), type: recordType, encBody: envelope,
  /** Private: the record key under the caller's user key. Team folder: under the folder key. */
  wrappedRecordKey: envelope,
  /** Team folders only: the record key under the caller's user key (the owner's own wrap, as POST /records). */
  ownerWrappedRecordKey: keyEnvelope.optional(),
});

/**
 * Import and bulk migration: creates up to 25 new records in one request (all or nothing), into no folder, the
 * caller's own live private folders, or live team folders where the caller is owner or editor. A team-folder record
 * carries two wraps like POST /records: the folder's (wrappedRecordKey) and the caller's own (ownerWrappedRecordKey).
 * Any folder the caller can't file into answers 404 folder_not_found (403 forbidden for a view/use team member).
 */
export const recordBatchRoutes: FastifyPluginAsync = async (app) => {
  app.post("/records/batch", { preHandler: [app.requireAuth, app.orgOptional, privateLockGuard(app)] }, async (req, reply) => {
    const { records } = z.object({ records: z.array(item).min(1).max(25) }).parse(req.body);
    const userId = req.auth.userId;
    const ids = records.map((r) => r.id);
    if (new Set(ids).size !== ids.length) return reply.code(400).send({ error: "invalid_request" });
    const folderIds = [...new Set(records.map((r) => r.folderId).filter((x): x is string => x != null))];
    const teams = new Set<string>();
    if (folderIds.length) {
      const [mine, memberships] = await Promise.all([
        app.prisma.folder.findMany({ where: { id: { in: folderIds }, ownerId: userId, kind: "private", deletedAt: null }, select: { id: true } }),
        // Team folders only of the active org (none without one).
        req.org ? app.prisma.folderMember.findMany({ where: { userId, folderId: { in: folderIds }, folder: { kind: "team", deletedAt: null, orgId: req.org.id } }, select: { folderId: true, permission: true } }) : Promise.resolve([]),
      ]);
      for (const m of memberships) {
        if (!canEdit(m.permission)) return reply.code(403).send({ error: "forbidden" });
        teams.add(m.folderId);
      }
      if (mine.length + teams.size !== folderIds.length) return reply.code(404).send({ error: "folder_not_found" });
    }
    const over = teams.size ? await seatOverage(app.prisma, app.config, req.org!.id) : null;
    if (over) return reply.code(402).send({ error: "seat_limit", ...over });
    const missingOwnerWrap = records.findIndex((r) => r.folderId && teams.has(r.folderId) && !r.ownerWrappedRecordKey);
    if (missingOwnerWrap >= 0) return reply.code(400).send({ error: "invalid_request", issues: [`records.${missingOwnerWrap}.ownerWrappedRecordKey`] });
    if (await app.prisma.record.count({ where: { id: { in: ids } } })) return reply.code(409).send({ error: "exists" });
    const access = (r: z.infer<typeof item>) => r.folderId && teams.has(r.folderId)
      ? [{ holderType: "user" as const, holderId: userId, permission: "owner" as const, wrappedRecordKey: r.ownerWrappedRecordKey! },
         { holderType: "folder" as const, holderId: r.folderId, permission: "edit" as const, wrappedRecordKey: r.wrappedRecordKey }]
      : [{ holderType: "user" as const, holderId: userId, permission: "owner" as const, wrappedRecordKey: r.wrappedRecordKey }];
    try {
      await app.prisma.$transaction([
        ...records.map((r) => app.prisma.record.create({ data: {
          id: r.id, folderId: r.folderId, ownerId: userId, type: r.type, encBody: r.encBody, access: { create: access(r) },
        } })),
        app.prisma.event.createMany({ data: records.map((r) => ({ orgId: r.folderId && teams.has(r.folderId) ? req.org!.id : null, actorId: userId, action: "record.import", recordId: r.id })) }),
      ]);
    } catch (e) {
      if (isUniqueViolation(e)) return reply.code(409).send({ error: "exists" });
      throw e;
    }
    return reply.code(201).send({ created: records.length });
  });
};
