import type { FastifyPluginAsync, FastifyReply } from "fastify";
import { logEvent } from "../lib/events.js";
import { getEntitlements, PLAN_SELECT } from "../lib/plans.js";
import { readPolicies } from "../lib/policies.js";
import { attachmentConfig, instanceUsage, MIB, orgUsage } from "../lib/attachments/quota.js";
import { csvCell } from "./events.js";

type MemberUsage = { userId: string; name: string; email: string; files: number; bytes: number };
type RecordUsage = { recordId: string; ownerId: string; ownerName: string; folderId: string | null; files: number; bytes: number };

/** The org's file usage (docs/attachments.md): totals, by member (the records they own) and the largest records. */
export async function orgStorage(prisma: import("@prisma/client").PrismaClient, orgId: string) {
  const [members, largest, files] = await Promise.all([
    prisma.$queryRaw<MemberUsage[]>`
      SELECT u.id AS "userId", u.name, u.email, COUNT(a.id)::int AS files, COALESCE(SUM(a.size), 0)::float8 AS bytes
      FROM "Attachment" a JOIN "Record" r ON r.id = a."recordId" JOIN "Folder" f ON f.id = r."folderId" JOIN "User" u ON u.id = r."ownerId"
      WHERE a.state IN ('uploading', 'ready') AND f.kind = 'team' AND f."orgId" = ${orgId}::uuid
      GROUP BY u.id, u.name, u.email ORDER BY 5 DESC, u.name ASC`,
    prisma.$queryRaw<RecordUsage[]>`
      SELECT r.id AS "recordId", r."ownerId", u.name AS "ownerName", r."folderId", COUNT(a.id)::int AS files, COALESCE(SUM(a.size), 0)::float8 AS bytes
      FROM "Attachment" a JOIN "Record" r ON r.id = a."recordId" JOIN "Folder" f ON f.id = r."folderId" JOIN "User" u ON u.id = r."ownerId"
      WHERE a.state IN ('uploading', 'ready') AND f.kind = 'team' AND f."orgId" = ${orgId}::uuid
      GROUP BY r.id, r."ownerId", u.name, r."folderId" ORDER BY 6 DESC LIMIT 20`,
    prisma.$queryRaw<{ n: number }[]>`
      SELECT COUNT(a.id)::int AS n FROM "Attachment" a JOIN "Record" r ON r.id = a."recordId" JOIN "Folder" f ON f.id = r."folderId"
      WHERE a.state = 'ready' AND f.kind = 'team' AND f."orgId" = ${orgId}::uuid`,
  ]);
  return { used: await orgUsage(prisma, orgId), files: files[0]?.n ?? 0, members, largest };
}

const csv = (reply: FastifyReply, name: string, header: string[], rows: unknown[][]) =>
  reply.header("content-type", "text/csv; charset=utf-8").header("content-disposition", `attachment; filename="${name}-${new Date().toISOString().slice(0, 10)}.csv"`)
    .send([header.join(","), ...rows.map((r) => r.map(csvCell).join(","))].join("\r\n") + "\r\n");

/** /admin/storage: the active org's attachment storage for its owners and admins. Never a file name or type (they are encrypted). */
export const storageAdminRoutes: FastifyPluginAsync = async (app) => {
  const cfg = attachmentConfig(app.config);
  app.get("/", async (req) => {
    const orgId = req.org!.id;
    const [s, org] = await Promise.all([orgStorage(app.prisma, orgId), app.prisma.organization.findUniqueOrThrow({ where: { id: orgId }, select: { ...PLAN_SELECT, policies: true } })]);
    const p = readPolicies(org.policies, getEntitlements(app.config, org));
    return {
      enabled: cfg.enabled, used: s.used, quota: cfg.orgQuotaMb * MIB, files: s.files,
      limits: { maxFileMb: Math.min(cfg.maxFileMb, p.attachments.maxFileMb ?? Infinity), serverMaxFileMb: cfg.maxFileMb, maxPerRecord: cfg.maxPerRecord, maxRecordMb: cfg.maxRecordMb },
      policy: { ...p.attachments, linksAllowAttachments: p.links.allowAttachments },
      members: s.members, largest: s.largest,
    };
  });

  app.get("/members.csv", { config: { rateLimit: { max: 20, timeWindow: "1 minute" } } }, async (req, reply) => {
    const orgId = req.org!.id;
    await logEvent(app.prisma, { orgId, actorId: req.auth.userId, action: "admin.risk_export", ip: req.ip, meta: { what: "storage" } });
    const s = await orgStorage(app.prisma, orgId);
    return csv(reply, "storage-by-member", ["name", "email", "files", "bytes"], s.members.map((m) => [m.name, m.email, m.files, m.bytes]));
  });
};

/** /admin/instance/storage: instance admins. Backend, usage against the instance quota, per organisation, and the GC. */
export const instanceStorageRoutes: FastifyPluginAsync = async (app) => {
  const cfg = attachmentConfig(app.config);
  const view = async () => {
    const [used, perOrg, personal, rows, last] = await Promise.all([
      instanceUsage(app.prisma),
      app.prisma.$queryRaw<{ orgId: string; name: string; files: number; bytes: number }[]>`
        SELECT o.id AS "orgId", o.name, COUNT(a.id)::int AS files, COALESCE(SUM(a.size), 0)::float8 AS bytes
        FROM "Attachment" a JOIN "Record" r ON r.id = a."recordId" JOIN "Folder" f ON f.id = r."folderId" JOIN "Organization" o ON o.id = f."orgId"
        WHERE a.state IN ('uploading', 'ready') AND f.kind = 'team' GROUP BY o.id, o.name ORDER BY 4 DESC`,
      app.prisma.$queryRaw<{ files: number; bytes: number }[]>`
        SELECT COUNT(a.id)::int AS files, COALESCE(SUM(a.size), 0)::float8 AS bytes FROM "Attachment" a JOIN "Record" r ON r.id = a."recordId"
        LEFT JOIN "Folder" f ON f.id = r."folderId" WHERE a.state IN ('uploading', 'ready') AND (f.id IS NULL OR f.kind = 'private')`,
      app.prisma.attachment.groupBy({ by: ["storage", "state"], _count: { _all: true } }),
      app.prisma.backupRun.findFirst({ where: { status: "success" }, orderBy: { startedAt: "desc" }, select: { startedAt: true, bytes: true, attachmentBytes: true } }),
    ]);
    const count = (storage: string, state?: string) => rows.filter((r) => r.storage === storage && (!state || r.state === state)).reduce((a, r) => a + r._count._all, 0);
    const quota = cfg.instanceQuotaMb * MIB;
    return {
      enabled: cfg.enabled, backend: cfg.storage, s3: app.attachmentStores.s3?.describe() ?? null,
      used, quota, warn: quota > 0 && used > 0.8 * quota,
      quotas: { orgMb: cfg.orgQuotaMb, userMb: cfg.userQuotaMb, instanceMb: cfg.instanceQuotaMb, dailyUploadMb: cfg.dailyUploadMb, maxFileMb: cfg.maxFileMb },
      perOrg: perOrg.map((o) => ({ ...o, quota: cfg.orgQuotaMb * MIB })), personal: personal[0] ?? { files: 0, bytes: 0 },
      // Each row says where its chunks are: files still in the database after switching to S3 need attachments-move.
      rows: { db: count("db"), s3: count("s3"), uploading: rows.filter((r) => r.state === "uploading").reduce((a, r) => a + r._count._all, 0), pendingDelete: rows.filter((r) => r.state === "deleted").reduce((a, r) => a + r._count._all, 0) },
      tombstones: await app.prisma.attachmentTombstone.count(),
      gc: app.attachmentSweeper.last,
      backup: { chunkDataExcluded: await app.backups.excludesChunkData(),
        lastSuccess: last ? { startedAt: last.startedAt.toISOString(), bytes: last.bytes === null ? null : Number(last.bytes), attachmentBytes: last.attachmentBytes === null ? null : Number(last.attachmentBytes) } : null },
    };
  };
  app.get("/", view);
  /** Runs the attachment sweep now (it also runs every 10 minutes) and answers with the fresh report. */
  app.post("/sweep", { config: { rateLimit: { max: 6, timeWindow: "1 minute" } } }, async (req) => {
    await app.attachmentSweeper.run();
    await logEvent(app.prisma, { actorId: req.auth.userId, action: "instance.storage_sweep", ip: req.ip });
    return view();
  });
};
