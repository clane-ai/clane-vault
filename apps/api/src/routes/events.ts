import { Readable } from "node:stream";
import type { FastifyPluginAsync } from "fastify";
import type { Prisma } from "@prisma/client";
import { z } from "zod";
import { logEvent } from "../lib/events.js";

const filters = z.object({
  actor: z.string().uuid().optional(),
  /** An exact action ("folder.member_add"), or a family ending in a dot ("folder."). */
  action: z.string().trim().max(64).regex(/^[a-z0-9_.]+$/).optional(),
  from: z.string().datetime({ offset: true }).optional(),
  to: z.string().datetime({ offset: true }).optional(),
});
const page = filters.extend({ before: z.string().regex(/^\d{1,19}$/).optional(), limit: z.coerce.number().int().min(1).max(200).default(50) });

type Filters = z.infer<typeof filters>;
const whereOf = (orgId: string, f: Filters): Prisma.EventWhereInput => ({
  orgId,
  ...(f.actor ? { actorId: f.actor } : {}),
  ...(f.action ? (f.action.endsWith(".") ? { action: { startsWith: f.action } } : { action: f.action }) : {}),
  ...(f.from || f.to ? { at: { ...(f.from ? { gte: new Date(f.from) } : {}), ...(f.to ? { lte: new Date(f.to) } : {}) } } : {}),
});

const select = { id: true, at: true, action: true, actorId: true, targetUserId: true, recordId: true, folderId: true, ip: true, userAgent: true, meta: true } as const;
type Row = Prisma.EventGetPayload<{ select: typeof select }>;

/** CSV cell: quoted, and a leading formula character neutralised (spreadsheet formula injection). */
export function csvCell(v: unknown): string {
  let s = v === null || v === undefined ? "" : typeof v === "string" ? v : JSON.stringify(v);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return `"${s.replace(/"/g, '""')}"`;
}
const HEADER = ["id", "at", "action", "actor_id", "actor_name", "actor_email", "target_id", "target_name", "target_email", "record_id", "folder_id", "ip", "user_agent", "meta"];

/** /admin/events: the active org's event log for its owners and admins, with filters and a streamed CSV export. */
export const eventAdminRoutes: FastifyPluginAsync = async (app) => {
  async function people(rows: Row[]) {
    const ids = [...new Set(rows.flatMap((r) => [r.actorId, r.targetUserId]).filter((x): x is string => !!x))];
    return new Map((await app.prisma.user.findMany({ where: { id: { in: ids } }, select: { id: true, name: true, email: true } })).map((u) => [u.id, u]));
  }

  app.get("/", async (req) => {
    const q = page.parse(req.query);
    const rows = await app.prisma.event.findMany({ where: { ...whereOf(req.org!.id, q), ...(q.before ? { id: { lt: BigInt(q.before) } } : {}) }, orderBy: { id: "desc" }, take: q.limit + 1, select });
    const more = rows.length > q.limit;
    const list = rows.slice(0, q.limit);
    const who = await people(list);
    return {
      events: list.map((e) => ({ id: e.id.toString(), at: e.at.toISOString(), action: e.action, actor: e.actorId ? who.get(e.actorId) ?? { id: e.actorId, name: null, email: null } : null,
        target: e.targetUserId ? who.get(e.targetUserId) ?? { id: e.targetUserId, name: null, email: null } : null, recordId: e.recordId, folderId: e.folderId, ip: e.ip, meta: e.meta })),
      nextBefore: more ? list[list.length - 1]!.id.toString() : null,
    };
  });

  /** The actions that occur in this org's log (for the filter). */
  app.get("/actions", async (req) => {
    const rows = await app.prisma.event.findMany({ where: { orgId: req.org!.id }, distinct: ["action"], select: { action: true }, orderBy: { action: "asc" } });
    return { actions: rows.map((r) => r.action) };
  });

  /** Streams the filtered log as CSV, newest first, in pages (no size limit, constant memory). */
  app.get("/export.csv", { preHandler: app.requireEntitlement("eventExport"), config: { rateLimit: { max: 10, timeWindow: "1 minute" } } }, async (req, reply) => {
    const f = filters.parse(req.query);
    const where = whereOf(req.org!.id, f);
    await logEvent(app.prisma, { orgId: req.org!.id, actorId: req.auth.userId, action: "admin.events_export", ip: req.ip, meta: { ...f } });
    async function* lines() {
      yield `${HEADER.join(",")}\r\n`;
      let before: bigint | null = null;
      for (;;) {
        const rows: Row[] = await app.prisma.event.findMany({ where: { ...where, ...(before !== null ? { id: { lt: before } } : {}) }, orderBy: { id: "desc" }, take: 1000, select });
        if (!rows.length) return;
        const who = await people(rows);
        yield rows.map((e) => {
          const a = e.actorId ? who.get(e.actorId) : undefined, t = e.targetUserId ? who.get(e.targetUserId) : undefined;
          return [e.id.toString(), e.at.toISOString(), e.action, e.actorId, a?.name, a?.email, e.targetUserId, t?.name, t?.email, e.recordId, e.folderId, e.ip, e.userAgent, e.meta].map(csvCell).join(",");
        }).join("\r\n") + "\r\n";
        before = rows[rows.length - 1]!.id;
      }
    }
    const day = new Date().toISOString().slice(0, 10);
    return reply.header("content-type", "text/csv; charset=utf-8").header("content-disposition", `attachment; filename="events-${day}.csv"`).send(Readable.from(lines()));
  });
};
