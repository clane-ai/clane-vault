import type { FastifyPluginAsync } from "fastify";
import { z } from "zod";

const count = z.number().int().min(0).max(1_000_000);
const report = z.object({ score: z.number().int().min(0).max(100), total: count, weak: count, reused: count, old: count, breached: count.nullable() })
  .refine((r) => [r.weak, r.reused, r.old, r.breached ?? 0].every((n) => n <= r.total), { message: "counts above total" });

/**
 * Password health (docs/password-health.md). The check runs in the member's browser; it posts counts and a score only,
 * per user and org, and admins see those numbers per member. No password, hash or record id ever reaches the server.
 */
export const healthReportRoutes: FastifyPluginAsync = async (app) => {
  app.post("/me/health-report", { preHandler: [app.requireAuth, app.orgRequired], config: { rateLimit: { max: 20, timeWindow: "1 minute" } } }, async (req, reply) => {
    const r = report.parse(req.body);
    const orgId = req.org!.id, userId = req.auth.userId;
    await app.prisma.healthReport.upsert({ where: { orgId_userId: { orgId, userId } }, create: { orgId, userId, ...r }, update: { ...r, reportedAt: new Date() } });
    return reply.code(204).send();
  });
};

/** /admin/health: every member of the active org with their last report (or none). */
export const healthAdminRoutes: FastifyPluginAsync = async (app) => {
  app.get("/", async (req) => {
    const orgId = req.org!.id;
    const [members, reports] = await Promise.all([
      app.prisma.membership.findMany({ where: { orgId, status: { in: ["active", "disabled"] }, user: { kind: "person" } }, orderBy: { createdAt: "asc" }, select: { role: true, status: true, user: { select: { id: true, name: true, email: true } } } }),
      app.prisma.healthReport.findMany({ where: { orgId }, select: { userId: true, score: true, total: true, weak: true, reused: true, old: true, breached: true, reportedAt: true } }),
    ]);
    const byUser = new Map(reports.map((r) => [r.userId, r]));
    return { members: members.map((m) => {
      const r = byUser.get(m.user.id);
      return { ...m.user, role: m.role, status: m.status, report: r ? { score: r.score, total: r.total, weak: r.weak, reused: r.reused, old: r.old, breached: r.breached, reportedAt: r.reportedAt.toISOString() } : null };
    }) };
  });
};
