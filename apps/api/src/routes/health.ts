import type { FastifyPluginAsync } from "fastify";

export const healthRoutes: FastifyPluginAsync = async (app) => {
  app.get("/health", async () => {
    let db = true;
    try { await app.prisma.$queryRaw`SELECT 1`; } catch { db = false; }
    return { ok: true, db };
  });
};
