import type { FastifyPluginAsync } from "fastify";

/** Registered inside the admin routes, so the DB-checked admin guard applies. */
export const backupRoutes: FastifyPluginAsync = async (app) => {
  app.get("/backups", async () => app.backups.status());

  app.post("/backups/run", async (req, reply) => {
    const r = await app.backups.start("manual", { actorId: req.auth.userId });
    if (r.ok) return reply.code(202).send({ id: r.runId, status: "running" });
    if (r.reason === "disabled") return reply.code(409).send({ error: "backups_disabled" });
    if (r.reason === "running") return reply.code(409).send({ error: "backup_running" });
    return reply.code(500).send({ error: "server_error" });
  });
};
