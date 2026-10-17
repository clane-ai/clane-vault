import type { FastifyPluginAsync } from "fastify";
import { z } from "zod";
import { isPrivateLocked } from "../lib/privateLock.js";
import { syncFor } from "../lib/sync.js";

/** No X-Org-Id: the Personal space; X-Org-Id with `?space=org`: that org only; X-Org-Id alone: both (lib/sync.ts). */
const query = z.object({ space: z.enum(["org"]).optional() });

export const syncRoutes: FastifyPluginAsync = async (app) => {
  app.get("/sync", { preHandler: [app.requireAuth, app.orgOptional] }, async (req, reply) => {
    const orgId = req.org?.id ?? null;
    const q = query.safeParse(req.query);
    if (!q.success) return reply.code(400).send({ error: "invalid_request" });
    const orgOnly = q.data.space === "org";
    if (orgOnly && !orgId) return reply.code(403).send({ error: "org_required" });
    return syncFor(app.prisma, app.config, { userId: req.auth.userId, orgId, orgOnly, locked: isPrivateLocked(req) });
  });
};
