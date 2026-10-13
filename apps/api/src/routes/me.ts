import type { FastifyPluginAsync } from "fastify";
import { materialView, userView } from "./auth.js";
import { orgsOf } from "../lib/orgs.js";

export const meRoutes: FastifyPluginAsync = async (app) => {
  app.get("/me", { preHandler: app.requireAuth }, async (req) => {
    const u = await app.prisma.user.findUniqueOrThrow({ where: { id: req.auth.userId } });
    return { user: userView(u), material: materialView(u), orgs: await orgsOf(app.prisma, u.id) };
  });
};
