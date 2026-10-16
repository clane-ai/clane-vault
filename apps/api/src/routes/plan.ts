import type { FastifyPluginAsync } from "fastify";
import { getEntitlements, PLAN_SELECT } from "../lib/plans.js";

/** Registered only when BILLING_MODE=hosted, inside the orgRequired block. */
const planRoutes: FastifyPluginAsync = async (app) => {
  app.get("/org/plan", { preHandler: app.orgAdmin }, async (req) => {
    const o = await app.prisma.organization.findUniqueOrThrow({ where: { id: req.org!.id }, select: { ...PLAN_SELECT, currentPeriodEnd: true } });
    return { plan: o.plan, billingStatus: o.billingStatus, seatsPaid: o.seatsPaid, currentPeriodEnd: o.currentPeriodEnd, trialEndsAt: o.trialEndsAt, entitlements: getEntitlements(app.config, o) };
  });
};
export default planRoutes;
