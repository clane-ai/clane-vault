import type { FastifyPluginAsync } from "fastify";
import { getEntitlements, PLAN_SELECT } from "../lib/plans.js";
import { attachmentConfig, chargeQuota, orgUsage } from "../lib/attachments/quota.js";
import { seatsUsed } from "../lib/seats.js";

/** Registered only when BILLING_MODE=hosted, inside the orgRequired block. */
const planRoutes: FastifyPluginAsync = async (app) => {
  app.get("/org/plan", { preHandler: app.orgAdmin }, async (req) => {
    const o = await app.prisma.organization.findUniqueOrThrow({ where: { id: req.org!.id }, select: { ...PLAN_SELECT, currentPeriodEnd: true } });
    const entitlements = getEntitlements(app.config, o);
    const storageLimit = await chargeQuota(app.prisma, attachmentConfig(app.config), { kind: "org", orgId: req.org!.id });
    return { plan: o.plan, billingStatus: o.billingStatus, seatsPaid: o.seatsPaid, currentPeriodEnd: o.currentPeriodEnd, trialEndsAt: o.trialEndsAt, entitlements, seats: { used: await seatsUsed(app.prisma, req.org!.id), allowed: entitlements.seatsAllowed },
      storage: { used: await orgUsage(app.prisma, req.org!.id), limit: storageLimit } };
  });
};
export default planRoutes;
