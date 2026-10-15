import type { FastifyPluginAsync, FastifyRequest } from "fastify";
import { z } from "zod";
import { resetTwoFactorByEmail } from "../lib/twoFactor.js";

const email = z.string().trim().toLowerCase().email().max(254);

/**
 * /admin/instance/users/...: what an instance admin does for an account without seeing into its organisations
 * (registered in the instance-admin group of /admin, closed in demo mode): by email address, never by browsing
 * other organisations.
 */
export const instanceAdminRoutes: FastifyPluginAsync = async (app) => {
  const meta = (req: FastifyRequest) => ({ ip: req.ip, userAgent: String(req.headers["user-agent"] ?? "").slice(0, 300) });

  /**
   * Resets someone's authenticator by email address (docs/recovery.md): the only way to reset an organisation owner's,
   * since no organisation's admin may. Same effect as the organisation route (no re-authentication there either): back to
   * authenticator setup, signed out everywhere, emailed. Never your own account (400 self): the operator's CLI is for that.
   */
  app.post("/users/reset-2fa", { config: { rateLimit: { max: 10, timeWindow: "1 minute" } } }, async (req, reply) => {
    const b = z.object({ email }).parse(req.body);
    const r = await resetTwoFactorByEmail({ prisma: app.prisma, mail: app.mail, productName: () => app.brand.productName() }, { email: b.email, actorId: req.auth.userId, log: req.log, ...meta(req) });
    if (!r.ok) return reply.code(({ not_found: 404, self: 400, disabled: 409 } as const)[r.error]).send({ error: r.error });
    return { ok: true, email: r.user.email, emailed: r.emailed };
  });
};
