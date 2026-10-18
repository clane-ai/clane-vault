import type { FastifyPluginAsync, FastifyRequest } from "fastify";
import { z } from "zod";
import { logEvent } from "../lib/events.js";
import { lockedFor, registerFailure } from "../lib/lockout.js";
import { secretBox } from "../lib/secretBox.js";
import { consumeTotp } from "../lib/totp.js";
import { resetTwoFactorByEmail } from "../lib/twoFactor.js";

const email = z.string().trim().toLowerCase().email().max(254);

/**
 * /admin/instance/users/...: what an instance admin does for an account without seeing into its organisations
 * (registered in the instance-admin group of /admin, closed in demo mode): by email address, never by browsing
 * other organisations.
 */
export const instanceAdminRoutes: FastifyPluginAsync = async (app) => {
  const box = secretBox(app.config.serverSecret);
  const meta = (req: FastifyRequest) => ({ ip: req.ip, userAgent: String(req.headers["user-agent"] ?? "").slice(0, 300) });

  /**
   * Resets someone's authenticator by email address (docs/recovery.md): the only way to reset an organisation owner's,
   * since no organisation's admin may. Same effect as the organisation route: back to authenticator setup, signed out
   * everywhere, emailed. Never your own account (400 self): the operator's CLI is for that.
   *
   * It reaches every account on the server, so a signed-in session alone isn't enough: the instance admin's own fresh
   * authenticator code (`code`) is checked first, as for turning admin recovery on (wrong codes count toward their
   * lockout, 423 locked / 401 totp_invalid), and before the address is looked up, so it can't probe which exist.
   */
  app.post("/users/reset-2fa", { config: { rateLimit: { max: 10, timeWindow: "1 minute" } } }, async (req, reply) => {
    const b = z.object({ email, code: z.string().max(10) }).parse(req.body);
    const me = await app.prisma.user.findUniqueOrThrow({ where: { id: req.auth.userId } });
    const locked = lockedFor(me);
    if (locked) return reply.code(423).send({ error: "locked", retryAfterSeconds: locked });
    if (!(await consumeTotp(app.prisma, box, me, b.code))) {
      await registerFailure(app.prisma, me.id);
      await logEvent(app.prisma, { actorId: me.id, action: "auth.reauth_failed", ...meta(req), meta: { for: "instance.reset_2fa" } });
      return reply.code(401).send({ error: "totp_invalid" });
    }
    const r = await resetTwoFactorByEmail({ prisma: app.prisma, mail: app.mail, productName: () => app.brand.productName() }, { email: b.email, actorId: me.id, log: req.log, ...meta(req) });
    if (!r.ok) return reply.code(({ not_found: 404, self: 400, disabled: 409, is_agent: 409 } as const)[r.error]).send({ error: r.error });
    return { ok: true, email: r.user.email, emailed: r.emailed };
  });
};
