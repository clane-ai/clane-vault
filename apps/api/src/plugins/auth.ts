import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { verifyToken } from "../lib/tokens.js";
import { demoExpired } from "../lib/demo.js";

declare module "fastify" {
  interface FastifyRequest { auth: { userId: string; sessionId: string;
    /** The session skipped the authenticator code for this org's trusted IdP MFA: only that org until a step-up. */ totpSkippedForOrg?: string | null }; setupUserId: string;
    /** The org whose SSO sign-in led to this account setup (setup token claim), if any. */ setupSsoOrgId: string | null;
    /** The SSO proof of that sign-in (identity link and just-in-time join happen once the authenticator is set up). */ setupSsoProofId: string | null }
  interface FastifyInstance {
    requireAuth: (req: FastifyRequest, reply: FastifyReply) => Promise<void>;
    requireSetup: (req: FastifyRequest, reply: FastifyReply) => Promise<void>;
  }
}

const bearer = (req: FastifyRequest) => req.headers.authorization?.replace(/^Bearer /, "") ?? "";

export function registerAuth(app: FastifyInstance) {
  app.decorateRequest("auth", null as never);
  app.decorateRequest("setupUserId", "");
  app.decorateRequest("setupSsoOrgId", null);
  app.decorateRequest("setupSsoProofId", null);
  app.decorate("requireAuth", async (req: FastifyRequest, reply: FastifyReply) => {
    try {
      const t = await verifyToken(app.config, bearer(req), "access");
      const session = await app.prisma.session.findUnique({ where: { id: t.sid! }, include: { user: { select: { status: true, demoExpiresAt: true } } } });
      // A demo sandbox stops working the moment it expires, before the sweep deletes it (docs/demo.md).
      if (!session || session.revokedAt || session.expiresAt < new Date() || session.user.status !== "active" || demoExpired(session.user)) throw new Error("session ended");
      req.auth = { userId: t.sub, sessionId: t.sid!, totpSkippedForOrg: session.totpSkippedForOrg };
    } catch {
      await reply.code(401).send({ error: "unauthorized" });
    }
  });
  app.decorate("requireSetup", async (req: FastifyRequest, reply: FastifyReply) => {
    try { const t = await verifyToken(app.config, bearer(req), "setup"); req.setupUserId = t.sub; req.setupSsoOrgId = t.sso ?? null; req.setupSsoProofId = t.ssoProof ?? null; }
    catch { await reply.code(401).send({ error: "unauthorized" }); }
  });
}
