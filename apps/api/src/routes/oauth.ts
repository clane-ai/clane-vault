import { timingSafeEqual } from "node:crypto";
import type { FastifyPluginAsync, FastifyReply, FastifyRequest } from "fastify";
import { agentJwks, hashToken, signAgentAccess } from "../lib/tokens.js";
import { fromGateway } from "../plugins/agent.js";

const STATIC = /^cvat_([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})_[A-Za-z0-9_-]{43}$/;
type Form = Record<string, string | undefined>;
type Grant = (req: FastifyRequest, reply: FastifyReply, form: Form) => Promise<unknown>;

/** OAuth for agents (docs/agents.md), RFC 6749 error bodies. Registered only when agents are on. */
export const oauthRoutes: FastifyPluginAsync = async (app) => {
  // OAuth token requests are form-encoded (RFC 6749 §4.1.3); scoped to this plugin.
  app.addContentTypeParser("application/x-www-form-urlencoded", { parseAs: "string" },
    (_req, body, done) => done(null, Object.fromEntries(new URLSearchParams(body as string))));

  app.get("/.well-known/jwks.json", async (_req, reply) => {
    reply.header("cache-control", "public, max-age=300");
    return agentJwks(app.config);
  });

  /** The gateway trades an admin-issued static token for a 15-minute access token. */
  const agentToken: Grant = async (req, reply, form) => {
    if (!fromGateway(app, req)) return reply.code(401).send({ error: "invalid_client" });
    if (typeof form.token !== "string") return reply.code(400).send({ error: "invalid_request" });
    const id = STATIC.exec(form.token)?.[1];
    const now = new Date();
    const row = id ? await app.prisma.agentToken.findFirst({
      where: { id, revokedAt: null, OR: [{ expiresAt: null }, { expiresAt: { gt: now } }], agent: { revokedAt: null, user: { status: "active" } } },
      select: { id: true, tokenHash: true, agentId: true, agent: { select: { orgId: true } } },
    }) : null;
    const presented = Buffer.from(hashToken(form.token), "hex"), stored = Buffer.from(row?.tokenHash ?? "", "hex");
    if (!row || stored.length !== presented.length || !timingSafeEqual(stored, presented)) return reply.code(400).send({ error: "invalid_grant" });
    await app.prisma.agentToken.update({ where: { id: row.id }, data: { lastUsedAt: now } });
    const { token, expiresIn } = await signAgentAccess(app.config, { agentId: row.agentId, orgId: row.agent.orgId, grant: row.id });
    return { access_token: token, token_type: "Bearer", expires_in: expiresIn };
  };
  // Task 12 adds authorization_code and refresh_token here.
  const grants = new Map<string, Grant>([["urn:clane:agent-token", agentToken]]);

  // Preflight #12: the gateway's exchanges all come from one address, so they are counted per token instead.
  const rateKey = (req: FastifyRequest) => {
    const id = fromGateway(app, req) ? STATIC.exec(String((req.body as Form | undefined)?.token ?? ""))?.[1] : undefined;
    return id ? `agent-token:${id}` : req.ip;
  };
  app.post("/oauth/token", { config: { rateLimit: { max: 30, timeWindow: "1 minute", hook: "preHandler", keyGenerator: rateKey } } }, async (req, reply) => {
    const form = (req.body && typeof req.body === "object" ? req.body : {}) as Form;
    if (typeof form.grant_type !== "string") return reply.code(400).send({ error: "invalid_request" });
    const grant = grants.get(form.grant_type);
    return grant ? grant(req, reply, form) : reply.code(400).send({ error: "unsupported_grant_type" });
  });
};
