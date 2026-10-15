import type { FastifyPluginAsync, FastifyRequest } from "fastify";
import { z } from "zod";
import { cancelCustomerOrg, createCustomerOrg, listCustomerOrgs, resendCustomerInvite } from "../lib/customerOrgs.js";
import { displayName } from "../lib/names.js";

const email = z.string().trim().toLowerCase().email().max(254);
const orgParam = z.object({ orgId: z.string().uuid() });

/**
 * /admin/instance/orgs: organisations an instance admin creates for customers (docs/provisioning.md), registered in the
 * instance-admin group of /admin (closed in demo mode). Only the organisations created this way, and only what the
 * operator typed: never their members, records or events.
 */
export const customerOrgRoutes: FastifyPluginAsync = async (app) => {
  const meta = (req: FastifyRequest) => ({ ip: req.ip, userAgent: String(req.headers["user-agent"] ?? "").slice(0, 300) });

  /** Organisations created for customers: name, date, the owner's address and the invitation's status. */
  app.get("/", async () => ({ orgs: await listCustomerOrgs(app.prisma), hostedMode: !!app.config.hostedMode, emailConfigured: await app.mail.configured(null) }));

  /**
   * Creates an organisation for a customer: no members, and an owner invitation to `ownerEmail` (emailed; self-hosted,
   * the link also comes back once as `inviteUrl`).
   */
  app.post("/", { config: { rateLimit: { max: 10, timeWindow: "1 minute" } } }, async (req, reply) => {
    const b = z.object({ name: displayName, ownerEmail: email }).parse(req.body);
    const r = await createCustomerOrg(app, { name: b.name, ownerEmail: b.ownerEmail, actorId: req.auth.userId, log: req.log, meta: meta(req) });
    if (!r.ok) return reply.code(r.error === "self" ? 400 : 409).send({ error: r.error });
    return reply.code(201).send({ org: r.org, emailed: r.emailed, ...(!app.config.hostedMode && r.inviteUrl ? { inviteUrl: r.inviteUrl } : {}) });
  });

  app.post("/:orgId/resend", { config: { rateLimit: { max: 30, timeWindow: "1 minute" } } }, async (req, reply) => {
    const { orgId } = orgParam.parse(req.params);
    const r = await resendCustomerInvite(app, orgId, req.auth.userId, req.log, meta(req));
    if (!r.ok) return reply.code(({ not_found: 404, accepted: 409, email_required: 409, invite_cooldown: 409, too_soon: 429 } as const)[r.error]).send({ error: r.error });
    return { org: r.org, emailed: r.emailed, ...(!app.config.hostedMode && r.inviteUrl ? { inviteUrl: r.inviteUrl } : {}) };
  });

  /** Cancels the invitation and deletes the organisation; only while nobody has joined it (409 accepted). */
  app.delete("/:orgId", { config: { rateLimit: { max: 30, timeWindow: "1 minute" } } }, async (req, reply) => {
    const { orgId } = orgParam.parse(req.params);
    const r = await cancelCustomerOrg(app, orgId, req.auth.userId, meta(req));
    if (!r.ok) return reply.code(r.error === "not_found" ? 404 : 409).send({ error: r.error });
    return reply.code(204).send();
  });
};
