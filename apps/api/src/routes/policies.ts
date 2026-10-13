import type { FastifyPluginAsync, FastifyRequest } from "fastify";
import type { Prisma } from "@prisma/client";
import { logEvent } from "../lib/events.js";
import { BURN } from "../lib/links.js";
import { ipAllowed, normalizeIp, policySchema, readPolicies, readRiskIgnored, RISK_IGNORED, type Policies } from "../lib/policies.js";

/** /admin/settings/policies: the active org's policies (owners and admins; docs/policies.md). */
export const policyAdminRoutes: FastifyPluginAsync = async (app) => {
  const view = async (req: FastifyRequest) => {
    const o = await app.prisma.organization.findUniqueOrThrow({ where: { id: req.org!.id }, select: { policies: true, policiesChangedAt: true, policiesChangedBy: true } });
    const by = o.policiesChangedBy ? await app.prisma.user.findUnique({ where: { id: o.policiesChangedBy }, select: { id: true, name: true } }) : null;
    return { policies: readPolicies(o.policies), changedAt: o.policiesChangedAt?.toISOString() ?? null, changedBy: by, yourIp: req.ip ? normalizeIp(req.ip) : null };
  };

  app.get("/", async (req) => view(req));

  /**
   * Replaces the policies. Guards against locking yourself out: a non-empty allowlist must include the caller's address
   * unless they are the owner with break-glass on, and only the owner turns break-glass on or off.
   */
  app.put("/", async (req, reply) => {
    const next = policySchema.parse(req.body);
    const orgId = req.org!.id;
    const owner = req.org!.role === "owner";
    const r = await app.prisma.$transaction(async (tx) => {
      await tx.$queryRaw`SELECT id FROM "Organization" WHERE id = ${orgId}::uuid FOR UPDATE`;
      const stored = (await tx.organization.findUniqueOrThrow({ where: { id: orgId }, select: { policies: true } })).policies;
      const cur = readPolicies(stored);
      // Ignored risk benchmarks share the column (docs/risk-dashboard.md): saving the policies keeps them.
      const ignored = readRiskIgnored(stored);
      if (next.ownerBreakGlass !== cur.ownerBreakGlass && !owner) return { error: "owner_only" as const };
      // With break-glass off the owner is held to the list too, so an admin could shut them out by narrowing it (and
      // keep the org to themselves). Then only the owner narrows the list; admins may still widen or clear it.
      const narrows = next.ipAllowlist.length > 0 && (cur.ipAllowlist.length === 0 || cur.ipAllowlist.some((c) => !next.ipAllowlist.includes(c)));
      if (!owner && !next.ownerBreakGlass && narrows) return { error: "owner_only" as const };
      if (next.ipAllowlist.length && !ipAllowed(req.ip, next.ipAllowlist) && !(owner && next.ownerBreakGlass)) return { error: "would_lock_out" as const };
      await tx.organization.update({ where: { id: orgId }, data: { policies: { ...next, ...(ignored.length ? { [RISK_IGNORED]: ignored } : {}) } as unknown as Prisma.InputJsonValue, policiesChangedAt: new Date(), policiesChangedBy: req.auth.userId } });
      // Links switched off: the org's live links stop working now. A shorter maximum expiry or a new password
      // requirement ends the live links that break it (a policy tightened because of a leak must not wait out a week).
      let revoked = 0;
      if (cur.links.allowed && !next.links.allowed) {
        revoked = (await tx.shareLink.updateMany({ where: { orgId, revokedAt: null }, data: { revokedAt: new Date(), ...BURN } })).count;
      } else if (next.links.maxExpiryHours < cur.links.maxExpiryHours || (next.links.requirePassword && !cur.links.requirePassword)) {
        const live = await tx.shareLink.findMany({ where: { orgId, revokedAt: null, expiresAt: { gt: new Date() } }, select: { id: true, createdAt: true, expiresAt: true, accessHash: true } });
        const ids = live.filter((l) => l.expiresAt.getTime() - l.createdAt.getTime() > next.links.maxExpiryHours * 3600_000 + 60_000 || (next.links.requirePassword && l.accessHash === null)).map((l) => l.id);
        if (ids.length) revoked = (await tx.shareLink.updateMany({ where: { id: { in: ids }, revokedAt: null }, data: { revokedAt: new Date(), ...BURN } })).count;
      }
      // Files no longer allowed in links: live links that carry files stop now (docs/attachments.md).
      if (next.links.allowed && cur.links.allowAttachments && !next.links.allowAttachments) {
        revoked += (await tx.shareLink.updateMany({ where: { orgId, revokedAt: null, attachments: { some: {} } }, data: { revokedAt: new Date(), ...BURN } })).count;
      }
      const changed = (Object.keys(next) as (keyof Policies)[]).filter((k) => JSON.stringify(next[k]) !== JSON.stringify(cur[k]));
      return { changed, revoked };
    });
    if ("error" in r) return reply.code(r.error === "owner_only" ? 403 : 409).send({ error: r.error });
    if (r.changed.length) await logEvent(app.prisma, { orgId, actorId: req.auth.userId, action: "org.policies_update", ip: req.ip, meta: { changed: r.changed, ...(r.revoked ? { linksRevoked: r.revoked } : {}) } });
    return view(req);
  });
};
