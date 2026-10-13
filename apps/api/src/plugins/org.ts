import type { OrgRole } from "@prisma/client";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { isAdminRole } from "../lib/orgs.js";
import { logEvent } from "../lib/events.js";
import { ipAllowed, readPolicies } from "../lib/policies.js";

/** The caller's active organisation for this request (docs/design/2026-10-07-multi-org-design.md §4). */
export interface ActiveOrg { id: string; role: OrgRole; adminSince: Date | null }

declare module "fastify" {
  interface FastifyRequest { org: ActiveOrg | null }
  interface FastifyInstance {
    /** X-Org-Id optional: none → req.org = null; present but not an active membership → 403. Runs after requireAuth. */
    orgOptional: (req: FastifyRequest, reply: FastifyReply) => Promise<void>;
    /** X-Org-Id required and must be an active membership. */
    orgRequired: (req: FastifyRequest, reply: FastifyReply) => Promise<void>;
    /** X-Org-Id required, and the caller must be owner or admin of that org (read from the database). */
    orgAdmin: (req: FastifyRequest, reply: FastifyReply) => Promise<void>;
  }
}

export const ORG_HEADER = "x-org-id";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function registerOrg(app: FastifyInstance) {
  app.decorateRequest("org", null);

  /**
   * "Require SSO for members" (docs/sso.md): a member whose address is in one of the org's verified domains reaches the
   * org only from a session that this org's SSO established. The owner is exempt (break-glass when the identity
   * provider is down or misconfigured).
   */
  const bypassLogged = new Set<string>();
  async function ssoMissing(req: FastifyRequest, orgId: string, role: OrgRole, email: string): Promise<boolean> {
    const domain = email.slice(email.lastIndexOf("@") + 1).toLowerCase();
    if (!(await app.prisma.ssoDomain.findFirst({ where: { orgId, domain, verifiedAt: { not: null } }, select: { id: true } }))) return false;
    const s = await app.prisma.session.findUnique({ where: { id: req.auth.sessionId }, select: { ssoOrgIds: true } });
    const missing = !s?.ssoOrgIds.includes(orgId);
    if (missing && role === "owner") {
      // The owner's break-glass is allowed but never silent: one event per session and org.
      const k = `${req.auth.sessionId}:${orgId}`;
      if (!bypassLogged.has(k)) {
        if (bypassLogged.size > 50_000) bypassLogged.clear();
        bypassLogged.add(k);
        await logEvent(app.prisma, { orgId, actorId: req.auth.userId, action: "sso.bypass_owner", meta: { sessionId: req.auth.sessionId }, ip: req.ip });
      }
      return false;
    }
    return missing;
  }

  /**
   * IP allowlist (docs/policies.md): org-scoped requests only from the org's networks. The owner may keep a break-glass
   * path (on by default, only the owner turns it off); each session's first use of it is logged.
   */
  async function ipBlocked(req: FastifyRequest, orgId: string, role: OrgRole, raw: unknown): Promise<boolean> {
    const p = readPolicies(raw);
    if (ipAllowed(req.ip, p.ipAllowlist)) return false;
    if (role === "owner" && p.ownerBreakGlass) {
      const k = `ip:${req.auth.sessionId}:${orgId}`;
      if (!bypassLogged.has(k)) {
        if (bypassLogged.size > 50_000) bypassLogged.clear();
        bypassLogged.add(k);
        await logEvent(app.prisma, { orgId, actorId: req.auth.userId, action: "policy.ip_bypass_owner", meta: { sessionId: req.auth.sessionId }, ip: req.ip });
      }
      return false;
    }
    return true;
  }

  /** "none" when there is no header, "bad" when it doesn't name an org the caller is an active member of. */
  async function resolve(req: FastifyRequest): Promise<ActiveOrg | "none" | "bad" | "sso" | "ip"> {
    const raw = req.headers[ORG_HEADER];
    if (raw === undefined || raw === "") return "none";
    if (typeof raw !== "string" || !UUID.test(raw)) return "bad";
    // Checked on every request: a disable or a removal applies at once, whatever the access token says.
    const m = await app.prisma.membership.findFirst({ where: { orgId: raw.toLowerCase(), userId: req.auth.userId, status: "active", user: { status: "active" } },
      select: { orgId: true, role: true, adminSince: true, org: { select: { policies: true, sso: { select: { requireSso: true } } } }, user: { select: { email: true } } } });
    if (!m) return "bad";
    if (m.org.sso?.requireSso && await ssoMissing(req, m.orgId, m.role, m.user.email)) return "sso";
    if (await ipBlocked(req, m.orgId, m.role, m.org.policies)) return "ip";
    return { id: m.orgId, role: m.role, adminSince: m.adminSince };
  }

  const handler = (mode: "optional" | "required" | "admin") => async (req: FastifyRequest, reply: FastifyReply) => {
    if (reply.sent || !req.auth) return;
    const r = await resolve(req);
    if (r === "bad") { await reply.code(403).send({ error: "org_forbidden" }); return; }
    if (r === "ip") { await reply.code(403).send({ error: "ip_not_allowed", orgId: String(req.headers[ORG_HEADER]).toLowerCase() }); return; }
    if (r === "sso") { await reply.code(403).send({ error: "sso_required", orgId: String(req.headers[ORG_HEADER]).toLowerCase() }); return; }
    // A session that skipped the authenticator code (trusted IdP MFA) reaches that org only: other orgs and the
    // private vault (no header) need a TOTP step-up first.
    const skipped = req.auth.totpSkippedForOrg;
    if (skipped && (r === "none" || r.id !== skipped)) { await reply.code(403).send({ error: "totp_step_up_required" }); return; }
    if (r === "none") {
      if (mode !== "optional") { await reply.code(403).send({ error: "org_required" }); return; }
      req.org = null;
      return;
    }
    if (mode === "admin" && !isAdminRole(r.role)) { await reply.code(403).send({ error: "forbidden" }); return; }
    req.org = r;
  };
  app.decorate("orgOptional", handler("optional"));
  app.decorate("orgRequired", handler("required"));
  app.decorate("orgAdmin", handler("admin"));
}
