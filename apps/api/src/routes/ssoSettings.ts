import type { FastifyPluginAsync, FastifyRequest } from "fastify";
import { randomUUID } from "node:crypto";
import { z } from "zod";
import { logEvent } from "../lib/events.js";
import { last4 } from "../lib/settingsBox.js";
import {
  checkIssuerUrl, clientSecretAad, describeOidcError, normalizeDomain, openClientSecret, randomToken, redirectUri, SsoConfigError,
  testConnection, txtHasToken, VERIFY_PREFIX,
} from "../lib/sso.js";
import { isPublicMailDomain } from "../lib/publicMailDomains.js";
import { sendEmail, ssoChangedEmail } from "../lib/email.js";
import { assertPublicHost, PrivateHostError } from "../lib/netGuard.js";
import { disableDomainJoinIfNoDomain } from "../lib/domainJoin.js";

const body = z.object({
  issuer: z.string().trim().max(500),
  clientId: z.string().trim().min(1).max(500),
  /** Replaces the stored secret. Omitted: keep it. */
  clientSecret: z.string().min(1).max(2048).optional(),
  requireSso: z.boolean().default(false),
  trustIdpMfa: z.boolean().default(false),
  autoJoin: z.boolean().default(false),
});
const domainParam = z.object({ domain: z.string().max(260) });

/**
 * /admin/settings/sso: the active org's single sign-on (its owners and admins; registered in the org-admin group).
 * The client secret is write-only. Domains are verified with a DNS TXT record before just-in-time joining or
 * "Require SSO" apply to them.
 */
export const ssoSettingsRoutes: FastifyPluginAsync = async (app) => {
  const orgOf = (req: FastifyRequest) => req.org!.id;
  const meta = (req: FastifyRequest) => ({ ip: req.ip, userAgent: String(req.headers["user-agent"] ?? "").slice(0, 300) });

  async function view(orgId: string) {
    const [row, domains, org, links] = await Promise.all([
      app.prisma.orgSso.findUnique({ where: { orgId } }),
      app.prisma.ssoDomain.findMany({ where: { orgId }, orderBy: { domain: "asc" } }),
      app.prisma.organization.findUniqueOrThrow({ where: { id: orgId }, select: { slug: true } }),
      app.prisma.ssoIdentity.count({ where: { orgId } }),
    ]);
    const by = row?.updatedById ? await app.prisma.user.findUnique({ where: { id: row.updatedById }, select: { id: true, name: true } }) : null;
    return {
      config: row ? { issuer: row.issuer, clientId: row.clientId, clientSecret: { set: !!row.clientSecretEnc, last4: row.clientSecretLast4 },
        requireSso: row.requireSso, trustIdpMfa: row.trustIdpMfa, autoJoin: row.autoJoin, updatedAt: row.updatedAt.toISOString(), updatedBy: by } : null,
      domains: domains.map((d) => ({ domain: d.domain, verified: !!d.verifiedAt, verifiedAt: d.verifiedAt?.toISOString() ?? null,
        txtRecord: { name: d.domain, value: `${VERIFY_PREFIX}${d.token}` } })),
      redirectUri: redirectUri(app.config), orgSlug: org.slug, scopes: "openid email profile", linkedAccounts: links,
    };
  }
  async function checkIssuer(issuer: string) {
    const u = checkIssuerUrl(app.config, issuer);
    if (app.config.hostedMode) await assertPublicHost(u.hostname);
  }
  const issuerError = (e: unknown) => (e instanceof SsoConfigError ? e.code : e instanceof PrivateHostError ? "private_host" : "issuer_invalid");

  const isOwner = (req: FastifyRequest) => req.org!.role === "owner";
  /** Owners and admins hear about security-relevant SSO changes, through the server's own email (never the org's). */
  async function tellAdmins(req: FastifyRequest, what: string[]) {
    const orgId = orgOf(req);
    const [org, actor, admins] = await Promise.all([
      app.prisma.organization.findUniqueOrThrow({ where: { id: orgId }, select: { name: true } }),
      app.prisma.user.findUniqueOrThrow({ where: { id: req.auth.userId }, select: { name: true } }),
      app.prisma.user.findMany({ where: { status: "active", memberships: { some: { orgId, status: "active", role: { in: ["owner", "admin"] } } } }, select: { email: true } }),
    ]);
    for (const a of admins) void sendEmail(app.mail, a.email, ssoChangedEmail(await app.brand.productName(), org.name, actor.name, what), req.log);
  }

  app.get("/", async (req) => view(orgOf(req)));

  app.put("/", { config: { rateLimit: { max: 20, timeWindow: "1 minute" } } }, async (req, reply) => {
    const b = body.parse(req.body);
    const orgId = orgOf(req);
    const issuer = b.issuer.replace(/\/+$/, "");
    try { await checkIssuer(issuer); } catch (e) { return reply.code(400).send({ error: issuerError(e) }); }
    const cur = await app.prisma.orgSso.findUnique({ where: { orgId } });
    if (!b.clientSecret && !cur?.clientSecretEnc) return reply.code(400).send({ error: "secret_required" });
    // Who the org trusts and how much: the owner only (setting it up, the issuer, Require SSO, trusting the IdP's MFA).
    const sensitive = !cur ? ["created"] : [...(cur.issuer !== issuer ? ["issuer"] : []), ...(cur.requireSso !== b.requireSso ? ["requireSso"] : []), ...(cur.trustIdpMfa !== b.trustIdpMfa ? ["trustIdpMfa"] : [])];
    if (sensitive.length && !isOwner(req)) return reply.code(403).send({ error: "owner_only" });
    // "Require SSO" and just-in-time joining only make sense (and only apply) for verified domains.
    if ((b.requireSso || b.autoJoin) && !(await app.prisma.ssoDomain.count({ where: { orgId, verifiedAt: { not: null } } }))) return reply.code(409).send({ error: "domain_not_verified" });
    const id = cur?.id ?? randomUUID();
    const data = {
      issuer, clientId: b.clientId, requireSso: b.requireSso, trustIdpMfa: b.trustIdpMfa, autoJoin: b.autoJoin, updatedById: req.auth.userId,
      ...(b.clientSecret ? { clientSecretEnc: app.settingsBox.seal(b.clientSecret, clientSecretAad({ id, orgId })), clientSecretLast4: last4(b.clientSecret) } : {}),
    };
    const changed = cur ? (["issuer", "clientId", "requireSso", "trustIdpMfa", "autoJoin"] as const).filter((k) => data[k] !== cur[k]) as string[] : ["created"];
    if (cur && b.clientSecret) changed.push("clientSecret");
    await app.prisma.$transaction(async (tx) => {
      await tx.orgSso.upsert({ where: { orgId }, create: { id, orgId, ...data }, update: data });
      // Another identity provider: subjects from the old one mean nothing now.
      if (cur && cur.issuer !== issuer) await tx.ssoIdentity.deleteMany({ where: { orgId } });
    });
    if (cur) app.oidc.forget(cur.issuer);
    await logEvent(app.prisma, { orgId, actorId: req.auth.userId, action: "sso.settings_updated", meta: { changed, issuer }, ...meta(req) });
    if (changed.length) await tellAdmins(req, changed);
    return view(orgId);
  });

  app.delete("/", async (req, reply) => {
    if (!isOwner(req)) return reply.code(403).send({ error: "owner_only" });
    const orgId = orgOf(req);
    const n = await app.prisma.$transaction(async (tx) => {
      const d = await tx.orgSso.deleteMany({ where: { orgId } });
      await tx.ssoIdentity.deleteMany({ where: { orgId } });
      return d.count;
    });
    if (n) { await logEvent(app.prisma, { orgId, actorId: req.auth.userId, action: "sso.settings_removed", ...meta(req) }); await tellAdmins(req, ["removed"]); }
    return view(orgId);
  });

  /** Discovery, metadata and a client-credentials sanity check against the saved settings (or the ones in the body). */
  app.post("/test", { config: { rateLimit: { max: 10, timeWindow: "1 minute" } } }, async (req, reply) => {
    const orgId = orgOf(req);
    const b = z.object({ issuer: z.string().trim().max(500).optional(), clientId: z.string().trim().max(500).optional(), clientSecret: z.string().max(2048).optional() }).parse(req.body ?? {});
    const cur = await app.prisma.orgSso.findUnique({ where: { orgId } });
    const issuer = (b.issuer || cur?.issuer || "").replace(/\/+$/, "");
    const clientId = b.clientId || cur?.clientId || "";
    if (!issuer || !clientId) return reply.code(409).send({ error: "not_configured" });
    try { await checkIssuer(issuer); } catch (e) { return { ok: false, checks: [{ name: "discovery", ok: false, detail: describeOidcError(e) }] }; }
    // The stored secret only goes to the stored issuer and client: testing anything else needs the secret typed in.
    const sameClient = !!cur && cur.issuer === issuer && cur.clientId === clientId;
    if (!b.clientSecret && !sameClient) return reply.code(400).send({ error: "secret_required" });
    const secret = b.clientSecret || (cur && openClientSecret(app.settingsBox, cur)) || null;
    const checks = await testConnection(app.oidc, app.config, issuer, clientId, secret);
    const ok = checks.every((c) => c.ok);
    await logEvent(app.prisma, { orgId, actorId: req.auth.userId, action: "sso.test", meta: { ok, failed: checks.filter((c) => !c.ok).map((c) => c.name) }, ...meta(req) });
    return { ok, checks };
  });

  app.post("/domains", { config: { rateLimit: { max: 20, timeWindow: "1 minute" } } }, async (req, reply) => {
    const d = normalizeDomain(z.object({ domain: z.string().max(260) }).parse(req.body).domain);
    if (!d) return reply.code(400).send({ error: "invalid_domain" });
    if (isPublicMailDomain(d)) return reply.code(400).send({ error: "public_domain" });
    const orgId = orgOf(req);
    if ((await app.prisma.ssoDomain.count({ where: { orgId } })) >= 20) return reply.code(409).send({ error: "domain_limit" });
    const created = await app.prisma.ssoDomain.upsert({ where: { orgId_domain: { orgId, domain: d } }, create: { orgId, domain: d, token: randomToken(18) }, update: {} });
    await logEvent(app.prisma, { orgId, actorId: req.auth.userId, action: "sso.domain_added", meta: { domain: created.domain }, ...meta(req) });
    return reply.code(201).send(await view(orgId));
  });

  app.delete("/domains/:domain", async (req, reply) => {
    const d = normalizeDomain(domainParam.parse(req.params).domain);
    const orgId = orgOf(req);
    if (!d) return reply.code(404).send({ error: "not_found" });
    const n = await app.prisma.ssoDomain.deleteMany({ where: { orgId, domain: d } });
    if (!n.count) return reply.code(404).send({ error: "not_found" });
    // Without a verified domain, "Require SSO", just-in-time joining and email domain auto-join can't apply: switch them off.
    if (!(await app.prisma.ssoDomain.count({ where: { orgId, verifiedAt: { not: null } } }))) await app.prisma.orgSso.updateMany({ where: { orgId }, data: { requireSso: false, autoJoin: false } });
    await disableDomainJoinIfNoDomain(app.prisma, orgId);
    await logEvent(app.prisma, { orgId, actorId: req.auth.userId, action: "sso.domain_removed", meta: { domain: d }, ...meta(req) });
    return view(orgId);
  });

  /** Looks for `clane-vault-verify=<token>` in the domain's TXT records. */
  app.post("/domains/:domain/verify", { config: { rateLimit: { max: 10, timeWindow: "1 minute" } } }, async (req, reply) => {
    const d = normalizeDomain(domainParam.parse(req.params).domain);
    const orgId = orgOf(req);
    const row = d ? await app.prisma.ssoDomain.findUnique({ where: { orgId_domain: { orgId, domain: d } } }) : null;
    if (!row) return reply.code(404).send({ error: "not_found" });
    // One organisation per domain: whoever verified it first keeps it (until they remove it).
    if (await app.prisma.ssoDomain.findFirst({ where: { domain: row.domain, orgId: { not: orgId }, verifiedAt: { not: null } }, select: { id: true } }))
      return reply.code(409).send({ error: "domain_taken" });
    const found = await txtHasToken(app.ssoDeps, row.domain, row.token);
    if (found === "error") return reply.code(502).send({ error: "dns_failed", detail: "The DNS lookup failed or timed out. Try again." });
    const expected = `${VERIFY_PREFIX}${row.token}`;
    if (found === "no") {
      await logEvent(app.prisma, { orgId, actorId: req.auth.userId, action: "sso.domain_verify_failed", meta: { domain: row.domain }, ...meta(req) });
      return reply.code(409).send({ error: "txt_not_found", detail: `No TXT record "${expected}" on ${row.domain} yet. DNS changes can take a while to show.` });
    }
    await app.prisma.ssoDomain.update({ where: { id: row.id }, data: { checkedAt: new Date() } });
    if (!row.verifiedAt) {
      await app.prisma.ssoDomain.update({ where: { id: row.id }, data: { verifiedAt: new Date() } });
      await logEvent(app.prisma, { orgId, actorId: req.auth.userId, action: "sso.domain_verified", meta: { domain: row.domain }, ...meta(req) });
    }
    return view(orgId);
  });
};
