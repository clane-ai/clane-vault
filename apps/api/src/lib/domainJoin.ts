import { randomBytes } from "node:crypto";
import type { FastifyInstance } from "fastify";
import type { Db } from "./access.js";
import { domainJoinEmail, sendInviteEmail, sendEmail } from "./email.js";
import { logEvent } from "./events.js";
import { addPendingGroups, coolingDown, INVITE_TTL_MS, inviteUrlFor, joinUrlFor, RESEND_MIN_INTERVAL_MS } from "./invites.js";
import { orgEntitlements } from "./plans.js";
import { assertSeat, SeatLimitError } from "./seats.js";
import { isPublicMailDomain } from "./publicMailDomains.js";
import { domainStillVerified, emailDomain, normalizeDomain } from "./sso.js";
import { hashToken } from "./tokens.js";

/**
 * Email domain auto-join (docs/provisioning.md), Keeper's "email auto-provisioning": the owner of an organisation with a
 * domain verified by DNS (the SSO domain verification) lets anyone with an address in it join as a member, into chosen
 * groups. Joining always goes through an emailed link (the address is proved by reading the mailbox), then the usual
 * sign-up with master password and authenticator, or, for an existing account, signing in and accepting.
 */

/** Requests a day per organisation (sends; on top of the admins' own invite cap). */
export const domainJoinCap = (app: FastifyInstance) => app.config.invitesPerOrgPerDay ?? 50;

export interface DomainJoinTarget { orgId: string; orgName: string; domain: string; role: "member" | "admin"; groupIds: string[] }

/**
 * The organisation an address may join by its domain, or null. The domain must be verified by exactly one organisation
 * (one org per domain: a second can't verify it, and if two ever had it, nobody gets in), that organisation must have
 * auto-join on, the TXT record must still be there (re-checked at most daily; fails closed), and public email providers
 * never count.
 */
export async function domainJoinTarget(app: FastifyInstance, email: string): Promise<DomainJoinTarget | null> {
  const domain = normalizeDomain(emailDomain(email));
  if (!domain || isPublicMailDomain(domain)) return null;
  const owners = await app.prisma.ssoDomain.findMany({ where: { domain, verifiedAt: { not: null } }, select: { orgId: true }, take: 2 });
  if (owners.length !== 1) return null;
  const orgId = owners[0]!.orgId;
  const cfg = await app.prisma.orgDomainJoin.findUnique({ where: { orgId }, select: { enabled: true, role: true, groupIds: true, org: { select: { name: true } } } });
  if (!cfg?.enabled) return null;
  // Before the DNS re-check, which would un-verify a stored domain: a Team org's rows stay as they are.
  if (!(await orgEntitlements(app.prisma, app.config, orgId)).features.domains) return null;
  if (!(await domainStillVerified(app.prisma, app.ssoDeps, orgId, domain))) return null;
  return { orgId, orgName: cfg.org.name, domain, role: cfg.role === "admin" ? "admin" : "member", groupIds: cfg.groupIds };
}

/** Switches auto-join off for an org that has no verified domain left (a domain removed or un-verified). */
export async function disableDomainJoinIfNoDomain(db: Db, orgId: string): Promise<void> {
  if (await db.ssoDomain.count({ where: { orgId, verifiedAt: { not: null } } })) return;
  const n = await db.orgDomainJoin.updateMany({ where: { orgId, enabled: true }, data: { enabled: false } });
  if (n.count) await logEvent(db, { orgId, action: "org.domain_join_disabled", meta: { reason: "no_verified_domain" } });
}

export type DomainJoinOutcome = "sent" | "ineligible" | "member" | "pending" | "too_soon" | "cooldown" | "limit" | "no_email" | "send_failed" | "seat_limit";

/**
 * Handles "join with my work email". The answer to the caller never depends on the outcome (no enumeration of
 * organisations, accounts or members); the outcome is for tests and logs. Nothing joins here: an invitation (source
 * "domain") is created and its link emailed. No account: the link signs up (HOSTED_MODE adds the emailed code). An
 * existing account: the link (/join/<token>) is claimed signed in, then accepted from the organisation menu.
 */
export async function requestDomainJoin(app: FastifyInstance, email: string, log: { warn: (o: object, m: string) => void }, meta: { ip?: string; userAgent?: string } = {}): Promise<DomainJoinOutcome> {
  const t = await domainJoinTarget(app, email);
  if (!t) return "ineligible";
  if (!(await app.mail.configured(t.orgId))) return "no_email";
  const user = await app.prisma.user.findUnique({ where: { email }, select: { id: true, status: true, memberships: { where: { orgId: t.orgId }, select: { status: true } } } });
  if (user?.status === "disabled") return "ineligible";
  // Already in (or disabled in, or invited to) the org: nothing new to send.
  if (user?.memberships.length) return "member";
  if (await coolingDown(app.prisma, t.orgId, email)) return "cooldown";
  const now = new Date();
  const open = await app.prisma.invite.findFirst({ where: { orgId: t.orgId, email, acceptedAt: null, expiresAt: { gt: now } }, select: { id: true, source: true, lastSentAt: true, createdAt: true } });
  // An admin's own invitation stands (its role and groups are the admin's choice).
  if (open && open.source !== "domain") return "pending";
  if (open && now.getTime() - (open.lastSentAt ?? open.createdAt).getTime() < RESEND_MIN_INTERVAL_MS) return "too_soon";
  const since = new Date(now.getTime() - 24 * 3600e3);
  if ((await app.prisma.event.count({ where: { orgId: t.orgId, action: "org.domain_join_request", at: { gt: since } } })) >= domainJoinCap(app)) return "limit";

  const token = randomBytes(24).toString("base64url");
  const full = await app.prisma.$transaction(async (tx) => {
    await assertSeat(tx, app.config, t.orgId, 1, email);
    await tx.invite.deleteMany({ where: { orgId: t.orgId, email, acceptedAt: null, source: "domain" } });
    await tx.invite.create({ data: { orgId: t.orgId, email, role: t.role, tokenHash: hashToken(token), invitedById: null, source: "domain", lastSentAt: now, expiresAt: new Date(now.getTime() + INVITE_TTL_MS) } });
    // Only groups that are still this org's.
    const groups = t.groupIds.length ? (await tx.group.findMany({ where: { orgId: t.orgId, id: { in: t.groupIds } }, select: { id: true } })).map((g) => g.id) : [];
    await addPendingGroups(tx, t.orgId, email, groups, null);
    return false;
  }).catch((e) => { if (e instanceof SeatLimitError) return true; throw e; }); // the caller still gets the same 202
  if (full) return "seat_limit";
  await logEvent(app.prisma, { orgId: t.orgId, action: "org.domain_join_request", meta: { domain: t.domain }, ...meta });
  const productName = await app.brand.productName();
  const sent = user
    ? await sendEmail(app.mail, email, domainJoinEmail(productName, t.orgName, joinUrlFor(app, token), true), log, t.orgId)
    : await sendInviteEmail(app.mail, productName, email, inviteUrlFor(app, token), log, { id: t.orgId, name: t.orgName });
  return sent ? "sent" : "send_failed";
}
