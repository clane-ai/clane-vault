import { randomBytes } from "node:crypto";
import { TRIAL_MS } from "./plans.js";
import type { FastifyInstance } from "fastify";
import type { Db } from "./access.js";
import { ownerInviteEmail, sendEmail } from "./email.js";
import { logEvent } from "./events.js";
import { coolingDown, INVITE_TTL_MS, inviteUrlFor, joinUrlFor, RESEND_MIN_INTERVAL_MS } from "./invites.js";
import { slugFor } from "./orgs.js";
import { hashToken } from "./tokens.js";

/**
 * Customer organisations (docs/provisioning.md, "Organisations for customers"): an instance admin creates an
 * organisation with no members and an owner invitation, so the operator never joins (or sees into) a customer's
 * organisation. The invitee becomes its only owner when they accept; their browser then makes their membership key on
 * first unlock there, as for any organisation (docs/design/2026-10-08-per-org-keypairs.md, 6.1).
 *
 * What the operator sees is what they typed: the name, the address and whether the invitation is pending, expired or
 * accepted. Never members, records or events.
 */

export type CustomerOrgStatus = "pending" | "expired" | "accepted";
export interface CustomerOrgView { id: string; name: string; ownerEmail: string; createdAt: string; status: CustomerOrgStatus; expiresAt: string | null }

type Log = { warn: (o: object, m: string) => void };

/** Its invitation stays an owner invitation (lib/invites keeps `role: owner` for this source only). */
export const CUSTOMER_SOURCE = "customer";

const select = {
  id: true, name: true, createdAt: true, customerOwnerEmail: true,
  _count: { select: { memberships: { where: { status: { in: ["active", "disabled"] as ("active" | "disabled")[] } } } } },
  memberships: { where: { status: "invited" as const }, select: { createdAt: true } },
  invites: { where: { acceptedAt: null }, select: { expiresAt: true } },
} as const;

function viewOf(o: { id: string; name: string; createdAt: Date; customerOwnerEmail: string | null; _count: { memberships: number };
  memberships: { createdAt: Date }[]; invites: { expiresAt: Date }[] }, now = Date.now()): CustomerOrgView {
  // An invitation to an existing account lasts as long as an invite link (from its date).
  const ends = [...o.invites.map((i) => i.expiresAt.getTime()), ...o.memberships.map((m) => m.createdAt.getTime() + INVITE_TTL_MS)];
  const last = ends.length ? Math.max(...ends) : null;
  const status: CustomerOrgStatus = o._count.memberships > 0 ? "accepted" : last !== null && last > now ? "pending" : "expired";
  return { id: o.id, name: o.name, ownerEmail: o.customerOwnerEmail ?? "", createdAt: o.createdAt.toISOString(), status,
    expiresAt: status !== "accepted" && last !== null ? new Date(last).toISOString() : null };
}

/** Every organisation created for a customer, newest first. */
export async function listCustomerOrgs(db: Db): Promise<CustomerOrgView[]> {
  const rows = await db.organization.findMany({ where: { customerOwnerEmail: { not: null } }, orderBy: { createdAt: "desc" }, select });
  return rows.map((o) => viewOf(o));
}

async function customerOrg(db: Db, id: string): Promise<CustomerOrgView | null> {
  const o = await db.organization.findFirst({ where: { id, customerOwnerEmail: { not: null } }, select });
  return o ? viewOf(o) : null;
}

/**
 * The owner invitation, written inside the caller's transaction: an invite link for an address without an account (and,
 * self-hosted, for every address: the operator can pass it on), and for an existing account an invitation to accept in
 * the app (HOSTED_MODE: only that, as for other invitations). Any older one for the address is replaced. Returns the token.
 */
async function writeOwnerInvitation(tx: Db, o: { orgId: string; email: string; actorId: string; existingId: string | null; hosted: boolean; now: Date; resendCount?: number }): Promise<string | null> {
  const token = !o.hosted || !o.existingId ? randomBytes(24).toString("base64url") : null;
  await tx.invite.deleteMany({ where: { orgId: o.orgId, email: o.email, acceptedAt: null } });
  if (token) await tx.invite.create({ data: { orgId: o.orgId, email: o.email, role: "owner", source: CUSTOMER_SOURCE, tokenHash: hashToken(token), invitedById: o.actorId,
    expiresAt: new Date(o.now.getTime() + INVITE_TTL_MS), lastSentAt: o.now, resendCount: o.resendCount ?? 0 } });
  if (o.existingId) {
    // Its 7 days start over on a resend.
    const n = await tx.membership.updateMany({ where: { orgId: o.orgId, userId: o.existingId, status: "invited" }, data: { createdAt: o.now, role: "owner" } });
    if (!n.count) await tx.membership.create({ data: { orgId: o.orgId, userId: o.existingId, role: "owner", status: "invited", invitedById: o.actorId, createdAt: o.now } });
  }
  return token;
}

/** The email, through the new organisation's settings (it has none, so the server's). */
async function sendOwnerInvite(app: FastifyInstance, org: { id: string; name: string }, email: string, existing: boolean, token: string | null, log: Log): Promise<{ emailed: boolean; inviteUrl: string | null }> {
  const inviteUrl = token ? (existing ? joinUrlFor(app, token) : inviteUrlFor(app, token)) : null;
  const emailed = await sendEmail(app.mail, email, ownerInviteEmail(await app.brand.productName(), org.name, inviteUrl ?? `${app.config.publicUrl}/`, existing), log, org.id);
  return { emailed, inviteUrl };
}

export type CreateResult = { ok: true; org: CustomerOrgView; emailed: boolean; inviteUrl: string | null } | { ok: false; error: "self" | "email_required" };

/**
 * Creates the organisation with no members and its owner invitation. Not limited by ALLOW_ORG_CREATION or
 * MAX_OWNED_ORGS (the operator owns nothing here); the invitee's MAX_OWNED_ORGS is checked when they accept.
 */
export async function createCustomerOrg(app: FastifyInstance, o: { name: string; ownerEmail: string; actorId: string; log: Log; meta?: { ip?: string; userAgent?: string } }): Promise<CreateResult> {
  const hosted = !!app.config.hostedMode;
  const email = o.ownerEmail.trim().toLowerCase();
  const existing = await app.prisma.user.findUnique({ where: { email }, select: { id: true } });
  // The operator would become a member of the customer's organisation: they create organisations for themselves in the app.
  if (existing?.id === o.actorId) return { ok: false, error: "self" };
  // HOSTED_MODE: invitations are only ever emailed, so there must be a way to send one.
  if (hosted && !(await app.mail.configured(null))) return { ok: false, error: "email_required" };
  const now = new Date();
  const { org, token } = await app.prisma.$transaction(async (tx) => {
    const org = await tx.organization.create({ data: { name: o.name, slug: slugFor(o.name), customerOwnerEmail: email, customerCreatedById: o.actorId, ...(app.config.billingMode === "hosted" ? { trialEndsAt: new Date(Date.now() + TRIAL_MS) } : {}) }, select: { id: true, name: true } });
    const token = await writeOwnerInvitation(tx, { orgId: org.id, email, actorId: o.actorId, existingId: existing?.id ?? null, hosted, now });
    // Its own log (the owner sees who set it up) and the instance's.
    await logEvent(tx, { orgId: org.id, actorId: o.actorId, action: "org.create", ...o.meta, meta: { for: "customer" } });
    await logEvent(tx, { orgId: org.id, actorId: o.actorId, action: "admin.invite", ...o.meta, meta: { role: "owner" } });
    await logEvent(tx, { actorId: o.actorId, action: "instance.customer_org_create", ...o.meta, meta: { orgId: org.id } });
    return { org, token };
  });
  const sent = await sendOwnerInvite(app, org, email, !!existing, token, o.log);
  return { ok: true, org: (await customerOrg(app.prisma, org.id))!, ...sent };
}

export type ResendResult = { ok: true; org: CustomerOrgView; emailed: boolean; inviteUrl: string | null } | { ok: false; error: "not_found" | "accepted" | "email_required" | "too_soon" | "invite_cooldown" };

/** A fresh 7 days and the email again (a link gets a new token). Not more than every 5 minutes. */
export async function resendCustomerInvite(app: FastifyInstance, orgId: string, actorId: string, log: Log, meta?: { ip?: string; userAgent?: string }): Promise<ResendResult> {
  const org = await app.prisma.organization.findFirst({ where: { id: orgId, customerOwnerEmail: { not: null } }, select: { id: true, name: true, customerOwnerEmail: true,
    invites: { where: { acceptedAt: null }, select: { lastSentAt: true, createdAt: true, resendCount: true } }, memberships: { where: { status: "invited" }, select: { createdAt: true } } } });
  if (!org) return { ok: false, error: "not_found" };
  if ((await customerOrg(app.prisma, orgId))!.status === "accepted") return { ok: false, error: "accepted" };
  const email = org.customerOwnerEmail!;
  const hosted = !!app.config.hostedMode;
  if (hosted && !(await app.mail.configured(null))) return { ok: false, error: "email_required" };
  // They declined (or it was cancelled before): the same cooldown as any invitation.
  if (await coolingDown(app.prisma, orgId, email)) return { ok: false, error: "invite_cooldown" };
  const sentAt = [...org.invites.map((i) => (i.lastSentAt ?? i.createdAt).getTime()), ...org.memberships.map((m) => m.createdAt.getTime())];
  if (sentAt.length && Date.now() - Math.max(...sentAt) < RESEND_MIN_INTERVAL_MS) return { ok: false, error: "too_soon" };
  // Looked up again: they may have made an account since.
  const existing = await app.prisma.user.findUnique({ where: { email }, select: { id: true } });
  const now = new Date();
  const token = await app.prisma.$transaction(async (tx) => {
    const token = await writeOwnerInvitation(tx, { orgId, email, actorId, existingId: existing?.id ?? null, hosted, now, resendCount: Math.max(0, ...org.invites.map((i) => i.resendCount)) + 1 });
    await logEvent(tx, { orgId, actorId, action: "admin.invite_resend", ...meta, meta: { role: "owner" } });
    await logEvent(tx, { actorId, action: "instance.customer_org_resend", ...meta, meta: { orgId } });
    return token;
  });
  const sent = await sendOwnerInvite(app, org, email, !!existing, token, log);
  return { ok: true, org: (await customerOrg(app.prisma, orgId))!, ...sent };
}

class Accepted extends Error {}

/**
 * Cancels the owner invitation and deletes the organisation, which never had a member. Race-safe against accepting:
 * the invitation rows are deleted first (waiting for an accept in progress), then nobody may have joined.
 */
export async function cancelCustomerOrg(app: FastifyInstance, orgId: string, actorId: string, meta?: { ip?: string; userAgent?: string }): Promise<{ ok: true } | { ok: false; error: "not_found" | "accepted" }> {
  try {
    const name = await app.prisma.$transaction(async (tx) => {
      const org = await tx.organization.findFirst({ where: { id: orgId, customerOwnerEmail: { not: null } }, select: { name: true } });
      if (!org) return null;
      await tx.invite.deleteMany({ where: { orgId, acceptedAt: null } });
      await tx.membership.deleteMany({ where: { orgId, status: "invited" } });
      if (await tx.membership.count({ where: { orgId } })) throw new Accepted();
      // As deleting an organisation: its events go with it (kept, they would show as organisation-less elsewhere).
      await tx.event.deleteMany({ where: { orgId } });
      await tx.organization.delete({ where: { id: orgId } });
      return org.name;
    });
    if (name === null) return { ok: false, error: "not_found" };
    await logEvent(app.prisma, { actorId, action: "instance.customer_org_cancel", ...meta, meta: { orgId, name } });
    return { ok: true };
  } catch (e) {
    if (e instanceof Accepted) return { ok: false, error: "accepted" };
    throw e;
  }
}
