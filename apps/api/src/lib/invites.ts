import { randomBytes } from "node:crypto";
import type { FastifyInstance } from "fastify";
import type { OrgRole } from "@prisma/client";
import type { Db } from "./access.js";
import { orgInvitationEmail, sendEmail, sendInviteEmail } from "./email.js";
import { logEvent } from "./events.js";
import { lockGroup, recomputeGroupFolders } from "./groups.js";
import { assertSeat } from "./seats.js";
import { hashToken } from "./tokens.js";

/** After a decline or a cancelled invitation, the same org can't invite that address again for this long. */
export const INVITE_COOLDOWN_MS = 24 * 3600e3;
/** Invitations (links and in-app ones) last a week. */
export const INVITE_TTL_MS = 7 * 24 * 3600e3;
/** The same invitation isn't sent again sooner than this (Resend, Resend all, a repeated domain auto-join request). */
export const RESEND_MIN_INTERVAL_MS = 5 * 60e3;
/** Events that count as one invitation email or link toward the org's daily cap (INVITES_PER_ORG_PER_DAY). */
export const INVITE_SEND_ACTIONS = ["admin.invite", "admin.invite_resend"];

type Log = { warn: (o: object, m: string) => void };

export async function coolDown(tx: Db, orgId: string, email: string, now = Date.now()) {
  const until = new Date(now + INVITE_COOLDOWN_MS);
  await tx.inviteCooldown.upsert({ where: { orgId_email: { orgId, email } }, create: { orgId, email, until }, update: { until } });
}

/** The org's daily invitation cap (INVITES_PER_ORG_PER_DAY, default 50). */
export const dailyInviteCap = (app: FastifyInstance) => app.config.invitesPerOrgPerDay ?? 50;

/** Invitations sent (new ones and resends) by the org's admins in the last 24 hours. */
export async function invitesSentToday(db: Db, orgId: string): Promise<number> {
  return db.event.count({ where: { orgId, action: { in: INVITE_SEND_ACTIONS }, at: { gt: new Date(Date.now() - 24 * 3600e3) } } });
}

/** Whether the address is cooling down after a decline or a cancelled invitation. */
export async function coolingDown(db: Db, orgId: string, email: string): Promise<boolean> {
  return !!(await db.inviteCooldown.findFirst({ where: { orgId, email, until: { gt: new Date() } }, select: { id: true } }));
}

/**
 * The role an invite link gives when it becomes an invitation to an existing account (claimed, or met at sign-up through
 * another organisation's link). An owner link (bootstrap) becomes admin, except a customer organisation's owner
 * invitation (lib/customerOrgs.ts): that one stays owner, and accepting it checks that the organisation still has no
 * owner and MAX_OWNED_ORGS.
 */
export const invitedRole = (inv: { role: OrgRole; source: string }): OrgRole => (inv.role === "owner" && inv.source !== "customer" ? "admin" : inv.role);

/** Invite and join links. `/join/<token>` is for someone who already has an account (they claim it signed in). */
export const inviteUrlFor = (app: FastifyInstance, token: string) => `${app.config.publicUrl}/invite/${token}`;
export const joinUrlFor = (app: FastifyInstance, token: string) => `${app.config.publicUrl}/join/${token}`;

/** Group memberships waiting for an invited address (they join the groups when they join the org). */
export async function addPendingGroups(tx: Db, orgId: string, email: string, groupIds: string[], addedBy: string | null): Promise<void> {
  if (!groupIds.length) return;
  await tx.pendingGroupMember.createMany({ data: [...new Set(groupIds)].map((groupId) => ({ orgId, groupId, email, addedBy })), skipDuplicates: true });
}

/** Drops the address's waiting group memberships in the org (a revoked or declined invitation, or offboarding). */
export async function dropPendingGroups(tx: Db, orgId: string, email: string): Promise<void> {
  await tx.pendingGroupMember.deleteMany({ where: { orgId, email } });
}

/**
 * Someone joined the org: their waiting group memberships become real ones, exactly as if an admin had added them now
 * (docs/groups.md). That gives NO folder key: each folder shared with the group still waits for a key holder (owner or
 * editor) to approve them explicitly. Run inside the transaction that activates the membership. Returns the group ids.
 */
export async function applyPendingGroups(tx: Db, orgId: string, userId: string, email: string): Promise<string[]> {
  const rows = await tx.pendingGroupMember.findMany({ where: { orgId, email, group: { orgId } }, select: { groupId: true, addedBy: true }, orderBy: { groupId: "asc" } });
  const added: string[] = [];
  for (const r of rows) {
    await lockGroup(tx, r.groupId);
    const n = await tx.groupMember.createMany({ data: [{ groupId: r.groupId, userId, addedBy: r.addedBy }], skipDuplicates: true });
    if (!n.count) continue;
    const folders = (await tx.folderGroup.findMany({ where: { groupId: r.groupId }, select: { folderId: true } })).map((f) => f.folderId);
    if (folders.length) await tx.groupAccessDecline.deleteMany({ where: { folderId: { in: folders }, userId } });
    await recomputeGroupFolders(tx, folders, [userId]);
    await logEvent(tx, { orgId, actorId: r.addedBy ?? undefined, action: "group.member_add", targetUserId: userId, meta: { groupId: r.groupId, via: "invite" } });
    added.push(r.groupId);
  }
  await dropPendingGroups(tx, orgId, email);
  return added;
}

/**
 * Sends one new invitation (an admin's, one by one or in bulk), after the caller's checks (cap, cooldown, duplicates).
 * The same behaviour whoever the address belongs to: self-hosted, a link (returned once); HOSTED_MODE, a link only for
 * addresses without an account and only by email. An existing account gets an invitation to accept in the app.
 * `already`: the address is already a member (nothing is created and no email goes out, as POST /admin/invites does).
 */
export async function sendNewInvite(app: FastifyInstance, o: {
  org: { id: string; name: string }; actorId: string; email: string; role: "admin" | "member"; groupIds?: string[]; nameHint?: string | null; bulk?: boolean; log: Log;
}): Promise<{ already: boolean; emailed: boolean; inviteUrl: string | null }> {
  const hosted = !!app.config.hostedMode;
  const existing = await app.prisma.user.findUnique({ where: { email: o.email }, select: { id: true, memberships: { where: { orgId: o.org.id }, select: { status: true } } } });
  const already = !!existing?.memberships.length;
  // Demo mode (docs/demo.md): sandboxes never reach each other. An address with an account elsewhere (another visitor's)
  // gets nothing: no invitation in their app, no link. The answer looks like any other invite's.
  if (app.config.demo && existing && !already) return { already: false, emailed: false, inviteUrl: null };
  const makeLink = !hosted || !existing;
  const token = makeLink ? randomBytes(24).toString("base64url") : null;
  const now = new Date();
  await app.prisma.$transaction(async (tx) => {
    if (!already) await assertSeat(tx, app.config, o.org.id, 1, o.email);
    if (token) {
      // One live invite per address and org: a new one replaces any pending one.
      await tx.invite.deleteMany({ where: { email: o.email, orgId: o.org.id, acceptedAt: null } });
      await tx.invite.create({ data: { orgId: o.org.id, email: o.email, role: o.role, tokenHash: hashToken(token), invitedById: o.actorId, expiresAt: new Date(now.getTime() + INVITE_TTL_MS),
        source: "admin", nameHint: o.nameHint ?? null, lastSentAt: now } });
    }
    if (existing && !already) await tx.membership.create({ data: { orgId: o.org.id, userId: existing.id, role: o.role, status: "invited", invitedById: o.actorId } });
    if (!already) await addPendingGroups(tx, o.org.id, o.email, o.groupIds ?? [], o.actorId);
  });
  const inviteUrl = token ? inviteUrlFor(app, token) : null;
  if (already) return { already, emailed: await app.mail.configured(o.org.id), inviteUrl };
  const productName = await app.brand.productName();
  let emailed: boolean;
  if (existing) {
    const inviter = await app.prisma.user.findUnique({ where: { id: o.actorId }, select: { name: true } });
    emailed = await sendEmail(app.mail, o.email, orgInvitationEmail(productName, o.org.name, inviter?.name ?? "An admin", `${app.config.publicUrl}/`), o.log, o.org.id);
  } else emailed = await sendInviteEmail(app.mail, productName, o.email, inviteUrl!, o.log, o.org);
  await logEvent(app.prisma, { orgId: o.org.id, actorId: o.actorId, action: "admin.invite", meta: { role: o.role, ...(o.bulk ? { bulk: true } : {}), ...(o.groupIds?.length ? { groups: o.groupIds.length } : {}) } });
  return { already, emailed, inviteUrl };
}

export type ResendError = "not_found" | "email_required" | "too_soon" | "invite_limit";
export type ResendResult = { ok: true; id: string; email: string; emailed: boolean; inviteUrl?: string } | { ok: false; error: ResendError };

/**
 * Sends a pending (or expired) invitation again: its expiry starts over (7 days), a link gets a new token (the old link
 * stops working), and the email goes out again. `inviteId` is an id from GET /admin/invites (an invite link, or an
 * invitation to an existing account). Counts toward the daily cap; not more often than every 5 minutes per invitation.
 * Self-hosted: the new link comes back (shown once), as for a new invite. Signature kept stable: other features call it.
 */
export async function resendInvite(app: FastifyInstance, orgId: string, inviteId: string, actorId: string, log?: Log): Promise<ResendResult> {
  const lg: Log = log ?? app.log;
  const row = await app.prisma.invite.findFirst({ where: { id: inviteId, orgId, acceptedAt: null }, select: { id: true, email: true, role: true, lastSentAt: true, createdAt: true, expiresAt: true } });
  const m = row ? null : await app.prisma.membership.findFirst({ where: { id: inviteId, orgId, status: "invited" }, select: { role: true, createdAt: true, user: { select: { email: true } } } });
  const email = row?.email ?? m?.user.email;
  if (!email) return { ok: false, error: "not_found" };
  const role: OrgRole = row?.role === "owner" ? "admin" : (row?.role ?? m!.role);
  const hosted = !!app.config.hostedMode;
  if (hosted && !(await app.mail.configured(orgId))) return { ok: false, error: "email_required" };
  const lastSent = row ? (row.lastSentAt ?? row.createdAt) : m!.createdAt;
  if (Date.now() - lastSent.getTime() < RESEND_MIN_INTERVAL_MS) return { ok: false, error: "too_soon" };
  if ((await invitesSentToday(app.prisma, orgId)) >= dailyInviteCap(app)) return { ok: false, error: "invite_limit" };

  const org = await app.prisma.organization.findUniqueOrThrow({ where: { id: orgId }, select: { id: true, name: true } });
  const existing = await app.prisma.user.findUnique({ where: { email }, select: { id: true, memberships: { where: { orgId }, select: { status: true } } } });
  // Joined (or disabled) since: nothing to resend.
  if (existing?.memberships.some((x) => x.status !== "invited")) return { ok: false, error: "not_found" };
  // Demo mode: never an invitation to another sandbox's account (as sendNewInvite).
  if (app.config.demo && existing) return { ok: false, error: "not_found" };
  const makeLink = !hosted || !existing;
  const token = makeLink ? randomBytes(24).toString("base64url") : null;
  const now = new Date();
  const id = await app.prisma.$transaction(async (tx) => {
    // A live invitation already holds its seat; an expired one needs one again.
    if (!(row ? row.expiresAt > now : m!.createdAt.getTime() + INVITE_TTL_MS > now.getTime())) await assertSeat(tx, app.config, orgId, 1, email);
    let id = inviteId;
    if (token) {
      const fresh = { tokenHash: hashToken(token), expiresAt: new Date(now.getTime() + INVITE_TTL_MS), lastSentAt: now,
        emailCodeHash: null, emailCodeExpiresAt: null, emailCodeAttempts: 0, emailCodeTotalAttempts: 0, emailCodeIssues: 0 };
      const cur = row ?? (await tx.invite.findFirst({ where: { orgId, email, acceptedAt: null }, select: { id: true } }));
      if (cur) { await tx.invite.update({ where: { id: cur.id }, data: { ...fresh, resendCount: { increment: 1 } } }); id = cur.id; }
      else id = (await tx.invite.create({ data: { orgId, email, role, invitedById: actorId, source: "admin", ...fresh, resendCount: 1 } })).id;
    }
    // An invitation to an existing account lasts 7 days from its date: it starts over.
    if (existing) {
      if (existing.memberships.length) await tx.membership.updateMany({ where: { orgId, userId: existing.id, status: "invited" }, data: { createdAt: now } });
      else await tx.membership.create({ data: { orgId, userId: existing.id, role, status: "invited", invitedById: actorId } });
    }
    return id;
  });
  const productName = await app.brand.productName();
  let emailed: boolean;
  if (existing) {
    const inviter = await app.prisma.user.findUnique({ where: { id: actorId }, select: { name: true } });
    emailed = await sendEmail(app.mail, email, orgInvitationEmail(productName, org.name, inviter?.name ?? "An admin", token ? joinUrlFor(app, token) : `${app.config.publicUrl}/`), lg, orgId);
  } else emailed = await sendInviteEmail(app.mail, productName, email, inviteUrlFor(app, token!), lg, org);
  await logEvent(app.prisma, { orgId, actorId, action: "admin.invite_resend" });
  return { ok: true, id, email, emailed, ...(!hosted && token ? { inviteUrl: inviteUrlFor(app, token) } : {}) };
}
