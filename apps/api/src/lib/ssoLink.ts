import type { FastifyInstance } from "fastify";
import { logEvent } from "./events.js";
import { lockUser } from "./orgs.js";
import { assertSeat, lockSeats } from "./seats.js";

export interface LinkInput { orgId: string; issuer: string; subject: string; email: string; jit: boolean }

/**
 * After a complete SSO sign-in (password and second factor done): the identity link (first time) and, just-in-time,
 * the membership. Never before the account's authenticator is set up.
 */
export async function linkAndJoin(app: FastifyInstance, p: LinkInput, user: { id: string }, log: { warn: (o: object, m: string) => void }, meta: { ip?: string; userAgent?: string } = {}) {
  // The membership goes first: a seat refusal (402) must leave no identity link behind.
  const joined = p.jit ? await app.prisma.$transaction(async (tx) => {
    await lockSeats(tx, app.config, p.orgId);
    await lockUser(tx, user.id);
    if (await tx.membership.findUnique({ where: { orgId_userId: { orgId: p.orgId, userId: user.id } }, select: { id: true } })) return null;
    await assertSeat(tx, app.config, p.orgId, 1, p.email);
    await tx.membership.create({ data: { orgId: p.orgId, userId: user.id, role: "member", status: "active", joinedAt: new Date() } });
    return true;
  }) : null;
  const existing = await app.prisma.ssoIdentity.findUnique({ where: { orgId_userId: { orgId: p.orgId, userId: user.id } } });
  if (existing) await app.prisma.ssoIdentity.updateMany({ where: { id: existing.id, issuer: p.issuer, subject: p.subject }, data: { lastLoginAt: new Date() } });
  else {
    await app.prisma.ssoIdentity.create({ data: { orgId: p.orgId, userId: user.id, issuer: p.issuer, subject: p.subject, email: p.email } }).catch(() => undefined);
    await logEvent(app.prisma, { orgId: p.orgId, actorId: user.id, action: "sso.identity_linked", targetUserId: user.id, ...meta });
  }
  if (joined) await logEvent(app.prisma, { orgId: p.orgId, actorId: user.id, action: "sso.jit_join", targetUserId: user.id, ...meta });
}
