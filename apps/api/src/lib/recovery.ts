import type { Prisma, PrismaClient } from "@prisma/client";
import { createHash, timingSafeEqual } from "node:crypto";
import type { Config } from "../config.js";
import type { Db } from "./access.js";
import { logEvent } from "./events.js";
import { getEntitlements, PLAN_SELECT, type OrgPlanFields } from "./plans.js";

/** An approved admin recovery link works for 24 hours, once. */
export const RECOVERY_LINK_TTL_MS = 24 * 3600e3;
/** A request nobody acted on lapses after 7 days. */
export const RECOVERY_REQUEST_TTL_MS = 7 * 24 * 3600e3;
/** Wrong link proofs before the request is burned. */
export const MAX_PROOF_ATTEMPTS = 5;

/**
 * Server form of a client-derived 256-bit value (recovery-kit auth value, admin-link proof). The input is already a
 * uniformly random HKDF output, so a plain SHA-256 is enough; the server can check it but learns nothing usable.
 */
export const hashSecretValue = (v: string) => createHash("sha256").update(v, "utf8").digest("hex");
export function secretValueMatches(storedHex: string | null | undefined, given: string): boolean {
  // Compare against a fixed dummy when there is nothing stored, so timing doesn't tell "no kit" from "wrong code".
  const a = Buffer.from(storedHex ?? "0".repeat(64), "hex"), b = Buffer.from(hashSecretValue(given), "hex");
  return a.length === b.length && timingSafeEqual(a, b) && !!storedHex;
}

/** What a burned request keeps: nothing that could unwrap a key or prove a link. */
export const BURN_REQUEST = { wrappedMembershipKey: null, proofHash: null } as const;

/** Whether this organisation's admin recovery is on (no org: whether any organisation has it on). */
export async function adminRecoveryEnabled(prisma: Db, cfg: Pick<Config, "billingMode">, orgId?: string): Promise<boolean> {
  if (orgId) { const o = await prisma.organization.findUnique({ where: { id: orgId }, select: { ...PLAN_SELECT, adminRecoveryEnabled: true } }); return !!o && adminRecoveryOn(cfg, o); }
  return (await prisma.organization.findMany({ where: { adminRecoveryEnabled: true }, select: PLAN_SELECT })).some((o) => adminRecoveryOn(cfg, { ...o, adminRecoveryEnabled: true }));
}
/** The stored flag counts only while the plan includes admin recovery (a downgrade leaves the flag, and the escrows, alone). */
export const adminRecoveryOn = (cfg: Pick<Config, "billingMode">, o: OrgPlanFields & { adminRecoveryEnabled: boolean }) => o.adminRecoveryEnabled && getEntitlements(cfg, o).features.adminRecovery;

/** When this account became an admin (or owner) of the org, if it still is an active one there. */
export async function adminSinceIn(prisma: Db, orgId: string, userId: string | null): Promise<{ adminSince: Date | null } | null> {
  if (!userId) return null;
  return prisma.membership.findFirst({ where: { orgId, userId, status: "active", role: { in: ["owner", "admin"] } }, select: { adminSince: true } });
}

/** Open requests (pending or approved) are the ones that can still lead somewhere. */
export const OPEN: Prisma.RecoveryRequestWhereInput = { status: { in: ["pending", "approved"] } };

/** Ends every open request of these users (or all users), burning the material. Returns how many ended. */
export async function expireOpenRequests(db: Db, where: Prisma.RecoveryRequestWhereInput = {}): Promise<{ id: string; userId: string; orgId: string }[]> {
  const open = await db.recoveryRequest.findMany({ where: { ...OPEN, ...where }, select: { id: true, userId: true, orgId: true } });
  if (open.length) await db.recoveryRequest.updateMany({ where: { id: { in: open.map((r) => r.id) }, ...OPEN }, data: { status: "expired", ...BURN_REQUEST } });
  return open;
}

/** Lapses approved links past their 24 h and pending requests past 7 days. Run on an interval and before listing. */
export async function sweepRecoveryRequests(prisma: PrismaClient, now = new Date()): Promise<number> {
  const ended = await expireOpenRequests(prisma, { OR: [
    { status: "approved", expiresAt: { lte: now } },
    { status: "pending", createdAt: { lte: new Date(now.getTime() - RECOVERY_REQUEST_TTL_MS) } },
  ] });
  for (const r of ended) await logEvent(prisma, { orgId: r.orgId, action: "recovery.request_expired", targetUserId: r.userId, meta: { requestId: r.id } });
  return ended.length;
}

/**
 * Admin recovery with a reset 2FA (docs/recovery.md): when the member's authenticator is gone (pending_2fa) or was set
 * up again only after the approval (i.e. through the link), the link would be the only factor. Then the 2FA reset and
 * the approval must come from two different admins, and the link may only start a new authenticator setup after a
 * waiting period since the reset.
 */
export function linkIsOnlyFactor(user: { status: string; totpEnabledAt: Date | null }, request: { approvedAt: Date | null }): boolean {
  if (user.status === "pending_2fa") return true;
  return !!user.totpEnabledAt && !!request.approvedAt && user.totpEnabledAt > request.approvedAt;
}
export const twoPersonOk = (user: { totpResetBy: string | null }, request: { approvedBy: string | null }) =>
  !!user.totpResetBy && !!request.approvedBy && user.totpResetBy !== request.approvedBy;
/** Seconds left before a reset account may set up a new authenticator through an admin link (0 = now). */
export function resetDelayLeft(user: { totpResetAt: Date | null }, delayHours: number, now = Date.now()): number {
  if (!user.totpResetAt) return 0;
  const until = user.totpResetAt.getTime() + delayHours * 3600e3;
  return until > now ? Math.ceil((until - now) / 1000) : 0;
}

/**
 * The approver of a reset for an account whose 2FA was reset must have been an admin since at least `minAgeDays`
 * before that reset (no sock-puppet admin invited for the occasion).
 */
export function approverOldEnough(approver: { adminSince: Date | null } | null, user: { totpResetAt: Date | null }, minAgeDays: number): boolean {
  if (!approver?.adminSince || !user.totpResetAt) return false;
  return approver.adminSince.getTime() <= user.totpResetAt.getTime() - minAgeDays * 864e5;
}
