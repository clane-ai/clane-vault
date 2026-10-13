import type { PrismaClient } from "@prisma/client";

/** Failed sign-in proofs (password, 2FA, recovery code) share one counter per account: 10 in a row lock it for 15 minutes. */
export const LOCK_AFTER = 10;
export const LOCK_MS = 15 * 60 * 1000;

/** Seconds until the account unlocks, or 0 when it isn't locked. */
export const lockedFor = (u: { lockedUntil: Date | null }, now = Date.now()) =>
  u.lockedUntil && u.lockedUntil.getTime() > now ? Math.ceil((u.lockedUntil.getTime() - now) / 1000) : 0;

/** Counts one failure and locks the account when the counter reaches LOCK_AFTER (the counter then restarts). */
export async function registerFailure(prisma: PrismaClient, userId: string): Promise<void> {
  const updated = await prisma.user.update({ where: { id: userId }, data: { failedLogins: { increment: 1 } }, select: { failedLogins: true } });
  if (updated.failedLogins >= LOCK_AFTER)
    await prisma.user.updateMany({ where: { id: userId, failedLogins: { gte: LOCK_AFTER } }, data: { failedLogins: 0, lockedUntil: new Date(Date.now() + LOCK_MS) } });
}
