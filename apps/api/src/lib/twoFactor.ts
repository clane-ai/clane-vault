import type { PrismaClient } from "@prisma/client";
import type { Db } from "./access.js";
import { sendEmail, twoFactorResetEmail } from "./email.js";
import { logEvent } from "./events.js";
import type { Mailer } from "./mailer.js";

type Log = { warn: (o: object, m: string) => void };

/**
 * Clears an account's authenticator: back to `pending_2fa` (a new authenticator is set up at the next sign-in) and every
 * session revoked. `by`: who reset it (null from the operator's CLI). Admin recovery reads `totpResetBy`/`totpResetAt`:
 * while the authenticator is being set up again, a recovery link needs a second admin and a waiting period
 * (docs/recovery.md); with no resetter recorded, no admin can be the second one, so a link waits for the new authenticator.
 */
export async function clearTwoFactor(tx: Db, userId: string, by: string | null, at: Date): Promise<void> {
  await tx.user.update({ where: { id: userId }, data: { status: "pending_2fa", totpSecretEnc: null, totpLastStep: null, totpEnabledAt: null, totpResetBy: by, totpResetAt: at } });
  await tx.session.updateMany({ where: { userId, revokedAt: null }, data: { revokedAt: at } });
}

export type InstanceResetResult = { ok: true; user: { id: string; email: string; name: string }; emailed: boolean } | { ok: false; error: "not_found" | "self" | "disabled" | "is_agent" };

/**
 * The instance-level authenticator reset by email address (docs/recovery.md, "Organisations"): the instance admin's
 * route (`actorId` set) and the operator's CLI (`actorId` null). The only reset that reaches an organisation owner, so
 * it lives outside every organisation: an `instance.reset_2fa` event (no organisation), and the person is emailed with
 * the instance's settings (never an organisation's, so no organisation's admins can silence it).
 */
export async function resetTwoFactorByEmail(deps: { prisma: PrismaClient; mail: Mailer; productName: () => Promise<string> },
  o: { email: string; actorId: string | null; log: Log; at?: Date; ip?: string; userAgent?: string }): Promise<InstanceResetResult> {
  const email = o.email.trim().toLowerCase();
  const user = await deps.prisma.user.findUnique({ where: { email }, select: { id: true, email: true, name: true, status: true, kind: true } });
  if (!user) return { ok: false, error: "not_found" };
  // Agents are not people: no authenticator, no sign-in (docs/agents.md).
  if (user.kind === "agent") return { ok: false, error: "is_agent" };
  // Your own authenticator is never reset from your own (signed-in, so working) session: that would make a stolen session
  // into a takeover. The operator's CLI is the way for a locked-out instance admin.
  if (user.id === o.actorId) return { ok: false, error: "self" };
  // As the organisation route: a disabled account stays as it is (it can't sign in to set one up anyway).
  if (user.status === "disabled") return { ok: false, error: "disabled" };
  const at = o.at ?? new Date();
  await deps.prisma.$transaction(async (tx) => {
    await clearTwoFactor(tx, user.id, o.actorId, at);
    await logEvent(tx, { actorId: o.actorId ?? undefined, action: "instance.reset_2fa", targetUserId: user.id, ip: o.ip, userAgent: o.userAgent, meta: { via: o.actorId ? "app" : "cli" } });
  });
  const actor = o.actorId ? await deps.prisma.user.findUnique({ where: { id: o.actorId }, select: { name: true } }) : null;
  const productName = await deps.productName();
  // Awaited (the organisation route doesn't wait): the operator sees whether the person was told, and the CLI must not
  // exit before the email is out.
  const emailed = await sendEmail(deps.mail, user.email, twoFactorResetEmail(productName, actor?.name ?? `The ${productName} server's operator`, at), o.log);
  return { ok: true, user: { id: user.id, email: user.email, name: user.name }, emailed };
}
