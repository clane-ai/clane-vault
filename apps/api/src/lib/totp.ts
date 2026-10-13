import { authenticator } from "otplib";

/** otpauth:// URI for the authenticator app; the product name is the issuer people see (PRODUCT_NAME). */
export function totpKeyUri(productName: string, email: string, secret: string): string {
  return authenticator.keyuri(email, productName, secret);
}

/** TOTP is checked with a ±1 step window (30 s steps). */
authenticator.options = { window: 1 };
export const TOTP_STEP_MS = 30_000;

type Opener = { open: (s: string) => string };
type Db = { user: { updateMany: (a: { where: object; data: object }) => Promise<{ count: number }> } };

/**
 * Checks a 6-digit code against the user's authenticator and consumes its time step: each step is accepted once
 * per account, everywhere (sign-in, 2FA setup, recovery, admin approvals, policy changes). Returns false for a
 * wrong code and for a replayed one.
 */
export async function consumeTotp(prisma: Db, box: Opener, user: { id: string; totpSecretEnc: string | null }, code: string | undefined, now = Date.now()): Promise<boolean> {
  if (!code || !/^\d{6}$/.test(code) || !user.totpSecretEnc) return false;
  let secret: string;
  try {
    secret = box.open(user.totpSecretEnc);
  } catch {
    throw new Error("This account's authenticator secret can't be decrypted: SERVER_SECRET differs from the one it was set up under. Restore the original SERVER_SECRET or reset this account's 2FA.");
  }
  const delta = authenticator.checkDelta(code, secret);
  if (delta === null || delta === undefined) return false;
  const step = Math.floor(now / TOTP_STEP_MS) + delta;
  const n = await prisma.user.updateMany({ where: { id: user.id, OR: [{ totpLastStep: null }, { totpLastStep: { lt: step } }] }, data: { totpLastStep: step } });
  return n.count === 1;
}
