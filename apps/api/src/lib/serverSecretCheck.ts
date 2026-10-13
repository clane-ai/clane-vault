import type { PrismaClient } from "@prisma/client";
import { secretBox } from "./secretBox.js";
import { settingsBox } from "./settingsBox.js";

const AAD = "server-secret-check";
const PLAIN = "clane-vault server secret check v1";
/** Authenticator secrets sampled when a database has no check row yet (an upgrade from before 1.6.1). */
const SAMPLE = 20;

export class ServerSecretMismatch extends Error {
  constructor(detail: string) {
    super(
      `SERVER_SECRET does not match this database: ${detail}. ` +
        "Put back the SERVER_SECRET this database was set up with (from your saved .env or its backup). " +
        "If that secret is lost for good, set ACCEPT_NEW_SERVER_SECRET=true for one start: every account must then have its 2FA reset, " +
        "and email and SSO secrets entered again (deploy/client/README.md, \"SERVER_SECRET\").",
    );
    this.name = "ServerSecretMismatch";
  }
}

type Log = { warn: (msg: string) => void };
export type SecretCheckResult = { status: "ok" | "created" | "accepted"; unreadableTotp: number };

/**
 * Runs before the server listens. A database remembers a value sealed under its SERVER_SECRET; a different secret
 * can't open it, and the server stops with a message saying what to do instead of answering every 2FA sign-in with
 * a 500. Databases from before this check get the row on first start, unless their authenticator secrets show the
 * secret already changed (none of a sample opens).
 */
export async function checkServerSecret(prisma: PrismaClient, serverSecret: string, opts: { accept?: boolean; log?: Log } = {}): Promise<SecretCheckResult> {
  const sealed = settingsBox(serverSecret).seal(PLAIN, AAD);
  const row = await prisma.serverSecretCheck.findUnique({ where: { id: 1 } });
  if (row) {
    if (opens(() => settingsBox(serverSecret).open(row.sealed, AAD))) return { status: "ok", unreadableTotp: 0 };
    if (!opts.accept) throw new ServerSecretMismatch("the value sealed with the original secret can't be opened");
    await prisma.serverSecretCheck.update({ where: { id: 1 }, data: { sealed, createdAt: new Date() } });
    opts.log?.warn("ACCEPT_NEW_SERVER_SECRET=true: this database now uses the new SERVER_SECRET. Reset every account's 2FA and re-enter email and SSO secrets, then remove the setting.");
    return { status: "accepted", unreadableTotp: 0 };
  }
  const users = await prisma.user.findMany({ where: { totpSecretEnc: { not: null } }, select: { totpSecretEnc: true }, orderBy: { totpEnabledAt: { sort: "desc", nulls: "last" } }, take: SAMPLE });
  const box = secretBox(serverSecret);
  const unreadable = users.filter((u) => !opens(() => box.open(u.totpSecretEnc!))).length;
  if (users.length > 0 && unreadable === users.length && !opts.accept)
    throw new ServerSecretMismatch(`none of ${users.length} authenticator secrets in it can be opened`);
  if (unreadable > 0)
    opts.log?.warn(`${unreadable} of ${users.length} sampled accounts set up their authenticator under a different SERVER_SECRET and can't sign in: reset their 2FA (Admin → People → Reset 2FA).`);
  // Two servers starting at once: the first row wins and both check against it on their next start.
  await prisma.serverSecretCheck.createMany({ data: [{ id: 1, sealed }], skipDuplicates: true });
  return { status: opts.accept && unreadable > 0 ? "accepted" : "created", unreadableTotp: unreadable };
}

function opens(f: () => string): boolean {
  try {
    f();
    return true;
  } catch {
    return false;
  }
}
