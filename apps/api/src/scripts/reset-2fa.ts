// Operator CLI: reset an account's authenticator (two-step sign-in), for example an instance admin who is locked out,
// or an organisation owner on a self-hosted server.
//   node dist/src/scripts/reset-2fa.js --email someone@company.com
//   (dev: npm run reset-2fa -w @clane-vault/api -- --email ...)
// The account sets up a new authenticator at its next sign-in; its sessions end and it is emailed (when email is set up).
// Confirm who is asking out-of-band first (docs/recovery.md).
import { loadConfig } from "../config.js";
import { createPrisma } from "../db.js";
import { BrandCache } from "../lib/brand.js";
import { Mailer } from "../lib/mailer.js";
import { settingsBox } from "../lib/settingsBox.js";
import { resetTwoFactorByEmail } from "../lib/twoFactor.js";

const arg = (name: string) => { const i = process.argv.indexOf(name); return i >= 0 ? process.argv[i + 1] : undefined; };
const email = arg("--email")?.trim().toLowerCase();
if (!email || !email.includes("@")) { console.error("Usage: reset-2fa --email someone@company.com"); process.exit(1); }
const config = loadConfig();
const prisma = createPrisma(config.databaseUrl);
const mail = new Mailer({ prisma, config, box: settingsBox(config.serverSecret) });
const brand = new BrandCache(prisma, config.productName);
const log = { warn: (o: object, m: string) => console.error(`${m} ${JSON.stringify(o)}`) };
const r = await resetTwoFactorByEmail({ prisma, mail, productName: () => brand.productName() }, { email, actorId: null, log });
await prisma.$disconnect();
if (!r.ok) {
  console.error(r.error === "not_found" ? `No account for ${email}.` : `${email} is disabled: enable the account first.`);
  process.exit(1);
}
console.log(`${email}: authenticator reset and signed out everywhere. They set up a new one at their next sign-in.${r.emailed ? " They were emailed." : " No email was sent (email isn't set up or failed): tell them yourself."}`);
