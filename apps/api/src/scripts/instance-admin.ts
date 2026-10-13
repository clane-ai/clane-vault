// Operator CLI: grant or revoke instance admin (Backups) for an existing account.
//   node dist/src/scripts/instance-admin.js --email you@company.com --grant|--revoke
//   (dev: npm run instance-admin -w @clane-vault/api -- --email ... --grant)
// Instance admin is bound to the account, never to an email address in configuration.
import { loadConfig } from "../config.js";
import { createPrisma } from "../db.js";

const arg = (name: string) => { const i = process.argv.indexOf(name); return i >= 0 ? process.argv[i + 1] : undefined; };
const email = arg("--email")?.trim().toLowerCase();
const grant = process.argv.includes("--grant"), revoke = process.argv.includes("--revoke");
if (!email || !email.includes("@") || grant === revoke) {
  console.error("Usage: instance-admin --email you@company.com --grant|--revoke");
  process.exit(1);
}
const config = loadConfig();
const prisma = createPrisma(config.databaseUrl);
const user = await prisma.user.findUnique({ where: { email }, select: { id: true, status: true } });
if (!user) { console.error(`No account for ${email}.`); process.exit(1); }
if (grant && user.status !== "active") { console.error(`${email} is not an active account.`); process.exit(1); }
await prisma.user.update({ where: { id: user.id }, data: { instanceAdmin: grant } });
await prisma.event.create({ data: { action: grant ? "instance.admin_granted" : "instance.admin_revoked", targetUserId: user.id, meta: { via: "cli" } } });
console.log(`${email} is ${grant ? "now" : "no longer"} an instance admin.`);
await prisma.$disconnect();
