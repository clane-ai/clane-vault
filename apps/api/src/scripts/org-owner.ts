// Operator CLI: make an active member the owner of an organisation (the previous owner, if any, becomes an admin).
//   node dist/src/scripts/org-owner.js --email you@company.com [--org <slug or id>]   (default: the main organisation)
// For an organisation left without an owner, or a lost owner account.
import { loadConfig } from "../config.js";
import { createPrisma } from "../db.js";
import { defaultOrg } from "../lib/orgs.js";

const arg = (name: string) => { const i = process.argv.indexOf(name); return i >= 0 ? process.argv[i + 1] : undefined; };
const email = arg("--email")?.trim().toLowerCase();
const orgArg = arg("--org");
if (!email || !email.includes("@")) { console.error("Usage: org-owner --email you@company.com [--org <slug or id>]"); process.exit(1); }
const config = loadConfig();
const prisma = createPrisma(config.databaseUrl);
const isId = !!orgArg && /^[0-9a-f-]{36}$/i.test(orgArg);
const org = orgArg ? await prisma.organization.findFirst({ where: isId ? { id: orgArg } : { slug: orgArg }, select: { id: true, name: true } }) : await defaultOrg(prisma);
if (!org) { console.error("No such organisation."); process.exit(1); }
const m = await prisma.membership.findFirst({ where: { orgId: org.id, status: "active", user: { email, status: "active" } }, select: { id: true, userId: true, adminSince: true } });
if (!m) { console.error(`${email} is not an active member of ${org.name}.`); process.exit(1); }
await prisma.$transaction([
  prisma.membership.updateMany({ where: { orgId: org.id, role: "owner", id: { not: m.id } }, data: { role: "admin" } }),
  prisma.membership.update({ where: { id: m.id }, data: { role: "owner", adminSince: m.adminSince ?? new Date() } }),
  prisma.event.create({ data: { orgId: org.id, action: "org.owner_set", targetUserId: m.userId, meta: { via: "cli" } } }),
]);
console.log(`${email} now owns ${org.name}.`);
await prisma.$disconnect();
