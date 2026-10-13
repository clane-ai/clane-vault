import { createHash, randomBytes } from "node:crypto";
import { loadConfig } from "../config.js";
import { createPrisma } from "../db.js";
import { defaultOrg, ensureDefaultOrg } from "../lib/orgs.js";

const email = process.argv[process.argv.indexOf("--email") + 1];
if (!email || !email.includes("@")) { console.error("Usage: npm run bootstrap -w @clane-vault/api -- --email you@company.com"); process.exit(1); }
const config = loadConfig();
const prisma = createPrisma(config.databaseUrl);
await ensureDefaultOrg(prisma, config);
const org = (await defaultOrg(prisma))!;
// The first account owns the default organisation (and is an instance admin).
if ((await prisma.membership.count({ where: { orgId: org.id, role: { in: ["owner", "admin"] } } })) > 0) { console.error("An admin already exists. Invite people from the app."); process.exit(1); }
const token = randomBytes(24).toString("base64url");
await prisma.invite.create({ data: { orgId: org.id, email: email.toLowerCase(), role: "owner", instanceAdmin: true, tokenHash: createHash("sha256").update(token).digest("hex"), expiresAt: new Date(Date.now() + 48 * 3600e3) } });
console.log(`Owner invite for ${email} to ${org.name} (valid 48 hours):\n${config.publicUrl}/invite/${token}`);
await prisma.$disconnect();
