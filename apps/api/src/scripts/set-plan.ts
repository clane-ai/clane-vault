// Operator CLI: set an organisation's plan by hand (before billing is wired up, or to comp a customer).
//   node dist/src/scripts/set-plan.js --org <id> --plan team|business [--seats N]
//   (dev: npm run set-plan -w @clane-vault/api -- --org ... --plan business --seats 20)
import { loadConfig } from "../config.js";
import { createPrisma } from "../db.js";
import { logEvent } from "../lib/events.js";

const arg = (name: string) => { const i = process.argv.indexOf(name); return i >= 0 ? process.argv[i + 1] : undefined; };
const org = arg("--org"), plan = arg("--plan"), seatsArg = arg("--seats");
const seats = seatsArg === undefined ? undefined : Number(seatsArg);
if (!org || (plan !== "team" && plan !== "business") || (seats !== undefined && !(Number.isInteger(seats) && seats >= 1))) {
  console.error("Usage: set-plan --org <id> --plan team|business [--seats N]"); process.exit(1);
}
const prisma = createPrisma(loadConfig().databaseUrl);
const before = await prisma.organization.findUnique({ where: { id: org }, select: { plan: true, seatsPaid: true } }).catch(() => null);
if (!before) { console.error(`No organisation ${org}.`); await prisma.$disconnect(); process.exit(1); }
const seatsPaid = seats ?? before.seatsPaid;
await prisma.organization.update({ where: { id: org }, data: { plan, seatsPaid } });
await logEvent(prisma, { orgId: org, action: "org.plan_change", meta: { from: before.plan, to: plan, seatsPaid, by: "operator" } });
await prisma.$disconnect();
console.log(`${org}: plan ${before.plan} -> ${plan}, seats ${seatsPaid ?? "default"}.`);
