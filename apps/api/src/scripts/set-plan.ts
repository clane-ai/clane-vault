// Operator CLI: set an organisation's plan by hand (before billing is wired up, or to comp a customer).
//   node dist/src/scripts/set-plan.js --org <id> --plan team|business [--seats N]
//   (dev: npm run set-plan -w @clane-vault/api -- --org ... --plan business --seats 20)
import { loadConfig } from "../config.js";
import { createPrisma } from "../db.js";
import { applyPlan, parseSetPlanArgs, SET_PLAN_USAGE } from "../lib/setPlan.js";

const args = parseSetPlanArgs(process.argv);
if (!args) { console.error(SET_PLAN_USAGE); process.exit(1); }
const prisma = createPrisma(loadConfig().databaseUrl);
try { console.log(await applyPlan(prisma, args)); }
catch (e) { console.error(e instanceof Error ? e.message : e); process.exitCode = 1; }
finally { await prisma.$disconnect(); }
