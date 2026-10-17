import type { PrismaClient } from "@prisma/client";
import { logEvent } from "./events.js";

export const SET_PLAN_USAGE = "Usage: set-plan --org <id> --plan team|business [--seats N]";

export function parseSetPlanArgs(argv: string[]): { org: string; plan: "team" | "business"; seats?: number } | null {
  const arg = (name: string) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : undefined; };
  const org = arg("--org"), plan = arg("--plan"), seatsArg = arg("--seats");
  const seats = seatsArg === undefined ? undefined : Number(seatsArg);
  if (!org || (plan !== "team" && plan !== "business") || (seats !== undefined && !(Number.isInteger(seats) && seats >= 1))) return null;
  return { org, plan, seats };
}

/** Returns the message to print; throws `Error` with an operator-readable message for a refusal. */
export async function applyPlan(prisma: PrismaClient, a: { org: string; plan: "team" | "business"; seats?: number }): Promise<string> {
  let before;
  try { before = await prisma.organization.findUnique({ where: { id: a.org }, select: { plan: true, seatsPaid: true } }); }
  catch (e) { if ((e as { code?: string }).code !== "P2023") throw e; } // P2023: not a UUID
  if (!before) throw new Error(`No organisation ${a.org}.`);
  const seatsPaid = a.seats ?? before.seatsPaid;
  if (a.plan === "business" && seatsPaid == null) throw new Error("Business needs seats: pass --seats N.");
  await prisma.organization.update({ where: { id: a.org }, data: { plan: a.plan, seatsPaid } });
  await logEvent(prisma, { orgId: a.org, action: "org.plan_change", meta: { from: before.plan, to: a.plan, seatsPaid, by: "operator" } });
  return `${a.org}: plan ${before.plan} -> ${a.plan}, seats ${seatsPaid ?? "default"}.`;
}
