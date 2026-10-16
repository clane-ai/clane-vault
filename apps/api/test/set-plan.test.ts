import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { applyPlan, parseSetPlanArgs } from "../src/lib/setPlan.js";
import { makeTestApp, resetDb, createActiveUser } from "./helpers.js";

const t = await makeTestApp();
afterAll(() => t.app.close());
beforeEach(() => resetDb(t.prisma));

describe("set-plan", () => {
  it("parses and validates the arguments", () => {
    expect(parseSetPlanArgs(["--org", "x", "--plan", "business", "--seats", "20"])).toEqual({ org: "x", plan: "business", seats: 20 });
    expect(parseSetPlanArgs(["--org", "x", "--plan", "gold"])).toBeNull();
    expect(parseSetPlanArgs(["--org", "x", "--plan", "team", "--seats", "0"])).toBeNull();
  });

  it("refuses business without seats, accepts it with --seats or an existing seatsPaid", async () => {
    const orgId = (await createActiveUser(t, { role: "owner" })).orgId!;
    await expect(applyPlan(t.prisma, { org: orgId, plan: "business" })).rejects.toThrow("Business needs seats");
    expect((await t.prisma.organization.findUniqueOrThrow({ where: { id: orgId } })).plan).toBe("team");
    await applyPlan(t.prisma, { org: orgId, plan: "business", seats: 20 });
    await applyPlan(t.prisma, { org: orgId, plan: "team" });
    await expect(applyPlan(t.prisma, { org: orgId, plan: "business" })).resolves.toContain("seats 20");
  });

  it("only a bad or unknown id reads as 'No organisation'", async () => {
    await expect(applyPlan(t.prisma, { org: "nope", plan: "team" })).rejects.toThrow("No organisation nope.");
    await expect(applyPlan(t.prisma, { org: "00000000-0000-4000-8000-000000000000", plan: "team" })).rejects.toThrow("No organisation");
  });
});
