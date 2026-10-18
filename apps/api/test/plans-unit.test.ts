import { describe, expect, it } from "vitest";
import { getEntitlements, getPersonalEntitlements } from "../src/lib/plans.js";

const off = { billingMode: "off" as const }, on = { billingMode: "hosted" as const };
const free = { plan: "team" as const, billingStatus: "free", seatsPaid: null, trialEndsAt: null };

describe("entitlements", () => {
  it("is unlimited with billing off", () => {
    expect(getEntitlements(off, free).plan).toBe("unlimited");
    expect(getEntitlements(off, free).seatsAllowed).toBeNull();
    expect(getPersonalEntitlements(off).plan).toBe("unlimited");
  });
  it("resolves Team, Business and Personal", () => {
    const team = getEntitlements(on, free);
    expect(team).toMatchObject({ plan: "team", seatsAllowed: 10, storageBytesPerSeat: 2 * 1024 ** 3, activeLinkLimit: null, eventLogDays: 30 });
    expect(Object.values(team.features).every((x) => !x)).toBe(true);
    expect(getEntitlements(on, { ...free, billingStatus: "active", seatsPaid: 15 }).seatsAllowed).toBe(15);
    const biz = getEntitlements(on, { plan: "business", billingStatus: "active", seatsPaid: 20, trialEndsAt: null });
    expect(biz).toMatchObject({ seatsAllowed: 20, storageBytesPerSeat: 10 * 1024 ** 3, eventLogDays: 365 });
    expect(Object.values(biz.features).every(Boolean)).toBe(true);
    expect(getEntitlements(on, { plan: "business", billingStatus: "free", seatsPaid: null, trialEndsAt: null }).seatsAllowed).toBe(0);
    expect(getPersonalEntitlements(on)).toMatchObject({ plan: "personal", activeLinkLimit: 5, storageBytesPerSeat: 1024 ** 3 });
  });
  it("sets the agent limit and the Business-only agent features", () => {
    const team = getEntitlements(on, free);
    const biz = getEntitlements(on, { plan: "business", billingStatus: "active", seatsPaid: 20, trialEndsAt: null });
    expect(team.agentLimit).toBe(3);
    expect(biz.agentLimit).toBe(10);
    expect(getEntitlements(off, free).agentLimit).toBeNull();
    expect(getPersonalEntitlements(on).agentLimit).toBe(0);
    expect([team.features.agentApprovals, team.features.agentPathPolicy]).toEqual([false, false]);
    expect([biz.features.agentApprovals, biz.features.agentPathPolicy]).toEqual([true, true]);
    const now = new Date("2026-11-01T00:00:00Z");
    expect(getEntitlements(on, { ...free, trialEndsAt: new Date(+now + 864e5) }, now).agentLimit).toBe(3);
  });
  it("gives a Team org Business features during its trial only", () => {
    const now = new Date("2026-11-01T00:00:00Z"), day = 864e5;
    const trial = getEntitlements(on, { ...free, trialEndsAt: new Date(+now + day) }, now);
    expect(trial).toMatchObject({ trial: true, seatsAllowed: 10, eventLogDays: 365 });
    expect(Object.values(trial.features).every(Boolean)).toBe(true);
    const after = getEntitlements(on, { ...free, trialEndsAt: new Date(+now - 1) }, now);
    expect(after).toMatchObject({ trial: false, plan: "team", eventLogDays: 30 });
    expect(after.features.sso).toBe(false);
  });
});
