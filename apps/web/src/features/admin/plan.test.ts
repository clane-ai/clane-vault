import { describe, expect, it } from "vitest";
import { ApiError } from "@/lib/api";
import { planMessage } from "./plan";

describe("planMessage", () => {
  it("maps the 402 codes to plain English", () => {
    expect(planMessage(new ApiError(402, "seat_limit", { error: "seat_limit", used: 10, allowed: 10 }))).toBe("All 10 seats are in use. An owner can add seats.");
    expect(planMessage(new ApiError(402, "link_limit", { error: "link_limit", limit: 5 }))).toBe("You can have 5 active one-time links. Revoke one to make another.");
    expect(planMessage(new ApiError(402, "plan_required", { error: "plan_required", feature: "sso", requiredPlan: "business" }))).toBe("Available on the Business plan.");
    expect(planMessage(new ApiError(402, "agent_limit", { error: "agent_limit", used: 10, allowed: 10 }))).toBe("All 10 agents on your plan are in use. Revoke one to add another.");
  });
  it("is null for anything else", () => {
    expect(planMessage(new ApiError(500, "server_error", {}))).toBeNull();
    expect(planMessage(new Error("x"))).toBeNull();
  });
});

describe("planMessage with a thin body", () => {
  it("never says undefined", () => {
    expect(planMessage(new ApiError(402, "seat_limit", {}))).toBe("All seats are in use. An owner can add seats.");
    expect(planMessage(new ApiError(402, "link_limit", null))).toBe("You've reached the limit of active one-time links. Revoke one to make another.");
  });
});

describe("planMessage for a member", () => {
  it("hides seat counts and upgrade prompts behind one line", () => {
    for (const [code, body] of [["seat_limit", { allowed: 10 }], ["link_limit", { limit: 5 }], ["plan_required", {}]] as const)
      expect(planMessage(new ApiError(402, code, body), true)).toBe("Your organisation is over its plan's limit. Ask an admin.");
    expect(planMessage(new ApiError(500, "server_error", {}), true)).toBeNull();
  });
});
