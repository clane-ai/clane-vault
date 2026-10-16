import { describe, expect, it } from "vitest";
import { ApiError } from "@/lib/api";
import { planMessage } from "./plan";

describe("planMessage", () => {
  it("maps the 402 codes to plain English", () => {
    expect(planMessage(new ApiError(402, "seat_limit", { error: "seat_limit", used: 10, allowed: 10 }))).toBe("All 10 seats are in use. An owner can add seats.");
    expect(planMessage(new ApiError(402, "link_limit", { error: "link_limit", limit: 5 }))).toBe("You can have 5 active one-time links. Revoke one to make another.");
    expect(planMessage(new ApiError(402, "plan_required", { error: "plan_required", feature: "sso", requiredPlan: "business" }))).toBe("Available on the Business plan.");
  });
  it("is null for anything else", () => {
    expect(planMessage(new ApiError(500, "server_error", {}))).toBeNull();
    expect(planMessage(new Error("x"))).toBeNull();
  });
});
