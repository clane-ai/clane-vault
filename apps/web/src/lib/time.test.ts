import { describe, expect, it } from "vitest";
import { relativeTime } from "./time";

describe("relativeTime", () => {
  const now = Date.parse("2026-10-05T12:00:00Z");
  it("says just now for recent changes", () => expect(relativeTime("2026-10-05T11:59:40Z", now)).toBe("just now"));
  it("uses minutes, hours and days", () => {
    expect(relativeTime("2026-10-05T11:55:00Z", now)).toMatch(/5 minutes ago/);
    expect(relativeTime("2026-10-05T09:00:00Z", now)).toMatch(/3 hours ago/);
    expect(relativeTime("2026-10-03T12:00:00Z", now)).toMatch(/2 days ago/);
  });
  it("returns empty for a bad date", () => expect(relativeTime("nope", now)).toBe(""));
});
