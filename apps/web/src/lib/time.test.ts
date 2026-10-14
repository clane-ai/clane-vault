import { describe, expect, it } from "vitest";
import { clockTime, relativeTime } from "./time";
import { initials } from "@/features/vault/people";

describe("clockTime", () => {
  it("formats like the status bar, for a Date or an ISO string", () => {
    const d = new Date("2026-10-14T15:03:00Z");
    const expected = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    expect(clockTime(d)).toBe(expected);
    expect(clockTime(d.toISOString())).toBe(expected);
  });
});

describe("initials", () => {
  it("skips brackets and punctuation", () => {
    expect(initials("Northwind (demo)")).toBe("N");
    expect(initials("Acme & Co.")).toBe("AC");
    expect(initials("(demo)")).toBe("D");
    expect(initials("Sara O'Neil")).toBe("SO");
    expect(initials("bea lindqvist")).toBe("BL");
    expect(initials("  ")).toBe("?");
  });
});

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
