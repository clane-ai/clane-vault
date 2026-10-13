import { describe, expect, it, vi } from "vitest";
import type { VaultRecord } from "@/features/vault/types";
import { healthReport, orgScopedReport, reportPayload } from "./health";
import { breachedRecords, clearBreachCache, parseRange, sha1Hex } from "./hibp";

const NOW = Date.parse("2026-10-08T00:00:00Z");
const rec = (id: string, password: string | undefined, updatedAt = "2026-10-01T00:00:00Z", extra: Partial<VaultRecord["body"] & object> = {}): VaultRecord => ({
  id, folderId: null, type: "login", revision: 1, updatedAt, deleted: false, permission: "owner", recordKey: null,
  body: { type: "login", title: id, ...(password ? { password } : {}), ...extra },
});

describe("password health report", () => {
  it("counts weak, reused and old passwords and scores the share without issues", () => {
    const strong = "correct horse battery staple 9!";
    const r = healthReport([
      rec("a", "password1"), // weak
      rec("b", strong), rec("c", strong), // reused
      rec("d", "Zq8!vT3#pL6@wX1&", "2025-01-01T00:00:00Z"), // old by updatedAt
      rec("e", "Mn5$kR9^bH2*yJ7(", "2025-01-01T00:00:00Z", { passwordChangedAt: "2026-09-01T00:00:00Z" }), // changed recently: not old
      rec("f", "Gt4%cW8&nF1)eQ6!", "2026-10-01T00:00:00Z", { passwordChangedAt: "2024-01-01T00:00:00Z" }), // edited lately but password is old
      rec("note", undefined),
      { ...rec("gone", "password1"), deleted: true },
    ], { now: NOW });
    expect(r.total).toBe(6);
    expect([r.weak, r.reused, r.old, r.breached]).toEqual([1, 2, 2, null]);
    expect(r.issues.get("a")).toEqual(["weak"]);
    expect(r.issues.get("f")).toEqual(["old"]);
    expect(r.issues.has("e")).toBe(false);
    expect(r.score).toBe(17); // 1 of 6 has no issue
    expect(reportPayload(r)).toEqual({ score: 17, total: 6, weak: 1, reused: 2, old: 2, breached: null });
    expect(healthReport([], { now: NOW }).score).toBe(100);
  });

  it("adds breached records when the breach check ran", () => {
    const r = healthReport([rec("a", "Zq8!vT3#pL6@wX1&"), rec("b", "Mn5$kR9^bH2*yJ7(")], { now: NOW, breached: new Set(["b"]) });
    expect(r.breached).toBe(1);
    expect(r.issues.get("b")).toEqual(["breached"]);
    expect(r.score).toBe(50);
  });
});

describe("what the org's admins get", () => {
  it("counts only the org's records (team folders, shared with me), never my own private ones", () => {
    const strong = "correct horse battery staple 9!";
    const records = [
      { ...rec("team", strong), folderId: "tf" }, // in a team folder; its password is reused in a private record
      { ...rec("shared", "password1"), permission: "view" as const }, // shared with me in this org, weak
      rec("mine", strong), // private: reused
      rec("mine-weak", "password1"), { ...rec("mine-old", "Zq8!vT3#pL6@wX1&", "2020-01-01T00:00:00Z"), folderId: "pf" },
    ];
    const full = healthReport(records, { now: NOW, breached: new Set(["mine-weak"]) });
    expect(full.total).toBe(5);
    const org = orgScopedReport(full, records, new Set(["tf"]));
    expect(reportPayload(org)).toEqual({ score: 0, total: 2, weak: 1, reused: 2, old: 0, breached: 0 });
    expect([...org.issues.keys()].sort()).toEqual(["shared", "team"]);
    expect(orgScopedReport(healthReport(records, { now: NOW }), records, new Set()).breached).toBeNull();
    expect(reportPayload(orgScopedReport(full, records.slice(2), new Set(["tf"])))).toEqual({ score: 100, total: 0, weak: 0, reused: 0, old: 0, breached: 0 });
  });
});

describe("Have I Been Pwned range check", () => {
  it("hashes with SHA-1 and parses ranges", async () => {
    expect(await sha1Hex("password")).toBe("5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8");
    expect(parseRange("1E4C9B93F3F0682250B6CF8331B7EE68FD8:9545824\r\n0018A45C4D1DEF81644B54AB7F969B88D65:0\n")).toEqual(new Map([["1E4C9B93F3F0682250B6CF8331B7EE68FD8", 9545824], ["0018A45C4D1DEF81644B54AB7F969B88D65", 0]]));
  });

  it("sends only the 5-character prefix (once per prefix) and matches the suffix locally", async () => {
    clearBreachCache();
    const urls: string[] = [];
    const fetcher = vi.fn(async (url: string) => {
      urls.push(url);
      return new Response(url.endsWith("5BAA6") ? "1E4C9B93F3F0682250B6CF8331B7EE68FD8:3\r\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:0" : "0000000000000000000000000000000000A:0");
    });
    const out = await breachedRecords([rec("a", "password"), rec("b", "password"), rec("c", "Zq8!vT3#pL6@wX1&")], fetcher);
    expect(out).toEqual(new Set(["a", "b"]));
    expect(urls).toHaveLength(2);
    for (const u of urls) expect(u).toMatch(/^https:\/\/api\.pwnedpasswords\.com\/range\/[0-9A-F]{5}$/);
    expect(urls.map((u) => u.slice(u.lastIndexOf("/") + 1))).toEqual(expect.arrayContaining(["5BAA6"]));
    // Cached: no second request for the same prefixes.
    await breachedRecords([rec("a", "password")], fetcher);
    expect(fetcher).toHaveBeenCalledTimes(2);
  });
});
