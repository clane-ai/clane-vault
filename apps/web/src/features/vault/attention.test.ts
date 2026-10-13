import { describe, expect, it } from "vitest";
import { attentionReasons, isWeakPassword, reasonLine, strengthOf } from "./attention";
import type { VaultRecord } from "./types";

const now = Date.parse("2026-10-06T00:00:00Z");
const rec = (id: string, password: string | undefined, o: Partial<VaultRecord> = {}): VaultRecord => ({
  id, folderId: null, type: "login", body: { type: "login", title: id, ...(password ? { password } : {}) }, revision: 1,
  updatedAt: "2026-09-01T00:00:00Z", deleted: false, permission: "owner", recordKey: null, ...o,
});

describe("attention rules", () => {
  it("figma123 is weak, and so are short or low-score passwords", () => {
    expect(isWeakPassword("figma123")).toBe(true);
    expect(isWeakPassword("Summer2024")).toBe(true);
    expect(isWeakPassword("Xk9#q")).toBe(true); // short
    expect(isWeakPassword("password12345")).toBe(true); // low score
    expect(isWeakPassword("Tg7#qL2v!Rm9zW4x")).toBe(false);
  });

  it("the strength label follows the same rule", () => {
    expect(strengthOf("figma123").label).toBe("Weak");
    expect(strengthOf("figma123").score).toBeLessThanOrEqual(1);
    expect(strengthOf("Tg7#qL2v!Rm9zW4x").label).toBe("Strong");
  });

  it("flags reuse across records, ignoring trashed records", () => {
    const r = attentionReasons([rec("a", "Tg7#qL2v!Rm9zW4x"), rec("b", "Tg7#qL2v!Rm9zW4x"), rec("c", "Zq8$wP3n!Lk7xV2m"), rec("d", "Zq8$wP3n!Lk7xV2m", { deleted: true })], now);
    expect(r.get("a")).toEqual(["reused"]);
    expect(r.get("b")).toEqual(["reused"]);
    expect(r.has("c")).toBe(false);
    expect(r.has("d")).toBe(false);
  });

  it("counts records shared with me (directly or through a team folder) when looking for reuse", () => {
    const r = attentionReasons([rec("mine", "Tg7#qL2v!Rm9zW4x"), rec("shared", "Tg7#qL2v!Rm9zW4x", { permission: "view", sharedBy: "Ana", ownerId: "u2" }),
      rec("team", "Zq8$wP3n!Lk7xV2m", { permission: "use", folderId: "f1" }), rec("mine2", "Zq8$wP3n!Lk7xV2m")], now);
    expect(r.get("mine")).toEqual(["reused"]);
    expect(r.get("shared")).toEqual(["reused"]);
    expect(r.get("team")).toEqual(["reused"]);
    expect(r.get("mine2")).toEqual(["reused"]);
  });

  it("flags passwords unchanged for over a year, combines reasons, skips records without a password", () => {
    const r = attentionReasons([rec("old", "Tg7#qL2v!Rm9zW4x", { updatedAt: "2025-09-01T00:00:00Z" }), rec("w", "figma123"), rec("w2", "figma123"), rec("none", undefined), rec("broken", undefined, { body: null })], now);
    expect(r.get("old")).toEqual(["old"]);
    expect(r.get("w")).toEqual(["weak", "reused"]);
    expect(r.has("none")).toBe(false);
    expect(r.has("broken")).toBe(false);
  });

  it("explains reasons in one line", () => {
    expect(reasonLine(["weak"])).toBe("This password is weak.");
    expect(reasonLine(["weak", "reused", "old"])).toBe("This password is weak, is used on another record too and hasn't changed in over a year.");
  });
});
