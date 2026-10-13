import { describe, expect, it } from "vitest";
import { filterRecords, groupByFolder } from "./filter";
import type { VaultFolder, VaultRecord } from "./types";

const rec = (p: Partial<VaultRecord> & { title?: string }): VaultRecord => ({
  id: p.id ?? crypto.randomUUID(), folderId: p.folderId ?? null, type: "login", revision: 1, updatedAt: p.updatedAt ?? "2026-10-01T00:00:00Z",
  deleted: p.deleted ?? false, permission: "owner", recordKey: null, error: p.error,
  body: p.error ? null : { type: "login", title: p.title ?? "x", username: (p as { username?: string }).username, url: (p as { url?: string }).url },
});

describe("filterRecords", () => {
  const rs = [rec({ title: "Stripe", updatedAt: "2026-10-03T00:00:00Z" }), rec({ title: "aws root", url: "console.aws.amazon.com" } as never), rec({ title: "Old", deleted: true }), rec({ error: "cannot_open" })];
  it("hides trash in the vault and sorts by name, broken last", () => {
    expect(filterRecords(rs, { view: "vault", query: "", sort: "name" }).map((r) => r.body?.title ?? "broken")).toEqual(["aws root", "Stripe", "broken"]);
  });
  it("shows only trash in trash", () => {
    expect(filterRecords(rs, { view: "trash", query: "", sort: "name" }).map((r) => r.body!.title)).toEqual(["Old"]);
  });
  it("searches title and website, case-insensitive", () => {
    expect(filterRecords(rs, { view: "vault", query: "AMAZON", sort: "name" }).map((r) => r.body!.title)).toEqual(["aws root"]);
  });
  it("sorts by most recently changed", () => {
    expect(filterRecords(rs, { view: "vault", query: "", sort: "recent" })[0]!.body!.title).toBe("Stripe");
  });
});

describe("groupByFolder", () => {
  it("orders folders by name, unfiled last, skips deleted folders", () => {
    const fA: VaultFolder = { id: "a", name: "Northwind", kind: "private", deleted: false };
    const fB: VaultFolder = { id: "b", name: "Clane AI", kind: "private", deleted: false };
    const fC: VaultFolder = { id: "c", name: "Gone", kind: "private", deleted: true };
    const groups = groupByFolder([rec({ title: "1", folderId: "a" }), rec({ title: "2" })], [fA, fB, fC]);
    expect(groups.map((g) => g.folder?.name ?? "No folder")).toEqual(["Clane AI", "Northwind", "No folder"]);
    expect(groups[0]!.records).toHaveLength(0);
  });
});

describe("shared with me", () => {
  it("lists live records shared directly by someone else", () => {
    const mine = rec({ title: "Mine" });
    const shared = { ...rec({ title: "From Ana" }), sharedBy: "Ana", permission: "view" as const };
    const gone = { ...rec({ title: "Old share", deleted: true }), sharedBy: "Ana" };
    expect(filterRecords([mine, shared, gone], { view: "shared", query: "", sort: "name" }).map((r) => r.body!.title)).toEqual(["From Ana"]);
  });
});
