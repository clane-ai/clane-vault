import { describe, expect, it } from "vitest";
import type { VaultFolder, VaultRecord } from "@/features/vault/types";
import commander from "./fixtures/commander.json?raw";
import webvault from "./fixtures/webvault.json?raw";
import { parseKeeperExport } from "./keeper";
import { buildPlan, defaultSelection, dupKey, joins, planTypeCounts, recordsToWrite, totals, type PlanContext } from "./plan";

const users: PlanContext["users"] = [
  { id: "u-admin", name: "Admin", email: "admin@acme.test", status: "active", publicKey: "pk-admin" },
  { id: "u-bob", name: "Bob", email: "bob@acme.test", status: "active", publicKey: "pk-bob" },
  { id: "u-eve", name: "Eve", email: "eve@acme.test", status: "pending_2fa", publicKey: "pk-eve" },
  { id: "u-dave", name: "Dave", email: "dave@acme.test", status: "disabled", publicKey: "pk-dave" },
];
const salesId = "f-sales", personalId = "f-personal";
const folders: VaultFolder[] = [
  { id: salesId, name: "sales", kind: "team", deleted: false, myPermission: "owner" },
  { id: "f-infra-not-mine", name: "Engineering / Infra", kind: "team", deleted: false, myPermission: "edit" },
  { id: personalId, name: "Personal", kind: "private", deleted: false },
];
const rec = (folderId: string | null, title: string, username: string, url: string): VaultRecord =>
  ({ id: crypto.randomUUID(), folderId, type: "login", body: { type: "login", title, username, url }, revision: 1, updatedAt: "", deleted: false, permission: "owner", recordKey: null });
const ctx: PlanContext = {
  me: { id: "u-admin", email: "Admin@acme.test" }, users, invitedEmails: ["carol@acme.test"], folders,
  records: [
    { ...rec(personalId, "HQ ADDRESS", "", ""), body: { v: 2, type: "address", title: "HQ ADDRESS", data: { street1: "1 main st", postcode: "D01" } } },
    rec(null, "Netflix", "me@home.test", "https://netflix.com"), rec("elsewhere", "Company Visa", "", ""),
  ],
};

describe("buildPlan", () => {
  const plan = buildPlan(parseKeeperExport(commander), ctx);
  const folder = (name: string) => plan.folders.find((f) => f.name === name)!;

  it("maps shared folders to team folders, personal folders to private ones; reuses folders I own by name", () => {
    expect(plan.folders.map((f) => [f.name, f.kind, f.existingId])).toEqual([
      ["Engineering / Infra", "team", null], // a team folder with that name exists, but I don't own it
      ["Sales", "team", salesId],
      ["Personal", "private", personalId],
      ["Personal / Work", "private", null],
      ["No folder", "none", null],
    ]);
    expect(folder("Engineering / Infra").records.map((r) => r.body.title)).toEqual(["AWS root", "Postgres prod", "Bastion key"]);
  });

  it("maps members by email: active → added, unknown → invited, existing invite, unfinished sign-up, disabled, teams, me", () => {
    expect(folder("Engineering / Infra").members.map((m) => [m.label, m.status, m.permission, m.manager])).toEqual([
      ["admin@acme.test", "self", "edit", true],
      ["bob@acme.test", "add", "edit", true],
      ["carol@acme.test", "invited", "view", false],
      ["Platform Team", "team", "edit", false],
    ]);
    expect(folder("Engineering / Infra").members[1]).toMatchObject({ userId: "u-bob", publicKey: "pk-bob" });
    expect(folder("Sales").members.map((m) => [m.label, m.status, m.permission])).toEqual([["dave@acme.test", "disabled", "view"], ["eve@acme.test", "awaiting-setup", "edit"]]);
    expect(plan.teams).toEqual([{ name: "Platform Team", folders: ["Engineering / Infra"] }]);
    expect(plan.people.map((p) => [p.email, p.status])).toEqual([["bob@acme.test", "add"], ["carol@acme.test", "invited"], ["dave@acme.test", "disabled"], ["eve@acme.test", "awaiting-setup"]]);
  });

  it("flags duplicates already in the target folder and repeated in the export; copies multi-folder records", () => {
    expect(folder("Personal").duplicates).toBe(1); // HQ address (case-insensitive)
    expect(folder("No folder").duplicates).toBe(1); // Netflix
    expect(folder("Sales").records.map((r) => [r.body.title, r.duplicate])).toEqual([["Company Visa", false], ["Salesforce", false], ["Salesforce", true]]);
    expect(folder("Personal / Work").records.map((r) => r.body.title)).toEqual(["Salesforce"]);
    expect(plan.multiFolder).toBe(1);
    expect(plan.attachments).toEqual([{ title: "Bastion key", folder: "Engineering / Infra", files: ["bastion-ca.pub"] }]);
    expect(plan.skipped).toHaveLength(1);
  });

  it("totals follow the selection: excluded folders, duplicates skip/import, unticked invites", () => {
    const sel = defaultSelection();
    expect(totals(plan, sel)).toEqual({ folders: 4, newFolders: 2, records: 6, duplicates: 3, skippedDuplicates: 3, people: 3, addNow: 1, invites: 0, later: 2 });
    sel.duplicates = "import";
    expect(totals(plan, sel).records).toBe(9);
    sel.excluded.add(folder("Engineering / Infra").key);
    expect(totals(plan, sel)).toMatchObject({ folders: 3, records: 6, people: 1, addNow: 0 });
    expect(recordsToWrite(folder("Engineering / Infra"), sel)).toEqual([]);
  });

  it("unknown emails are invited unless unticked", () => {
    const p = buildPlan(parseKeeperExport(commander), { ...ctx, invitedEmails: [] });
    const carol = p.folders[0]!.members.find((m) => m.email === "carol@acme.test")!;
    expect(carol.status).toBe("invite");
    const sel = defaultSelection();
    expect(joins(carol, sel)).toBe(true);
    expect(totals(p, sel)).toMatchObject({ invites: 1, people: 3 });
    sel.noInvite.add("carol@acme.test");
    expect(joins(carol, sel)).toBe(false);
    expect(totals(p, sel)).toMatchObject({ invites: 0, people: 2 });
  });

  it("web-vault export: team folders with only me", () => {
    const p = buildPlan(parseKeeperExport(webvault), { ...ctx, records: [] });
    expect(p.source).toBe("web-vault");
    expect(p.folders.map((f) => [f.name, f.kind, f.members.length, f.records.length])).toEqual([["Dev Tools", "team", 0, 2], ["Home / Network", "private", 0, 1], ["No folder", "none", 0, 9]]);
  });

  it("typed duplicates: same type and identifying field; another type with the same title is not a duplicate", () => {
    expect(dupKey({ type: "card", title: "Visa", data: { number: "4242424242424242" } })).toBe(dupKey({ type: "card", title: "visa", data: { number: "4242 4242 4242 4242" } }));
    expect(dupKey({ type: "card", title: "Visa", data: { number: "4242424242424242" } })).not.toBe(dupKey({ type: "card", title: "Visa", data: { number: "5555555555554444" } }));
    expect(dupKey({ type: "address", title: "HQ" })).not.toBe(dupKey({ type: "login", title: "HQ" }));
    expect(dupKey({ type: "note", title: "N" })).toBe(dupKey({ type: "note", title: "n" }));
  });

  it("counts records per type (counts only)", () => {
    expect(planTypeCounts(plan)).toEqual([
      { type: "login", label: "Login", count: 5 }, { type: "address", label: "Address", count: 1 }, { type: "database", label: "Database credentials", count: 1 },
      { type: "card", label: "Payment card", count: 1 }, { type: "sshKey", label: "SSH key", count: 1 },
    ]);
  });
});
