import { describe, expect, it } from "vitest";
import { normalizeRecordBody } from "@clane-vault/crypto";
import { ImportFormatError } from "@/features/import/parsers";
import commander from "./fixtures/commander.json?raw";
import webvault from "./fixtures/webvault.json?raw";
import { flattenPath, humanize, parseKeeperExport } from "./keeper";

describe("parseKeeperExport: Keeper Commander JSON", () => {
  const ex = parseKeeperExport(commander);
  const byTitle = (t: string) => ex.items.filter((i) => i.body.title === t);

  it("detects Commander and reads shared folders with members, flattening nested paths", () => {
    expect(ex.source).toBe("commander");
    expect(ex.sharedFolders.map((f) => f.name)).toEqual(["Engineering / Infra", "Sales"]);
    const infra = ex.sharedFolders[0]!;
    expect(infra.members).toEqual([
      { name: "admin@acme.test", email: "admin@acme.test", manageRecords: true, manageUsers: true, canEdit: false },
      { name: "Bob@Acme.test", email: "bob@acme.test", manageRecords: true, manageUsers: true, canEdit: false },
      { name: "carol@acme.test", email: "carol@acme.test", manageRecords: false, manageUsers: false, canEdit: false },
      { name: "Platform Team", email: null, manageRecords: true, manageUsers: false, canEdit: false },
    ]);
  });

  it("every record is a valid record body", () => {
    for (const it of ex.items) expect(() => normalizeRecordBody(it.body)).not.toThrow();
  });

  it("login: otpauth custom field → totpSecret; extra URLs and custom fields → custom fields", () => {
    const [aws] = byTitle("AWS root");
    expect(aws!.body).toEqual({
      type: "login", title: "AWS root", username: "ops@acme.test", password: "Tg7#qL2v!Rm9zW4x", url: "https://console.aws.amazon.com", totpSecret: "JBSWY3DPEHPK3PXP",
      notes: "Break-glass only.",
      fields: [{ id: "f1", label: "Account ID", kind: "text", value: "123456789012" }, { id: "f2", label: "Website", kind: "url", value: "https://signin.aws.amazon.com" }],
    });
    expect(aws!.locations).toEqual([{ kind: "shared", folder: "Engineering / Infra", sub: null }]);
    // Legacy "TFC:Keeper" works too.
    expect(byTitle("Salesforce")[0]!.body.totpSecret).toBe("KRSXG5CTMVRXEZLU");
  });

  it("database credentials become a database record; subfolders of a shared folder stay in it", () => {
    const [pg] = byTitle("Postgres prod");
    expect(pg!.body).toEqual({ type: "database", title: "Postgres prod", username: "app", password: "pg-s3cret-pass", data: { host: "db.acme.internal", port: "5432", dbType: "postgresql" } });
    expect(pg!.keeperType).toBe("databaseCredentials");
    expect(pg!.locations).toEqual([{ kind: "shared", folder: "Engineering / Infra", sub: "Databases" }]);
  });

  it("bank cards, SSH keys and addresses map to their record types", () => {
    expect(byTitle("Company Visa")[0]!.body).toEqual({
      type: "card", title: "Company Visa", notes: "Monthly limit 10k.",
      data: { number: "4111111111111111", expiry: "12/30", cvv: "123", cardholder: "Acme Ltd", pin: "4321" },
    });
    const ssh = byTitle("Bastion key")[0]!;
    expect(ssh.body).toEqual({
      type: "sshKey", title: "Bastion key", username: "deploy",
      data: { privateKey: "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----", publicKey: "ssh-ed25519 AAAAC3Nza deploy@bastion", host: "bastion.acme.test", passphrase: "key-passphrase" },
      fields: [{ id: "f1", label: "Port", kind: "text", value: "22" }],
    });
    expect(ssh.attachments).toEqual(["bastion-ca.pub"]);
    const addr = byTitle("HQ address")[0]!;
    expect(addr.body).toEqual({ type: "address", title: "HQ address", data: { street1: "1 Main St", city: "Dublin", postcode: "D01", country: "IE" } });
    expect(addr.locations).toEqual([{ kind: "personal", folder: "Personal" }]);
  });

  it("records in several folders keep every location; legacy custom fields; no folder; unreadable records skipped", () => {
    expect(byTitle("Salesforce")[0]!.locations).toEqual([{ kind: "shared", folder: "Sales", sub: null }, { kind: "personal", folder: "Personal / Work" }]);
    const nf = byTitle("Netflix")[0]!;
    expect(nf.body.fields).toEqual([{ id: "f1", label: "Security question", kind: "text", value: "First pet: Rex" }]);
    expect(nf.body.notes).toBeUndefined();
    expect(nf.locations).toEqual([{ kind: "personal", folder: null }]);
    expect(ex.items).toHaveLength(8);
    expect(ex.skipped).toEqual([{ row: 9, reason: "No title" }]);
  });
});

describe("parseKeeperExport: Keeper web vault JSON", () => {
  it("records only: shared folders named on records become team folders without members", () => {
    const ex = parseKeeperExport(webvault);
    expect(ex.source).toBe("web-vault");
    expect(ex.sharedFolders).toEqual([{ path: "Dev Tools", name: "Dev Tools", members: [], canEdit: false, manageRecords: false }]);
    expect(ex.items.slice(0, 4).map((i) => [i.body.title, i.body.type, i.locations[0]])).toEqual([
      ["GitHub", "login", { kind: "shared", folder: "Dev Tools", sub: null }],
      ["Jira", "login", { kind: "shared", folder: "Dev Tools", sub: "Atlassian" }],
      ["Router", "login", { kind: "personal", folder: "Home / Network" }],
      ["Wi-Fi note", "note", { kind: "personal", folder: null }],
    ]);
    expect(ex.items[0]!.body.totpSecret).toBe("GEZDGNBVGY3TQOJQ");
    for (const it of ex.items) expect(() => normalizeRecordBody(it.body)).not.toThrow();
  });

  it("typed records: Wi-Fi, server, bank account, licence, passport, contact, membership; Keeper dates (epoch ms) become ISO dates", () => {
    const ex = parseKeeperExport(webvault);
    const body = (t: string) => ex.items.find((i) => i.body.title === t)!.body;
    expect(body("Office Wi-Fi")).toEqual({ type: "wifi", title: "Office Wi-Fi", password: "wifi-pass-123", data: { ssid: "acme-guest", security: "wpa2" } });
    expect(body("Build server")).toEqual({ type: "server", title: "Build server", username: "root", password: "srv-pass-456", data: { hostname: "10.0.0.5", port: "2222" } });
    expect(body("Ops bank")).toEqual({
      type: "bankAccount", title: "Ops bank", username: "acme-ops", password: "bank-pass-789",
      data: { accountNumber: "IE29AIBK93115212345678", routing: "AIBKIE2D", accountName: "Acme Ltd" }, fields: [{ id: "f1", label: "Account type", kind: "text", value: "Checking" }],
    });
    expect(body("Office licence")).toEqual({ type: "softwareLicence", title: "Office licence", data: { licenceKey: "ABCD-EFGH-1234", expiryDate: "2030-01-01", purchaseDate: "2024-01-01" } });
    expect(body("Ada passport")).toEqual({
      type: "identity", title: "Ada passport", data: { docType: "passport", fullName: "Ada Lovelace", number: "P1234567", expiryDate: "2030-01-01", issueDate: "2020-01-01" },
      fields: [{ id: "f1", label: "Birth date", kind: "date", value: "1980-01-01" }],
    });
    expect(body("Jane Doe")).toEqual({ type: "contact", title: "Jane Doe", data: { name: "Jane Doe", company: "Acme", email: "jane@acme.test", phone: "+353 1 234 5678" } });
    expect(body("Gym")).toEqual({ type: "membership", title: "Gym", password: "gym-pw", data: { memberId: "M-998", organisation: "FitCo", expiryDate: "2030-01-01" } });
    expect(body("Alarm")).toEqual({ type: "note", title: "Alarm", notes: "Front door", fields: [{ id: "f1", label: "Floor", kind: "text", value: "3" }, { id: "f2", label: "Code", kind: "secret", value: "4321" }] });
  });

  it("rejects files that aren't Keeper JSON", () => {
    expect(() => parseKeeperExport("title,login\nx,y")).toThrow(ImportFormatError);
    expect(() => parseKeeperExport(JSON.stringify({ items: [] }))).toThrow(/isn't a Keeper export/);
    expect(() => parseKeeperExport("  ")).toThrow(/empty/);
  });
});

describe("helpers", () => {
  it("flattens Keeper paths and humanizes field names", () => {
    expect(flattenPath("A\\B\\C")).toBe("A / B / C");
    expect(flattenPath("Back\\\\slash\\Sub")).toBe("Back\\slash / Sub");
    expect(humanize("cardExpirationDate")).toBe("Expires");
    expect(humanize("someCustomThing")).toBe("Some custom thing");
  });
});
