import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { RECORD_TYPE_DEFS, RECORD_TYPES, normalizeRecordBody, type RecordBody } from "@clane-vault/crypto";
import { attentionReasons } from "./attention";
import { filterRecords } from "./filter";
import { NewRecordDialog } from "./NewRecordDialog";
import { RecordEditor } from "./RecordEditor";
import { RecordList } from "./RecordList";
import { RecordPanel } from "./RecordPanel";
import { recordSubtitle, searchableText, shownFields } from "./recordKinds";
import type { VaultRecord } from "./types";

vi.mock("@/lib/clipboard", () => ({ copySecret: vi.fn(async () => undefined) }));
import { copySecret } from "@/lib/clipboard";

const rec = (body: RecordBody, o: Partial<VaultRecord> = {}): VaultRecord => ({
  id: o.id ?? crypto.randomUUID(), folderId: null, type: body.type === "login" ? "login" : "item", body, revision: 1, updatedAt: "2026-10-01T00:00:00Z",
  deleted: false, permission: "owner", recordKey: new Uint8Array(32), ...o,
});

const card: RecordBody = { v: 2, type: "card", title: "Company Visa", notes: "Travel only",
  data: { cardholder: "Ada Lovelace", number: "4242424242424242", expiry: "12/29", cvv: "737", pin: "9876", billingAddress: "1 Main St\nDublin" },
  fields: [{ id: "f1", label: "Bank hotline", kind: "phone", value: "+353 1 555 0100" }, { id: "f2", label: "3-D Secure code", kind: "secret", value: "s3cure-phrase" }] };
const server: RecordBody = { v: 2, type: "server", title: "Build box", username: "deploy", password: "Zq8$wP3n!Lk7xV2m", data: { hostname: "10.20.0.5", port: "2222", protocol: "ssh" },
  fields: [{ id: "otp", label: "Console OTP", kind: "totp", value: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" }] };
const ssh: RecordBody = { v: 2, type: "sshKey", title: "Deploy key", username: "git", data: { host: "github.com", privateKey: "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk\n-----END OPENSSH PRIVATE KEY-----", publicKey: "ssh-ed25519 AAAAC3Nz deploy", passphrase: "horse battery" } };
const wifi: RecordBody = { v: 2, type: "wifi", title: "Office", password: "figma123", data: { ssid: "Clane-Staff", security: "wpa3" } };
const licence: RecordBody = { v: 2, type: "softwareLicence", title: "Acrobat", data: { product: "Acrobat Pro", licenceKey: "AAAA-BBBB-CCCC", version: "2026" } };

describe("record types in the panel", () => {
  it("a card: number masked to its last four, reveal and copy for each secret, plain fields shown", async () => {
    render(<RecordPanel record={rec(card)} folderName={null} onClose={vi.fn()} onEdit={vi.fn()} onTrash={vi.fn()} />);
    expect(screen.getByText("Payment card")).toBeInTheDocument();
    expect(screen.getByLabelText("Card number")).toHaveTextContent("•••• •••• •••• 4242");
    expect(screen.queryByText("737")).not.toBeInTheDocument();
    expect(screen.getByLabelText("Cardholder")).toHaveTextContent("Ada Lovelace");
    expect(screen.getByLabelText("Expiry")).toHaveTextContent("12/29");
    await userEvent.click(screen.getByRole("button", { name: "Show card number" }));
    expect(screen.getByLabelText("Card number")).toHaveTextContent("4242 4242 4242 4242");
    await userEvent.click(screen.getByRole("button", { name: "Copy card number" }));
    expect(copySecret).toHaveBeenLastCalledWith("4242424242424242");
    await userEvent.click(screen.getByRole("button", { name: "Copy security code" }));
    expect(copySecret).toHaveBeenLastCalledWith("737");
    expect(screen.getByRole("button", { name: "Show PIN" })).toBeInTheDocument();
    expect(screen.getByLabelText("Bank hotline")).toHaveTextContent("+353 1 555 0100");
    expect(screen.queryByText("s3cure-phrase")).not.toBeInTheDocument();
    // A card has no password: no strength meter.
    expect(screen.queryByText(/Strong|Weak|Fair/)).not.toBeInTheDocument();
  });

  it("use only: every secret-kind field stays hidden with no reveal (card number, CVV, PIN, custom secrets, keys)", async () => {
    for (const body of [card, ssh, server, licence]) {
      const { unmount } = render(<RecordPanel record={rec(body, { permission: "use" })} folderName={null} onClose={vi.fn()} onEdit={vi.fn()} onTrash={vi.fn()} />);
      expect(screen.queryAllByRole("button", { name: /^Show / })).toHaveLength(0);
      for (const f of shownFields(body).filter((x) => x.kind === "secret" || x.kind === "hiddenMultiline")) expect(document.body).not.toHaveTextContent(f.value);
      unmount();
    }
    render(<RecordPanel record={rec(card, { permission: "use" })} folderName={null} onClose={vi.fn()} onEdit={vi.fn()} onTrash={vi.fn()} />);
    expect(screen.getAllByText("Use only: you can copy it, not view it.").length).toBeGreaterThanOrEqual(4);
  });

  it("server credentials: host, port and protocol shown; password with strength; a custom TOTP field shows a live code", async () => {
    render(<RecordPanel record={rec(server)} folderName={null} onClose={vi.fn()} onEdit={vi.fn()} onTrash={vi.fn()} />);
    expect(screen.getByText("Server credentials")).toBeInTheDocument();
    expect(screen.getByLabelText("Hostname or IP")).toHaveTextContent("10.20.0.5");
    expect(screen.getByLabelText("Protocol")).toHaveTextContent("SSH");
    expect(screen.getByText("Strong")).toBeInTheDocument();
    // The code is computed asynchronously (WebCrypto); "—" is shown until then.
    await waitFor(() => expect(screen.getByLabelText("Console OTP")).toHaveTextContent(/^\d{3} \d{3}$/));
    expect(screen.queryByText(server.fields![0]!.value)).not.toBeInTheDocument();
  });

  it("SSH key: the private key is hidden until revealed, the public key is shown", async () => {
    render(<RecordPanel record={rec(ssh)} folderName={null} onClose={vi.fn()} onEdit={vi.fn()} onTrash={vi.fn()} />);
    expect(screen.getByLabelText("Public key")).toHaveTextContent("ssh-ed25519");
    expect(screen.getByLabelText("Private key")).not.toHaveTextContent("BEGIN");
    await userEvent.click(screen.getByRole("button", { name: "Show private key" }));
    expect(screen.getByLabelText("Private key")).toHaveTextContent("BEGIN OPENSSH PRIVATE KEY");
  });
});

describe("record types in the editor", () => {
  it("renders every type's template fields", () => {
    for (const t of RECORD_TYPES) {
      const { unmount } = render(<RecordEditor mode="create" type={t} initial={{ type: t, title: "X" }} folderId={null} folders={[]} onSave={vi.fn()} onCancel={vi.fn()} />);
      for (const f of RECORD_TYPE_DEFS[t].fields) expect(screen.getByText(f.core && f.kind === "totp" ? `${f.label} (optional)` : f.label, { selector: "label" })).toBeInTheDocument();
      expect(screen.getByLabelText("Notes")).toBeInTheDocument();
      unmount();
    }
  });

  it("a card: digits grouped as typed, a Luhn hint, MM/YY expiry, values saved in data", async () => {
    const onSave = vi.fn(async (_b: RecordBody, _f: string | null) => undefined);
    render(<RecordEditor mode="create" type="card" initial={{ type: "card", title: "Visa" }} folderId={null} folders={[]} onSave={onSave} onCancel={vi.fn()} />);
    expect(screen.getByRole("heading", { name: "New payment card" })).toBeInTheDocument();
    expect(screen.getByLabelText("Cardholder")).toHaveFocus();
    await userEvent.type(screen.getByLabelText("Cardholder"), "Ada Lovelace");
    const num = screen.getByLabelText("Card number") as HTMLInputElement;
    expect(num.type).toBe("password");
    await userEvent.type(num, "4242424242424241");
    expect(num.value).toBe("4242 4242 4242 4241");
    expect(screen.getByText(/doesn't pass the card check/)).toBeInTheDocument();
    await userEvent.clear(num); await userEvent.type(num, "4242424242424242");
    expect(screen.queryByText(/doesn't pass the card check/)).not.toBeInTheDocument();
    const exp = screen.getByLabelText("Expiry") as HTMLInputElement;
    await userEvent.type(exp, "1329");
    expect(exp.value).toBe("13/29");
    await userEvent.type(screen.getByLabelText("Security code"), "737");
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(screen.getByRole("alert")).toHaveTextContent("Expiry: use MM/YY");
    await userEvent.clear(exp); await userEvent.type(exp, "1229");
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    const body = onSave.mock.calls[0]![0] as RecordBody;
    expect(body).toEqual({ type: "card", title: "Visa", data: { cardholder: "Ada Lovelace", number: "4242424242424242", expiry: "12/29", cvv: "737" } });
    expect(() => normalizeRecordBody(body)).not.toThrow();
  });

  it("server credentials: port must be a number in range; password can be generated", async () => {
    const onSave = vi.fn(async (_b: RecordBody, _f: string | null) => undefined);
    render(<RecordEditor mode="create" type="server" initial={{ type: "server", title: "Box" }} folderId={null} folders={[]} onSave={onSave} onCancel={vi.fn()} />);
    await userEvent.type(screen.getByLabelText("Hostname or IP"), "10.0.0.5");
    await userEvent.type(screen.getByLabelText("Port"), "99999");
    await userEvent.click(screen.getByRole("button", { name: "Generate password" }));
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(screen.getByRole("alert")).toHaveTextContent("Port: use a number from 1 to 65535.");
    await userEvent.clear(screen.getByLabelText("Port")); await userEvent.type(screen.getByLabelText("Port"), "22ab");
    expect(screen.getByLabelText("Port")).toHaveValue("22");
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    const body = onSave.mock.calls[0]![0] as RecordBody;
    expect(body).toMatchObject({ type: "server", title: "Box", data: { hostname: "10.0.0.5", port: "22" } });
    expect(body.password).toHaveLength(20);
    expect(body.passwordChangedAt).toBeTruthy();
  });

  it("SSH key: the private key is a hidden multi-line field with reveal; edits keep the rest", async () => {
    const onSave = vi.fn(async (_b: RecordBody, _f: string | null) => undefined);
    render(<RecordEditor mode="edit" type="sshKey" initial={ssh} folderId={null} folders={[]} onSave={onSave} onCancel={vi.fn()} />);
    const pk = screen.getByLabelText("Private key");
    expect(pk.tagName).toBe("TEXTAREA");
    expect(pk).toHaveAttribute("data-masked", "true");
    await userEvent.click(screen.getByRole("button", { name: "Show private key" }));
    expect(pk).not.toHaveAttribute("data-masked");
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    const { v: _v, ...rest } = ssh;
    expect(onSave).toHaveBeenCalledWith(rest, null);
  });

  it("identity: document type is a list", async () => {
    const onSave = vi.fn(async (_b: RecordBody, _f: string | null) => undefined);
    render(<RecordEditor mode="create" type="identity" initial={{ type: "identity", title: "Passport" }} folderId={null} folders={[]} onSave={onSave} onCancel={vi.fn()} />);
    await userEvent.click(screen.getByRole("combobox", { name: "Document type" }));
    await userEvent.click(await screen.findByRole("option", { name: "Driving licence" }));
    await userEvent.type(screen.getByLabelText("Expiry date"), "2031-05-01");
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(onSave).toHaveBeenCalledWith({ type: "identity", title: "Passport", data: { docType: "drivingLicence", expiryDate: "2031-05-01" } }, null);
  });

  it("custom fields: add, label, kind, reorder, remove; a TOTP field is checked; blank ones dropped", async () => {
    const onSave = vi.fn(async (_b: RecordBody, _f: string | null) => undefined);
    render(<RecordEditor mode="create" type="note" initial={{ type: "note", title: "Runbook" }} folderId={null} folders={[]} onSave={onSave} onCancel={vi.fn()} />);
    await userEvent.click(screen.getByRole("button", { name: "Add field" }));
    expect(screen.getByLabelText("Field 1 label")).toHaveFocus();
    await userEvent.type(screen.getByLabelText("Field 1 label"), "Account ID");
    await userEvent.type(screen.getAllByPlaceholderText("Value")[0]!, "123456");
    await userEvent.click(screen.getByRole("button", { name: "Add field" }));
    await userEvent.type(screen.getByLabelText("Field 2 label"), "Root token");
    await userEvent.click(screen.getByRole("combobox", { name: "Field 2 type" }));
    await userEvent.click(await screen.findByRole("option", { name: "Secret (hidden)" }));
    const secret = screen.getAllByPlaceholderText("Value")[1] as HTMLInputElement;
    expect(secret.type).toBe("password");
    await userEvent.type(secret, "tok-123");
    await userEvent.click(screen.getByRole("button", { name: "Add field" }));
    await userEvent.type(screen.getByLabelText("Field 3 label"), "2FA");
    await userEvent.click(screen.getByRole("combobox", { name: "Field 3 type" }));
    await userEvent.click(await screen.findByRole("option", { name: "2FA code (TOTP)" }));
    await userEvent.type(screen.getByPlaceholderText("2FA setup key"), "not base32!");
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(screen.getByRole("alert")).toHaveTextContent("2FA: that 2FA secret isn't valid.");
    await userEvent.click(screen.getByRole("button", { name: "Remove field 3" }));
    await userEvent.click(screen.getByRole("button", { name: "Move field 2 up" }));
    await userEvent.click(screen.getByRole("button", { name: "Add field" })); // left blank: dropped
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    const body = onSave.mock.calls[0]![0] as RecordBody;
    expect(body.fields!.map((f) => [f.label, f.kind, f.value])).toEqual([["Root token", "secret", "tok-123"], ["Account ID", "text", "123456"]]);
    expect(() => normalizeRecordBody(body)).not.toThrow();
  });

  it("a custom field needs a label", async () => {
    render(<RecordEditor mode="create" type="login" initial={{ type: "login", title: "X" }} folderId={null} folders={[]} onSave={vi.fn()} onCancel={vi.fn()} />);
    await userEvent.click(screen.getByRole("button", { name: "Add field" }));
    await userEvent.type(screen.getByPlaceholderText("Value"), "v");
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(screen.getByRole("alert")).toHaveTextContent("Give every custom field a label.");
  });
});

describe("the type picker", () => {
  it("lists every type, grouped, with an icon", async () => {
    const onNext = vi.fn();
    render(<NewRecordDialog open folders={[]} onNext={onNext} onCancel={vi.fn()} />);
    await userEvent.click(screen.getByRole("combobox", { name: "Record Type" }));
    const list = await screen.findByRole("listbox");
    for (const g of ["Logins & access", "Payments & finance", "Identity", "Other"]) expect(within(list).getByText(g)).toBeInTheDocument();
    const options = within(list).getAllByRole("option");
    expect(options).toHaveLength(RECORD_TYPES.length);
    for (const o of options) expect(o.querySelector("svg")).not.toBeNull();
    await userEvent.click(within(list).getByRole("option", { name: "SSH key" }));
    await userEvent.type(screen.getByLabelText("Title"), "Deploy key");
    await userEvent.click(screen.getByRole("button", { name: "Next" }));
    expect(onNext).toHaveBeenCalledWith({ type: "sshKey", title: "Deploy key", folderId: null });
  });
});

describe("record types in the list", () => {
  it("rows show the type glyph and a subtitle that never holds a secret", () => {
    const records = [rec(card, { id: "c" }), rec(server, { id: "s" }), rec(wifi, { id: "w" }), rec(ssh, { id: "k" })];
    render(<RecordList groups={[]} flat={records} mode="flat" selectedId={null} onSelect={vi.fn()} />);
    const rows = screen.getAllByTestId("record-row");
    expect(rows[0]).toHaveTextContent("•••• 4242 · Ada Lovelace");
    expect(rows[0]).not.toHaveTextContent("4242424242424242");
    expect(within(rows[0]!).getByTestId("record-avatar")).toHaveAttribute("data-kind", "card");
    expect(rows[1]).toHaveTextContent("deploy@10.20.0.5:2222");
    expect(rows[2]).toHaveTextContent("Clane-Staff");
    expect(rows[3]).toHaveTextContent("git@github.com");
  });

  it("subtitles for every type", () => {
    expect(recordSubtitle({ type: "bankAccount", title: "x", data: { bank: "AIB", accountNumber: "IE29 AIBK 9311 5212 3456 78" } })).toBe("AIB · •••• 5678");
    expect(recordSubtitle({ type: "database", title: "x", data: { dbType: "postgresql", host: "db", port: "5432", database: "app" } })).toBe("PostgreSQL · db:5432/app");
    expect(recordSubtitle({ type: "identity", title: "x", data: { docType: "passport", fullName: "Ada L", number: "PX123" } })).toBe("Passport · Ada L");
    expect(recordSubtitle({ type: "apiKey", title: "x", data: { service: "Stripe", secret: "sk_live" } })).toBe("Stripe");
    expect(recordSubtitle({ type: "address", title: "x", data: { street1: "1 Main St", city: "Dublin", country: "Ireland" } })).toBe("1 Main St · Dublin · Ireland");
    expect(recordSubtitle({ type: "contact", title: "x", data: { name: "Ana", company: "Acme" } })).toBe("Ana · Acme");
    expect(recordSubtitle({ type: "membership", title: "x", data: { organisation: "RIAI", memberId: "M-7" } })).toBe("RIAI · M-7");
    expect(recordSubtitle({ type: "softwareLicence", title: "x", data: { product: "Office", licenceKey: "K" } })).toBe("Office");
    expect(recordSubtitle({ type: "card", title: "x" })).toBe("Payment card");
  });
});

describe("search and the type filter", () => {
  const records = [rec(card, { id: "c" }), rec(server, { id: "s" }), rec(wifi, { id: "w" }), rec(licence, { id: "l" })];
  const find = (query: string, type: RecordBody["type"] | null = null) => filterRecords(records, { view: "vault", query, sort: "name", type }).map((r) => r.id);
  it("finds non-secret fields (host, SSID, cardholder, option labels, custom text)", () => {
    expect(find("10.20.0")).toEqual(["s"]);
    expect(find("clane-staff")).toEqual(["w"]);
    expect(find("lovelace")).toEqual(["c"]);
    expect(find("wpa3")).toEqual(["w"]);
    expect(find("555 0100")).toEqual(["c"]);
  });
  it("never matches a secret: card number, CVV, PIN, custom secrets, passwords, licence keys", () => {
    for (const q of ["4242424242", "737", "9876", "s3cure", "Zq8$", "figma123", "AAAA-BBBB", "GEZDGNBV"]) expect(find(q)).toEqual([]);
    expect(searchableText(card).join(" ")).not.toContain("4242424242424242");
  });
  it("filters by type", () => {
    expect(find("", "card")).toEqual(["c"]);
    expect(find("", "login")).toEqual([]);
  });
});

describe("password health over record types", () => {
  it("counts login, server, database, bank, Wi-Fi and membership passwords; not CVVs, PINs, card numbers, licence keys or SSH keys", () => {
    const now = Date.parse("2026-10-06T00:00:00Z");
    const weak = (b: RecordBody, id: string) => rec(b, { id });
    const reasons = attentionReasons([
      weak(wifi, "wifi"), weak({ v: 2, type: "membership", title: "Gym", password: "abc" }, "member"),
      weak({ v: 2, type: "database", title: "DB", password: "pw1" }, "db"), weak({ v: 2, type: "bankAccount", title: "Bank", password: "pw2" }, "bank"),
      weak({ ...card, data: { ...card.data!, cvv: "1", pin: "1", number: "1" } }, "card"), weak(licence, "lic"),
      weak({ ...ssh, data: { ...ssh.data!, passphrase: "a" } }, "ssh"),
      weak({ v: 2, type: "note", title: "n", fields: [{ id: "x", label: "Password", kind: "secret", value: "a" }] }, "custom"),
    ], now);
    expect([...reasons.keys()].sort()).toEqual(["bank", "db", "member", "wifi"]);
  });
});
