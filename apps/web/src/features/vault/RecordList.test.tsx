import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import * as clipboard from "@/lib/clipboard";
import { RecordList } from "./RecordList";
import type { VaultFolder, VaultRecord } from "./types";

const r = (id: string, title: string, folderId: string | null, extra: Partial<VaultRecord> = {}): VaultRecord => ({ id, folderId, type: "login", revision: 1, updatedAt: "", deleted: false, permission: "owner", recordKey: null, body: { type: "login", title, username: `${title}@x`, password: `pw-${title}` }, ...extra });
const note = (id: string, title: string, folderId: string | null): VaultRecord => ({ ...r(id, title, folderId), type: "note", body: { type: "note", title, notes: "secret" } });
const priv: VaultFolder = { id: "f", name: "Infrastructure", kind: "private", deleted: false };
const team: VaultFolder = { id: "t", name: "Marketing", kind: "team", deleted: false, myPermission: "edit", folderKey: new Uint8Array(32),
  members: ["Olga Owner", "Max Member", "Sam Smith", "Kim Lee"].map((name, i) => ({ userId: `u${i}`, name, email: `${i}@x`, publicKey: "", permission: "edit" as const })) };

describe("RecordList", () => {
  it("expands a folder and selects a record", async () => {
    const onSelect = vi.fn();
    const groups = [{ folder: priv, records: [r("1", "AWS", "f")] }, { folder: null, records: [r("2", "Stripe", null)] }];
    render(<RecordList groups={groups} flat={[]} mode="folders" selectedId={null} onSelect={onSelect} />);
    expect(screen.getAllByText("1 record")).toHaveLength(2);
    expect(screen.queryByText("AWS")).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /^Infrastructure/ }));
    await userEvent.click(screen.getByRole("button", { name: /AWS/ }));
    expect(onSelect).toHaveBeenCalledWith("1");
  });

  it("shows an empty state with a next step", () => {
    render(<RecordList groups={[]} flat={[]} mode="folders" selectedId={null} onSelect={vi.fn()} />);
    expect(screen.getByText("No records yet")).toBeInTheDocument();
    expect(screen.getByText(/Use \+ New to add your first login/)).toBeInTheDocument();
  });

  it("folder glyphs: private, shared (people badge, no Team chip), shared without its key (lock), No folder; open when expanded", async () => {
    const locked: VaultFolder = { ...team, id: "l", name: "Locked", folderKey: null, members: [] };
    const groups = [{ folder: priv, records: [] }, { folder: team, records: [] }, { folder: locked, records: [] }, { folder: null, records: [r("2", "Stripe", null)] }];
    render(<RecordList groups={groups} flat={[]} mode="folders" selectedId={null} onSelect={vi.fn()} />);
    const glyph = (name: RegExp) => within(screen.getByRole("button", { name })).getByTestId("folder-glyph");
    expect(glyph(/^Infrastructure/)).toHaveAttribute("data-kind", "private");
    expect(within(glyph(/^Infrastructure/)).queryByTestId("people-badge")).not.toBeInTheDocument();
    expect(glyph(/^Marketing/)).toHaveAttribute("data-kind", "team");
    expect(within(glyph(/^Marketing/)).getByTestId("people-badge")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^Marketing, shared folder/ })).toBeInTheDocument();
    expect(screen.queryByText("Team")).not.toBeInTheDocument();
    expect(glyph(/^Locked/)).toHaveAttribute("data-locked", "true");
    expect(glyph(/^No folder/)).toHaveAttribute("data-kind", "none");
    expect(glyph(/^Infrastructure/)).not.toHaveAttribute("data-open");
    await userEvent.click(screen.getByRole("button", { name: /^Infrastructure/ }));
    expect(glyph(/^Infrastructure/)).toHaveAttribute("data-open", "true");
  });

  it("a shared folder shows up to three members plus +n, and its count as plain text", () => {
    render(<RecordList groups={[{ folder: team, records: [r("1", "Ads", "t"), r("2", "Blog", "t")] }]} flat={[]} mode="folders" selectedId={null} onSelect={vi.fn()} />);
    const row = screen.getByRole("button", { name: /^Marketing/ });
    expect(row).toHaveTextContent("OO");
    expect(row).toHaveTextContent("+1");
    expect(row).not.toHaveTextContent("KL");
    expect(within(row).getByText("4 people")).toBeInTheDocument();
    expect(within(row).getByText("2 records")).toBeInTheDocument();
  });

  it("an open, empty folder shows a hint with New record (only where a record can be filed)", async () => {
    const onNewRecord = vi.fn();
    const viewOnly: VaultFolder = { ...team, id: "v", name: "Read only", myPermission: "view" };
    render(<RecordList groups={[{ folder: priv, records: [] }, { folder: viewOnly, records: [] }]} flat={[]} mode="folders" selectedId={null} onSelect={vi.fn()} onNewRecord={onNewRecord} />);
    await userEvent.click(screen.getByRole("button", { name: /^Infrastructure/ }));
    expect(screen.getByText("No records here yet")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "New record" }));
    expect(onNewRecord).toHaveBeenCalledWith("f");
    await userEvent.click(screen.getByRole("button", { name: /^Infrastructure/ }));
    await userEvent.click(screen.getByRole("button", { name: /^Read only/ }));
    expect(screen.getByText("No records here yet")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "New record" })).not.toBeInTheDocument();
  });

  it("records: 22 px avatar, note glyph for secure notes, second line falls back to the website, then Secure note", async () => {
    const site = r("3", "Site", "f", { body: { type: "login", title: "Site", url: "https://www.example.com/login" } });
    render(<RecordList groups={[{ folder: priv, records: [r("1", "AWS", "f"), note("2", "VPN runbook", "f"), site] }]} flat={[]} mode="folders" selectedId="1" onSelect={vi.fn()} />);
    await userEvent.click(screen.getByRole("button", { name: /^Infrastructure/ }));
    const aws = screen.getByRole("button", { name: /AWS/ });
    expect(aws).toHaveAttribute("aria-current", "true");
    expect(within(aws).getByTestId("record-avatar")).toHaveClass("size-[22px]");
    const vpn = screen.getByRole("button", { name: /VPN runbook/ });
    expect(within(vpn).getByTestId("record-avatar")).toHaveAttribute("data-kind", "note");
    expect(vpn).toHaveTextContent("Secure note");
    expect(screen.getByRole("button", { name: /^Site/ })).toHaveTextContent("example.com/login");
  });

  it("hover copy: username and password for logins, without selecting the row; none for notes", async () => {
    const copy = vi.spyOn(clipboard, "copySecret").mockResolvedValue();
    const onSelect = vi.fn();
    render(<RecordList groups={[]} flat={[r("1", "AWS", null), note("2", "VPN runbook", null)]} mode="flat" selectedId={null} onSelect={onSelect} />);
    const [aws, vpn] = screen.getAllByTestId("record-row");
    await userEvent.click(within(aws!).getByRole("button", { name: "Copy this record's password" }));
    expect(copy).toHaveBeenCalledWith("pw-AWS");
    await userEvent.click(within(aws!).getByRole("button", { name: "Copy this record's username" }));
    expect(copy).toHaveBeenCalledWith("AWS@x");
    expect(onSelect).not.toHaveBeenCalled();
    expect(within(vpn!).queryByRole("button", { name: /^Copy/ })).not.toBeInTheDocument();
    copy.mockRestore();
  });

  it("\"Use only\" records never get the list's copy-password shortcut; the Trash gets no copy buttons", () => {
    const { unmount } = render(<RecordList groups={[]} flat={[r("1", "Team DB", null, { permission: "use", sharedBy: "Max" })]} mode="flat" view="shared" selectedId={null} onSelect={vi.fn()} />);
    expect(screen.queryByRole("button", { name: "Copy this record's password" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Copy this record's username" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Team DB/ })).toHaveTextContent("Use only");
    unmount();
    render(<RecordList groups={[]} flat={[r("2", "Old", null, { deleted: true })]} mode="flat" view="trash" selectedId={null} onSelect={vi.fn()} />);
    expect(screen.queryByRole("button", { name: /^Copy/ })).not.toBeInTheDocument();
  });

  it("attention: a dot in the vault, reason chips in Needs attention, nothing in the Trash; shared marker and folder crumb", () => {
    const reasons = new Map([["1", ["weak" as const]]]);
    const shared = r("1", "AWS", "t", { sharedWith: [{ userId: "u", name: "Max", permission: "view" }] });
    const folderOf = (id: string | null) => (id === "t" ? team : null);
    const { unmount } = render(<RecordList groups={[]} flat={[shared]} mode="flat" reasons={reasons} folderOf={folderOf} selectedId={null} onSelect={vi.fn()} />);
    const row = screen.getByRole("button", { name: /AWS/ });
    expect(row).toHaveTextContent("Needs attention");
    expect(row).not.toHaveTextContent("Weak");
    expect(row).toHaveTextContent("Shared with 1 person");
    expect(row).toHaveTextContent("Marketing");
    expect(within(row).getByTestId("folder-glyph")).toHaveAttribute("data-kind", "team");
    unmount();
    const { unmount: u2 } = render(<RecordList groups={[]} flat={[shared]} mode="flat" view="attention" reasons={reasons} selectedId={null} onSelect={vi.fn()} />);
    expect(screen.getByRole("button", { name: /AWS/ })).toHaveTextContent("Weak");
    u2();
    render(<RecordList groups={[]} flat={[{ ...shared, deleted: true }]} mode="flat" view="trash" reasons={reasons} selectedId={null} onSelect={vi.fn()} />);
    expect(screen.getByRole("button", { name: /AWS/ })).not.toHaveTextContent("Needs attention");
  });
});
