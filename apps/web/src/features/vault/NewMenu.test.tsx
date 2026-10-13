import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { NewMenu } from "./NewMenu";
import { NewRecordDialog } from "./NewRecordDialog";
import type { VaultFolder } from "./types";

describe("NewMenu", () => {
  it("Personal: titled Create New, lists Record, Folder, Shared Folder (an organisation's), Generate Password, then Import", async () => {
    const onNew = vi.fn();
    render(<NewMenu onNew={onNew} team={false} />);
    await userEvent.click(screen.getByRole("button", { name: "New" }));
    expect(screen.getByText("Create New")).toBeInTheDocument();
    expect(screen.getAllByRole("menuitem").map((x) => x.getAttribute("aria-label") ?? x.textContent)).toEqual(["Record", "Folder", "Shared Folder", "Generate Password", "Import"]);
    const shared = screen.getByRole("menuitem", { name: "Shared Folder" });
    expect(shared).toHaveAttribute("aria-disabled", "true");
    expect(shared).toHaveAccessibleDescription("Shared folders belong to an organisation: switch to one");
    await userEvent.click(screen.getByRole("menuitem", { name: "Record" }));
    expect(onNew).toHaveBeenCalledWith("record");
  });

  it("works from the keyboard", async () => {
    const onNew = vi.fn();
    render(<NewMenu onNew={onNew} team={false} />);
    screen.getByRole("button", { name: "New" }).focus();
    await userEvent.keyboard("{Enter}");
    // Enter opens the menu on its first item (Record).
    await userEvent.keyboard("{ArrowDown}{Enter}");
    expect(onNew).toHaveBeenCalledWith("folder");
  });

  it("in an organisation: shared folders and records in them; no private folder, and imports go to Personal", async () => {
    const onNew = vi.fn();
    render(<NewMenu onNew={onNew} team />);
    await userEvent.click(screen.getByRole("button", { name: "New" }));
    expect(screen.getAllByRole("menuitem").map((x) => x.getAttribute("aria-label") ?? x.textContent)).toEqual(["Record", "Shared Folder", "Generate Password", "Import"]);
    const imp = screen.getByRole("menuitem", { name: "Import" });
    expect(imp).toHaveAttribute("aria-disabled", "true");
    expect(imp).toHaveAccessibleDescription("Imports go to your Personal vault");
    await userEvent.click(screen.getByRole("menuitem", { name: "Shared Folder" }));
    expect(onNew).toHaveBeenCalledWith("team");
  });

  it("in an organisation without a shared folder to add to, Record says why it can't", async () => {
    render(<NewMenu onNew={vi.fn()} team recordHint="Create a shared folder first" />);
    await userEvent.click(screen.getByRole("button", { name: "New" }));
    const rec = screen.getByRole("menuitem", { name: "Record" });
    expect(rec).toHaveAttribute("aria-disabled", "true");
    expect(rec).toHaveAccessibleDescription("Create a shared folder first");
  });
});

const folders: VaultFolder[] = [
  { id: "f1", name: "Infrastructure", kind: "private", deleted: false },
  { id: "t1", name: "Ops", kind: "team", deleted: false, myPermission: "edit" },
  { id: "t2", name: "Finance", kind: "team", deleted: false, myPermission: "view" },
  { id: "old", name: "Old", kind: "private", deleted: true },
];

describe("NewRecordDialog", () => {
  it("starts in the open folder, offers only folders I can file into, and Next hands over type, title and folder", async () => {
    const onNext = vi.fn();
    render(<NewRecordDialog open folders={folders} folderId="t1" onNext={onNext} onCancel={vi.fn()} />);
    expect(screen.getByRole("combobox", { name: "Location" })).toHaveTextContent("Ops");
    expect(screen.getByRole("combobox", { name: "Record Type" })).toHaveTextContent("Login");
    expect(screen.getByLabelText("Title")).toHaveFocus();
    expect(screen.getByRole("button", { name: "Next" })).toBeDisabled();
    await userEvent.click(screen.getByRole("combobox", { name: "Location" }));
    expect((await screen.findAllByRole("option")).map((o) => o.textContent)).toEqual(["No folder", "Infrastructure", "Ops · Shared"]);
    await userEvent.click(screen.getByRole("option", { name: "Infrastructure" }));
    await userEvent.click(screen.getByRole("combobox", { name: "Record Type" }));
    await userEvent.click(await screen.findByRole("option", { name: "Secure note" }));
    await userEvent.type(screen.getByLabelText("Title"), "Office Wi-Fi{Enter}");
    expect(onNext).toHaveBeenCalledWith({ type: "note", title: "Office Wi-Fi", folderId: "f1" });
  });

  it("Enter does nothing until there is a title; a folder I can't file into falls back to No folder", async () => {
    const onNext = vi.fn();
    render(<NewRecordDialog open folders={folders} folderId="t2" onNext={onNext} onCancel={vi.fn()} />);
    expect(screen.getByRole("combobox", { name: "Location" })).toHaveTextContent("No folder");
    await userEvent.type(screen.getByLabelText("Title"), "   {Enter}");
    expect(onNext).not.toHaveBeenCalled();
  });

  it("Cancel closes it", async () => {
    const onCancel = vi.fn();
    render(<NewRecordDialog open folders={[]} onNext={vi.fn()} onCancel={onCancel} />);
    await userEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(onCancel).toHaveBeenCalled();
  });
});

describe("NewRecordDialog in an organisation", () => {
  it("offers its shared folders only (no \"No folder\") and starts in the first one I can add to", async () => {
    const onNext = vi.fn();
    const team = folders.filter((f) => f.kind === "team");
    render(<NewRecordDialog open folders={team} folderId={null} noFolder={false} onNext={onNext} onCancel={vi.fn()} />);
    expect(screen.getByRole("combobox", { name: "Location" })).toHaveTextContent("Ops");
    await userEvent.click(screen.getByRole("combobox", { name: "Location" }));
    expect((await screen.findAllByRole("option")).map((o) => o.textContent)).toEqual(["Ops · Shared"]);
    await userEvent.keyboard("{Escape}");
    await userEvent.type(screen.getByLabelText("Title"), "DB{Enter}");
    expect(onNext).toHaveBeenCalledWith({ type: "login", title: "DB", folderId: "t1" });
  });
});
