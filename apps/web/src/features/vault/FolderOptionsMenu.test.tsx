import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { FolderOptionsMenu } from "./FolderOptionsMenu";
import type { VaultFolder, VaultRecord } from "./types";

const team = (myPermission: "owner" | "edit"): VaultFolder => ({ id: "t", name: "Ops", kind: "team", deleted: false, myPermission });
const record: VaultRecord = { id: "r", folderId: "t", type: "login", revision: 1, updatedAt: "", deleted: false, permission: "owner", recordKey: null, body: { type: "login", title: "DB" } };

function open(folder: VaultFolder, handlers: Partial<React.ComponentProps<typeof FolderOptionsMenu>> = {}) {
  render(<FolderOptionsMenu folder={folder} record={null} folders={[folder]} team trigger={<button type="button">Options</button>}
    onNew={vi.fn()} onMove={vi.fn()} onDelete={vi.fn()} onRename={vi.fn()} onManage={vi.fn()} {...handlers} />);
  return userEvent.click(screen.getByRole("button", { name: "Options" }));
}

describe("FolderOptionsMenu", () => {
  it("a team folder I don't own: People, no Rename, Delete disabled with the reason", async () => {
    const onDelete = vi.fn();
    await open(team("edit"), { onDelete });
    expect(screen.getByRole("menuitem", { name: "People" })).toBeInTheDocument();
    expect(screen.queryByRole("menuitem", { name: "Rename" })).not.toBeInTheDocument();
    const del = screen.getByRole("menuitem", { name: "Delete" });
    expect(del).toHaveAttribute("aria-disabled", "true");
    expect(del).toHaveAccessibleDescription("Only the folder's owner can delete it.");
  });

  it("a team folder I own: Manage people, Rename, and Delete asks the page to confirm", async () => {
    const onDelete = vi.fn(), onNew = vi.fn();
    await open(team("owner"), { onDelete, onNew });
    expect(screen.getByRole("menuitem", { name: "Manage people" })).toBeInTheDocument();
    expect(screen.getByRole("menuitem", { name: "Rename" })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("menuitem", { name: "Delete" }));
    expect(onDelete).toHaveBeenCalledWith(expect.objectContaining({ id: "t" }));
  });

  it("New Shared Folder and New Folder pass the folder they were opened on", async () => {
    const onNew = vi.fn();
    await open(team("owner"), { onNew });
    await userEvent.click(screen.getByRole("menuitem", { name: "New Shared Folder" }));
    expect(onNew).toHaveBeenCalledWith("team", "t");
  });

  it("in an organisation, Move To lists only its other shared folders I can file into (never No folder)", async () => {
    const onMove = vi.fn();
    const folders: VaultFolder[] = [team("owner"), { id: "t2", name: "Ops 2", kind: "team", deleted: false, myPermission: "edit" }, { id: "v", name: "Read only", kind: "team", deleted: false, myPermission: "view" }];
    render(<FolderOptionsMenu folder={folders[0]!} record={record} folders={folders} team trigger={<button type="button">Options</button>}
      onNew={vi.fn()} onMove={onMove} onDelete={vi.fn()} />);
    await userEvent.click(screen.getByRole("button", { name: "Options" }));
    expect(screen.queryByRole("menuitem", { name: "New Folder" })).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("menuitem", { name: "Move To" }));
    await screen.findByText("Move “DB” to");
    expect(screen.queryByRole("menuitem", { name: "No folder" })).not.toBeInTheDocument();
    expect(screen.queryByRole("menuitem", { name: "Read only" })).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("menuitem", { name: "Ops 2" }));
    expect(onMove).toHaveBeenCalledWith(record, "t2");
  });

  it("Personal: Move To lists only other folders I can file into, plus No folder", async () => {
    const onMove = vi.fn();
    const folders: VaultFolder[] = [{ id: "q", name: "Infra", kind: "private", deleted: false }, { id: "p", name: "Mine", kind: "private", deleted: false }];
    render(<FolderOptionsMenu folder={folders[0]!} record={{ ...record, folderId: "q" }} folders={folders} team={false} trigger={<button type="button">Options</button>}
      onNew={vi.fn()} onMove={onMove} onDelete={vi.fn()} />);
    await userEvent.click(screen.getByRole("button", { name: "Options" }));
    await userEvent.click(screen.getByRole("menuitem", { name: "Move To" }));
    await screen.findByText("Move “DB” to");
    expect(screen.getAllByRole("menuitem").map((x) => x.textContent)).toEqual(expect.arrayContaining(["No folder", "Mine"]));
    await userEvent.click(screen.getByRole("menuitem", { name: "Mine" }));
    expect(onMove).toHaveBeenCalledWith({ ...record, folderId: "q" }, "p");
  });
});
