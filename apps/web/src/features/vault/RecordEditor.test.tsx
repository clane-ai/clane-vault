import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { RecordEditor } from "./RecordEditor";

const folders = [{ id: "f1", name: "Infrastructure", kind: "private" as const, deleted: false }];

describe("RecordEditor", () => {
  it("creates a login with a generated password in a folder", async () => {
    const onSave = vi.fn(async () => undefined);
    render(<RecordEditor mode="create" type="login" folderId={null} folders={folders} onSave={onSave} onCancel={vi.fn()} />);
    await userEvent.type(screen.getByLabelText("Title"), "Cloudflare");
    await userEvent.type(screen.getByLabelText("Username"), "dns@clane.ai");
    await userEvent.click(screen.getByRole("button", { name: "Generate password" }));
    expect((screen.getByLabelText("Password") as HTMLInputElement).value).toHaveLength(20);
    await userEvent.type(screen.getByLabelText("Website"), "dash.cloudflare.com");
    await userEvent.click(screen.getByRole("combobox", { name: "Folder" }));
    await userEvent.click(await screen.findByRole("option", { name: "Infrastructure" }));
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(onSave).toHaveBeenCalledWith(expect.objectContaining({ type: "login", title: "Cloudflare", username: "dns@clane.ai", url: "dash.cloudflare.com" }), "f1");
  });

  it("starts from New Record: title and folder filled in, Username focused, saved there", async () => {
    const onSave = vi.fn(async () => undefined);
    render(<RecordEditor mode="create" type="login" initial={{ type: "login", title: "AWS root account" }} folderId="f1" folders={folders} onSave={onSave} onCancel={vi.fn()} />);
    expect(screen.getByLabelText("Title")).toHaveValue("AWS root account");
    expect(screen.getByRole("combobox", { name: "Folder" })).toHaveTextContent("Infrastructure");
    expect(screen.getByLabelText("Username")).toHaveFocus();
    await userEvent.type(screen.getByLabelText("Username"), "ops@clane.ai");
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(onSave).toHaveBeenCalledWith({ type: "login", title: "AWS root account", username: "ops@clane.ai" }, "f1");
  });

  it("a new secure note from New Record starts in Notes", () => {
    render(<RecordEditor mode="create" type="note" initial={{ type: "note", title: "Wi-Fi" }} folderId={null} folders={[]} onSave={vi.fn()} onCancel={vi.fn()} />);
    expect(screen.getByRole("heading", { name: "New secure note" })).toBeInTheDocument();
    expect(screen.getByLabelText("Notes")).toHaveFocus();
  });

  it("requires a title", async () => {
    const onSave = vi.fn();
    render(<RecordEditor mode="create" type="note" folderId={null} folders={[]} onSave={onSave} onCancel={vi.fn()} />);
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(screen.getByRole("alert")).toHaveTextContent("Give it a title.");
    expect(onSave).not.toHaveBeenCalled();
  });

  it("rejects an invalid 2FA secret", async () => {
    render(<RecordEditor mode="create" type="login" folderId={null} folders={[]} onSave={vi.fn()} onCancel={vi.fn()} />);
    await userEvent.type(screen.getByLabelText("Title"), "X");
    await userEvent.type(screen.getByLabelText("2FA secret (optional)"), "not base32!");
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(screen.getByRole("alert")).toHaveTextContent("That 2FA secret isn't valid. Copy the setup key from the website.");
  });

  it("edits an existing note", async () => {
    const onSave = vi.fn(async () => undefined);
    render(<RecordEditor mode="edit" type="note" initial={{ type: "note", title: "Wi-Fi", notes: "old" }} folderId={null} folders={[]} onSave={onSave} onCancel={vi.fn()} />);
    const notes = screen.getByLabelText("Notes");
    await userEvent.clear(notes); await userEvent.type(notes, "new");
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(onSave).toHaveBeenCalledWith({ type: "note", title: "Wi-Fi", notes: "new" }, null);
  });
});
