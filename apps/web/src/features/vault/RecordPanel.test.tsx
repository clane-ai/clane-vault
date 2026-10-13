import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { RecordPanel } from "./RecordPanel";
import type { VaultRecord } from "./types";

vi.mock("@/lib/clipboard", () => ({ copySecret: vi.fn(async () => undefined) }));
import { copySecret } from "@/lib/clipboard";

const record: VaultRecord = { id: "r1", folderId: null, type: "login", revision: 1, updatedAt: "2026-10-04T09:00:00Z", deleted: false, permission: "owner", recordKey: new Uint8Array(32),
  body: { type: "login", title: "AWS root account", username: "ops@clane.ai", password: "Tg7#qL2v!Rm9zW4x", url: "console.aws.amazon.com", totpSecret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" } };

describe("RecordPanel", () => {
  it("masks the password until revealed and copies with one click", async () => {
    render(<RecordPanel record={record} folderName="Infrastructure" onClose={vi.fn()} onEdit={vi.fn()} onTrash={vi.fn()} />);
    expect(screen.getByRole("heading", { name: "AWS root account" })).toBeInTheDocument();
    expect(screen.queryByText("Tg7#qL2v!Rm9zW4x")).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Show password" }));
    expect(screen.getByText("Tg7#qL2v!Rm9zW4x")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Copy password" }));
    expect(copySecret).toHaveBeenCalledWith("Tg7#qL2v!Rm9zW4x");
    expect(screen.getByText("Strong")).toBeInTheDocument();
    expect(await screen.findByLabelText("2FA code")).toHaveTextContent(/^\d{3} \d{3}$/);
  });

  it("shows a clear state for a record that can't be opened", () => {
    render(<RecordPanel record={{ ...record, body: null, recordKey: null, error: "cannot_open" }} folderName={null} onClose={vi.fn()} onEdit={vi.fn()} onTrash={vi.fn()} />);
    expect(screen.getByText("Can't open this record")).toBeInTheDocument();
  });
  it("restores and deletes forever from the trash with an inline confirm", async () => {
    const onRestore = vi.fn(), onPurge = vi.fn();
    render(<RecordPanel record={{ ...record, deleted: true }} folderName={null} onClose={vi.fn()} onEdit={vi.fn()} onTrash={vi.fn()} onRestore={onRestore} onPurge={onPurge} />);
    await userEvent.click(screen.getByRole("button", { name: "Restore" }));
    expect(onRestore).toHaveBeenCalled();
    await userEvent.click(screen.getByRole("button", { name: "Delete forever" }));
    expect(onPurge).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole("button", { name: "Delete" }));
    expect(onPurge).toHaveBeenCalled();
  });
  it("labels figma123 Weak and offers a new password when the record needs attention", async () => {
    const onNewPassword = vi.fn();
    render(<RecordPanel record={{ ...record, body: { ...record.body!, password: "figma123" } }} folderName={null} onClose={vi.fn()} onEdit={vi.fn()} onTrash={vi.fn()}
      reasons={["weak", "reused"]} onNewPassword={onNewPassword} />);
    expect(screen.getByText("Weak")).toBeInTheDocument();
    expect(screen.getByRole("note", { name: "Needs attention" })).toHaveTextContent("This password is weak and is used on another record too.");
    await userEvent.click(screen.getByRole("button", { name: "Generate new password" }));
    expect(onNewPassword).toHaveBeenCalled();
  });
  it("offers Generate new password only to people who can edit", () => {
    for (const permission of ["view", "use"] as const) {
      const { unmount } = render(<RecordPanel record={{ ...record, permission, body: { ...record.body!, password: "figma123" } }} folderName={null} onClose={vi.fn()} onEdit={vi.fn()} onTrash={vi.fn()}
        reasons={["weak"]} onNewPassword={vi.fn()} />);
      expect(screen.getByRole("note", { name: "Needs attention" })).toBeInTheDocument();
      expect(screen.queryByRole("button", { name: "Generate new password" })).not.toBeInTheDocument();
      unmount();
    }
  });
  it("offers a one-time link only to people who can edit; owners find it in the Share sheet", () => {
    const owner = render(<RecordPanel record={record} folderName={null} onClose={vi.fn()} onEdit={vi.fn()} onTrash={vi.fn()} onShare={vi.fn()} />);
    expect(screen.getByRole("button", { name: "Share" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "One-time link" })).not.toBeInTheDocument();
    owner.unmount();
    const { unmount } = render(<RecordPanel record={{ ...record, permission: "edit", sharedBy: "Ana" }} folderName={null} onClose={vi.fn()} onEdit={vi.fn()} onTrash={vi.fn()} onShare={vi.fn()} />);
    expect(screen.getByRole("button", { name: "One-time link" })).toBeInTheDocument();
    unmount();
    render(<RecordPanel record={{ ...record, permission: "view" }} folderName={null} onClose={vi.fn()} onEdit={vi.fn()} onTrash={vi.fn()} />);
    expect(screen.queryByRole("button", { name: "One-time link" })).not.toBeInTheDocument();
  });

  it("use only: hides the password and the reveal button but keeps Copy", async () => {
    render(<RecordPanel record={{ ...record, permission: "use" }} folderName={null} onClose={vi.fn()} onEdit={vi.fn()} onTrash={vi.fn()} onShare={vi.fn()} />);
    expect(screen.queryByRole("button", { name: "Show password" })).not.toBeInTheDocument();
    expect(screen.queryByText("Tg7#qL2v!Rm9zW4x")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Edit" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Share" })).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Copy password" }));
    expect(copySecret).toHaveBeenCalledWith("Tg7#qL2v!Rm9zW4x");
  });

  it("shows Share to the owner only", () => {
    const onShare = vi.fn();
    const { rerender } = render(<RecordPanel record={record} folderName={null} onClose={vi.fn()} onEdit={vi.fn()} onTrash={vi.fn()} onShare={onShare} />);
    expect(screen.getByRole("button", { name: "Share" })).toBeInTheDocument();
    rerender(<RecordPanel record={{ ...record, permission: "edit", sharedBy: "Ana" }} folderName={null} onClose={vi.fn()} onEdit={vi.fn()} onTrash={vi.fn()} onShare={onShare} />);
    expect(screen.queryByRole("button", { name: "Share" })).not.toBeInTheDocument();
    expect(screen.getByText(/Shared by Ana/)).toBeInTheDocument();
  });
});
