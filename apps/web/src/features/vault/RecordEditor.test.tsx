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

  describe("Agent use", () => {
    const stored = { type: "apiKey" as const, title: "Stripe", data: { secret: "sk_x" }, agentPolicy: { v: 1 as const, hosts: ["api.stripe.com"], inject: { kind: "bearer" as const }, secret: "data.secret", methods: ["GET" as const] } };
    const editor = (over: Partial<React.ComponentProps<typeof RecordEditor>> = {}) =>
      <RecordEditor mode="edit" type="apiKey" initial={stored} folderId={null} folders={[]} agentUse onSave={vi.fn(async () => undefined)} onCancel={vi.fn()} {...over} />;

    it("creates a policy", async () => {
      const onSave = vi.fn(async () => undefined);
      render(<RecordEditor mode="create" type="apiKey" folderId={null} folders={[]} agentUse onSave={onSave} onCancel={vi.fn()} />);
      await userEvent.type(screen.getByLabelText("Title"), "Stripe");
      await userEvent.type(screen.getByLabelText("Allowed hosts"), "api.stripe.com");
      await userEvent.click(screen.getByRole("button", { name: "Save" }));
      expect(onSave.mock.calls[0]![0].agentPolicy).toEqual({ v: 1, hosts: ["api.stripe.com"], inject: { kind: "bearer" } });
    });

    it("keeps the policy when only the title changes", async () => {
      const onSave = vi.fn(async () => undefined);
      render(editor({ onSave }));
      await userEvent.type(screen.getByLabelText("Title"), " live");
      await userEvent.click(screen.getByRole("button", { name: "Save" }));
      expect(onSave.mock.calls[0]![0].agentPolicy).toEqual(stored.agentPolicy);
      expect(onSave.mock.calls[0]![0].agentPolicy).toBe(stored.agentPolicy);
    });

    it("refuses an IP host and disables Save", async () => {
      render(editor({ initial: { ...stored, agentPolicy: undefined } }));
      await userEvent.type(screen.getByLabelText("Allowed hosts"), "10.0.0.5");
      expect(screen.getByRole("alert")).toHaveTextContent("IP addresses are not allowed as hosts");
      expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();
    });

    it("refuses a unicode host with a punycode message", async () => {
      render(editor({ initial: { ...stored, agentPolicy: undefined } }));
      await userEvent.type(screen.getByLabelText("Allowed hosts"), "bücher.example.com");
      expect(screen.getByRole("alert")).toHaveTextContent("punycode");
      expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();
    });

    it("explains a type change that drops the secret field, and saves nothing", async () => {
      const onSave = vi.fn(async () => undefined);
      const props = { mode: "edit" as const, folderId: null, folders: [], agentUse: true, onSave, onCancel: vi.fn() };
      // Only the policy is invalid for a note: the record has no data.
      const { rerender } = render(<RecordEditor {...props} type="apiKey" initial={{ type: "apiKey", title: "Stripe", agentPolicy: stored.agentPolicy }} />);
      rerender(<RecordEditor {...props} type="note" initial={{ type: "apiKey", title: "Stripe", agentPolicy: stored.agentPolicy }} />);
      expect(screen.getByRole("alert")).toHaveTextContent(/Agent policy: secret names a field this record doesn't have/);
      expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();
      expect(onSave).not.toHaveBeenCalled();
      await userEvent.clear(screen.getByLabelText("Allowed hosts"));
      expect(screen.queryByRole("alert")).toBeNull();
      await userEvent.click(screen.getByRole("button", { name: "Save" }));
      expect(onSave.mock.calls[0]![0]).not.toHaveProperty("agentPolicy");
    });

    it("warns about the query option, encoded path characters, and keeps blank methods omitted", async () => {
      const onSave = vi.fn(async () => undefined);
      render(editor({ onSave, initial: { ...stored, agentPolicy: undefined } }));
      await userEvent.type(screen.getByLabelText("Allowed hosts"), "api.stripe.com");
      await userEvent.click(screen.getByRole("combobox", { name: "Send it as" }));
      await userEvent.click(await screen.findByRole("option", { name: "Query parameter (weaker)" }));
      expect(screen.getByText("Weaker: URLs end up in logs.")).toBeInTheDocument();
      await userEvent.type(screen.getByLabelText("Parameter name"), "key");
      await userEvent.type(screen.getByLabelText("Allowed paths"), "/a%2Fb");
      expect(screen.getByRole("status")).toHaveTextContent("%2f");
      await userEvent.clear(screen.getByLabelText("Allowed paths"));
      await userEvent.type(screen.getByLabelText("Allowed methods"), "none");
      await userEvent.click(screen.getByRole("button", { name: "Save" }));
      expect(onSave.mock.calls[0]![0].agentPolicy).toEqual({ v: 1, hosts: ["api.stripe.com"], inject: { kind: "query", name: "key" }, methods: [] });
    });

    it("shows methods and paths locked and keeps them", async () => {
      const onSave = vi.fn(async () => undefined);
      render(editor({ onSave, pathsLocked: true }));
      expect(screen.getByLabelText("Allowed methods")).toBeDisabled();
      expect(screen.getByText("Available on the Business plan.")).toBeInTheDocument();
      await userEvent.type(screen.getByLabelText("Allowed hosts"), "{enter}api.example.com");
      await userEvent.click(screen.getByRole("button", { name: "Save" }));
      expect(onSave.mock.calls[0]![0].agentPolicy).toEqual({ ...stored.agentPolicy, hosts: ["api.stripe.com", "api.example.com"] });
    });

    it("is hidden without edit rights", () => {
      render(editor({ agentUse: false }));
      expect(screen.queryByRole("region", { name: "Agent use" })).toBeNull();
    });
  });
});
