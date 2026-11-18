import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type { RecordBody } from "@clane-vault/crypto";
import { requestPreview } from "./AgentPolicyEditor";
import { agentAccess, AgentUseSheet, agentUseStatus } from "./AgentUseSheet";
import { RecordPanel } from "./RecordPanel";
import type { VaultRecord } from "./types";

globalThis.ResizeObserver ??= class { observe() {} unobserve() {} disconnect() {} } as never;

const policy = { v: 1 as const, hosts: ["api.stripe.com"], inject: { kind: "bearer" as const }, secret: "data.secret", methods: ["GET" as const] };
const bare: RecordBody = { type: "apiKey", title: "Stripe", data: { secret: "sk_x" } };
const stored: RecordBody = { ...bare, agentPolicy: policy };
const record = (body: RecordBody | null, o: Partial<VaultRecord> = {}): VaultRecord =>
  ({ id: "r1", folderId: null, type: "item", revision: 1, updatedAt: "2026-11-18T09:00:00Z", deleted: false, permission: "owner", recordKey: new Uint8Array(32), body, ...o });

function sheet(body: RecordBody, o: Partial<React.ComponentProps<typeof AgentUseSheet>> = {}) {
  const onSave = vi.fn(async (_b: RecordBody) => undefined);
  render(<AgentUseSheet record={record(body)} open onClose={vi.fn()} onSave={onSave} access={[]} {...o} />);
  return onSave;
}
const hosts = () => screen.getByLabelText("Allowed hosts");
const save = () => screen.getByRole("button", { name: "Save" });
const preview = () => screen.getByLabelText("Request preview").textContent;

describe("the Agent use button in the record panel", () => {
  const panel = (r: VaultRecord, onAgentUse: (() => void) | undefined = vi.fn()) =>
    render(<RecordPanel record={r} folderName={null} onClose={vi.fn()} onEdit={vi.fn()} onTrash={vi.fn()} onShare={vi.fn()} onAgentUse={onAgentUse} />);
  const button = () => screen.queryByRole("button", { name: /^Agent use/ });

  it("sits beside Edit and Share and opens the sheet", async () => {
    const onAgentUse = vi.fn();
    panel(record(bare), onAgentUse);
    const row = screen.getByRole("button", { name: "Edit" }).parentElement!;
    expect(within(row).getAllByRole("button").map((b) => b.textContent)).toEqual(["Edit", "Share", "Agent useOff", ""]);
    await userEvent.click(button()!);
    expect(onAgentUse).toHaveBeenCalledOnce();
  });

  it("shows the status: Off, Use, See, Use + See", () => {
    const see = { agentGrants: [{ agentId: "a1", use: false, write: false, reveal: ["username"] }] };
    expect(agentUseStatus(record(bare))).toBe("Off");
    expect(agentUseStatus(record(stored))).toBe("Use");
    expect(agentUseStatus(record(bare, see))).toBe("See");
    expect(agentUseStatus(record(stored, see))).toBe("Use + See");
    // A use grant alone is not See; reading without approval is.
    expect(agentUseStatus(record(stored, { agentGrants: [{ agentId: "a1", use: true, write: false }] }))).toBe("Use");
    expect(agentUseStatus(record({ ...stored, agentReveal: { v: 1, agents: ["a1"], fields: ["username"] } }))).toBe("Use + See");
    panel(record(stored, see));
    expect(button()).toHaveAccessibleName("Agent use: Use + See");
  });

  it("is for people who can edit, where agents are on (onAgentUse given)", () => {
    for (const permission of ["owner", "edit"] as const) { const v = panel(record(bare, { permission })); expect(button()).not.toBeNull(); v.unmount(); }
    for (const permission of ["view", "use"] as const) { const v = panel(record(bare, { permission })); expect(button()).toBeNull(); v.unmount(); }
    render(<RecordPanel record={record(bare)} folderName={null} onClose={vi.fn()} onEdit={vi.fn()} onTrash={vi.fn()} />);
    expect(button()).toBeNull();
  });

  it("is for items with something to send: a default secret, a secret custom field, env keys, or a policy already there", () => {
    const shown = (body: RecordBody) => { const v = panel(record(body)); const there = !!button(); v.unmount(); return there; };
    expect(shown({ type: "login", title: "AWS" })).toBe(true);
    expect(shown({ type: "note", title: "Wi-Fi" })).toBe(false);
    expect(shown({ type: "note", title: "Wi-Fi", fields: [{ id: "f1", label: "Token", kind: "secret", value: "x" }] })).toBe(true);
    expect(shown({ type: "envFile", title: "Shop", data: { content: "" } })).toBe(false);
    expect(shown({ type: "envFile", title: "Shop", data: { content: "A=1\n" } })).toBe(true);
    expect(shown({ type: "note", title: "Wi-Fi", agentPolicy: policy })).toBe(true);
  });

  it("is not on a record in the trash or one that can't be opened", () => {
    const a = panel(record(stored, { deleted: true })); expect(button()).toBeNull(); a.unmount();
    panel(record(null)); expect(button()).toBeNull();
  });
});

describe("the request preview", () => {
  it("shows each way of sending with the secret masked", () => {
    expect(requestPreview({ hosts: ["api.stripe.com"], inject: { kind: "bearer" } })).toEqual(["GET / HTTP/1.1", "Host: api.stripe.com", "Authorization: Bearer ••••••••"]);
    expect(requestPreview({ hosts: ["api.stripe.com"], inject: { kind: "basic" } })[2]).toBe("Authorization: Basic base64(username:••••••••)");
    expect(requestPreview({ hosts: ["h.example.com"], inject: { kind: "header", name: "X-Api-Key", prefix: "Token " } })[2]).toBe("X-Api-Key: Token ••••••••");
    expect(requestPreview({ hosts: ["h.example.com:8443"], inject: { kind: "query", name: "key" }, methods: ["POST"], paths: ["/v1/charges"] }))
      .toEqual(["POST /v1/charges?key=•••••••• HTTP/1.1", "Host: h.example.com:8443"]);
  });

  it("says so when the policy refuses every request, and stands in for what isn't filled in yet", () => {
    expect(requestPreview({ hosts: ["h.example.com"], inject: { kind: "bearer" }, methods: [] })).toEqual(["No request is sent: the allowed methods or paths are set to none."]);
    expect(requestPreview({ hosts: [], inject: { kind: "header", name: "" } })).toEqual(["GET / HTTP/1.1", "Host: api.example.com", "X-Api-Key: ••••••••"]);
  });

  it("follows the form as it is filled in, and never shows the secret", async () => {
    sheet(bare);
    expect(preview()).toBe("GET / HTTP/1.1Host: api.example.comAuthorization: Bearer ••••••••");
    await userEvent.type(hosts(), "api.stripe.com");
    await userEvent.click(screen.getByRole("radio", { name: "Header" }));
    await userEvent.type(screen.getByLabelText("Header name"), "X-Key");
    expect(preview()).toBe("GET / HTTP/1.1Host: api.stripe.comX-Key: ••••••••");
    await userEvent.click(screen.getByRole("radio", { name: "Query" }));
    expect(screen.getByText("Weaker: URLs end up in logs.")).toBeInTheDocument();
    expect(preview()).toContain("?X-Key=••••••••");
    expect(document.body.textContent).not.toContain("sk_x");
  });
});

describe("the Agent use sheet", () => {
  it("is titled with the item and says what agents can and can't do", () => {
    sheet(bare);
    expect(screen.getByRole("dialog", { name: "Agent use: Stripe" })).toHaveAccessibleDescription("Agents send this credential only to these hosts. They never see it.");
    expect(save()).toBeDisabled();
    expect(screen.queryByRole("button", { name: "Remove agent use" })).toBeNull();
  });

  it("saves a new policy into the whole body, everything else as it was", async () => {
    const body: RecordBody = { ...bare, notes: "n", fields: [{ id: "f1", label: "Token", kind: "secret", value: "t" }] };
    const onSave = sheet(body);
    await userEvent.type(hosts(), "api.stripe.com{Enter}");
    expect(within(screen.getByRole("list", { name: "Hosts added" })).getByText("api.stripe.com")).toBeInTheDocument();
    await userEvent.click(save());
    expect(onSave).toHaveBeenCalledWith({ ...body, agentPolicy: { v: 1, hosts: ["api.stripe.com"], inject: { kind: "bearer" } } });
  });

  it("hosts are chips: Enter, a comma or a space adds one, a paste adds several, the button and Backspace remove", async () => {
    const onSave = sheet(bare);
    await userEvent.type(hosts(), "a.example.com,b.example.com c.example.com{Enter}");
    await userEvent.click(hosts());
    await userEvent.paste("d.example.com\ne.example.com");
    const chips = () => within(screen.getByRole("list", { name: "Hosts added" })).getAllByRole("listitem").map((x) => x.textContent);
    expect(chips()).toEqual(["a.example.com", "b.example.com", "c.example.com", "d.example.com", "e.example.com"]);
    await userEvent.click(screen.getByRole("button", { name: "Remove b.example.com" }));
    await userEvent.type(hosts(), "{Backspace}");
    expect(chips()).toEqual(["a.example.com", "c.example.com", "d.example.com"]);
    // What is typed and not yet a chip is saved too.
    await userEvent.type(hosts(), "f.example.com");
    await userEvent.click(save());
    expect(onSave.mock.calls[0]![0].agentPolicy!.hosts).toEqual(["a.example.com", "c.example.com", "d.example.com", "f.example.com"]);
  });

  it("refuses an IP host and a unicode host with the validator's words, marks the chip, and disables Save", async () => {
    sheet(bare);
    await userEvent.type(hosts(), "10.0.0.5{Enter}");
    expect(screen.getByRole("alert")).toHaveTextContent("IP addresses are not allowed as hosts");
    expect(screen.getByText("10.0.0.5").closest("li")).toHaveAttribute("data-invalid", "true");
    expect(save()).toBeDisabled();
    await userEvent.click(screen.getByRole("button", { name: "Remove 10.0.0.5" }));
    await userEvent.type(hosts(), "bücher.example.com");
    expect(screen.getByRole("alert")).toHaveTextContent("punycode");
    expect(save()).toBeDisabled();
  });

  it("round trip: an edit keeps what the form doesn't show, and the saved policy opens as it was saved", async () => {
    const onSave = sheet({ ...stored, agentPolicy: { ...policy, approval: true } }, { pathsLocked: true });
    expect(save()).toBeDisabled();
    expect(screen.getByLabelText("Allowed methods")).toBeDisabled();
    expect(screen.getByText("Available on the Business plan.")).toBeInTheDocument();
    await userEvent.type(hosts(), "api.example.com");
    await userEvent.click(save());
    const saved = onSave.mock.calls[0]![0];
    expect(saved.agentPolicy).toEqual({ ...policy, approval: true, hosts: ["api.stripe.com", "api.example.com"] });
    // Opened again on what was saved: the same chips, nothing to save.
    cleanup();
    sheet(saved);
    const again = screen.getByRole("dialog");
    expect(within(within(again).getByRole("list", { name: "Hosts added" })).getAllByRole("listitem").map((x) => x.textContent)).toEqual(["api.stripe.com", "api.example.com"]);
    expect(within(again).getByRole("radio", { name: "Bearer" })).toBeChecked();
    expect(within(again).getByRole("button", { name: "Save" })).toBeDisabled();
  });

  it("warns about encoded path characters and treats none, in any case, as deny all", async () => {
    const onSave = sheet(bare);
    await userEvent.type(hosts(), "api.stripe.com");
    await userEvent.type(screen.getByLabelText("Allowed paths"), "/a%2Fb");
    expect(screen.getByRole("status")).toHaveTextContent("%2f");
    await userEvent.clear(screen.getByLabelText("Allowed paths"));
    await userEvent.type(screen.getByLabelText("Allowed paths"), "None");
    expect(preview()).toBe("No request is sent: the allowed methods or paths are set to none.");
    await userEvent.click(save());
    expect(onSave.mock.calls[0]![0].agentPolicy).toEqual({ v: 1, hosts: ["api.stripe.com"], inject: { kind: "bearer" }, paths: [] });
  });

  it("with every host taken away it asks for one or for Remove agent use, and saves nothing", async () => {
    const onSave = sheet(stored);
    await userEvent.click(screen.getByRole("button", { name: "Remove api.stripe.com" }));
    expect(screen.getByText("Add at least one host, or choose Remove agent use.")).toBeInTheDocument();
    expect(save()).toBeDisabled();
    expect(onSave).not.toHaveBeenCalled();
  });

  it("Remove agent use asks first, then saves the body without the policy", async () => {
    const onSave = sheet({ ...stored, notes: "n" });
    await userEvent.click(screen.getByRole("button", { name: "Remove agent use" }));
    expect(onSave).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole("button", { name: "Keep" }));
    await userEvent.click(screen.getByRole("button", { name: "Remove agent use" }));
    await userEvent.click(screen.getByRole("button", { name: "Remove" }));
    expect(onSave).toHaveBeenCalledWith({ ...bare, notes: "n" });
  });

  it("shows a failed save and stays open", async () => {
    const onSave = vi.fn(async () => { throw new Error("Couldn't save. Check your connection and try again."); });
    sheet(bare, { onSave });
    await userEvent.type(hosts(), "api.stripe.com");
    await userEvent.click(save());
    expect(await screen.findByRole("alert")).toHaveTextContent("Couldn't save. Check your connection and try again.");
    expect(save()).toBeEnabled();
  });

  it("the segmented control moves with the arrow keys", async () => {
    sheet(bare);
    screen.getByRole("radio", { name: "Bearer" }).focus();
    // Held: Radix moves focus on the next tick and selects only while the arrow key is still down.
    await userEvent.keyboard("{ArrowRight>}");
    await waitFor(() => expect(screen.getByRole("radio", { name: "Basic" })).toBeChecked());
    expect(preview()).toContain("Authorization: Basic base64(username:••••••••)");
  });

  it("the summary lists the agents that hold the item, with their modes, and links to Share", async () => {
    const onManageAccess = vi.fn();
    const r = record(stored, { agentGrants: [{ agentId: "a1", use: true, write: true, reveal: ["username"] }, { agentId: "a2", use: false, write: false }] });
    const access = agentAccess({ ...r, body: { ...stored, username: "sara" } }, { myAgents: [{ id: "a1", name: "My bot" }] as never, teamFolder: null });
    expect(access).toEqual([{ id: "a1", name: "My bot", use: true, write: true, see: ["Username"], standing: false }]);
    sheet(stored, { access, onManageAccess });
    const status = screen.getByRole("region", { name: "Status" });
    expect(status).toHaveTextContent("1 agent can use this item.");
    expect(within(status).getByRole("listitem", { name: "My bot" })).toHaveTextContent("My botUseUpdateSee: Username");
    await userEvent.click(within(status).getByRole("button", { name: "Manage in Share" }));
    expect(onManageAccess).toHaveBeenCalledOnce();
  });

  it("the summary in an organisation: agents among the direct shares and the team folder's members", () => {
    const r = record(stored, { sharedWith: [{ userId: "u1", name: "Sara", permission: "edit" }, { userId: "g1", name: "Billing bot", permission: "use" }] });
    const teamFolder = { id: "f1", name: "Payments", kind: "team" as const, deleted: false, members: [
      { userId: "g1", name: "Billing bot", email: "g1@agents.invalid", publicKey: "", permission: "use" as const, kind: "agent" as const },
      { userId: "g2", name: "Ops bot", email: "g2@agents.invalid", publicKey: "", permission: "use" as const, kind: "agent" as const },
      { userId: "u2", name: "Tom", email: "tom@acme.test", publicKey: "", permission: "edit" as const }] };
    const people = [{ id: "u1", name: "Sara", email: "sara@acme.test", publicKey: "" }, { id: "g1", name: "Billing bot", email: "g1@agents.invalid", publicKey: "", kind: "agent" as const }];
    expect(agentAccess(r, { myAgents: [], people, teamFolder })).toEqual([
      { id: "g1", name: "Billing bot", use: true, see: [], via: "Shared directly" }, { id: "g2", name: "Ops bot", use: true, see: [], via: "via Payments" }]);
  });

  it("the summary says when the policy is set but no agent has the item, and when it is off", () => {
    sheet(stored);
    expect(screen.getByRole("region", { name: "Status" })).toHaveTextContent("Ready, but no agent has this item yet.");
    cleanup();
    sheet(bare);
    expect(screen.getByRole("region", { name: "Status" })).toHaveTextContent("Off. No agent can use this item.");
  });
});
