import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type { RecordBody } from "@clane-vault/crypto";
import type { MyAgent, MyAgents } from "@/features/settings/myAgents";
import { RecordEditor } from "./RecordEditor";
import { grantStandingAgents, standingOn } from "./AgentRevealEditor";
import type { VaultRecord } from "./types";

const AGENT_ID = "bbbbbbbb-0000-4000-8000-000000000002";
const agent = { id: AGENT_ID, name: "My bot", status: "active" } as MyAgent;
const body: RecordBody = { v: 2, type: "login", title: "Office wifi", username: "u", password: "p" };
const edit = (initial: RecordBody, onSave: (b: RecordBody) => Promise<void>) =>
  render(<RecordEditor mode="edit" type={initial.type} initial={initial} folderId={null} folders={[]} onSave={onSave} onCancel={vi.fn()} standingReveal={{ agents: [agent] }} />);

describe("Reading without approval", () => {
  it("is offered only when the policies and the gateway both say standing", () => {
    const d = (rules: string, gw: string) => ({ rules: { reveal: rules }, gateway: { reveal: gw } }) as unknown as MyAgents;
    expect(standingOn(d("standing", "standing"))).toBe(true);
    for (const [r, g] of [["approval", "standing"], ["standing", "approval"], ["off", "off"]]) expect(standingOn(d(r!, g!))).toBe(false);
    expect(standingOn(undefined)).toBe(false);
    render(<RecordEditor mode="edit" type="login" initial={body} folderId={null} folders={[]} onSave={vi.fn()} onCancel={vi.fn()} />);
    expect(screen.queryByRole("region", { name: "Reading without approval" })).toBeNull();
  });

  it("the switch stays off until the title is typed exactly; saving writes agentReveal, and a key goes to an agent without one", async () => {
    const onSave = vi.fn(async (_b: RecordBody) => undefined);
    edit(body, onSave);
    expect(screen.getByRole("region", { name: "Reading without approval" })).toHaveTextContent("The AI model can read these fields whenever it asks. Nobody is asked first.");
    const sw = screen.getByRole("switch", { name: "My bot reads without approval" });
    expect(sw).toBeDisabled();
    await userEvent.click(screen.getByRole("button", { name: "Turn on…" }));
    const typed = screen.getByRole("textbox", { name: "Type the item's title to let My bot read without approval" });
    await userEvent.type(typed, "Office wif");
    expect(sw).toBeDisabled();
    await userEvent.type(typed, "i");
    expect(sw).toBeEnabled();
    await userEvent.click(sw);
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    const saved = onSave.mock.calls[0]![0];
    expect(saved.agentReveal).toEqual({ v: 1, agents: [AGENT_ID], fields: ["username"] });
    const grant = vi.fn(async () => undefined);
    await grantStandingAgents({ id: "r", agentGrants: [] } as unknown as VaultRecord, saved, [agent], grant);
    expect(grant).toHaveBeenCalledTimes(1);
    grant.mockClear();
    await grantStandingAgents({ id: "r", agentGrants: [{ agentId: AGENT_ID, use: true, write: false }] } as unknown as VaultRecord, saved, [agent], grant);
    expect(grant).not.toHaveBeenCalled();
  });

  it("an untouched save keeps agentReveal byte for byte", async () => {
    const initial = { ...body, agentReveal: { v: 1 as const, agents: [AGENT_ID], fields: ["password", "username"] } };
    const onSave = vi.fn(async (_b: RecordBody) => undefined);
    edit(initial, onSave);
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(JSON.stringify(onSave.mock.calls[0]![0].agentReveal)).toBe(JSON.stringify(initial.agentReveal));
  });

  it("removing a field it lists is refused with the validator's message", async () => {
    const initial: RecordBody = { ...body, fields: [{ id: "f1", label: "Account", kind: "text", value: "42" }], agentReveal: { v: 1, agents: [AGENT_ID], fields: ["field:f1"] } };
    const onSave = vi.fn(async (_b: RecordBody) => undefined);
    edit(initial, onSave);
    await userEvent.click(screen.getByRole("button", { name: "Remove field 1" }));
    expect(await screen.findByText(/Reading without approval: "field:f1" isn't a revealable field of this record/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();
    expect(onSave).not.toHaveBeenCalled();
  });
});
