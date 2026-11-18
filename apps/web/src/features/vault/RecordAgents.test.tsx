import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { http, HttpResponse } from "msw";
import {
  agentUpdateMessage, b64url, decryptRecordBody, encryptNewRecord, encryptRecordBody, gatewayKeyId, generateIdentityKeyPair, generateKeyPair, openPersonalAgentRecordKey, randomBytes,
  sha256B64, signGatewayMessage, signPersonalAgentKey,
} from "@clane-vault/crypto";
import { server } from "@/test/server";
import * as sessionModule from "@/lib/session";
import { PERSONAL_SLOT, pinGateway, type GatewayIdentity } from "@/lib/orgKeys";
import type { MyAgent } from "@/features/settings/myAgents";
import VaultPage from "./VaultPage";
import { ShareSheet } from "./ShareSheet";
import type { VaultFolder, VaultRecord } from "./types";

globalThis.ResizeObserver ??= class { observe() {} unobserve() {} disconnect() {} } as never;
const ME = "11111111-0000-4000-8000-000000000001";
const AGENT_ID = "bbbbbbbb-0000-4000-8000-000000000002";
const me = { userKey: randomBytes(32), ...(await generateKeyPair()) };
const ownerPublicKey = b64url.encode(me.publicKey);
const agentKeys = await generateKeyPair();
const agentPub = b64url.encode(agentKeys.publicKey);
const ORG = { id: "o1", name: "Acme", slug: "acme", role: "member", isDefault: true };
vi.spyOn(sessionModule, "useSession").mockReturnValue({ org: null, orgs: [ORG], applyOrgs: vi.fn(), user: { id: ME, name: "Sara", role: "member" }, generation: () => 0, lock: vi.fn(), signOut: vi.fn(), keys: me } as never);

let gw: { identity: GatewayIdentity; attest: (publicKey: string) => Promise<string>; sign: (message: string) => Promise<string> };
let writeAllowed: boolean;
/** The server's side of Changed by agent: an ack or a save drops it from /sync; `syncs` counts the refetches. */
let srv: { acked: boolean; saved: boolean; syncs: number };
let agents: MyAgent[];
const row = (o: Partial<MyAgent> = {}): MyAgent => ({ id: AGENT_ID, name: "My bot", status: "active", publicKey: agentPub, attestation: "", expiresAt: null, lastUsedAt: null,
  createdAt: "2026-11-15T00:00:00Z", verifiedAt: "2026-11-15T00:00:00Z", items: 0, owner: { userId: ME, publicKey: ownerPublicKey }, tokens: [], grants: [], ...o });

beforeEach(async () => {
  try { localStorage.clear(); } catch { /* none */ }
  const kp = await generateIdentityKeyPair();
  const identity = { keyId: await gatewayKeyId(kp.publicKey), publicKey: b64url.encode(kp.publicKey) };
  gw = { identity, attest: (publicKey) => signPersonalAgentKey(kp.privateKey, identity.keyId, { ownerUserId: ME, ownerPublicKey, agentId: AGENT_ID, publicKey }),
    sign: (message) => signGatewayMessage(kp.privateKey, identity.keyId, "u1", message) };
  writeAllowed = false;
  srv = { acked: false, saved: false, syncs: 0 };
  await pinGateway(ME, PERSONAL_SLOT, identity);
  agents = [row({ attestation: await gw.attest(agentPub) })];
  server.use(
    http.get("/api/v1/me/agents", () => HttpResponse.json({ agents, allowance: { used: 1, allowed: 2 }, rules: { allowed: true, blockedByOrgId: null, write: writeAllowed, reveal: "off" }, gateway: null, revealEmail: true })),
    http.get("/api/v1/records/:id/activity", () => HttpResponse.json({ events: [] })),
    http.get("/api/v1/users", () => HttpResponse.json({ users: [] })),
  );
});

async function serveRecord(o: { agentGrants?: unknown[]; agentPolicy?: boolean; agentChange?: "signed" | "unsigned"; createdByAgent?: boolean; envFile?: boolean } = {}) {
  const id = crypto.randomUUID();
  const body = { ...(o.envFile ? { type: "envFile" as const, data: { content: "STRIPE_KEY=sk_live_1\n" } } : { type: "login" as const, password: "pw" }), title: "Stripe", ...(o.agentPolicy === false ? {} : { agentPolicy: { v: 1 as const, hosts: ["api.stripe.com"], inject: { kind: "bearer" as const } } }) };
  const enc = await encryptNewRecord(id, body, me.userKey);
  const revision = o.agentChange ? 2 : 1;
  // "unsigned": signed for another revision, so the signature doesn't cover the current body.
  const signature = o.agentChange ? await gw.sign(agentUpdateMessage({ ownerUserId: ME, agentId: AGENT_ID, id, revision: o.agentChange === "signed" ? revision : revision + 1, encBodyHash: await sha256B64(enc.encBody) })) : "";
  server.use(
    http.get("/api/v1/sync", () => { srv.syncs++; return HttpResponse.json({ serverTime: "", folders: [], records: [{ id, folderId: null, type: "login", encBody: enc.encBody, wrappedRecordKey: enc.wrappedRecordKey,
      revision: srv.saved ? revision + 1 : revision, updatedAt: "2026-11-15T10:00:00Z", deletedAt: null, permission: "owner", holderType: "user", ownerId: ME, ownerName: "Sara", sharedWith: [], agentGrants: o.agentGrants ?? [],
      ...(o.createdByAgent ? { createdByAgent: { id: AGENT_ID, name: "My bot", at: "2026-11-15T10:00:00Z" } } : {}),
      ...(o.agentChange && !srv.acked && !srv.saved ? { agentChange: { agentId: AGENT_ID, agentName: "My bot", at: "2026-11-16T10:00:00Z", signature } } : {}) }] }); }),
    http.post("/api/v1/records/:id/agent-overwrites/ack", () => { srv.acked = true; return HttpResponse.json({ ok: true }); }),
  );
  return { id, enc, revision };
}
let qc: QueryClient;
async function openRecord() {
  qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={qc}><MemoryRouter initialEntries={["/p/vault"]}><VaultPage /></MemoryRouter></QueryClientProvider>);
  await userEvent.click(await screen.findByRole("button", { name: /^No folder/ }));
  await userEvent.click(await screen.findByRole("button", { name: /Stripe/ }));
  return screen.findByRole("complementary", { name: "Record details" });
}
async function openShare() {
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter initialEntries={["/p/vault"]}><VaultPage /></MemoryRouter></QueryClientProvider>);
  await userEvent.click(await screen.findByRole("button", { name: /^No folder/ }));
  await userEvent.click(await screen.findByRole("button", { name: /Stripe/ }));
  await userEvent.click(screen.getByRole("button", { name: "Share" }));
  const sheet = await screen.findByRole("dialog");
  return within(sheet).findByRole("region", { name: "Agents" });
}
async function choose(section: HTMLElement, option: string) {
  await userEvent.click(await within(section).findByRole("combobox", { name: "Access for My bot" }));
  await userEvent.click(await screen.findByRole("option", { name: option }));
}

describe("giving an item to a personal agent", () => {
  it("Can use seals the record key to the agent, bound to me, the agent and the record; the warning comes first", async () => {
    const { id, enc } = await serveRecord();
    let posted: { agentId: string; wrappedRecordKey: string } | null = null;
    server.use(http.post("/api/v1/records/:id/agent-grants", async ({ request }) => { posted = (await request.json()) as never; return HttpResponse.json({ ok: true }, { status: 201 }); }));
    const section = await openShare();
    const warning = within(section).getByRole("note", { name: "Sharing with an agent" });
    const select = await within(section).findByRole("combobox", { name: "Access for My bot" });
    expect(warning.compareDocumentPosition(select) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(within(section).queryByText("This item has no Agent use settings yet, so the agent can't use it.")).toBeNull();
    await choose(section, "Can use");
    await waitFor(() => expect(posted).not.toBeNull());
    expect(posted!.agentId).toBe(AGENT_ID);
    const rk = await openPersonalAgentRecordKey(posted!.wrappedRecordKey, { ownerUserId: ME, agentId: AGENT_ID, recordId: id }, agentKeys);
    expect((await decryptRecordBody(id, enc.encBody, rk)).title).toBe("Stripe");
    await expect(openPersonalAgentRecordKey(posted!.wrappedRecordKey, { ownerUserId: ME, agentId: AGENT_ID, recordId: crypto.randomUUID() }, agentKeys)).rejects.toThrow();
  });

  it("an env file says the gateway can open the whole file; other types don't", async () => {
    await serveRecord();
    const login = await openShare();
    await within(login).findByRole("combobox", { name: "Access for My bot" });
    expect(within(login).queryByText("The gateway can open this whole file. It will only send the entry you chose.")).toBeNull();
    cleanup();
    await serveRecord({ envFile: true, agentPolicy: false });
    const env = await openShare();
    expect(await within(env).findByText("The gateway can open this whole file. It will only send the entry you chose.")).toBeInTheDocument();
  });

  it("a tampered attestation posts nothing and says why", async () => {
    await serveRecord({ agentPolicy: false });
    agents = [row({ attestation: await gw.attest(b64url.encode((await generateKeyPair()).publicKey)) })];
    let posted = false;
    server.use(http.post("/api/v1/records/:id/agent-grants", () => { posted = true; return HttpResponse.json({ ok: true }, { status: 201 }); }));
    const section = await openShare();
    expect(within(section).getByText("This item has no Agent use settings yet, so the agent can't use it.")).toBeInTheDocument();
    await choose(section, "Can use");
    expect(await within(section).findByRole("alert")).toHaveTextContent("The gateway did not sign this agent's key, so nothing was shared.");
    expect(posted).toBe(false);
  });

  it("None takes the item away (DELETE)", async () => {
    const { id } = await serveRecord({ agentGrants: [{ agentId: AGENT_ID, use: true, write: false }] });
    let deleted: string | null = null;
    server.use(http.delete("/api/v1/records/:id/agent-grants/:agentId", ({ params }) => { deleted = `${params.id}/${params.agentId}`; return new HttpResponse(null, { status: 204 }); }));
    const section = await openShare();
    expect(await within(section).findByRole("combobox", { name: "Access for My bot" })).toHaveTextContent("Can use");
    await choose(section, "None");
    await waitFor(() => expect(deleted).toBe(`${id}/${AGENT_ID}`));
  });

  it("without agents the section links to Settings → My agents", async () => {
    await serveRecord();
    agents = [];
    const section = await openShare();
    expect(await within(section).findByRole("link", { name: /My agents/ })).toHaveAttribute("href", "/settings/agents");
  });

  it("is absent for a record in a team folder and for a record shared with me", async () => {
    const base = { id: "r1", folderId: null, type: "login", body: { type: "login", title: "Stripe" }, revision: 1, updatedAt: "", deleted: false, permission: "owner", recordKey: randomBytes(32), ownerId: ME, sharedWith: [] } as unknown as VaultRecord;
    const team = { id: "f1", name: "Payments", kind: "team", deleted: false, members: [] } as unknown as VaultFolder;
    const sheet = (record: VaultRecord, teamFolder: VaultFolder | null) => render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter>
      <ShareSheet record={record} teamFolder={teamFolder} open onClose={() => undefined} onShare={vi.fn()} onUpdate={vi.fn()} onRemove={vi.fn()} onGrantAgent={vi.fn()} onRevokeAgent={vi.fn()} />
    </MemoryRouter></QueryClientProvider>);
    const own = sheet(base, null);
    expect(await screen.findByRole("region", { name: "Agents" })).toBeInTheDocument();
    own.unmount();
    const inTeam = sheet({ ...base, folderId: "f1" }, team);
    await screen.findByRole("dialog");
    expect(screen.queryByRole("region", { name: "Agents" })).toBeNull();
    inTeam.unmount();
    const shared = sheet({ ...base, sharedBy: "Bob", ownerId: "u2" }, null);
    await screen.findByRole("dialog");
    expect(screen.queryByRole("region", { name: "Agents" })).toBeNull();
    shared.unmount();
    // A record whose key doesn't open (cannot_open) can't be sealed to anyone.
    sheet({ ...base, recordKey: null }, null);
    await screen.findByRole("dialog");
    expect(screen.queryByRole("region", { name: "Agents" })).toBeNull();
  });

  it("Give to agent… on several items gives the new ones and skips the rest", async () => {
    const a = await serveRecord({ agentGrants: [{ agentId: AGENT_ID, use: true, write: false }] });
    const id2 = crypto.randomUUID();
    const enc2 = await encryptNewRecord(id2, { type: "login", title: "GitHub", password: "pw" }, me.userKey);
    const posts: string[] = [];
    server.use(
      http.get("/api/v1/sync", () => HttpResponse.json({ serverTime: "", folders: [], records: [a.id, id2].map((id, i) => ({ id, folderId: null, type: "login",
        encBody: i ? enc2.encBody : a.enc.encBody, wrappedRecordKey: i ? enc2.wrappedRecordKey : a.enc.wrappedRecordKey, revision: 1, updatedAt: "2026-11-15T10:00:00Z", deletedAt: null,
        permission: "owner", holderType: "user", ownerId: ME, ownerName: "Sara", sharedWith: [], agentGrants: i ? [] : [{ agentId: AGENT_ID, use: true, write: false }] })) })),
      http.post("/api/v1/records/:id/agent-grants", ({ params }) => { posts.push(params.id as string); return HttpResponse.json({ ok: true }, { status: 201 }); }),
    );
    render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter initialEntries={["/p/vault"]}><VaultPage /></MemoryRouter></QueryClientProvider>);
    await userEvent.click(await screen.findByRole("button", { name: /^No folder/ }));
    await userEvent.click(await screen.findByRole("checkbox", { name: "Select Stripe" }));
    await userEvent.click(screen.getByRole("checkbox", { name: "Select GitHub" }));
    await userEvent.click(screen.getByRole("button", { name: "Give to agent…" }));
    const dialog = await screen.findByRole("dialog", { name: "Give 2 items to an agent" });
    expect(within(dialog).getByRole("note", { name: "Sharing with an agent" })).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole("radio", { name: "My bot" }));
    await userEvent.click(within(dialog).getByRole("button", { name: "Give" }));
    expect(await within(dialog).findByRole("status")).toHaveTextContent("1 given, 1 skipped");
    expect(posts).toEqual([id2]);
    await userEvent.click(within(dialog).getByRole("button", { name: "Done" }));
    // The selection is cleared once it's done.
    await waitFor(() => expect(screen.getByRole("checkbox", { name: "Select Stripe" })).not.toBeChecked());
    expect(screen.getByRole("checkbox", { name: "Select GitHub" })).not.toBeChecked();
    expect(screen.queryByRole("button", { name: "Give to agent…" })).toBeNull();
    expect(screen.getByRole("checkbox", { name: "Select Stripe" }).parentElement).toHaveClass("size-6"); // a 24px hit area
  });

  it("the selection is cleared when the view changes", async () => {
    await serveRecord();
    render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter initialEntries={["/p/vault"]}><VaultPage /></MemoryRouter></QueryClientProvider>);
    await userEvent.click(await screen.findByRole("button", { name: /^No folder/ }));
    await userEvent.click(await screen.findByRole("checkbox", { name: "Select Stripe" }));
    expect(screen.getByText("1 selected")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("link", { name: /Needs attention/ }));
    await userEvent.click(screen.getByRole("link", { name: /^Vault/ }));
    expect(await screen.findByRole("checkbox", { name: "Select Stripe" })).not.toBeChecked();
    expect(screen.queryByText("1 selected")).toBeNull();
  });

  it("the first grant on this device pins the gateway and shows its fingerprint", async () => {
    await serveRecord();
    localStorage.clear();
    server.use(
      http.get("/api/v1/me/agents/gateway", () => HttpResponse.json({ identityKeyId: gw.identity.keyId, identityPublicKey: gw.identity.publicKey })),
      http.post("/api/v1/records/:id/agent-grants", () => HttpResponse.json({ ok: true }, { status: 201 })),
    );
    const section = await openShare();
    expect(within(section).queryByLabelText("Gateway identity")).toBeNull();
    await choose(section, "Can use");
    expect(await within(section).findByLabelText("Gateway identity")).toBeInTheDocument();
  });

  it("Agent can update: shown for an agent with Can use when writes are allowed, and sends PATCH { write }", async () => {
    writeAllowed = true;
    const { id } = await serveRecord({ agentGrants: [{ agentId: AGENT_ID, use: true, write: false }] });
    let patched: { path: string; body: unknown } | null = null;
    server.use(http.patch("/api/v1/records/:id/agent-grants/:agentId", async ({ params, request }) => { patched = { path: `${params.id}/${params.agentId}`, body: await request.json() }; return HttpResponse.json({ ok: true }); }));
    const section = await openShare();
    await userEvent.click(await within(section).findByRole("checkbox", { name: "Agent can update this item" }));
    await waitFor(() => expect(patched).toEqual({ path: `${id}/${AGENT_ID}`, body: { write: true } }));
  });

  it("Agent can update is hidden when the rules forbid writes", async () => {
    await serveRecord({ agentGrants: [{ agentId: AGENT_ID, use: true, write: false }] });
    const section = await openShare();
    await within(section).findByRole("combobox", { name: "Access for My bot" });
    expect(within(section).queryByRole("checkbox", { name: "Agent can update this item" })).toBeNull();
  });
});

describe("provenance and Changed by agent", () => {
  it("a kept deposit says which agent created it", async () => {
    await serveRecord({ createdByAgent: true });
    const panel = await openRecord();
    expect(panel).toHaveTextContent(`Created by agent My bot on ${new Date("2026-11-15T10:00:00Z").toLocaleDateString()}`);
  });

  it("a signed change shows the banner; opening doesn't ack it, so it survives a refetch", async () => {
    await serveRecord({ agentChange: "signed" });
    const panel = await openRecord();
    expect(within(panel).getByRole("note", { name: "Changed by agent" })).toHaveTextContent("Changed by agent My bot");
    const before = srv.syncs;
    await qc.invalidateQueries();
    await waitFor(() => expect(srv.syncs).toBeGreaterThan(before));
    expect(srv.acked).toBe(false);
    expect(within(panel).getByRole("note", { name: "Changed by agent" })).toBeInTheDocument();
    expect(within(panel).getByRole("button", { name: "Restore previous" })).toBeInTheDocument();
  });

  it("Looks right acks the change and the banner goes", async () => {
    await serveRecord({ agentChange: "signed" });
    const panel = await openRecord();
    await userEvent.click(within(panel).getByRole("button", { name: "Looks right" }));
    await waitFor(() => expect(within(panel).queryByRole("note", { name: "Changed by agent" })).toBeNull());
    expect(srv.acked).toBe(true);
  });

  it("Restore previous saves the previous body through the normal edit path, acks, and the banner goes", async () => {
    const { id, enc, revision } = await serveRecord({ agentChange: "signed" });
    const prev = { type: "login" as const, title: "Stripe", password: "old-password" };
    let put: { encBody: string; revision: number } | null = null;
    server.use(
      http.get("/api/v1/records/:id/agent-overwrites", async () => HttpResponse.json({ overwrites: [{ id: "ow1", agentId: AGENT_ID, agentName: "My bot",
        prevEncBody: await encryptRecordBody(id, prev, enc.recordKey), newRevision: revision, signature: "", createdAt: "2026-11-16T10:00:00Z" }] })),
      http.put("/api/v1/records/:id", async ({ request }) => { put = (await request.json()) as never; srv.saved = true; return HttpResponse.json({ ok: true }); }),
    );
    const panel = await openRecord();
    await userEvent.click(within(panel).getByRole("button", { name: "Restore previous" }));
    await waitFor(() => expect(put).not.toBeNull());
    expect(put!.revision).toBe(revision);
    expect((await decryptRecordBody(id, put!.encBody, enc.recordKey)).password).toBe("old-password");
    await waitFor(() => expect(srv.acked).toBe(true));
    await waitFor(() => expect(within(panel).queryByRole("note", { name: "Changed by agent" })).toBeNull());
  });

  it("a change the gateway didn't sign over the current body says so", async () => {
    await serveRecord({ agentChange: "unsigned" });
    const panel = await openRecord();
    expect(within(panel).getByRole("note", { name: "Changed by agent" })).toHaveTextContent("Changed, but not signed by the gateway");
  });

  it("a previous version whose key no longer opens (the record key was rotated since) says so", async () => {
    const { id, revision } = await serveRecord({ agentChange: "signed" });
    server.use(
      http.get("/api/v1/records/:id/agent-overwrites", async () => HttpResponse.json({ overwrites: [{ id: "ow1", agentId: AGENT_ID, agentName: "My bot",
        prevEncBody: await encryptRecordBody(id, { type: "login", title: "x" }, randomBytes(32)), newRevision: revision, signature: "", createdAt: "2026-11-16T10:00:00Z" }] })),
    );
    const panel = await openRecord();
    await userEvent.click(within(panel).getByRole("button", { name: "Restore previous" }));
    expect(await within(panel).findByRole("alert")).toHaveTextContent("The previous version can't be opened any more: this item's key changed after the agent's change.");
  });
});
