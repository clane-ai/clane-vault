import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { http, HttpResponse } from "msw";
import {
  agentUpdateMessage, b64url, decryptRecordBody, encryptNewRecord, encryptRecordBody, gatewayKeyId, generateIdentityKeyPair, generateKeyPair, openPersonalAgentRecordKey, randomBytes,
  openRevealStub, sha256B64, type RecordBody, signGatewayMessage, signPersonalAgentKey, standingRevealTag, verifyStandingRevealTag,
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
/** rules.reveal and the gateway's GATEWAY_REVEAL as GET /me/agents reports them. */
let reveal: { rules: string; gateway: string };
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
  reveal = { rules: "off", gateway: "off" };
  srv = { acked: false, saved: false, syncs: 0 };
  await pinGateway(ME, PERSONAL_SLOT, identity);
  agents = [row({ attestation: await gw.attest(agentPub) })];
  server.use(
    http.get("/api/v1/me/agents", () => HttpResponse.json({ agents, allowance: { used: 1, allowed: 2 }, rules: { allowed: true, blockedByOrgId: null, write: writeAllowed, reveal: reveal.rules },
      gateway: { url: "https://gw.test/mcp", identityKeyId: identity.keyId, identityPublicKey: identity.publicKey, reveal: reveal.gateway }, revealEmail: true })),
    http.get("/api/v1/records/:id/activity", () => HttpResponse.json({ events: [] })),
    http.get("/api/v1/users", () => HttpResponse.json({ users: [] })),
  );
});

/** The owner's tag (I2) for one agent, as the gateway checks it: the agent's private key with the owner's public key. */
const tagged = (recordId: string, b: RecordBody | undefined, agentId: string, privateKey = agentKeys.privateKey) =>
  verifyStandingRevealTag(b?.agentReveal?.auth?.[agentId], privateKey, me.publicKey, { recordId, agentId, fields: b?.agentReveal?.fields ?? [] });

async function serveRecord(o: { /** A login with a 2FA secret. */ totp?: boolean; /** The first agent reads these fields without asking (agentReveal), with the owner's tag unless `untagged` (an item set on 1.9.2). */ standing?: string[]; untagged?: boolean; agentGrants?: unknown[]; agentPolicy?: boolean; agentChange?: "signed" | "unsigned"; createdByAgent?: boolean; envFile?: boolean } = {}) {
  const id = crypto.randomUUID();
  const auth = o.standing && !o.untagged ? { auth: { [AGENT_ID]: await standingRevealTag(me.privateKey, agentKeys.publicKey, { recordId: id, agentId: AGENT_ID, fields: o.standing }) } } : {};
  const body = { ...(o.envFile ? { type: "envFile" as const, data: { content: "STRIPE_KEY=sk_live_1\n" } } : { type: "login" as const, username: "sara", password: "pw", ...(o.totp ? { totpSecret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" } : {}) }), title: "Stripe", ...(o.standing ? { agentReveal: { v: 1 as const, agents: [AGENT_ID], fields: o.standing, ...auth } } : {}), ...(o.agentPolicy === false ? {} : { agentPolicy: { v: 1 as const, hosts: ["api.stripe.com"], inject: { kind: "bearer" as const } } }) };
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

describe("Can reveal", () => {
  it("Can reveal with the default field seals a stub to the agent and gives it no record key", async () => {
    reveal = { rules: "approval", gateway: "approval" };
    const { id } = await serveRecord();
    let put: { path: string; body: { sealedStub: string; fields: string[] } } | null = null, granted = false;
    server.use(
      http.put("/api/v1/records/:id/agent-reveal/:agentId", async ({ params, request }) => { put = { path: `${params.id}/${params.agentId}`, body: (await request.json()) as never }; return HttpResponse.json({ ok: true }); }),
      http.post("/api/v1/records/:id/agent-grants", () => { granted = true; return HttpResponse.json({ ok: true }, { status: 201 }); }),
    );
    const section = await openShare();
    await choose(section, "Can reveal");
    expect(within(section).getByText("Can reveal lets the AI model read these fields. Clane Vault cannot take them back afterwards.")).toBeInTheDocument();
    expect(within(section).getByText("Prefer Can use. Reveal only what can't be sent in an HTTP call and is easy to change.")).toBeInTheDocument();
    expect(within(section).getByRole("checkbox", { name: "Password" })).not.toBeChecked();
    await userEvent.click(within(section).getByRole("button", { name: "Save" }));
    await waitFor(() => expect(put).not.toBeNull());
    expect(put!.path).toBe(`${id}/${AGENT_ID}`);
    expect(put!.body.fields).toEqual(["username"]);
    expect(await openRevealStub(put!.body.sealedStub, { ownerUserId: ME, agentId: AGENT_ID, recordId: id }, agentKeys)).toEqual({ title: "Stripe", type: "login", fields: ["username"] });
    expect(granted).toBe(false);
  });

  it("the reveal options are absent when the gateway or the rules say off", async () => {
    for (const r of [{ rules: "approval", gateway: "off" }, { rules: "off", gateway: "approval" }]) {
      reveal = r;
      await serveRecord();
      const section = await openShare();
      await userEvent.click(await within(section).findByRole("combobox", { name: "Access for My bot" }));
      expect(await screen.findByRole("option", { name: "Can use" })).toBeInTheDocument();
      expect(screen.queryByRole("option", { name: "Can reveal" })).toBeNull();
      cleanup();
    }
  });

  it("an env file lists its keys, none ticked, and no whole-file option", async () => {
    reveal = { rules: "approval", gateway: "approval" };
    await serveRecord({ envFile: true, agentPolicy: false });
    const section = await openShare();
    await choose(section, "Can reveal");
    expect(within(section).getByRole("checkbox", { name: "STRIPE_KEY" })).not.toBeChecked();
    expect(within(section).queryByRole("checkbox", { name: /Contents/ })).toBeNull();
    expect(within(section).getByRole("button", { name: "Save" })).toBeDisabled();
  });
});

/** What the sheet saved through the editor's save (VaultScreen passes it as `agentUse.onSave`): the bodies, in order. */
let savedBodies: RecordBody[];
const page = () => <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter initialEntries={["/p/vault"]}>
  <VaultPage agentUse={{ pathsLocked: false, onSave: async (_r, body) => { savedBodies.push(body); } }} /></MemoryRouter></QueryClientProvider>;
/** The record's panel with Agent use on in this space, and its sheet opened from the header. */
async function openAgentUse(status: string) {
  savedBodies = [];
  render(page());
  await userEvent.click(await screen.findByRole("button", { name: /^No folder/ }));
  await userEvent.click(await screen.findByRole("button", { name: /Stripe/ }));
  await userEvent.click(await screen.findByRole("button", { name: `Agent use: ${status}` }));
  return screen.findByRole("dialog", { name: "Agent use: Stripe" });
}

describe("the Agent use sheet on a Personal item", () => {
  const SEE = "Let the AI see this value";
  const WITHOUT = "Without asking", ASK = "Ask me each time";
  const everywhere = { rules: "standing", gateway: "standing" };
  const toggleOf = (section: HTMLElement, name = "My bot") => within(section).getByRole("switch", { name: `Let ${name} see values from this item` });
  const calls = () => {
    const seen = { stub: null as { path: string; body: { sealedStub: string; fields: string[] } } | null, granted: [] as string[], unrevealed: [] as string[], revoked: [] as string[] };
    server.use(
      http.put("/api/v1/records/:id/agent-reveal/:agentId", async ({ params, request }) => { seen.stub = { path: `${params.id}/${params.agentId}`, body: (await request.json()) as never }; return HttpResponse.json({ ok: true }); }),
      http.post("/api/v1/records/:id/agent-grants", async ({ request }) => { seen.granted.push(((await request.json()) as { agentId: string }).agentId); return HttpResponse.json({ ok: true }, { status: 201 }); }),
      http.delete("/api/v1/records/:id/agent-reveal/:agentId", ({ params }) => { seen.unrevealed.push(String(params.agentId)); return HttpResponse.json({ ok: true }); }),
      http.delete("/api/v1/records/:id/agent-grants/:agentId", ({ params }) => { seen.revoked.push(String(params.agentId)); return HttpResponse.json({ ok: true }); }),
    );
    return seen;
  };

  it("the share sheet's no-settings line opens it", async () => {
    await serveRecord({ agentPolicy: false });
    savedBodies = [];
    render(page());
    await userEvent.click(await screen.findByRole("button", { name: /^No folder/ }));
    await userEvent.click(await screen.findByRole("button", { name: /Stripe/ }));
    await userEvent.click(screen.getByRole("button", { name: "Share" }));
    const agents = await within(await screen.findByRole("dialog")).findByRole("region", { name: "Agents" });
    expect(within(agents).getByText("This item has no Agent use settings yet, so the agent can't use it.")).toBeInTheDocument();
    await userEvent.click(within(agents).getByRole("button", { name: "Set up Agent use" }));
    expect(await screen.findByRole("dialog", { name: "Agent use: Stripe" })).toBeInTheDocument();
    expect(screen.queryByRole("dialog", { name: "Share Stripe" })).toBeNull();
  });

  it("the summary names the agent that holds the item", async () => {
    await serveRecord({ agentGrants: [{ agentId: AGENT_ID, use: true, write: false }] });
    const sheet = await openAgentUse("Use");
    const status = within(sheet).getByRole("region", { name: "Status" });
    expect(status).toHaveTextContent("1 agent can use this item.");
    expect(await within(status).findByRole("listitem", { name: "My bot" })).toHaveTextContent("Use");
  });

  it("turning See on is the consent: Without asking by default, one dialog the first time, then the item's encrypted setting and the key", async () => {
    reveal = everywhere;
    const { id } = await serveRecord({ totp: true });
    const seen = calls();
    const section = await within(await openAgentUse("Use")).findByRole("region", { name: SEE });
    expect(section).toHaveTextContent("Off until you turn it on. Turning it on is your consent");
    expect(within(section).queryByRole("note", { name: "Reading values here" })).toBeNull();
    expect(toggleOf(section)).not.toBeChecked();
    expect(within(section).queryByRole("checkbox")).toBeNull();
    await userEvent.click(toggleOf(section));
    expect(within(section).getByRole("radio", { name: new RegExp(WITHOUT) })).toBeChecked();
    expect(within(section).getByRole("radio", { name: new RegExp(ASK) })).not.toBeChecked();
    expect(within(section).getByText("The AI model reads these fields. Clane Vault can't take back what it has read.")).toBeInTheDocument();
    expect(within(section).getByRole("note", { name: "Sharing with an agent" })).toBeInTheDocument();
    expect(within(section).getByRole("checkbox", { name: "Username" })).toBeChecked();
    expect(within(section).getByRole("checkbox", { name: "Password" })).not.toBeChecked();
    await userEvent.click(within(section).getByRole("checkbox", { name: "Current one-time code" }));
    await userEvent.click(within(section).getByRole("button", { name: "Save" }));
    // Nothing is saved before the dialog is answered, and there is no title to type.
    const dialog = await screen.findByRole("dialog", { name: "Let My bot see this?" });
    expect(dialog).toHaveTextContent("My bot will be able to read Username and Current one-time code of Stripe whenever it needs them, without asking you. Clane Vault can't take back what it has read.");
    expect(within(dialog).queryByRole("textbox")).toBeNull();
    expect(savedBodies).toEqual([]);
    await userEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    expect(savedBodies).toEqual([]);
    await userEvent.click(within(section).getByRole("button", { name: "Save" }));
    await userEvent.click(within(await screen.findByRole("dialog", { name: "Let My bot see this?" })).getByRole("button", { name: "Allow" }));
    await waitFor(() => expect(seen.granted).toEqual([AGENT_ID]));
    // The setting is in the record's body (the editor's save); the agent gets the item's key; no approval stub.
    expect(savedBodies).toHaveLength(1);
    expect(savedBodies[0]!.agentReveal).toMatchObject({ v: 1, agents: [AGENT_ID], fields: ["totp", "username"] });
    // With the owner's tag for that agent, so the gateway knows the owner turned it on (I2).
    expect(await tagged(id, savedBodies[0], AGENT_ID)).toBe(true);
    expect(savedBodies[0]).toMatchObject({ title: "Stripe", username: "sara", password: "pw", agentPolicy: { hosts: ["api.stripe.com"] } });
    // The same fields as an approval stub too, so a later approval rule makes the agent ask instead of reading nothing.
    await waitFor(() => expect(seen.stub?.body.fields).toEqual(["totp", "username"]));
  });

  it("Ask me each time is the approval way: a stub sealed to the agent, no key, and the record is not saved", async () => {
    reveal = everywhere;
    const { id } = await serveRecord();
    const seen = calls();
    const section = await within(await openAgentUse("Use")).findByRole("region", { name: SEE });
    await userEvent.click(toggleOf(section));
    await userEvent.click(within(section).getByRole("radio", { name: new RegExp(ASK) }));
    await userEvent.click(within(section).getByRole("button", { name: "Save" }));
    const dialog = await screen.findByRole("dialog", { name: "Let My bot see this?" });
    expect(dialog).toHaveTextContent("My bot will be able to read Username of Stripe after you approve each read. Clane Vault can't take back what it has read.");
    await userEvent.click(within(dialog).getByRole("button", { name: "Allow" }));
    await waitFor(() => expect(seen.stub).not.toBeNull());
    expect(seen.stub!.path).toBe(`${id}/${AGENT_ID}`);
    expect(seen.stub!.body.fields).toEqual(["username"]);
    expect(await openRevealStub(seen.stub!.body.sealedStub, { ownerUserId: ME, agentId: AGENT_ID, recordId: id }, agentKeys)).toEqual({ title: "Stripe", type: "login", fields: ["username"] });
    expect(seen.granted).toEqual([]);
    expect(savedBodies).toEqual([]);
  });

  it("the dialog is for the first time on an item: a second agent is added without it, and shares the fields", async () => {
    reveal = everywhere;
    const SECOND = "cccccccc-0000-4000-8000-000000000003";
    const kp = await generateKeyPair();
    const pub = b64url.encode(kp.publicKey);
    // The fixture's attestation names the first agent's id, so the second one's key is refused: the body is saved first.
    agents = [...agents, row({ id: SECOND, name: "Second bot", publicKey: pub, attestation: await gw.attest(pub) })];
    const { id } = await serveRecord({ standing: ["username"], agentGrants: [{ agentId: AGENT_ID, use: true, write: false }] });
    calls();
    const section = await within(await openAgentUse("Use + See")).findByRole("region", { name: SEE });
    expect(within(section).getAllByRole("switch").map((s) => s.getAttribute("aria-label"))).toEqual(["Let My bot see values from this item", "Let Second bot see values from this item"]);
    expect(within(section).getByRole("listitem", { name: "My bot" })).toHaveTextContent("Reads without asking: Username");
    await userEvent.click(toggleOf(section, "Second bot"));
    expect(within(section).getByText("Agents that read without asking share one list of fields.")).toBeInTheDocument();
    await userEvent.click(within(section).getByRole("button", { name: "Save" }));
    await waitFor(() => expect(savedBodies).toHaveLength(1));
    expect(screen.queryByRole("dialog", { name: /^Let .* see this\?$/ })).toBeNull();
    expect(savedBodies[0]!.agentReveal).toMatchObject({ v: 1, agents: [AGENT_ID, SECOND], fields: ["username"] });
    expect(await tagged(id, savedBodies[0], AGENT_ID)).toBe(true);
    expect(await tagged(id, savedBodies[0], SECOND, kp.privateKey)).toBe(true);
  });

  it("an item set to Without asking with no owner's tag (1.9.2, or listed by an editor) asks to be turned on again, and only the owner's save tags it (I2)", async () => {
    reveal = everywhere;
    const SECOND = "cccccccc-0000-4000-8000-000000000003";
    const kp = await generateKeyPair();
    agents = [...agents, row({ id: SECOND, name: "Second bot", publicKey: b64url.encode(kp.publicKey), attestation: await gw.attest(b64url.encode(kp.publicKey)) })];
    const { id } = await serveRecord({ standing: ["username"], untagged: true, agentGrants: [{ agentId: AGENT_ID, use: true, write: false }] });
    calls();
    const section = await within(await openAgentUse("Use + See")).findByRole("region", { name: SEE });
    const mine = within(section).getByRole("listitem", { name: "My bot" });
    await waitFor(() => expect(mine).toHaveTextContent("Turn this on again to keep reading without asking."));
    // Adding another agent doesn't tag the untagged one.
    await userEvent.click(toggleOf(section, "Second bot"));
    await userEvent.click(within(section).getByRole("button", { name: "Save" }));
    await waitFor(() => expect(savedBodies).toHaveLength(1));
    expect(await tagged(id, savedBodies[0], SECOND, kp.privateKey)).toBe(true);
    expect(await tagged(id, savedBodies[0], AGENT_ID)).toBe(false);
    cleanup();
    // Saving it again for that agent is the owner's consent: now it is tagged.
    const again = await serveRecord({ standing: ["username"], untagged: true, agentGrants: [{ agentId: AGENT_ID, use: true, write: false }] });
    const s2 = await within(await openAgentUse("Use + See")).findByRole("region", { name: SEE });
    await userEvent.click(within(within(s2).getByRole("listitem", { name: "My bot" })).getByRole("button", { name: "Change" }));
    await userEvent.click(within(s2).getByRole("button", { name: "Save" }));
    await waitFor(() => expect(savedBodies).toHaveLength(1));
    expect(await tagged(again.id, savedBodies[0], AGENT_ID)).toBe(true);
  });

  it("an organisation that requires approval overrides the item: Without asking can't be chosen, and the section says why", async () => {
    reveal = { rules: "approval", gateway: "standing" };
    await serveRecord();
    calls();
    const section = await within(await openAgentUse("Use")).findByRole("region", { name: SEE });
    expect(within(section).getByRole("note", { name: "Reading values here" })).toHaveTextContent("Your organisation requires approval for each read.");
    await userEvent.click(toggleOf(section));
    expect(within(section).getByRole("radio", { name: new RegExp(WITHOUT) })).toBeDisabled();
    expect(within(section).getByRole("radio", { name: new RegExp(ASK) })).toBeChecked();
    cleanup();
    // The operator's setting does the same, in its own words.
    reveal = { rules: "standing", gateway: "approval" };
    await serveRecord();
    const again = await within(await openAgentUse("Use")).findByRole("region", { name: SEE });
    expect(within(again).getByRole("note", { name: "Reading values here" })).toHaveTextContent("This server requires approval for each read.");
    cleanup();
    // An agent set to read without asking falls back to asking, for the fields its stub names.
    await serveRecord({ standing: ["username"], agentGrants: [{ agentId: AGENT_ID, use: true, write: false, reveal: ["username"] }] });
    const third = await within(await openAgentUse("Use + See")).findByRole("region", { name: SEE });
    expect(within(third).getByRole("listitem", { name: "My bot" })).toHaveTextContent("Reads without asking: Username (asks first for now)");
  });

  it("reading switched off says so on the item, and offers no switch", async () => {
    for (const [r, words] of [[{ rules: "off", gateway: "standing" }, "Your organisation has turned reading values off."], [{ rules: "standing", gateway: "off" }, "Reading values is off on this server."]] as const) {
      reveal = r;
      await serveRecord();
      const section = await within(await openAgentUse("Use")).findByRole("region", { name: SEE });
      expect(within(section).getByRole("note", { name: "Reading values here" })).toHaveTextContent(words);
      expect(within(section).queryByRole("switch")).toBeNull();
      cleanup();
    }
  });

  it("what is on can be turned off where it is no longer offered; without asking shows as paused", async () => {
    reveal = { rules: "approval", gateway: "standing" };
    await serveRecord({ standing: ["username"], agentPolicy: false, agentGrants: [{ agentId: AGENT_ID, use: true, write: false }] });
    const seen = calls();
    const section = await within(await openAgentUse("See")).findByRole("region", { name: SEE });
    expect(within(section).getByRole("listitem", { name: "My bot" })).toHaveTextContent("Reads without asking: Username (paused)");
    await userEvent.click(toggleOf(section));
    await waitFor(() => expect(seen.revoked).toEqual([AGENT_ID]));
    // The setting leaves the body, and the key it needed goes too: the item has no Agent use settings to use it with.
    expect(savedBodies).toHaveLength(1);
    expect(savedBodies[0]).not.toHaveProperty("agentReveal");
  });

  it("turning off Ask me each time takes the fields away (DELETE); the header marks an item whose agents all ask first", async () => {
    reveal = everywhere;
    await serveRecord({ agentGrants: [{ agentId: AGENT_ID, use: false, write: false, reveal: ["username"] }] });
    const seen = calls();
    const section = await within(await openAgentUse("Use + See, asks first")).findByRole("region", { name: SEE });
    expect(within(section).getByRole("listitem", { name: "My bot" })).toHaveTextContent("Asks first: Username");
    expect(toggleOf(section)).toBeChecked();
    await userEvent.click(toggleOf(section));
    await waitFor(() => expect(seen.unrevealed).toEqual([AGENT_ID]));
    expect(savedBodies).toEqual([]);
  });

  it("changing from Ask me each time to Without asking: the setting and the key go in, and the stub stays for an approval rule", async () => {
    reveal = everywhere;
    await serveRecord({ agentGrants: [{ agentId: AGENT_ID, use: false, write: false, reveal: ["username"] }] });
    const seen = calls();
    const section = await within(await openAgentUse("Use + See, asks first")).findByRole("region", { name: SEE });
    await userEvent.click(within(section).getByRole("button", { name: "Change" }));
    expect(within(section).getByRole("radio", { name: new RegExp(ASK) })).toBeChecked();
    await userEvent.click(within(section).getByRole("radio", { name: new RegExp(WITHOUT) }));
    await userEvent.click(within(section).getByRole("button", { name: "Save" }));
    await waitFor(() => expect(seen.stub?.body.fields).toEqual(["username"]));
    expect(seen.unrevealed).toEqual([]);
    expect(savedBodies[0]!.agentReveal).toMatchObject({ v: 1, agents: [AGENT_ID], fields: ["username"] });
    expect(seen.granted).toEqual([AGENT_ID]);
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

  it("an env file: the banner lists the changed keys, and Restore previous saves the previous text exactly", async () => {
    const { id, enc, revision } = await serveRecord({ agentChange: "signed", envFile: true, agentPolicy: false });
    const prevText = "STRIPE_KEY=sk_old\r\n# kept\r\nOLD=1\r\n";
    let put: { encBody: string; revision: number } | null = null;
    server.use(
      http.get("/api/v1/records/:id/agent-overwrites", async () => HttpResponse.json({ overwrites: [{ id: "ow1", agentId: AGENT_ID, agentName: "My bot",
        prevEncBody: await encryptRecordBody(id, { type: "envFile", title: "Stripe", data: { content: prevText } }, enc.recordKey), newRevision: revision, signature: "", createdAt: "2026-11-16T10:00:00Z" }] })),
      http.put("/api/v1/records/:id", async ({ request }) => { put = (await request.json()) as never; srv.saved = true; return HttpResponse.json({ ok: true }); }),
    );
    const panel = await openRecord();
    const banner = within(panel).getByRole("note", { name: "Changed by agent" });
    await waitFor(() => expect(banner).toHaveTextContent("Changed: STRIPE_KEY"));
    expect(banner).toHaveTextContent("Removed: OLD");
    await userEvent.click(within(panel).getByRole("button", { name: "Restore previous" }));
    await waitFor(() => expect(put).not.toBeNull());
    expect((await decryptRecordBody(id, put!.encBody, enc.recordKey)).data?.content).toBe(prevText);
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
