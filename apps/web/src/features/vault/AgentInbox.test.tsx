import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { http, HttpResponse } from "msw";
import * as cryptoModule from "@clane-vault/crypto";
import {
  agentDepositMessage, b64url, encryptRecordBody, gatewayKeyId, generateIdentityKeyPair, generateKeyPair, openPersonalAgentRecordKey, randomBytes, sealDepositKeyToOwner,
  sha256B64, signGatewayMessage, signPersonalAgentKey, unwrapKey, type RecordBody,
} from "@clane-vault/crypto";
import { server } from "@/test/server";
import * as sessionModule from "@/lib/session";
import { PERSONAL_SLOT, pinGateway, pinnedGateway, type GatewayIdentity } from "@/lib/orgKeys";
import type { MyAgent } from "@/features/settings/myAgents";
import { AgentInbox } from "./AgentInbox";
import VaultPage from "./VaultPage";
import type { VaultRecord } from "./types";

// Every call to openDepositKey is recorded: nothing may be opened before the gateway's signature checks out (spec §8).
vi.mock("@clane-vault/crypto", async (orig) => {
  const real = await orig<typeof import("@clane-vault/crypto")>();
  return { ...real, openDepositKey: vi.fn(real.openDepositKey) };
});
const openSpy = vi.mocked(cryptoModule.openDepositKey);

globalThis.ResizeObserver ??= class { observe() {} unobserve() {} disconnect() {} } as never;
const ME = "11111111-0000-4000-8000-000000000001";
const AGENT_ID = "bbbbbbbb-0000-4000-8000-000000000002";
const me = { userKey: randomBytes(32), ...(await generateKeyPair()) };
const ownerPublicKey = b64url.encode(me.publicKey);
const agentKeys = await generateKeyPair();
const agentPub = b64url.encode(agentKeys.publicKey);
/** The session's lock generation: bumped to simulate a lock while a fetch is running. */
let gen = 0;
const session = { org: null, orgs: [], applyOrgs: vi.fn(), user: { id: ME, name: "Sara", role: "member" }, generation: () => gen, lock: vi.fn(), signOut: vi.fn(), keys: me };
vi.spyOn(sessionModule, "useSession").mockImplementation(() => session as never);

const BODY: RecordBody = { type: "login", title: "Stripe", username: "sara@example.com", password: "sk_live_x", agentPolicy: { v: 1, hosts: ["api.stripe.com"], inject: { kind: "bearer" } } };
let gw: { identity: GatewayIdentity; privateKey: Uint8Array };
let deposits: unknown[];
let agents: MyAgent[];
let inboxLoads: number;

async function deposit(o: { signer?: Uint8Array; noSignature?: boolean; ownerKey?: string; createdAt?: string; expiresAt?: string; agentId?: string; body?: RecordBody } = {}) {
  const id = crypto.randomUUID();
  const recordKey = randomBytes(32);
  const encBody = await encryptRecordBody(id, o.body ?? BODY, recordKey);
  const message = agentDepositMessage({ ownerUserId: ME, ownerPublicKey: o.ownerKey ?? ownerPublicKey, agentId: o.agentId ?? AGENT_ID, id, revision: 1, encBodyHash: await sha256B64(encBody) });
  const signature = o.noSignature ? "" : await signGatewayMessage(o.signer ?? gw.privateKey, gw.identity.keyId, "d1", message);
  // The server's agentName isn't covered by the signature: the page names the agent from My agents.
  const row = { id, agentId: o.agentId ?? AGENT_ID, agentName: "Server's name", app: "Claude", type: "login", encBody, revision: 1, signature,
    ownerSealedKey: await sealDepositKeyToOwner(recordKey, { ownerUserId: ME, id }, me.publicKey),
    createdAt: o.createdAt ?? new Date().toISOString(), updatedAt: new Date().toISOString(), expiresAt: o.expiresAt ?? new Date(Date.now() + 90 * 864e5).toISOString() };
  return { row, recordKey, id };
}

beforeEach(async () => {
  try { localStorage.clear(); } catch { /* none */ }
  openSpy.mockClear();
  gen = 0;
  const kp = await generateIdentityKeyPair();
  gw = { identity: { keyId: await gatewayKeyId(kp.publicKey), publicKey: b64url.encode(kp.publicKey) }, privateKey: kp.privateKey };
  await pinGateway(ME, PERSONAL_SLOT, gw.identity);
  const attestation = await signPersonalAgentKey(kp.privateKey, gw.identity.keyId, { ownerUserId: ME, ownerPublicKey, agentId: AGENT_ID, publicKey: agentPub });
  agents = [{ id: AGENT_ID, name: "My bot", status: "active", publicKey: agentPub, attestation, expiresAt: null, lastUsedAt: null, createdAt: "2026-11-15T00:00:00Z",
    verifiedAt: "2026-11-15T00:00:00Z", items: 0, owner: { userId: ME, publicKey: ownerPublicKey }, tokens: [], grants: [] }];
  deposits = [];
  inboxLoads = 0;
  server.use(
    http.get("/api/v1/me/agent-deposits", () => { inboxLoads++; return HttpResponse.json({ deposits }); }),
    http.get("/api/v1/me/agents", () => HttpResponse.json({ agents, allowance: { used: 1, allowed: 2 }, rules: { allowed: true, blockedByOrgId: null, write: true, reveal: "off" }, gateway: null, revealEmail: true })),
    http.get("/api/v1/me/agents/gateway", () => HttpResponse.json({ identityKeyId: gw.identity.keyId, identityPublicKey: gw.identity.publicKey })),
  );
});

const renderInbox = (records: VaultRecord[] = []) => render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
  <MemoryRouter><AgentInbox folders={[]} records={records} /></MemoryRouter></QueryClientProvider>);
const REFUSAL = "Not signed by the gateway — delete it";

describe("From agents", () => {
  it("a deposit signed by the pinned gateway for my key shows its title, username, agent, app and the agent's policy", async () => {
    const good = await deposit();
    deposits = [good.row];
    renderInbox();
    const card = await screen.findByRole("article", { name: "Stripe" });
    expect(within(card).getByText("sara@example.com")).toBeInTheDocument();
    expect(card).toHaveTextContent("From My bot");
    expect(card).not.toHaveTextContent("Server's name");
    expect(card).toHaveTextContent("Claude");
    expect(card).toHaveTextContent(/set by the agent/);
    expect(card).toHaveTextContent("api.stripe.com");
    expect(within(card).queryByText(REFUSAL)).toBeNull();
    expect(openSpy).toHaveBeenCalledTimes(1);
  });

  it("another identity's signature, no signature, or another owner key: the refusal with Delete only, and nothing is opened", async () => {
    const other = await generateIdentityKeyPair();
    const bad = [await deposit({ signer: other.privateKey }), await deposit({ noSignature: true }), await deposit({ ownerKey: b64url.encode((await generateKeyPair()).publicKey) })];
    deposits = bad.map((d) => d.row);
    renderInbox();
    await waitFor(() => expect(screen.getAllByText(REFUSAL)).toHaveLength(3));
    expect(screen.queryByRole("button", { name: "Keep" })).toBeNull();
    expect(screen.getAllByRole("button", { name: "Delete" })).toHaveLength(3);
    expect(screen.queryByText("Stripe")).toBeNull();
    expect(openSpy).not.toHaveBeenCalled();
  });

  it("with no gateway pinned on this device it asks to verify the gateway first (no refusal, no Keep), and the pin flow opens it", async () => {
    localStorage.clear();
    const good = await deposit();
    deposits = [good.row];
    renderInbox();
    expect(await screen.findByText("Verify your gateway on this device first")).toBeInTheDocument();
    expect(screen.queryByText(REFUSAL)).toBeNull();
    expect(screen.queryByRole("button", { name: "Keep" })).toBeNull();
    expect(openSpy).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole("button", { name: "Verify gateway" }));
    expect(await screen.findByRole("article", { name: "Stripe" })).toBeInTheDocument();
    expect(screen.getByLabelText("Gateway identity")).toBeInTheDocument();
    expect(pinnedGateway(ME, PERSONAL_SLOT)).toEqual(gw.identity);
  });

  it("Keep wraps the record key under my user key and, ticked, seals it to the agent; unticked it is left out", async () => {
    const a = await deposit(), b = await deposit();
    deposits = [a.row];
    const posts: Record<string, { revision: number; wrappedRecordKey: string; folderId: string | null; agentWrappedRecordKey?: string }> = {};
    server.use(http.post("/api/v1/me/agent-deposits/:id/keep", async ({ params, request }) => {
      posts[params.id as string] = (await request.json()) as never;
      deposits = deposits.filter((d) => (d as { id: string }).id !== params.id);
      return HttpResponse.json({ id: params.id, revision: 1 }, { status: 201 });
    }));
    const view = renderInbox();
    const card = await screen.findByRole("article", { name: "Stripe" });
    expect(within(card).getByRole("checkbox", { name: "My bot can keep using this item" })).toBeChecked();
    await userEvent.click(within(card).getByRole("button", { name: "Keep" }));
    await waitFor(() => expect(posts[a.id]).toBeDefined());
    const p = posts[a.id]!;
    expect(p.revision).toBe(1);
    expect(p.folderId).toBeNull();
    expect(await unwrapKey(p.wrappedRecordKey, me.userKey, `record-key:${a.id}`)).toEqual(a.recordKey);
    expect(await openPersonalAgentRecordKey(p.agentWrappedRecordKey!, { ownerUserId: ME, agentId: AGENT_ID, recordId: a.id }, agentKeys)).toEqual(a.recordKey);
    view.unmount();

    deposits = [b.row];
    renderInbox();
    const card2 = await screen.findByRole("article", { name: "Stripe" });
    await userEvent.click(within(card2).getByRole("checkbox", { name: "My bot can keep using this item" }));
    await userEvent.click(within(card2).getByRole("button", { name: "Keep" }));
    await waitFor(() => expect(posts[b.id]).toBeDefined());
    expect(posts[b.id]!.agentWrappedRecordKey).toBeUndefined();
    expect(await unwrapKey(posts[b.id]!.wrappedRecordKey, me.userKey, `record-key:${b.id}`)).toEqual(b.recordKey);
  });

  it("kept, but the agent holds 200 items: says the agent won't get it", async () => {
    deposits = [(await deposit()).row];
    server.use(http.post("/api/v1/me/agent-deposits/:id/keep", () => { deposits = []; return HttpResponse.json({ id: "x", revision: 1, agentRow: false }, { status: 201 }); }));
    renderInbox();
    await userEvent.click(await screen.findByRole("button", { name: "Keep" }));
    expect(await screen.findByText(/^Kept\. My bot already has 200 items, so it can't use this one\./)).toHaveAttribute("role", "status");
  });

  it("a stale revision (409 conflict) reloads the inbox and says the agent changed it; the replaced copy's key is zeroed", async () => {
    deposits = [(await deposit()).row];
    server.use(http.post("/api/v1/me/agent-deposits/:id/keep", () => HttpResponse.json({ error: "conflict" }, { status: 409 })));
    renderInbox();
    await userEvent.click(await screen.findByRole("button", { name: "Keep" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("The agent changed this item. Check it again.");
    await waitFor(() => expect(inboxLoads).toBe(2));
    const first = await openSpy.mock.results[0]!.value as Uint8Array;
    await waitFor(() => expect(first.every((b) => b === 0)).toBe(true));
  });

  it("a fetch that finishes after a lock keeps nothing: the opened keys are zeroed and nothing is shown", async () => {
    deposits = [(await deposit()).row];
    server.use(http.get("/api/v1/me/agent-deposits", () => { gen++; return HttpResponse.json({ deposits }); }));
    renderInbox();
    await waitFor(() => expect(openSpy).toHaveBeenCalled());
    const key = await openSpy.mock.results[0]!.value as Uint8Array;
    await waitFor(() => expect(key.every((b) => b === 0)).toBe(true));
    expect(screen.queryByRole("article", { name: "Stripe" })).toBeNull();
  });

  it("while loading it says so", async () => {
    server.use(http.get("/api/v1/me/agent-deposits", () => new Promise(() => undefined)));
    renderInbox();
    expect(await screen.findByRole("status")).toHaveTextContent("Checking items from your agents…");
  });

  it("an agent not in My agents is named 'an agent', never by the server's word", async () => {
    deposits = [(await deposit({ agentId: "cccccccc-0000-4000-8000-000000000003" })).row];
    renderInbox();
    const card = await screen.findByRole("article", { name: "Stripe" });
    expect(card).toHaveTextContent("From an agent");
    expect(card).not.toHaveTextContent("Server's name");
  });

  it("Delete asks first, then deletes it", async () => {
    const d = await deposit();
    deposits = [d.row];
    let deleted: string | null = null;
    server.use(http.delete("/api/v1/me/agent-deposits/:id", ({ params }) => { deleted = params.id as string; deposits = []; return new HttpResponse(null, { status: 204 }); }));
    renderInbox();
    const card = await screen.findByRole("article", { name: "Stripe" });
    await userEvent.click(within(card).getByRole("button", { name: "Delete" }));
    expect(deleted).toBeNull();
    expect(within(card).getByText("Delete this item? It can't be undone.")).toBeInTheDocument();
    await userEvent.click(within(card).getByRole("button", { name: "Cancel" }));
    expect(deleted).toBeNull();
    await userEvent.click(within(card).getByRole("button", { name: "Delete" }));
    await userEvent.click(within(card).getByRole("button", { name: "Delete it" }));
    await waitFor(() => expect(deleted).toBe(d.id));
  });

  it("a failed Delete says so on the card", async () => {
    deposits = [(await deposit()).row];
    server.use(http.delete("/api/v1/me/agent-deposits/:id", () => HttpResponse.json({ error: "internal" }, { status: 500 })));
    renderInbox();
    const card = await screen.findByRole("article", { name: "Stripe" });
    await userEvent.click(within(card).getByRole("button", { name: "Delete" }));
    await userEvent.click(within(card).getByRole("button", { name: "Delete it" }));
    expect(await within(card).findByRole("alert")).toHaveTextContent("Couldn't delete it. Try again.");
  });

  it("/p/agents: private-locked shows the authenticator step-up; with personal agents off (404) it goes to the vault", async () => {
    server.use(http.get("/api/v1/sync", () => HttpResponse.json({ serverTime: "", folders: [], records: [], privateLocked: true })));
    const view = render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter initialEntries={["/p/agents"]}><VaultPage /></MemoryRouter></QueryClientProvider>);
    expect(await screen.findByRole("region", { name: "Confirm with your authenticator" })).toBeInTheDocument();
    expect(screen.queryByText("Nothing from your agents")).toBeNull();
    view.unmount();

    server.use(
      http.get("/api/v1/sync", () => HttpResponse.json({ serverTime: "", folders: [], records: [] })),
      http.get("/api/v1/me/agent-deposits", () => HttpResponse.json({ error: "not_found" }, { status: 404 })),
    );
    render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter initialEntries={["/p/agents"]}><VaultPage /></MemoryRouter></QueryClientProvider>);
    expect(await screen.findByRole("heading", { name: "Personal vault" })).toBeInTheDocument();
    expect(screen.queryByText(/Couldn't load/)).toBeNull();
  });

  it("from day 60 it warns when it will be deleted", async () => {
    const created = Date.now() - 70 * 864e5;
    deposits = [(await deposit({ createdAt: new Date(created).toISOString(), expiresAt: new Date(created + 90 * 864e5).toISOString() })).row, (await deposit()).row];
    renderInbox();
    await waitFor(() => expect(screen.getAllByRole("article", { name: "Stripe" })).toHaveLength(2));
    expect(screen.getAllByText("Deleted in 20 days unless you keep it.")).toHaveLength(1);
  });

  it("the Personal sidebar has From agents with the count from /sync; an organisation space has none", async () => {
    server.use(http.get("/api/v1/sync", () => HttpResponse.json({ serverTime: "", folders: [], records: [], agentInbox: 3 })));
    const view = render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter initialEntries={["/p/vault"]}><VaultPage /></MemoryRouter></QueryClientProvider>);
    const link = await screen.findByRole("link", { name: /From agents/ });
    expect(link).toHaveTextContent("3");
    expect(link).toHaveAttribute("href", "/p/agents");
    view.unmount();

    const ORG = { id: "o1", name: "Acme", slug: "acme", role: "member", isDefault: true };
    const prev = { ...session };
    Object.assign(session, { org: ORG, orgs: [ORG] });
    try {
      server.use(http.get("/api/v1/sync", () => HttpResponse.json({ serverTime: "", folders: [], records: [], orgId: "o1", membershipKeys: [] })));
      render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter initialEntries={["/o/acme/vault"]}><VaultPage /></MemoryRouter></QueryClientProvider>);
      await screen.findByRole("link", { name: /Trash/ });
      expect(screen.queryByRole("link", { name: /From agents/ })).toBeNull();
    } finally { Object.assign(session, prev); }
  });
});

describe("From agents: .env files", () => {
  const POLICY = { v: 1 as const, hosts: ["api.billing.dev"], inject: { kind: "bearer" as const }, secret: "env:A" };
  const envBody = (o: { project?: string; content?: string } = {}): RecordBody =>
    ({ type: "envFile", title: "Billing from agent", data: { project: o.project ?? "billing", fileName: ".env", content: o.content ?? "A=1\nB=3\nC=4\n" } });
  let existingKey: Uint8Array;
  let existing: VaultRecord;
  let calls: string[];
  let put: { encBody: string; revision: number } | null;
  beforeEach(() => {
    existingKey = randomBytes(32);
    existing = { id: crypto.randomUUID(), folderId: null, type: "item", revision: 3, updatedAt: "2026-11-10T00:00:00Z", deleted: false, permission: "owner", recordKey: existingKey,
      body: { type: "envFile", title: "Billing", notes: "billing secrets", data: { project: "billing", fileName: ".env", content: "A=1\nB=2\nD=4\n" }, agentPolicy: POLICY } };
    calls = []; put = null;
    server.use(
      http.put("/api/v1/records/:id", async ({ params, request }) => { calls.push(`PUT ${params.id}`); put = (await request.json()) as never; return HttpResponse.json({ ok: true }); }),
      http.delete("/api/v1/me/agent-deposits/:id", ({ params }) => { calls.push(`DELETE ${params.id}`); deposits = []; return new HttpResponse(null, { status: 204 }); }),
      http.post("/api/v1/me/agent-deposits/:id/keep", ({ params }) => { calls.push(`KEEP ${params.id}`); return HttpResponse.json({ id: params.id, revision: 1 }, { status: 201 }); }),
    );
  });

  it("shows the entries masked until Show", async () => {
    deposits = [(await deposit({ body: envBody() })).row];
    renderInbox();
    const card = await screen.findByRole("article", { name: "Billing from agent" });
    const rows = within(within(card).getByRole("list", { name: "Entries" })).getAllByRole("listitem");
    expect(rows.map((r) => r.textContent?.slice(0, 1))).toEqual(["A", "B", "C"]);
    expect(within(card).getByLabelText("B value")).not.toHaveTextContent("3");
    await userEvent.click(within(card).getByRole("button", { name: "Show B" }));
    expect(within(card).getByLabelText("B value")).toHaveTextContent("3");
  });

  it("preselects Replace the contents of the matching file, shows the differences, and replaces it: one PUT then one DELETE, no keep", async () => {
    const d = await deposit({ body: envBody() });
    deposits = [d.row];
    renderInbox([existing]);
    const card = await screen.findByRole("article", { name: "Billing from agent" });
    expect(within(card).getByRole("radio", { name: "Replace the contents of" })).toBeChecked();
    expect(within(card).getByRole("combobox", { name: "Item to replace" })).toHaveTextContent("Billing");
    expect(card).toHaveTextContent("Added: C");
    expect(card).toHaveTextContent("Changed: B");
    expect(card).toHaveTextContent("Removed: D");
    expect(card).toHaveTextContent("The current contents will be replaced.");
    expect(card).toHaveTextContent("The existing item keeps its own agent settings.");
    expect(within(card).getByRole("button", { name: "Download current" })).toBeInTheDocument();
    await userEvent.click(within(card).getByRole("button", { name: "Replace" }));
    await waitFor(() => expect(calls).toEqual([`PUT ${existing.id}`, `DELETE ${d.id}`]));
    expect(put!.revision).toBe(3);
    const saved = await cryptoModule.decryptRecordBody(existing.id, put!.encBody, existingKey);
    expect(saved.title).toBe("Billing");
    expect(saved.notes).toBe("billing secrets");
    expect(saved.data?.content).toBe("A=1\nB=3\nC=4\n");
    expect(saved.data?.project).toBe("billing");
    expect(JSON.stringify(saved.agentPolicy)).toBe(JSON.stringify(POLICY));
  });

  it("a file without the entry the existing policy injects is refused with the validator's message; nothing is sent", async () => {
    deposits = [(await deposit({ body: envBody({ content: "B=3\nC=4\n" }) })).row];
    renderInbox([existing]);
    const card = await screen.findByRole("article", { name: "Billing from agent" });
    await userEvent.click(within(card).getByRole("button", { name: "Replace" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Agent policy: secret names a field this record doesn't have");
    expect(calls).toEqual([]);
  });

  it("another project: Keep as a new item is the default, and the file is still offered", async () => {
    deposits = [(await deposit({ body: envBody({ project: "shop" }) })).row];
    renderInbox([existing]);
    const card = await screen.findByRole("article", { name: "Billing from agent" });
    expect(within(card).getByRole("radio", { name: "Keep as a new item" })).toBeChecked();
    expect(within(card).getByRole("button", { name: "Keep" })).toBeInTheDocument();
    await userEvent.click(within(card).getByRole("radio", { name: "Replace the contents of" }));
    expect(within(card).getByRole("combobox", { name: "Item to replace" })).toHaveTextContent("Billing");
    expect(card).toHaveTextContent("Changed: B");
  });

  it("identical entries say No differences.", async () => {
    deposits = [(await deposit({ body: envBody({ content: "A=1\nB=2\nD=4\n" }) })).row];
    renderInbox([existing]);
    const card = await screen.findByRole("article", { name: "Billing from agent" });
    expect(card).toHaveTextContent("No differences.");
    expect(card).not.toHaveTextContent("Added:");
  });

  it("no env file of mine in the vault (only a shared one, or one in the trash): no second choice", async () => {
    deposits = [(await deposit({ body: envBody() })).row];
    renderInbox([{ ...existing, permission: "edit" }, { ...existing, id: crypto.randomUUID(), deleted: true }]);
    const card = await screen.findByRole("article", { name: "Billing from agent" });
    expect(within(card).queryByRole("radio")).toBeNull();
    expect(within(card).getByRole("button", { name: "Keep" })).toBeInTheDocument();
  });

  it("a deposit that fails the signature check offers neither Keep nor Replace", async () => {
    deposits = [(await deposit({ body: envBody(), signer: (await generateIdentityKeyPair()).privateKey })).row];
    renderInbox([existing]);
    expect(await screen.findByText(REFUSAL)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Keep" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Replace" })).toBeNull();
    expect(screen.queryByRole("radio")).toBeNull();
  });
});
