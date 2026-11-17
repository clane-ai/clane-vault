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
const session = { org: null, orgs: [], applyOrgs: vi.fn(), user: { id: ME, name: "Sara", role: "member" }, generation: () => 0, lock: vi.fn(), signOut: vi.fn(), keys: me };
vi.spyOn(sessionModule, "useSession").mockImplementation(() => session as never);

const BODY: RecordBody = { type: "login", title: "Stripe", username: "sara@example.com", password: "sk_live_x", agentPolicy: { v: 1, hosts: ["api.stripe.com"], inject: { kind: "bearer" } } };
let gw: { identity: GatewayIdentity; privateKey: Uint8Array };
let deposits: unknown[];
let agents: MyAgent[];
let inboxLoads: number;

async function deposit(o: { signer?: Uint8Array; noSignature?: boolean; ownerKey?: string; createdAt?: string; expiresAt?: string } = {}) {
  const id = crypto.randomUUID();
  const recordKey = randomBytes(32);
  const encBody = await encryptRecordBody(id, BODY, recordKey);
  const message = agentDepositMessage({ ownerUserId: ME, ownerPublicKey: o.ownerKey ?? ownerPublicKey, agentId: AGENT_ID, id, revision: 1, encBodyHash: await sha256B64(encBody) });
  const signature = o.noSignature ? "" : await signGatewayMessage(o.signer ?? gw.privateKey, gw.identity.keyId, "d1", message);
  const row = { id, agentId: AGENT_ID, agentName: "My bot", app: "Claude", type: "login", encBody, revision: 1, signature,
    ownerSealedKey: await sealDepositKeyToOwner(recordKey, { ownerUserId: ME, id }, me.publicKey),
    createdAt: o.createdAt ?? new Date().toISOString(), updatedAt: new Date().toISOString(), expiresAt: o.expiresAt ?? new Date(Date.now() + 90 * 864e5).toISOString() };
  return { row, recordKey, id };
}

beforeEach(async () => {
  try { localStorage.clear(); } catch { /* none */ }
  openSpy.mockClear();
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

const renderInbox = () => render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
  <MemoryRouter><AgentInbox folders={[]} /></MemoryRouter></QueryClientProvider>);
const REFUSAL = "Not signed by the gateway — delete it";

describe("From agents", () => {
  it("a deposit signed by the pinned gateway for my key shows its title, username, agent, app and the agent's policy", async () => {
    const good = await deposit();
    deposits = [good.row];
    renderInbox();
    const card = await screen.findByRole("article", { name: "Stripe" });
    expect(within(card).getByText("sara@example.com")).toBeInTheDocument();
    expect(card).toHaveTextContent("My bot");
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
    expect(await screen.findByRole("status")).toHaveTextContent("Kept. My bot already has 200 items, so it can't use this one.");
  });

  it("a stale revision (409 conflict) reloads the inbox and says the agent changed it", async () => {
    deposits = [(await deposit()).row];
    server.use(http.post("/api/v1/me/agent-deposits/:id/keep", () => HttpResponse.json({ error: "conflict" }, { status: 409 })));
    renderInbox();
    await userEvent.click(await screen.findByRole("button", { name: "Keep" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("The agent changed this item. Check it again.");
    await waitFor(() => expect(inboxLoads).toBe(2));
  });

  it("Delete deletes it", async () => {
    const d = await deposit();
    deposits = [d.row];
    let deleted: string | null = null;
    server.use(http.delete("/api/v1/me/agent-deposits/:id", ({ params }) => { deleted = params.id as string; deposits = []; return new HttpResponse(null, { status: 204 }); }));
    renderInbox();
    const card = await screen.findByRole("article", { name: "Stripe" });
    await userEvent.click(within(card).getByRole("button", { name: "Delete" }));
    await waitFor(() => expect(deleted).toBe(d.id));
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
