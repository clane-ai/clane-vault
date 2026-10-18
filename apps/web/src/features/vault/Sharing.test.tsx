import { act, render, renderHook, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { http, HttpResponse } from "msw";
import {
  b64url, decryptRecordBody, encryptNewRecord, gatewayKeyId, generateIdentityKeyPair, generateKeyPair, openFolderKey, openSharedRecordKey, randomBytes, signAgentKey,
} from "@clane-vault/crypto";
import { server } from "@/test/server";
import * as sessionModule from "@/lib/session";
import { AgentAttestationError, pinGateway, pinnedGateway } from "@/lib/orgKeys";
import VaultPage from "./VaultPage";
import { AGENT_DISCLOSURE, AGENT_WARNING } from "./AgentWarning";
import { useVault } from "./useVault";

const me = { userKey: randomBytes(32), ...(await generateKeyPair()) };
const bob = await generateKeyPair();
const BOB = { id: "u2", name: "Bob Stone", email: "bob@clane.ai", publicKey: b64url.encode(bob.publicKey) };
vi.spyOn(sessionModule, "useSession").mockReturnValue({ org: { id: "o1", name: "Acme", slug: "acme", role: "member", isDefault: true }, orgs: [{ id: "o1", name: "Acme", slug: "acme", role: "member", isDefault: true }], applyOrgs: vi.fn(), user: { id: "u1", name: "Sara", role: "member" }, generation: () => 0, lock: vi.fn(), signOut: vi.fn(), keys: me } as never);

function renderPage() {
  return render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter><VaultPage /></MemoryRouter></QueryClientProvider>);
}

describe("sharing", () => {
  it("shares a record: the record key is sealed to the recipient's public key and bound to the record", async () => {
    const id = crypto.randomUUID();
    const enc = await encryptNewRecord(id, { type: "login", title: "Stripe", password: "pw" }, me.userKey);
    let posted: { userId: string; permission: string; sealedRecordKey: string } | null = null;
    server.use(
      http.get("/api/v1/sync", () => HttpResponse.json({ serverTime: "", folders: [], records: [{ id, folderId: null, type: "login", encBody: enc.encBody, wrappedRecordKey: enc.wrappedRecordKey,
        revision: 1, updatedAt: "2026-10-04T10:00:00Z", deletedAt: null, permission: "owner", holderType: "user", ownerId: "u1", ownerName: "Sara", sharedWith: [] }] })),
      http.get("/api/v1/users", () => HttpResponse.json({ users: [{ id: "u1", name: "Sara", email: "sara@clane.ai", publicKey: b64url.encode(me.publicKey) }, BOB] })),
      http.get("/api/v1/records/:id/activity", () => HttpResponse.json({ events: [{ action: "record.create", at: "2026-10-04T10:00:00Z", actor: "Sara", target: null }] })),
      http.post("/api/v1/records/:id/shares", async ({ request }) => { posted = (await request.json()) as never; return HttpResponse.json({ ok: true }, { status: 201 }); }),
    );
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: /^Shared directly/ }));
    await userEvent.click(await screen.findByRole("button", { name: /Stripe/ }));
    expect(await screen.findByText("created it")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Share" }));
    const sheet = await screen.findByRole("dialog");
    await userEvent.click(within(sheet).getByRole("combobox", { name: "Person" }));
    await userEvent.click(await screen.findByRole("option", { name: /Bob Stone/ }));
    await userEvent.click(within(sheet).getByRole("combobox", { name: "Permission for new person" }));
    await userEvent.click(await screen.findByRole("option", { name: "Can edit" }));
    await userEvent.click(within(sheet).getByRole("button", { name: "Share" }));
    await waitFor(() => expect(posted).not.toBeNull());
    expect(posted!).toMatchObject({ userId: "u2", permission: "edit" });
    const rk = await openSharedRecordKey(posted!.sealedRecordKey, id, bob);
    expect((await decryptRecordBody(id, enc.encBody, rk)).title).toBe("Stripe");
    await expect(openSharedRecordKey(posted!.sealedRecordKey, crypto.randomUUID(), bob)).rejects.toThrow();
  });

  it("Personal: a private record is shared inside an organisation the owner picks (its X-Org-Id, its people), and managed there", async () => {
    const base = sessionModule.useSession();
    vi.spyOn(sessionModule, "useSession").mockReturnValue({ ...base, org: null } as never);
    const id = crypto.randomUUID();
    const enc = await encryptNewRecord(id, { type: "login", title: "Stripe", password: "pw" }, me.userKey);
    let posted: { org: string | null; body: { userId: string } } | null = null;
    const usersAskedIn: (string | null)[] = [];
    server.use(
      http.get("/api/v1/sync", ({ request }) => HttpResponse.json({ serverTime: "", folders: [], records: request.headers.get("x-org-id") ? [] : [{ id, folderId: null, type: "login", encBody: enc.encBody, wrappedRecordKey: enc.wrappedRecordKey,
        revision: 1, updatedAt: "2026-10-04T10:00:00Z", deletedAt: null, permission: "owner", holderType: "user", ownerId: "u1", ownerName: "Sara", sharedWith: [], sharedIn: ["o1"] }] })),
      http.get("/api/v1/users", ({ request }) => { usersAskedIn.push(request.headers.get("x-org-id")); return HttpResponse.json({ users: [BOB] }); }),
      http.get("/api/v1/records/:id/activity", () => HttpResponse.json({ events: [] })),
      http.post("/api/v1/records/:id/shares", async ({ request }) => { posted = { org: request.headers.get("x-org-id"), body: (await request.json()) as never }; return HttpResponse.json({ ok: true }, { status: 201 }); }),
    );
    render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter initialEntries={["/p/vault"]}><VaultPage /></MemoryRouter></QueryClientProvider>);
    await userEvent.click(await screen.findByRole("button", { name: /^No folder/ }));
    await userEvent.click(await screen.findByRole("button", { name: /Stripe/ }));
    await userEvent.click(screen.getByRole("button", { name: "Share" }));
    const sheet = await screen.findByRole("dialog");
    expect(within(sheet).getByRole("combobox", { name: "Share inside" })).toHaveTextContent("Acme");
    // Already shared in Acme: managed in Acme's space.
    expect(within(sheet).getByRole("link", { name: "Manage in Acme" })).toHaveAttribute("href", `/o/acme/vault/record/${id}`);
    await userEvent.click(within(sheet).getByRole("combobox", { name: "Person" }));
    await userEvent.click(await screen.findByRole("option", { name: /Bob Stone/ }));
    await userEvent.click(within(sheet).getByRole("button", { name: "Share" }));
    await waitFor(() => expect(posted).not.toBeNull());
    expect(posted!.org).toBe("o1");
    expect(posted!.body.userId).toBe("u2");
    expect(usersAskedIn.every((o) => o === "o1")).toBe(true);
    vi.spyOn(sessionModule, "useSession").mockReturnValue(base as never);
  });

  it("the Share sheet's One-time link tab creates a link for the record", async () => {
    const id = crypto.randomUUID();
    const enc = await encryptNewRecord(id, { type: "login", title: "Stripe", password: "pw" }, me.userKey);
    let posted: { recordId: string } | null = null;
    server.use(
      http.get("/api/v1/sync", () => HttpResponse.json({ serverTime: "", folders: [], records: [{ id, folderId: null, type: "login", encBody: enc.encBody, wrappedRecordKey: enc.wrappedRecordKey,
        revision: 1, updatedAt: "2026-10-04T10:00:00Z", deletedAt: null, permission: "owner", holderType: "user", ownerId: "u1", ownerName: "Sara", sharedWith: [] }] })),
      http.get("/api/v1/users", () => HttpResponse.json({ users: [BOB] })),
      http.get("/api/v1/records/:id/activity", () => HttpResponse.json({ events: [] })),
      http.get("/api/v1/records/:id/links", () => HttpResponse.json({ links: [] })),
      http.post("/api/v1/links", async ({ request }) => { posted = (await request.json()) as never; return HttpResponse.json({}, { status: 201 }); }),
    );
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: /^Shared directly/ }));
    await userEvent.click(await screen.findByRole("button", { name: /Stripe/ }));
    expect(screen.queryByRole("button", { name: "One-time link" })).not.toBeInTheDocument(); // owners use the Share sheet
    await userEvent.click(screen.getByRole("button", { name: "Share" }));
    const sheet = await screen.findByRole("dialog");
    await userEvent.click(within(sheet).getByRole("tab", { name: "One-time link" }));
    await userEvent.click(await within(sheet).findByRole("button", { name: "Create link" }));
    expect(await within(sheet).findByLabelText("Link to send")).toHaveTextContent(/\/s\/[0-9a-f-]{36}#/);
    expect(posted!).toMatchObject({ recordId: id });
  });

  it("creates a team folder with people: the folder key is sealed to each member", async () => {
    const posts: { url: string; body: Record<string, string> }[] = [];
    server.use(
      http.get("/api/v1/sync", () => HttpResponse.json({ serverTime: "", folders: [], records: [] })),
      http.get("/api/v1/users", () => HttpResponse.json({ users: [BOB] })),
      http.post("/api/v1/folders", async ({ request }) => { posts.push({ url: "folders", body: (await request.json()) as never }); return HttpResponse.json({}, { status: 201 }); }),
      http.post("/api/v1/folders/:id/members", async ({ request }) => { posts.push({ url: "members", body: (await request.json()) as never }); return HttpResponse.json({}, { status: 201 }); }),
    );
    const { default: VaultScreen } = await import("./VaultScreen");
    render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter><VaultScreen /></MemoryRouter></QueryClientProvider>);
    await userEvent.click(await screen.findByRole("button", { name: "New" }));
    await userEvent.click(await screen.findByRole("menuitem", { name: "Shared Folder" }));
    await userEvent.type(await screen.findByLabelText("Folder name"), "Infra");
    await userEvent.click(screen.getByRole("combobox", { name: "Person" }));
    await userEvent.click(await screen.findByRole("option", { name: /Bob Stone/ }));
    await userEvent.click(screen.getByRole("button", { name: "Add" }));
    expect(await screen.findByRole("listitem", { name: "Bob Stone" })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Create" }));
    await waitFor(() => expect(posts.map((p) => p.url)).toEqual(["folders", "members"]));
    const folder = posts[0]!.body, member = posts[1]!.body;
    expect(folder.kind).toBe("team");
    const mine = await openFolderKey(folder.wrappedFolderKey!, folder.id!, me);
    const bobs = await openFolderKey(member.wrappedFolderKey!, folder.id!, bob);
    expect(bobs).toEqual(mine);
    expect(member).toMatchObject({ userId: "u2", permission: "view" });
  });
});

// An agent the gateway enrolled: its key, signed by the gateway identity over agent-key:<org>:<agent>:<key>.
const gw = await generateIdentityKeyPair();
const GATEWAY = { keyId: await gatewayKeyId(gw.publicKey), publicKey: b64url.encode(gw.publicKey) };
const bot = await generateKeyPair();
const BOT_KEY = b64url.encode(bot.publicKey);
const BOT = { id: "a1", name: "Billing bot", email: "agent+a1@agents.invalid", kind: "agent", publicKey: BOT_KEY, membershipKey: null,
  attestation: await signAgentKey(gw.privateKey, GATEWAY.keyId, { orgId: "o1", agentId: "a1", publicKey: BOT_KEY }), gatewayKeyId: GATEWAY.keyId };

describe("sharing to agents", () => {
  beforeEach(() => { localStorage.clear(); });
  async function openShareSheet(users: unknown[]) {
    const id = crypto.randomUUID();
    const enc = await encryptNewRecord(id, { type: "login", title: "Stripe", password: "pw" }, me.userKey);
    const posted: { userId: string; permission: string; sealedRecordKey: string }[] = [];
    server.use(
      http.get("/api/v1/sync", () => HttpResponse.json({ serverTime: "", folders: [], records: [{ id, folderId: null, type: "login", encBody: enc.encBody, wrappedRecordKey: enc.wrappedRecordKey,
        revision: 1, updatedAt: "2026-10-04T10:00:00Z", deletedAt: null, permission: "owner", holderType: "user", ownerId: "u1", ownerName: "Sara", sharedWith: [] }] })),
      http.get("/api/v1/users", () => HttpResponse.json({ users })),
      http.get("/api/v1/records/:id/activity", () => HttpResponse.json({ events: [] })),
      http.post("/api/v1/records/:id/shares", async ({ request }) => { posted.push((await request.json()) as never); return HttpResponse.json({ ok: true }, { status: 201 }); }),
    );
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: /^Shared directly/ }));
    await userEvent.click(await screen.findByRole("button", { name: /Stripe/ }));
    await userEvent.click(await screen.findByRole("button", { name: "Share" }));
    const sheet = await screen.findByRole("dialog");
    const pick = async (name: RegExp) => {
      await userEvent.click(within(sheet).getByRole("combobox", { name: "Person" }));
      await userEvent.click(await screen.findByRole("option", { name }));
    };
    return { id, enc, posted, sheet, pick };
  }

  it("an agent is locked to Use only, the warning sits above the confirm button every time, and the key is sealed to the attested agent key", async () => {
    await pinGateway("u1", "o1", GATEWAY);
    const { id, enc, posted, sheet, pick } = await openShareSheet([BOB, BOT]);
    await userEvent.click(within(sheet).getByRole("combobox", { name: "Person" }));
    const option = await screen.findByRole("option", { name: /Billing bot/ });
    expect(within(option).getByRole("img", { name: "Agent" })).toBeInTheDocument();
    await userEvent.click(option);
    const perm = within(sheet).getByRole("combobox", { name: "Permission for new person" });
    expect(perm).toHaveTextContent("Use only");
    expect(perm).toBeDisabled();
    const warning = within(sheet).getByRole("note", { name: "Sharing with an agent" });
    expect(warning).toHaveTextContent(AGENT_WARNING);
    expect(warning).toHaveTextContent(AGENT_DISCLOSURE);
    expect(within(warning).queryByRole("button")).not.toBeInTheDocument(); // never dismissable
    const confirm = within(sheet).getByRole("button", { name: "Share" });
    expect(warning.compareDocumentPosition(confirm) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    await userEvent.click(confirm);
    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0]).toMatchObject({ userId: "a1", permission: "use" });
    const rk = await openSharedRecordKey(posted[0]!.sealedRecordKey, id, bot);
    expect((await decryptRecordBody(id, enc.encBody, rk)).title).toBe("Stripe");
    // The next agent selection shows the warning again.
    await waitFor(() => expect(within(sheet).queryByRole("note", { name: "Sharing with an agent" })).not.toBeInTheDocument());
    await pick(/Billing bot/);
    expect(within(sheet).getByRole("note", { name: "Sharing with an agent" })).toHaveTextContent(AGENT_WARNING);
  });

  it("a person gets no agent warning and keeps the permission choice", async () => {
    await pinGateway("u1", "o1", GATEWAY);
    const { sheet, pick } = await openShareSheet([BOB, BOT]);
    await pick(/Bob Stone/);
    expect(within(sheet).queryByRole("note", { name: "Sharing with an agent" })).not.toBeInTheDocument();
    expect(within(sheet).getByRole("combobox", { name: "Permission for new person" })).toBeEnabled();
  });

  it("the first share to an agent pins the gateway identity from the server (fingerprint shown); people-only shares never ask", async () => {
    let asked = 0;
    server.use(http.get("/api/v1/org/agents/gateway", () => { asked++; return HttpResponse.json({ url: "https://gw/mcp", identityKeyId: GATEWAY.keyId, identityPublicKey: GATEWAY.publicKey }); }));
    const { posted, sheet, pick } = await openShareSheet([BOB, BOT]);
    await pick(/Bob Stone/);
    await userEvent.click(within(sheet).getByRole("button", { name: "Share" }));
    await waitFor(() => expect(posted).toHaveLength(1));
    expect(asked).toBe(0);
    await pick(/Billing bot/);
    expect(await within(sheet).findByLabelText("Gateway identity")).toHaveTextContent(/fingerprint/);
    expect(pinnedGateway("u1", "o1")).toEqual(GATEWAY);
    await userEvent.click(within(sheet).getByRole("button", { name: "Share" }));
    await waitFor(() => expect(posted).toHaveLength(2));
    expect(posted[1]).toMatchObject({ userId: "a1", permission: "use" });
  });

  it("refuses to seal to an agent when the gateway identity can't be confirmed, when it changed, or when the server swapped the agent's key", async () => {
    server.use(http.get("/api/v1/org/agents/gateway", () => HttpResponse.json({ error: "gateway_unavailable" }, { status: 503 })));
    const { posted, sheet, pick } = await openShareSheet([{ ...BOT, publicKey: b64url.encode((await generateKeyPair()).publicKey) }, { ...BOT, id: "a2", name: "Other bot", gatewayKeyId: "AAAAAAAAAAAAAAAA", attestation: "g1.AAAAAAAAAAAAAAAA.sig" }]);
    await pick(/Billing bot/);
    await userEvent.click(within(sheet).getByRole("button", { name: "Share" }));
    expect(await within(sheet).findByText(/Couldn't confirm the agent gateway's identity/)).toBeInTheDocument();
    await pinGateway("u1", "o1", GATEWAY);
    await pick(/Other bot/);
    await userEvent.click(within(sheet).getByRole("button", { name: "Share" }));
    expect(await within(sheet).findByText(/signed by a different gateway/)).toBeInTheDocument();
    await pick(/Billing bot/);
    await userEvent.click(within(sheet).getByRole("button", { name: "Share" }));
    expect(await within(sheet).findByText(/The gateway did not sign this agent's key/)).toBeInTheDocument();
    expect(posted).toHaveLength(0);
  });

  it("a new team folder with an agent shows the warning above Create, and the agent's copy is sealed Use only", async () => {
    await pinGateway("u1", "o1", GATEWAY);
    const posts: { url: string; body: Record<string, string> }[] = [];
    server.use(
      http.get("/api/v1/sync", () => HttpResponse.json({ serverTime: "", folders: [], records: [] })),
      http.get("/api/v1/users", () => HttpResponse.json({ users: [BOT] })),
      http.post("/api/v1/folders", async ({ request }) => { posts.push({ url: "folders", body: (await request.json()) as never }); return HttpResponse.json({}, { status: 201 }); }),
      http.post("/api/v1/folders/:id/members", async ({ request }) => { posts.push({ url: "members", body: (await request.json()) as never }); return HttpResponse.json({}, { status: 201 }); }),
    );
    const { default: VaultScreen } = await import("./VaultScreen");
    render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter><VaultScreen /></MemoryRouter></QueryClientProvider>);
    await userEvent.click(await screen.findByRole("button", { name: "New" }));
    await userEvent.click(await screen.findByRole("menuitem", { name: "Shared Folder" }));
    await userEvent.type(await screen.findByLabelText("Folder name"), "Billing");
    await userEvent.click(screen.getByRole("combobox", { name: "Person" }));
    await userEvent.click(await screen.findByRole("option", { name: /Billing bot/ }));
    await userEvent.click(screen.getByRole("button", { name: "Add" }));
    expect(await screen.findByRole("listitem", { name: "Billing bot" })).toBeInTheDocument();
    const warning = screen.getByRole("note", { name: "Sharing with an agent" });
    expect(warning.compareDocumentPosition(screen.getByRole("button", { name: "Create" })) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: "Create" }));
    await waitFor(() => expect(posts.map((p) => p.url)).toEqual(["folders", "members"]));
    expect(posts[1]!.body).toMatchObject({ userId: "a1", permission: "use" });
    expect(await openFolderKey(posts[1]!.body.wrappedFolderKey!, posts[0]!.body.id!, bot)).toBeTruthy();
  });

  it("Share again to an agent that needs access has the warning above it", async () => {
    await pinGateway("u1", "o1", GATEWAY);
    const id = crypto.randomUUID();
    const enc = await encryptNewRecord(id, { type: "login", title: "Stripe", password: "pw" }, me.userKey);
    server.use(
      http.get("/api/v1/sync", () => HttpResponse.json({ serverTime: "", folders: [], records: [{ id, folderId: null, type: "login", encBody: enc.encBody, wrappedRecordKey: enc.wrappedRecordKey,
        revision: 1, updatedAt: "2026-10-04T10:00:00Z", deletedAt: null, permission: "owner", holderType: "user", ownerId: "u1", ownerName: "Sara",
        sharedWith: [{ userId: "a1", name: "Billing bot", permission: "use", needsAccess: true }] }] })),
      http.get("/api/v1/users", () => HttpResponse.json({ users: [{ ...BOT, membershipKey: BOT_KEY }] })),
      http.get("/api/v1/records/:id/activity", () => HttpResponse.json({ events: [] })),
    );
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: /^Shared directly/ }));
    await userEvent.click(await screen.findByRole("button", { name: /Stripe/ }));
    await userEvent.click(await screen.findByRole("button", { name: "Share" }));
    const sheet = await screen.findByRole("dialog");
    const again = await within(sheet).findByRole("button", { name: "Share again" });
    const warning = within(sheet).getByRole("note", { name: "Sharing with an agent" });
    expect(warning).toHaveTextContent(AGENT_WARNING);
    expect(warning.compareDocumentPosition(again) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(within(sheet).getByRole("combobox", { name: "Permission for Billing bot" })).toBeDisabled();
  });

  it("Give access again re-verifies an agent's attestation from /sync before resealing", async () => {
    const puts: unknown[] = [];
    server.use(
      http.get("/api/v1/sync", () => HttpResponse.json({ serverTime: "", folders: [], records: [] })),
      http.put("/api/v1/folders/:id/members/:uid/key", async ({ request }) => { puts.push(await request.json()); return HttpResponse.json({ ok: true }); }),
    );
    const { result } = renderHook(() => useVault(), { wrapper: ({ children }) => <QueryClientProvider client={new QueryClient()}>{children}</QueryClientProvider> });
    const folder = { id: crypto.randomUUID(), name: "Infra", kind: "team" as const, deleted: false, myPermission: "owner" as const, folderKey: randomBytes(32) };
    const member = { userId: "a1", name: "Billing bot", email: BOT.email, kind: "agent" as const, publicKey: BOT_KEY, membershipKey: null, permission: "use" as const,
      attestation: BOT.attestation, gatewayKeyId: GATEWAY.keyId, needsAccess: true };
    await pinGateway("u1", "o1", GATEWAY);
    const swapped = b64url.encode((await generateKeyPair()).publicKey);
    await expect(act(() => result.current.giveAccessAgain(folder, { ...member, publicKey: swapped }))).rejects.toBeInstanceOf(AgentAttestationError);
    expect(puts).toHaveLength(0);
    await act(() => result.current.giveAccessAgain(folder, member));
    const sealed = puts[0] as { wrappedFolderKey: string };
    expect(await openFolderKey(sealed.wrappedFolderKey, folder.id, bot)).toEqual(folder.folderKey);
  });
});
