import { render, renderHook, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { http, HttpResponse } from "msw";
import {
  b64url, decryptFolderAgents, decryptRecordBody, encryptFolderAgents, encryptFolderName, encryptNewRecord, gatewayKeyId, generateIdentityKeyPair, generateKeyPair,
  openPersonalAgentRecordKey, randomBytes, signPersonalAgentKey,
} from "@clane-vault/crypto";
import { server } from "@/test/server";
import * as sessionModule from "@/lib/session";
import { PERSONAL_SLOT, pinGateway } from "@/lib/orgKeys";
import type { MyAgent } from "@/features/settings/myAgents";
import VaultPage from "./VaultPage";
import { useVault } from "./useVault";

globalThis.ResizeObserver ??= class { observe() {} unobserve() {} disconnect() {} } as never;
const ME = "11111111-0000-4000-8000-000000000001";
const AGENT_ID = "bbbbbbbb-0000-4000-8000-000000000002";
const FOLDER = "ffffffff-0000-4000-8000-000000000003";
const me = { userKey: randomBytes(32), ...(await generateKeyPair()) };
const ownerPublicKey = b64url.encode(me.publicKey);
const agentKeys = await generateKeyPair();
const agentPub = b64url.encode(agentKeys.publicKey);
vi.spyOn(sessionModule, "useSession").mockReturnValue({ org: null, orgs: [], applyOrgs: vi.fn(), user: { id: ME, name: "Sara", role: "member" }, generation: () => 0, lock: vi.fn(), signOut: vi.fn(), keys: me } as never);

let agents: MyAgent[];
/** The server's side: the folder's encAgents, which records the agent holds, and what was posted and deleted. */
let s: { encAgents: string | null; grants: Set<string>; posts: { id: string; agentId: string; wrappedRecordKey: string }[]; deletes: string[] };
let ids: string[];
let encs: Awaited<ReturnType<typeof encryptNewRecord>>[];

beforeEach(async () => {
  try { localStorage.clear(); } catch { /* none */ }
  const kp = await generateIdentityKeyPair();
  const identity = { keyId: await gatewayKeyId(kp.publicKey), publicKey: b64url.encode(kp.publicKey) };
  await pinGateway(ME, PERSONAL_SLOT, identity);
  const attestation = await signPersonalAgentKey(kp.privateKey, identity.keyId, { ownerUserId: ME, ownerPublicKey, agentId: AGENT_ID, publicKey: agentPub });
  agents = [{ id: AGENT_ID, name: "My bot", status: "active", publicKey: agentPub, attestation, expiresAt: null, lastUsedAt: null, createdAt: "", verifiedAt: "", items: 0,
    owner: { userId: ME, publicKey: ownerPublicKey }, tokens: [], grants: [] }];
  // A folder "Ops" with Stripe (already given to the agent) and GitHub.
  ids = [crypto.randomUUID(), crypto.randomUUID()];
  encs = await Promise.all(ids.map((id, i) => encryptNewRecord(id, { type: "login", title: i ? "GitHub" : "Stripe", password: "pw" }, me.userKey)));
  s = { encAgents: null, grants: new Set([ids[0]]), posts: [], deletes: [] };
  const encName = await encryptFolderName(FOLDER, "Ops", me.userKey);
  server.use(
    http.get("/api/v1/me/agents", () => HttpResponse.json({ agents, allowance: { used: 1, allowed: 2 }, rules: { allowed: true, blockedByOrgId: null, write: false, reveal: "off" },
      gateway: { url: "https://gw.test/mcp", identityKeyId: identity.keyId, identityPublicKey: identity.publicKey, reveal: "off" }, revealEmail: true })),
    http.get("/api/v1/sync", () => HttpResponse.json({ serverTime: "", folders: [{ id: FOLDER, kind: "private", encName, ownerId: ME, deletedAt: null, ...(s.encAgents ? { encAgents: s.encAgents } : {}) }],
      records: ids.map((id, i) => ({ id, folderId: FOLDER, type: "login", encBody: encs[i].encBody, wrappedRecordKey: encs[i].wrappedRecordKey, revision: 1, updatedAt: "2026-11-15T10:00:00Z", deletedAt: null,
        permission: "owner", holderType: "user", ownerId: ME, ownerName: "Sara", sharedWith: [], agentGrants: s.grants.has(id) ? [{ agentId: AGENT_ID, use: true, write: false }] : [] })) })),
    http.post("/api/v1/records/:id/agent-grants", async ({ params, request }) => {
      s.posts.push({ id: params.id as string, ...((await request.json()) as { agentId: string; wrappedRecordKey: string }) }); s.grants.add(params.id as string);
      return HttpResponse.json({ ok: true }, { status: 201 });
    }),
    http.delete("/api/v1/records/:id/agent-grants/:agentId", ({ params }) => { s.deletes.push(params.id as string); s.grants.delete(params.id as string); return HttpResponse.json({ ok: true }); }),
    http.patch("/api/v1/folders/:id", async ({ request }) => { s.encAgents = ((await request.json()) as { encAgents: string | null }).encAgents; return HttpResponse.json({ ok: true }); }),
  );
});

async function choose(where: HTMLElement, option: string) {
  await userEvent.click(within(where).getByRole("combobox", { name: "Access for My bot" }));
  await userEvent.click(await screen.findByRole("option", { name: option }));
}

describe("giving a Personal folder to a personal agent", () => {
  it("Can use gives every item in it (sealed as a single grant) and remembers the agent, encrypted; None takes them back", async () => {
    render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter initialEntries={["/p/vault"]}><VaultPage onNew={vi.fn()} /></MemoryRouter></QueryClientProvider>);
    expect(within(await screen.findByRole("button", { name: /^Ops/ })).queryByTestId("agent-mark")).toBeNull();
    await userEvent.click(await screen.findByRole("button", { name: "Options for Ops" }));
    await userEvent.click(await screen.findByRole("menuitem", { name: "Give to agent…" }));
    const dialog = await screen.findByRole("dialog", { name: "Give Ops to an agent" });
    expect(within(dialog).getByRole("note", { name: "Sharing with an agent" })).toBeInTheDocument();
    await choose(dialog, "Can use");
    expect(await within(dialog).findByRole("status")).toHaveTextContent("My bot was given 1 item. Items you add here later are given too.");
    expect(s.posts.map((p) => p.id)).toEqual([ids[1]]);
    const rk = await openPersonalAgentRecordKey(s.posts[0].wrappedRecordKey, { ownerUserId: ME, agentId: AGENT_ID, recordId: ids[1] }, agentKeys);
    expect((await decryptRecordBody(ids[1], encs[1].encBody, rk)).title).toBe("GitHub");
    expect(await decryptFolderAgents(FOLDER, s.encAgents!, me.userKey)).toEqual([AGENT_ID]);
    await waitFor(() => expect(within(dialog).getByRole("combobox", { name: "Access for My bot" })).toHaveTextContent("Can use"));
    // Behind the open dialog (aria-hidden), the folder row now carries the mark.
    expect(within(screen.getByRole("button", { name: /^Ops/, hidden: true })).getByTestId("agent-mark")).toBeInTheDocument();
    await choose(dialog, "None");
    expect(await within(dialog).findByText("My bot no longer has 2 items from this folder.")).toBeInTheDocument();
    expect(s.deletes.sort()).toEqual([...ids].sort());
    expect(s.encAgents).toBeNull();
  });

  it("an item saved or moved into the folder is given to its agents; one saved elsewhere isn't", async () => {
    s.encAgents = await encryptFolderAgents(FOLDER, [AGENT_ID], me.userKey);
    s.grants.clear();
    server.use(http.post("/api/v1/records", () => HttpResponse.json({ ok: true }, { status: 201 })), http.put("/api/v1/records/:id/folder", () => HttpResponse.json({ ok: true })));
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    client.setQueryData(["my-agents", ME], { agents });
    const { result } = renderHook(() => useVault(), { wrapper: ({ children }) => <QueryClientProvider client={client}>{children}</QueryClientProvider> });
    await waitFor(() => expect(result.current.folders[0]?.agentIds).toEqual([AGENT_ID]));
    const id = await result.current.createRecord({ folderId: FOLDER, body: { type: "login", title: "New", password: "pw" } });
    await result.current.createRecord({ folderId: null, body: { type: "login", title: "Loose", password: "pw" } });
    await result.current.moveRecord(result.current.records.find((r) => r.id === ids[1])!, FOLDER);
    expect(s.posts.map((p) => [p.id, p.agentId])).toEqual([[id, AGENT_ID], [ids[1], AGENT_ID]]);
  });
});
