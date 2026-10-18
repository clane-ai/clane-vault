import { render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { http, HttpResponse } from "msw";
import { b64url, generateKeyPair, openFolderKey, randomBytes } from "@clane-vault/crypto";
import { server } from "@/test/server";
import * as sessionModule from "@/lib/session";
import { GroupsSection } from "./GroupsSection";
import { FolderPeopleSheet } from "@/features/vault/FolderPeopleSheet";
import type { VaultFolder } from "@/features/vault/types";

const ORG = { id: "o1", name: "Acme", slug: "acme", role: "admin", isDefault: true };
vi.spyOn(sessionModule, "useSession").mockReturnValue({ org: ORG, orgs: [ORG], user: { id: "a1", name: "Ada", role: "admin" }, generation: () => 0 } as never);
const wrap = (ui: React.ReactNode) => render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter>{ui}</MemoryRouter></QueryClientProvider>);

describe("Groups (admin People page)", () => {
  it("creates a group, adds and removes members, deletes it", async () => {
    const groups = [{ id: "g1", name: "Engineering", createdAt: "2026-10-01T00:00:00Z", folderCount: 2, members: [{ id: "m1", name: "Mia", email: "mia@clane.ai" }] }];
    const calls: string[] = [];
    server.use(
      http.get("/api/v1/admin/groups", () => HttpResponse.json({ groups })),
      http.get("/api/v1/users", () => HttpResponse.json({ users: [{ id: "m1", name: "Mia", email: "mia@clane.ai", publicKey: "" }, { id: "b1", name: "Ben", email: "ben@clane.ai", publicKey: "" }] })),
      http.post("/api/v1/admin/groups", async ({ request }) => { calls.push(`create ${JSON.stringify(await request.json())}`); return HttpResponse.json({ id: "g2", name: "Ops" }, { status: 201 }); }),
      http.post("/api/v1/admin/groups/:id/members", async ({ params, request }) => { calls.push(`add ${params.id} ${JSON.stringify(await request.json())}`); return HttpResponse.json({ added: 1 }, { status: 201 }); }),
      http.delete("/api/v1/admin/groups/:id/members/:uid", ({ params }) => { calls.push(`remove ${params.id} ${params.uid}`); return new HttpResponse(null, { status: 204 }); }),
      http.delete("/api/v1/admin/groups/:id", ({ params }) => { calls.push(`delete ${params.id}`); return new HttpResponse(null, { status: 204 }); }),
    );
    wrap(<GroupsSection />);
    const g = await screen.findByRole("listitem", { name: "Group Engineering" });
    expect(within(g).getByText("2 folders")).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText("New group"), "Ops");
    await userEvent.click(screen.getByRole("button", { name: "Create group" }));
    await waitFor(() => expect(calls).toContain(`create {"name":"Ops"}`));

    await userEvent.click(within(g).getByRole("combobox", { name: "Add someone to Engineering" }));
    // Mia is already in the group: only Ben is offered.
    expect(screen.queryByRole("option", { name: /Mia/ })).not.toBeInTheDocument();
    await userEvent.click(await screen.findByRole("option", { name: /Ben/ }));
    await userEvent.click(within(g).getByRole("button", { name: "Add" }));
    await waitFor(() => expect(calls).toContain(`add g1 {"userIds":["b1"]}`));

    await userEvent.click(within(g).getByRole("button", { name: "Remove Mia from Engineering" }));
    await waitFor(() => expect(calls).toContain("remove g1 m1"));

    await userEvent.click(within(g).getByRole("button", { name: "Delete Engineering" }));
    expect(await screen.findByText(/People lose the team folders they could open only through this group/)).toBeInTheDocument();
    await userEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Delete" }));
    await waitFor(() => expect(calls).toContain("delete g1"));
  });

  it("explains a name clash", async () => {
    server.use(http.post("/api/v1/admin/groups", () => HttpResponse.json({ error: "exists" }, { status: 409 })));
    wrap(<GroupsSection />);
    await userEvent.type(await screen.findByLabelText("New group"), "Ops");
    await userEvent.click(screen.getByRole("button", { name: "Create group" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("A group with that name already exists.");
  });
});

describe("Groups in the folder people sheet", () => {
  it("shows group access, and the owner shares the folder with a group by sealing the key to its members", async () => {
    const mia = await generateKeyPair(), ben = await generateKeyPair();
    const folderKey = randomBytes(32);
    const folder: VaultFolder = { id: crypto.randomUUID(), name: "Infra", kind: "team", deleted: false, ownerId: "a1", myPermission: "owner", folderKey,
      members: [
        { userId: "a1", name: "Ada", email: "ada@clane.ai", publicKey: "", permission: "owner", directPermission: "owner" },
        { userId: "m1", name: "Mia", email: "mia@clane.ai", publicKey: b64url.encode(mia.publicKey), permission: "edit", directPermission: null },
      ],
      groups: [{ id: "g1", name: "Engineering", permission: "edit", memberIds: ["m1"] }] };
    let posted: { groupId: string; permission: string; wraps: { userId: string; wrappedFolderKey: string }[] } | null = null;
    server.use(
      http.get("/api/v1/groups", () => HttpResponse.json({ groups: [
        { id: "g1", name: "Engineering", members: [] },
        { id: "g2", name: "Support", members: [{ id: "b1", name: "Ben", email: "ben@clane.ai", publicKey: b64url.encode(ben.publicKey) }] },
      ] })),
      http.get("/api/v1/users", () => HttpResponse.json({ users: [] })),
      http.get("/api/v1/admin/people", () => HttpResponse.json({ users: [], invites: [] })),
      http.post("/api/v1/folders/:id/groups", async ({ request }) => { posted = (await request.json()) as never; return HttpResponse.json({ ok: true, added: 1, pending: 0 }, { status: 201 }); }),
    );
    wrap(<FolderPeopleSheet folder={folder} onClose={() => undefined} onAdd={vi.fn()} onUpdate={vi.fn()} onRemove={vi.fn()} />);
    const members = await screen.findByRole("list", { name: "Members" });
    const miaRow = within(members).getByRole("listitem", { name: "Mia" });
    // Access only through a group: shown, and managed on the group (no direct controls).
    expect(within(miaRow).getByText("via Engineering")).toBeInTheDocument();
    expect(within(miaRow).queryByRole("button", { name: "Remove Mia" })).not.toBeInTheDocument();
    expect(within(screen.getByRole("list", { name: "Groups with access" })).getByText("Engineering")).toBeInTheDocument();

    await userEvent.click(await screen.findByRole("combobox", { name: "Group to share with" }));
    await userEvent.click(await screen.findByRole("option", { name: /Support/ }));
    await userEvent.click(screen.getByRole("button", { name: "Share" }));
    await waitFor(() => expect(posted).not.toBeNull());
    expect(posted!).toMatchObject({ groupId: "g2", permission: "view", wraps: [{ userId: "b1" }] });
    const opened = await openFolderKey(posted!.wraps[0]!.wrappedFolderKey, folder.id, ben);
    expect([...opened]).toEqual([...folderKey]);
  });
});

describe("group access requests", () => {
  it("nothing is sealed until a key holder approves; the prompt names the person, the group and who added them", async () => {
    const { GroupAccessBanner } = await import("./GroupAccessBanner");
    const { createMembershipKeys, openOrgFolderKey } = await import("@clane-vault/crypto");
    const folderKey = randomBytes(32);
    const folder: VaultFolder = { id: crypto.randomUUID(), name: "Infra", kind: "team", deleted: false, ownerId: "a1", myPermission: "owner", folderKey, members: [],
      groups: [{ id: "g1", name: "Engineering", permission: "view", memberIds: ["m1", "x1"] }] };
    const mia = await createMembershipKeys(randomBytes(32), { orgId: ORG.id, userId: "m1" });
    const pending = [
      { folderId: folder.id, userId: "m1", name: "Mia", email: "mia@clane.ai", publicKey: "", membershipKey: mia.material.publicKey, permission: "view", groups: ["Engineering"], declined: false,
        via: [{ groupId: "g1", groupName: "Engineering", addedBy: { id: "ad", name: "Admin Al" } }] },
    ];
    let approved = null as null | { wraps: { userId: string; wrappedFolderKey: string; sealedTo: string | null }[] };
    let declined: unknown = null;
    server.use(
      http.get("/api/v1/group-access/pending", () => HttpResponse.json({ pending: approved || declined ? [] : pending })),
      http.post("/api/v1/folders/:id/group-access", async ({ request }) => { approved = (await request.json()) as never; return HttpResponse.json({ added: ["m1"], skipped: 0 }); }),
      http.post("/api/v1/folders/:id/group-access/decline", async ({ request }) => { declined = await request.json(); return HttpResponse.json({ declined: 1 }); }),
    );
    wrap(<GroupAccessBanner folders={[folder]} />);
    const banner = await screen.findByRole("status", { name: "Group access requests" });
    expect(banner).toHaveTextContent("1 person is waiting for access to a team folder through a group");
    await new Promise((r) => setTimeout(r, 50));
    expect(approved).toBeNull(); // never automatic
    await userEvent.click(within(banner).getByRole("button", { name: "Review" }));
    const req = await screen.findByRole("region", { name: "Requests for Infra" });
    expect(req).toHaveTextContent("1 person waiting for access to Infra via Engineering");
    expect(req).toHaveTextContent("Mia");
    expect(req).toHaveTextContent("mia@clane.ai");
    expect(req).toHaveTextContent("Engineering (added by Admin Al)");
    await userEvent.click(within(req).getByRole("button", { name: "Approve" }));
    await waitFor(() => expect(approved).not.toBeNull());
    expect(approved!.wraps[0]).toMatchObject({ userId: "m1", sealedTo: mia.material.publicKey });
    expect(await openOrgFolderKey(approved!.wraps[0]!.wrappedFolderKey, { orgId: ORG.id, folderId: folder.id }, mia.keys)).toEqual(folderKey);
  });
});

describe("agents in groups (attested by the pinned gateway; Use only; the restricted-credential warning)", () => {
  async function enrolledAgent(id: string) {
    const { gatewayKeyId, generateIdentityKeyPair, signAgentKey } = await import("@clane-vault/crypto");
    const gw = await generateIdentityKeyPair();
    const gateway = { keyId: await gatewayKeyId(gw.publicKey), publicKey: b64url.encode(gw.publicKey) };
    const keys = await generateKeyPair();
    const publicKey = b64url.encode(keys.publicKey);
    return { gateway, keys, publicKey, attestation: await signAgentKey(gw.privateKey, gateway.keyId, { orgId: ORG.id, agentId: id, publicKey }), gatewayKeyId: gateway.keyId };
  }
  beforeEach(() => { localStorage.clear(); });

  it("a pending agent is marked Agent, the warning sits above Approve, and approval refuses an agent the pinned gateway didn't attest", async () => {
    const { GroupAccessBanner } = await import("./GroupAccessBanner");
    const { AGENT_WARNING } = await import("@/features/vault/AgentWarning");
    const { pinGateway } = await import("@/lib/orgKeys");
    const bot = await enrolledAgent("ag1");
    const folderKey = randomBytes(32);
    const folder: VaultFolder = { id: crypto.randomUUID(), name: "Infra", kind: "team", deleted: false, ownerId: "a1", myPermission: "owner", folderKey, members: [],
      groups: [{ id: "g1", name: "Bots", permission: "view", memberIds: ["ag1"] }] };
    const pending = [{ folderId: folder.id, userId: "ag1", name: "Billing bot", email: "agent+ag1@agents.invalid", kind: "agent", publicKey: bot.publicKey, membershipKey: null,
      attestation: bot.attestation, gatewayKeyId: bot.gatewayKeyId, permission: "use", groups: ["Bots"], declined: false, via: [{ groupId: "g1", groupName: "Bots", addedBy: null }] }];
    let approved = null as null | { wraps: { userId: string; wrappedFolderKey: string }[] };
    server.use(
      http.get("/api/v1/group-access/pending", () => HttpResponse.json({ pending: approved ? [] : pending })),
      http.post("/api/v1/folders/:id/group-access", async ({ request }) => { approved = (await request.json()) as never; return HttpResponse.json({ added: ["ag1"], skipped: 0 }); }),
    );
    wrap(<GroupAccessBanner folders={[folder]} />);
    await userEvent.click(within(await screen.findByRole("status", { name: "Group access requests" })).getByRole("button", { name: "Review" }));
    const req = await screen.findByRole("region", { name: "Requests for Infra" });
    expect(within(req).getByText("Agent")).toBeInTheDocument();
    const warning = within(req).getByRole("note", { name: "Sharing with an agent" });
    expect(warning).toHaveTextContent(AGENT_WARNING);
    const approve = within(req).getByRole("button", { name: "Approve" });
    expect(warning.compareDocumentPosition(approve) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    // The gateway identity can't be confirmed (unreachable, nothing pinned): refused, nothing sealed.
    server.use(http.get("/api/v1/org/agents/gateway", () => HttpResponse.json({ error: "gateway_unavailable" }, { status: 503 })));
    await userEvent.click(approve);
    expect(await within(req).findByRole("alert")).toHaveTextContent(/Not given to Billing bot: Couldn't confirm the agent gateway's identity/);
    expect(approved).toBeNull();
    await pinGateway("a1", ORG.id, bot.gateway);
    await userEvent.click(within(req).getByRole("button", { name: "Approve" }));
    await waitFor(() => expect(approved).not.toBeNull());
    expect(await openFolderKey(approved!.wraps[0]!.wrappedFolderKey, folder.id, bot.keys)).toEqual(folderKey);
  });

  it("approving people and an agent the gateway didn't attest: the people get access, the agent is named as refused", async () => {
    const { GroupAccessBanner } = await import("./GroupAccessBanner");
    const { createMembershipKeys } = await import("@clane-vault/crypto");
    const bot = await enrolledAgent("ag1");
    // First use: pinned from the server.
    server.use(http.get("/api/v1/org/agents/gateway", () => HttpResponse.json({ url: "https://gw/mcp", identityKeyId: bot.gateway.keyId, identityPublicKey: bot.gateway.publicKey })));
    const folder: VaultFolder = { id: crypto.randomUUID(), name: "Infra", kind: "team", deleted: false, ownerId: "a1", myPermission: "owner", folderKey: randomBytes(32), members: [],
      groups: [{ id: "g1", name: "Ops", permission: "view", memberIds: ["m1", "ag1"] }] };
    const mia = await createMembershipKeys(randomBytes(32), { orgId: ORG.id, userId: "m1" });
    const via = [{ groupId: "g1", groupName: "Ops", addedBy: null }];
    const pending = [
      { folderId: folder.id, userId: "m1", name: "Mia", email: "mia@clane.ai", publicKey: "", membershipKey: mia.material.publicKey, permission: "view", groups: ["Ops"], declined: false, via },
      { folderId: folder.id, userId: "ag1", name: "Billing bot", email: "agent+ag1@agents.invalid", kind: "agent", publicKey: b64url.encode((await generateKeyPair()).publicKey), membershipKey: null,
        attestation: bot.attestation, gatewayKeyId: bot.gatewayKeyId, permission: "use", groups: ["Ops"], declined: false, via },
    ];
    let approved = null as null | { wraps: { userId: string }[] };
    server.use(
      http.get("/api/v1/group-access/pending", () => HttpResponse.json({ pending })),
      http.post("/api/v1/folders/:id/group-access", async ({ request }) => { approved = (await request.json()) as never; return HttpResponse.json({ added: ["m1"], skipped: 0 }); }),
    );
    wrap(<GroupAccessBanner folders={[folder]} />);
    await userEvent.click(within(await screen.findByRole("status", { name: "Group access requests" })).getByRole("button", { name: "Review" }));
    const req = await screen.findByRole("region", { name: "Requests for Infra" });
    await userEvent.click(within(req).getByRole("button", { name: "Approve" }));
    await waitFor(() => expect(approved).not.toBeNull());
    expect(approved!.wraps.map((w) => w.userId)).toEqual(["m1"]);
    expect(await within(req).findByRole("alert")).toHaveTextContent(/Not given to Billing bot: The gateway did not sign this agent's key/);
  });

  it("sharing a folder with a group that has an agent shows the warning above Share; an agent whose key the gateway didn't sign is left out (it waits for approval)", async () => {
    const { AGENT_WARNING } = await import("@/features/vault/AgentWarning");
    const { pinGateway } = await import("@/lib/orgKeys");
    const bot = await enrolledAgent("ag1");
    await pinGateway("a1", ORG.id, bot.gateway);
    const ben = await generateKeyPair();
    const folder: VaultFolder = { id: crypto.randomUUID(), name: "Infra", kind: "team", deleted: false, ownerId: "a1", myPermission: "owner", folderKey: randomBytes(32), groups: [],
      members: [{ userId: "a1", name: "Ada", email: "ada@clane.ai", publicKey: "", permission: "owner", directPermission: "owner" }] };
    const forged = b64url.encode((await generateKeyPair()).publicKey);
    let posted: { wraps: { userId: string }[] } | null = null;
    server.use(
      http.get("/api/v1/groups", () => HttpResponse.json({ groups: [{ id: "g2", name: "Ops", members: [
        { id: "b1", name: "Ben", email: "ben@clane.ai", publicKey: b64url.encode(ben.publicKey) },
        { id: "ag1", name: "Billing bot", email: "agent+ag1@agents.invalid", kind: "agent", publicKey: forged, membershipKey: null, attestation: bot.attestation, gatewayKeyId: bot.gatewayKeyId },
      ] }] })),
      http.get("/api/v1/users", () => HttpResponse.json({ users: [] })),
      http.get("/api/v1/admin/people", () => HttpResponse.json({ users: [], invites: [] })),
      http.post("/api/v1/folders/:id/groups", async ({ request }) => { posted = (await request.json()) as never; return HttpResponse.json({ ok: true, added: 1, pending: 1 }, { status: 201 }); }),
    );
    wrap(<FolderPeopleSheet folder={folder} onClose={() => undefined} onAdd={vi.fn()} onUpdate={vi.fn()} onRemove={vi.fn()} />);
    await userEvent.click(await screen.findByRole("combobox", { name: "Group to share with" }));
    await userEvent.click(await screen.findByRole("option", { name: /Ops/ }));
    const warning = screen.getByRole("note", { name: "Sharing with an agent" });
    expect(warning).toHaveTextContent(AGENT_WARNING);
    const share = screen.getByRole("button", { name: "Share" });
    expect(warning.compareDocumentPosition(share) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    await userEvent.click(share);
    await waitFor(() => expect(posted).not.toBeNull());
    expect(posted!.wraps.map((w) => w.userId)).toEqual(["b1"]);
  });

  it("a folder's agent member shows the Agent badge and its permission is locked to Use only", async () => {
    const folder: VaultFolder = { id: crypto.randomUUID(), name: "Infra", kind: "team", deleted: false, ownerId: "a1", myPermission: "owner", folderKey: randomBytes(32), groups: [],
      members: [
        { userId: "a1", name: "Ada", email: "ada@clane.ai", publicKey: "", permission: "owner", directPermission: "owner" },
        { userId: "ag1", name: "Billing bot", email: "agent+ag1@agents.invalid", kind: "agent", publicKey: "", permission: "use", directPermission: "use" },
      ] };
    server.use(http.get("/api/v1/users", () => HttpResponse.json({ users: [] })), http.get("/api/v1/groups", () => HttpResponse.json({ groups: [] })), http.get("/api/v1/admin/people", () => HttpResponse.json({ users: [], invites: [] })));
    wrap(<FolderPeopleSheet folder={folder} onClose={() => undefined} onAdd={vi.fn()} onUpdate={vi.fn()} onRemove={vi.fn()} />);
    const row = await screen.findByRole("listitem", { name: "Billing bot" });
    expect(within(row).getByText("Agent")).toBeInTheDocument();
    expect(within(row).getByRole("combobox", { name: "Permission for Billing bot" })).toBeDisabled();
  });
});

describe("giving access again after a key change", () => {
  it("shows who needs access again; the key holder re-seals explicitly", async () => {
    const folder: VaultFolder = { id: crypto.randomUUID(), name: "Infra", kind: "team", deleted: false, ownerId: "a1", myPermission: "owner", folderKey: randomBytes(32), groups: [],
      members: [
        { userId: "a1", name: "Ada", email: "ada@clane.ai", publicKey: "", permission: "owner", directPermission: "owner" },
        { userId: "m1", name: "Mia", email: "mia@clane.ai", publicKey: "", membershipKey: b64url.encode((await generateKeyPair()).publicKey), needsAccess: true, permission: "view", directPermission: "view" },
      ] };
    server.use(http.get("/api/v1/users", () => HttpResponse.json({ users: [] })), http.get("/api/v1/groups", () => HttpResponse.json({ groups: [] })));
    const give = vi.fn(async () => undefined);
    wrap(<FolderPeopleSheet folder={folder} onClose={() => undefined} onAdd={vi.fn()} onUpdate={vi.fn()} onRemove={vi.fn()} onGiveAccess={give} />);
    const row = await screen.findByRole("listitem", { name: "Mia" });
    expect(row).toHaveTextContent("Needs access again");
    await userEvent.click(within(row).getByRole("button", { name: "Give access again" }));
    await waitFor(() => expect(give).toHaveBeenCalledWith(folder, folder.members![1]));
  });
});
