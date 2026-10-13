import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { http, HttpResponse } from "msw";
import { b64url, decryptRecordBody, encryptNewRecord, generateKeyPair, openFolderKey, openSharedRecordKey, randomBytes } from "@clane-vault/crypto";
import { server } from "@/test/server";
import * as sessionModule from "@/lib/session";
import VaultPage from "./VaultPage";

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
