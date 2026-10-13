import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { http, HttpResponse } from "msw";
import { encryptFolderName, encryptNewRecord, randomBytes } from "@clane-vault/crypto";
import { server } from "@/test/server";
import * as sessionModule from "@/lib/session";
import VaultPage from "./VaultPage";
import VaultScreen from "./VaultScreen";

const userKey = randomBytes(32);
vi.spyOn(sessionModule, "useSession").mockReturnValue({ org: { id: "o1", name: "Acme", slug: "acme", role: "member", isDefault: true }, orgs: [{ id: "o1", name: "Acme", slug: "acme", role: "member", isDefault: true }], applyOrgs: vi.fn(), user: { id: "u1", name: "Sara" }, generation: () => 0, lock: vi.fn(), signOut: vi.fn(), keys: { userKey, privateKey: new Uint8Array(), publicKey: new Uint8Array() } } as never);

/** The Personal space for one test: private folders, "No folder", no shared folders (lib/paths). */
function inPersonal() {
  const base = sessionModule.useSession();
  vi.spyOn(sessionModule, "useSession").mockReturnValue({ ...base, org: null } as never);
  return () => vi.spyOn(sessionModule, "useSession").mockReturnValue(base as never);
}
function renderPage(page: React.ReactElement = <VaultPage onNew={vi.fn()} />) {
  return render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter>{page}</MemoryRouter></QueryClientProvider>);
}
async function login(title: string, permission = "owner") {
  const id = crypto.randomUUID();
  const enc = await encryptNewRecord(id, { type: "login", title, password: "Zq8$wP3n!Lk7xV2m" }, userKey);
  return { id, folderId: null, type: "login", encBody: enc.encBody, revision: 1, updatedAt: new Date().toISOString(), deletedAt: null, permission, wrappedRecordKey: enc.wrappedRecordKey, holderType: "user" };
}
async function syncWithFolder() {
  const id = crypto.randomUUID();
  const encName = await encryptFolderName(id, "Infrastructure", userKey);
  return { id, body: { serverTime: "", folders: [{ id, encName, kind: "private", deletedAt: null }], records: [] } };
}

describe("VaultPage", () => {
  it("a session without the authenticator code shows a locked Private items row that asks for the step-up", async () => {
    const requestStepUp = vi.fn();
    const base = sessionModule.useSession();
    const spy = vi.spyOn(sessionModule, "useSession").mockReturnValue({ ...base, requestStepUp } as never);
    server.use(http.get("/api/v1/sync", () => HttpResponse.json({ serverTime: "", folders: [], records: [], privateLocked: true })));
    renderPage();
    const row = await screen.findByTestId("private-locked");
    expect(row).toHaveTextContent("Private items — verify with your authenticator to show");
    await userEvent.click(row);
    expect(requestStepUp).toHaveBeenCalledOnce();
    spy.mockReturnValue(base as never);
  });


  it("shows an error with Retry instead of an empty vault when sync fails", async () => {
    let fail = true;
    server.use(http.get("/api/v1/sync", () => fail ? HttpResponse.json({ error: "server_error" }, { status: 500 }) : HttpResponse.json({ serverTime: "", folders: [], records: [] })));
    renderPage();
    expect(await screen.findByText("Couldn't load your vault.")).toBeInTheDocument();
    expect(screen.queryByText("No records yet")).not.toBeInTheDocument();
    fail = false;
    await userEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByText("No records yet")).toBeInTheDocument();
    expect(screen.queryByText("Couldn't load your vault.")).not.toBeInTheDocument();
  });

  it("renames a folder from its actions menu", async () => {
    const f = await syncWithFolder();
    let patched: unknown = null;
    server.use(
      http.get("/api/v1/sync", () => HttpResponse.json(f.body)),
      http.patch("/api/v1/folders/:id", async ({ request }) => { patched = await request.json(); return new HttpResponse(null, { status: 204 }); }),
    );
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: "Options for Infrastructure" }));
    await userEvent.click(await screen.findByRole("menuitem", { name: "Rename" }));
    const input = await screen.findByLabelText("Name");
    expect(input).toHaveValue("Infrastructure");
    await userEvent.clear(input);
    await userEvent.type(input, "Ops");
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(patched).toMatchObject({ encName: expect.any(String) }));
  });

  it("deletes a folder only after confirming", async () => {
    const f = await syncWithFolder();
    let deleted = false;
    server.use(
      http.get("/api/v1/sync", () => HttpResponse.json(f.body)),
      http.delete("/api/v1/folders/:id", () => { deleted = true; return new HttpResponse(null, { status: 204 }); }),
    );
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: "Options for Infrastructure" }));
    await userEvent.click(await screen.findByRole("menuitem", { name: "Delete" }));
    expect(await screen.findByText("Delete folder Infrastructure? Its records move to Trash.")).toBeInTheDocument();
    expect(deleted).toBe(false);
    await userEvent.click(screen.getByRole("button", { name: "Delete" }));
    await waitFor(() => expect(deleted).toBe(true));
  });

  it("lists weak and reused passwords under Needs attention with reason chips", async () => {
    const rec = async (title: string, password: string) => {
      const id = crypto.randomUUID();
      const enc = await encryptNewRecord(id, { type: "login", title, password }, userKey);
      return { id, folderId: null, type: "login", encBody: enc.encBody, revision: 1, updatedAt: new Date().toISOString(), deletedAt: null, permission: "owner", wrappedRecordKey: enc.wrappedRecordKey, holderType: "user" };
    };
    const records = [await rec("Figma", "figma123"), await rec("Strong one", "Tg7#qL2v!Rm9zW4x"), await rec("Strong two", "Tg7#qL2v!Rm9zW4x"), await rec("Fine", "Zq8$wP3n!Lk7xV2m")];
    server.use(http.get("/api/v1/sync", () => HttpResponse.json({ serverTime: "", folders: [], records })));
    renderPage();
    const nav = await screen.findByRole("link", { name: /Needs attention/ });
    await waitFor(() => expect(nav).toHaveTextContent("3"));
    await userEvent.click(nav);
    expect(screen.getByRole("heading", { name: "Needs attention" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Figma/ })).toHaveTextContent("Weak");
    expect(screen.getByRole("button", { name: /Strong one/ })).toHaveTextContent("Reused");
    expect(screen.queryByRole("button", { name: /Fine/ })).not.toBeInTheDocument();
  });

  it("the header Options act on the open folder: New Record there; Move To and Delete say why they can't yet", async () => {
    const f = await syncWithFolder();
    server.use(http.get("/api/v1/sync", () => HttpResponse.json(f.body)));
    const onNew = vi.fn();
    const back = inPersonal();
    renderPage(<VaultPage onNew={onNew} />);
    // No folder open: the vault itself.
    await userEvent.click(await screen.findByRole("button", { name: "Options" }));
    expect(screen.getByText("My vault")).toBeInTheDocument();
    expect(screen.getByRole("menuitem", { name: "Delete" })).toHaveAccessibleDescription("Open a folder to delete it.");
    await userEvent.keyboard("{Escape}");
    await userEvent.click(screen.getByRole("button", { name: /^Infrastructure/ }));
    await userEvent.click(screen.getByRole("button", { name: "Options" }));
    expect(screen.getAllByRole("menuitem").map((x) => x.getAttribute("aria-label") ?? x.textContent)).toEqual(["New Record", "New Folder", "New Shared Folder", "Move To", "Rename", "Delete"]);
    expect(screen.getByRole("menuitem", { name: "Move To" })).toHaveAttribute("aria-disabled", "true");
    expect(screen.getByRole("menuitem", { name: "Move To" })).toHaveAccessibleDescription("Select a record to move it. Folders can't be moved.");
    expect(screen.getByRole("menuitem", { name: "Delete" })).not.toHaveAttribute("aria-disabled");
    await userEvent.click(screen.getByRole("menuitem", { name: "New Record" }));
    expect(onNew).toHaveBeenCalledWith("record", f.id);
    back();
  });

  it("an open, empty folder says so, with New record there", async () => {
    const f = await syncWithFolder();
    server.use(http.get("/api/v1/sync", () => HttpResponse.json(f.body)));
    const onNew = vi.fn();
    renderPage(<VaultPage onNew={onNew} />);
    await userEvent.click(await screen.findByRole("button", { name: /^Infrastructure/ }));
    expect(screen.getByText("No records here yet")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "New record" }));
    expect(onNew).toHaveBeenCalledWith("record", f.id);
  });

  it("flat lists show each record's folder; Shared with me shows the permission", async () => {
    const f = await syncWithFolder();
    const mine = { ...(await login("AWS")), folderId: f.id };
    const theirs = { ...(await login("Notion", "view")), sharedBy: "Max Member" };
    server.use(http.get("/api/v1/sync", () => HttpResponse.json({ ...f.body, records: [mine, theirs] })));
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: "List" }));
    expect(await screen.findByRole("button", { name: /AWS/ })).toHaveTextContent("Infrastructure");
    await userEvent.click(screen.getByRole("link", { name: /Shared with me/ }));
    const row = await screen.findByRole("button", { name: /Notion/ });
    expect(row).toHaveTextContent("Can view");
    expect(row).toHaveTextContent("Shared by Max Member");
  });

  it("Move To moves the selected record to another folder", async () => {
    const f = await syncWithFolder();
    const r = await login("AWS");
    let moved: unknown = null;
    server.use(
      http.get("/api/v1/sync", () => HttpResponse.json({ ...f.body, records: [r] })),
      http.put("/api/v1/records/:id/folder", async ({ request, params }) => { moved = { id: params.id, ...(await request.json() as object) }; return new HttpResponse(null, { status: 204 }); }),
    );
    const back = inPersonal();
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: /^No folder/ }));
    await userEvent.click(await screen.findByRole("button", { name: /AWS/ }));
    await userEvent.click(screen.getByRole("button", { name: "Options" }));
    await userEvent.click(screen.getByRole("menuitem", { name: "Move To" }));
    expect(await screen.findByText("Move “AWS” to")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("menuitem", { name: "Infrastructure" }));
    await waitFor(() => expect(moved).toMatchObject({ id: r.id, folderId: f.id, ownerWrappedRecordKey: expect.any(String) }));
    back();
  });

  it("Move To is for the record's owner only", async () => {
    const r = await login("Shared DB", "edit");
    server.use(http.get("/api/v1/sync", () => HttpResponse.json({ serverTime: "", folders: [], records: [r] })));
    renderPage();
    // In an organisation, records outside its shared folders are the ones shared directly.
    await userEvent.click(await screen.findByRole("button", { name: /^Shared directly/ }));
    await userEvent.click(await screen.findByRole("button", { name: /Shared DB/ }));
    await userEvent.click(screen.getByRole("button", { name: "Options" }));
    expect(screen.getByRole("menuitem", { name: "Move To" })).toHaveAccessibleDescription("Only the record's owner can move it.");
  });

  it("+ New → Record → Next opens the editor filled in; nothing is created until it saves", async () => {
    const f = await syncWithFolder();
    let posted: Record<string, unknown> | null = null;
    server.use(
      http.get("/api/v1/sync", () => HttpResponse.json(f.body)),
      http.post("/api/v1/records", async ({ request }) => { posted = await request.json() as Record<string, unknown>; return HttpResponse.json({}, { status: 201 }); }),
    );
    renderPage(<VaultScreen />);
    await userEvent.click(await screen.findByRole("button", { name: /^Infrastructure/ }));
    await userEvent.click(screen.getByRole("button", { name: "New" }));
    await userEvent.click(screen.getByRole("menuitem", { name: "Record" }));
    expect(await screen.findByRole("combobox", { name: "Location" })).toHaveTextContent("Infrastructure");
    await userEvent.type(screen.getByLabelText("Title"), "AWS root account{Enter}");
    expect(await screen.findByRole("heading", { name: "New login" })).toBeInTheDocument();
    expect(screen.getByLabelText("Title")).toHaveValue("AWS root account");
    expect(screen.getByRole("combobox", { name: "Folder" })).toHaveTextContent("Infrastructure");
    expect(posted).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(posted).toMatchObject({ folderId: f.id, type: "login" }));
  });
});
