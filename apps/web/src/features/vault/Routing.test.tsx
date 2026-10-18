import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, useLocation } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { http, HttpResponse } from "msw";
import { encryptNewRecord, randomBytes } from "@clane-vault/crypto";
import { server } from "@/test/server";
import * as sessionModule from "@/lib/session";
import VaultPage from "./VaultPage";

// Radix tooltips measure themselves; jsdom has no ResizeObserver.
globalThis.ResizeObserver ??= class { observe() {} unobserve() {} disconnect() {} } as never;

const userKey = randomBytes(32);
const ORG = { id: "o1", name: "Acme", slug: "acme", role: "member", isDefault: true };
const session = vi.spyOn(sessionModule, "useSession");
const asRole = (role: "member" | "admin" | "owner") => session.mockReturnValue({ org: { ...ORG, role }, orgs: [{ ...ORG, role }], applyOrgs: vi.fn(), generation: () => 0, lock: vi.fn(), signOut: vi.fn(),
  user: { id: "u1", name: "Sara", email: "sara@acme.test", role: role === "member" ? "member" : "admin", orgRole: role }, keys: { userKey, privateKey: new Uint8Array(), publicKey: new Uint8Array() } } as never);

const phone = (on: boolean) => vi.stubGlobal("matchMedia", vi.fn((q: string) => ({ matches: on && q.includes("max-width: 760px"), media: q, addEventListener: vi.fn(), removeEventListener: vi.fn() })));
function Where() { const l = useLocation(); return <output data-testid="where">{l.pathname + l.search}</output>; }
const where = () => screen.getByTestId("where").textContent;
const open = (path: string) => render(
  <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
    <MemoryRouter initialEntries={[path]}><VaultPage onNew={vi.fn()} /><Where /></MemoryRouter>
  </QueryClientProvider>);

async function login(title: string) {
  const id = crypto.randomUUID();
  const enc = await encryptNewRecord(id, { type: "login", title, password: "Zq8$wP3n!Lk7xV2m" }, userKey);
  return { id, folderId: null, type: "login", encBody: enc.encBody, revision: 1, updatedAt: new Date().toISOString(), deletedAt: null, permission: "owner", wrappedRecordKey: enc.wrappedRecordKey, holderType: "user" };
}

beforeEach(() => { phone(false); asRole("member"); localStorage.clear(); server.use(http.get("/api/v1/sync", () => HttpResponse.json({ serverTime: "", folders: [], records: [] }))); });
afterEach(() => vi.unstubAllGlobals());

describe("every page has a URL", () => {
  it("/ and unknown paths go to the vault of the space in use (/o/acme/vault)", async () => {
    const { unmount } = open("/");
    await waitFor(() => expect(where()).toBe("/o/acme/vault"));
    unmount();
    open("/nothing/here");
    await waitFor(() => expect(where()).toBe("/o/acme/vault"));
  });

  it("a record URL opens that record; closing it goes back to the list", async () => {
    const r = await login("AWS root");
    server.use(http.get("/api/v1/sync", () => HttpResponse.json({ serverTime: "", folders: [], records: [r] })));
    open(`/o/acme/vault/record/${r.id}`);
    expect(await screen.findByRole("heading", { name: "AWS root" })).toBeInTheDocument();
    await userEvent.keyboard("{Escape}");
    await waitFor(() => expect(where()).toBe("/o/acme/vault"));
    // Selecting a record puts it in the address.
    await userEvent.click(await screen.findByRole("button", { name: /^Shared directly/ }));
    await userEvent.click(await screen.findByRole("button", { name: /AWS root/ }));
    await waitFor(() => expect(where()).toBe(`/o/acme/vault/record/${r.id}`));
  });

  it("a record URL for something not in the vault goes back to the list", async () => {
    open(`/o/acme/trash/record/${crypto.randomUUID()}`);
    await waitFor(() => expect(where()).toBe("/o/acme/trash"));
  });

  it("members get Settings with their own sections; /settings opens Account on a desktop", async () => {
    open("/settings");
    await waitFor(() => expect(where()).toBe("/settings/account"));
    const sub = await screen.findByRole("navigation", { name: "Settings sections" });
    expect(within(sub).getAllByRole("link").map((l) => l.textContent)).toEqual(["Account", "Security", "This device", "Browser extension", "Password health"]);
    expect(within(sub).getByRole("link", { name: "Account" })).toHaveAttribute("aria-current", "page");
    expect(screen.getByRole("heading", { level: 1, name: "Account" })).toBeInTheDocument();
    await userEvent.click(within(sub).getByRole("link", { name: "Security" }));
    expect(where()).toBe("/settings/security");
    expect(await screen.findByRole("note", { name: "Who can recover your vault" })).toBeInTheDocument();
  });

  it("a member on an admin URL gets No access, never the admin page", async () => {
    open("/o/acme/admin/people");
    expect(await screen.findByRole("heading", { name: "You don't have access to this page" })).toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "People" })).not.toBeInTheDocument();
    expect(screen.queryByRole("navigation", { name: "Admin sections" })).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("link", { name: "Go to Settings" }));
    await waitFor(() => expect(where()).toBe("/settings/account"));
  });

  it("a member on the risk dashboard gets No access (and nothing is fetched)", async () => {
    let asked = false;
    server.use(http.get("/api/v1/admin/risk", () => { asked = true; return HttpResponse.json({}, { status: 403 }); }));
    open("/o/acme/admin/risk");
    expect(await screen.findByRole("heading", { name: "You don't have access to this page" })).toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "Risk dashboard" })).not.toBeInTheDocument();
    expect(asked).toBe(false);
  });

  it("admins: /admin opens the Risk dashboard; the sub-navigation has the org's pages and its settings (Server only for instance admins)", async () => {
    asRole("admin");
    server.use(http.get("/api/v1/admin/risk", () => HttpResponse.json({ error: "server_error" }, { status: 500 })), http.get("/api/v1/admin/pending-members", () => HttpResponse.json({ pending: [] })));
    open("/o/acme/admin");
    await waitFor(() => expect(where()).toBe("/o/acme/admin/risk"));
    const sub = await screen.findByRole("navigation", { name: "Admin sections" });
    expect(within(sub).getAllByRole("group").map((g) => g.getAttribute("aria-label"))).toEqual(["Organisation", "Organisation settings"]);
    expect(within(sub).getAllByRole("link").map((l) => l.textContent)).toEqual(["Risk dashboard", "People", "Groups", "Agents", "Event log", "Password health", "Migrate from Keeper", "General", "Policies", "Single sign-on", "Admin recovery", "Email", "Storage"]);
    expect(screen.getByRole("heading", { level: 1, name: "Risk dashboard" })).toBeInTheDocument();
  });

  it("old org settings paths land on their Admin page", async () => {
    asRole("owner");
    open("/org/settings/policies");
    await waitFor(() => expect(where()).toBe("/o/acme/admin/org/policies"));
    expect(await screen.findByRole("heading", { level: 1, name: "Policies" })).toBeInTheDocument();
  });

  it("admins without instance rights get No access on server pages", async () => {
    asRole("admin");
    open("/admin/server/backups");
    expect(await screen.findByRole("heading", { name: "You don't have access to this page" })).toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "Backups" })).not.toBeInTheDocument();
  });

  it("phones: /settings is the list of sections; a section has Back to it", async () => {
    phone(true);
    open("/settings");
    const list = await screen.findByRole("navigation", { name: "Settings sections" });
    await userEvent.click(within(list).getByRole("link", { name: /This device/ }));
    expect(where()).toBe("/settings/device");
    await userEvent.click(await screen.findByRole("link", { name: "Back to Settings" }));
    expect(where()).toBe("/settings");
  });
});

describe("collapsible sidebar", () => {
  it("Ctrl+B (or the edge button) switches to the icon rail and back, remembered on this device", async () => {
    open("/vault");
    const nav = screen.getByRole("navigation", { name: "Sections" });
    expect(nav).not.toHaveAttribute("data-collapsed");
    await userEvent.keyboard("{Control>}b{/Control}");
    expect(screen.getByRole("navigation", { name: "Sections" })).toHaveAttribute("data-collapsed");
    expect(localStorage.getItem("cv.sidebar.collapsed")).toBe("1");
    expect(screen.getByRole("button", { name: "New" })).not.toHaveTextContent("New");
    await userEvent.click(screen.getByRole("button", { name: "Expand sidebar" }));
    expect(screen.getByRole("navigation", { name: "Sections" })).not.toHaveAttribute("data-collapsed");
    expect(localStorage.getItem("cv.sidebar.collapsed")).toBe("0");
  });

  it("opens collapsed when that was the last choice; phones always get the drawer", () => {
    localStorage.setItem("cv.sidebar.collapsed", "1");
    const { unmount } = open("/vault");
    expect(screen.getByRole("navigation", { name: "Sections" })).toHaveAttribute("data-collapsed");
    unmount();
    phone(true);
    open("/vault");
    expect(screen.queryByRole("navigation", { name: "Sections" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Open menu" })).toBeInTheDocument();
  });
});
