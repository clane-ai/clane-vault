import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { http, HttpResponse } from "msw";
import { randomBytes } from "@clane-vault/crypto";
import { server } from "@/test/server";
import * as sessionModule from "@/lib/session";
import VaultPage from "./VaultPage";

const lock = vi.fn();
vi.spyOn(sessionModule, "useSession").mockReturnValue({ org: null, orgs: [], applyOrgs: vi.fn(), user: { id: "u1", name: "Sara" }, generation: () => 0, lock, signOut: vi.fn(),
  keys: { userKey: randomBytes(32), privateKey: new Uint8Array(), publicKey: new Uint8Array() } } as never);

const phone = (on: boolean) => vi.stubGlobal("matchMedia", vi.fn((q: string) => ({ matches: on && q.includes("max-width: 760px"), media: q, addEventListener: vi.fn(), removeEventListener: vi.fn() })));
const renderPage = () => render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter><VaultPage /></MemoryRouter></QueryClientProvider>);

beforeEach(() => server.use(http.get("/api/v1/sync", () => HttpResponse.json({ serverTime: "", folders: [], records: [] }))));
afterEach(() => vi.unstubAllGlobals());

describe("phone layout", () => {
  it("shows a top bar with menu and lock; the sections live in a drawer that closes on navigation", async () => {
    phone(true);
    renderPage();
    expect(screen.queryByRole("navigation", { name: "Sections" })).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Lock" }));
    expect(lock).toHaveBeenCalledOnce();
    await userEvent.click(screen.getByRole("button", { name: "Open menu" }));
    const nav = await screen.findByRole("navigation", { name: "Sections" });
    expect(nav).toHaveAttribute("data-drawer");
    // The account (avatar, name) sits at the bottom of the drawer too.
    expect(within(nav).getByRole("button", { name: "Account menu: Sara" })).toHaveTextContent("Sara");
    await userEvent.click(within(nav).getByRole("link", { name: /Trash/ }));
    await waitFor(() => expect(screen.queryByRole("navigation", { name: "Sections" })).not.toBeInTheDocument());
    expect(await screen.findByRole("heading", { name: "Trash" })).toBeInTheDocument();
  });

  it("keeps the sidebar on wider screens", () => {
    phone(false);
    renderPage();
    expect(screen.getByRole("navigation", { name: "Sections" })).not.toHaveAttribute("data-drawer");
    expect(screen.queryByRole("button", { name: "Open menu" })).not.toBeInTheDocument();
  });

  it("is a fixed-height shell: only the page area scrolls, never the sidebar with it", () => {
    for (const on of [false, true]) {
      phone(on);
      const { unmount } = renderPage();
      expect(screen.getByTestId("app-shell")).toHaveClass("relative", "h-dvh", "overflow-hidden");
      unmount();
    }
  });
});
