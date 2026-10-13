import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, useLocation } from "react-router";
import { describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Sidebar, type SidebarBadges, type SidebarView } from "./Sidebar";
import { listPath, ORG_VIEWS, PERSONAL_VIEWS } from "@/lib/paths";
import type { VaultView } from "./filter";

// Radix tooltips measure themselves; jsdom has no ResizeObserver.
globalThis.ResizeObserver ??= class { observe() {} unobserve() {} disconnect() {} } as never;

const counts = { vault: 3, shared: 0, attention: 1, links: null, trash: 0 };

function Where() { const l = useLocation(); return <output data-testid="where">{l.pathname}</output>; }

function renderSidebar(opts: { canAdmin?: boolean; badges?: SidebarBadges; view?: SidebarView; collapsed?: boolean; personal?: boolean } = {}) {
  const prefix = opts.personal ? "/p" : "/o/acme";
  const paths = { views: opts.personal ? PERSONAL_VIEWS : ORG_VIEWS, list: (v: VaultView) => listPath(prefix, v) };
  const fns = { onLock: vi.fn(), onSignOut: vi.fn(), onToggleCollapsed: vi.fn() };
  render(
    <QueryClientProvider client={new QueryClient()}>
      <MemoryRouter initialEntries={[`${prefix}/vault`]}>
        <Sidebar view={opts.view ?? "vault"} counts={counts} newButton={null} user={{ name: "Sara Lindqvist", email: "sara.lindqvist@acme.test" }}
          org={{ id: "o1", name: "Acme" }} adminHref={opts.canAdmin ? "/o/acme/admin" : null} paths={paths} badges={opts.badges} collapsed={opts.collapsed} {...fns} />
        <Where />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return fns;
}
const where = () => screen.getByTestId("where").textContent;

describe("account menu (sidebar footer)", () => {
  it("the Personal space's sections: no Shared with me (direct shares belong to an organisation)", () => {
    renderSidebar({ personal: true });
    const nav = screen.getByRole("navigation", { name: "Sections" });
    expect(within(nav).getByRole("link", { name: /^Vault/ })).toHaveAttribute("href", "/p/vault");
    expect(within(nav).getByRole("link", { name: /^Trash/ })).toHaveAttribute("href", "/p/trash");
    expect(within(nav).queryByRole("link", { name: /^Shared with me/ })).not.toBeInTheDocument();
  });

  it("shows the avatar, name and email; the vault sections are links in the sidebar, the rest is in the menu", async () => {
    renderSidebar({ canAdmin: true });
    const trigger = screen.getByRole("button", { name: "Account menu: Sara Lindqvist" });
    expect(trigger).toHaveTextContent("SL");
    expect(trigger).toHaveTextContent("Sara Lindqvist");
    expect(trigger).toHaveTextContent("sara.lindqvist@acme.test");
    const nav = screen.getByRole("navigation", { name: "Sections" });
    const hrefs = { Vault: "/o/acme/vault", "Shared with me": "/o/acme/shared", "Needs attention": "/o/acme/attention", "Share links": "/o/acme/links", Trash: "/o/acme/trash" };
    for (const [s, href] of Object.entries(hrefs)) expect(within(nav).getByRole("link", { name: new RegExp(`^${s}`) })).toHaveAttribute("href", href);
    expect(within(nav).getByRole("link", { name: /^Vault/ })).toHaveAttribute("aria-current", "page");
    for (const s of ["Settings", "Lock", "Sign out", "Admin", "Password health"]) expect(within(nav).queryByRole("link", { name: s })).not.toBeInTheDocument();
    await userEvent.click(within(nav).getByRole("link", { name: /^Trash/ }));
    expect(where()).toBe("/o/acme/trash");
  });

  it("members get Settings (their own sections), Password health, install, Lock and Sign out; no Admin", async () => {
    const fns = renderSidebar();
    await userEvent.click(screen.getByRole("button", { name: /^Account menu/ }));
    const menu = await screen.findByRole("menu");
    expect(menu).toHaveAttribute("data-side", "top");
    expect(within(menu).getAllByRole("menuitem").map((i) => i.textContent)).toEqual(["Settings", "Password health", "Install app", "Browser extension", "Lock", "Sign out"]);
    await userEvent.click(within(menu).getByRole("menuitem", { name: "Settings" }));
    expect(where()).toBe("/settings");
    await userEvent.click(screen.getByRole("button", { name: /^Account menu/ }));
    await userEvent.click(within(await screen.findByRole("menu")).getByRole("menuitem", { name: "Browser extension" }));
    expect(where()).toBe("/settings/extension");
    await userEvent.click(screen.getByRole("button", { name: /^Account menu/ }));
    await userEvent.click(within(await screen.findByRole("menu")).getByRole("menuitem", { name: "Lock" }));
    expect(fns.onLock).toHaveBeenCalledOnce();
    await userEvent.click(screen.getByRole("button", { name: /^Account menu/ }));
    await userEvent.click(within(await screen.findByRole("menu")).getByRole("menuitem", { name: "Sign out" }));
    expect(fns.onSignOut).toHaveBeenCalledOnce();
  });

  it("admins (and instance admins) get Admin, with the count of people waiting", async () => {
    renderSidebar({ canAdmin: true, badges: { admin: 2 } });
    expect(screen.getByRole("button", { name: "Account menu: Sara Lindqvist, needs attention" })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /^Account menu/ }));
    const admin = within(await screen.findByRole("menu")).getByRole("menuitem", { name: /^Admin/ });
    expect(admin).toHaveTextContent("Admin2");
    await userEvent.click(admin);
    expect(where()).toBe("/o/acme/admin");
  });

  it("marks Settings when there's no recovery kit yet", async () => {
    renderSidebar({ badges: { settings: 1 } });
    await userEvent.click(screen.getByRole("button", { name: "Account menu: Sara Lindqvist, needs attention" }));
    expect(within(await screen.findByRole("menu")).getByRole("menuitem", { name: /^Settings/ })).toContainElement(screen.getByLabelText("Needs attention"));
  });

  it("works from the keyboard: Enter opens it, arrows move, Enter picks, Escape closes", async () => {
    renderSidebar({ view: "settings" });
    const trigger = screen.getByRole("button", { name: /^Account menu/ });
    trigger.focus();
    await userEvent.keyboard("{Enter}");
    const menu = await screen.findByRole("menu");
    expect(within(menu).getByRole("menuitem", { name: "Settings" })).toHaveAttribute("aria-current", "page");
    await userEvent.keyboard("{Escape}");
    expect(screen.queryByRole("menu")).not.toBeInTheDocument();
    expect(trigger).toHaveFocus();
    await userEvent.keyboard("{Enter}");
    await screen.findByRole("menu");
    // Opened from the keyboard, the first item has focus.
    await waitFor(() => expect(screen.getByRole("menuitem", { name: "Settings" })).toHaveFocus());
    await userEvent.keyboard("{ArrowDown}");
    expect(screen.getByRole("menuitem", { name: "Password health" })).toHaveFocus();
    await userEvent.keyboard("{Enter}");
    expect(where()).toBe("/settings/health");
  });
});

describe("collapsible sidebar", () => {
  it("has a collapse button (with its shortcut) on the sidebar's edge", async () => {
    const fns = renderSidebar();
    const toggle = screen.getByRole("button", { name: "Collapse sidebar" });
    expect(toggle).toHaveAttribute("aria-keyshortcuts", "Control+B Meta+B");
    await userEvent.click(toggle);
    expect(fns.onToggleCollapsed).toHaveBeenCalledOnce();
  });

  it("collapsed: an icon rail of named links, tooltips, the round +, the avatar only", async () => {
    renderSidebar({ collapsed: true });
    const nav = screen.getByRole("navigation", { name: "Sections" });
    expect(nav).toHaveAttribute("data-collapsed");
    expect(nav).toHaveClass("w-16");
    expect(screen.getByRole("button", { name: "Expand sidebar" })).toBeInTheDocument();
    const vault = within(nav).getByRole("link", { name: "Vault" });
    expect(vault).not.toHaveTextContent("Vault");
    await userEvent.hover(vault);
    expect((await screen.findAllByText("Vault · 3")).length).toBeGreaterThan(0);
    const account = screen.getByRole("button", { name: /^Account menu/ });
    expect(account).not.toHaveTextContent("sara.lindqvist@acme.test");
    await userEvent.click(account);
    expect(await screen.findByRole("menu")).toHaveAttribute("data-side", "right");
  });
});
