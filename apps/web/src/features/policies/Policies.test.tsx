import { MemoryRouter } from "react-router";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { http, HttpResponse } from "msw";
import { server } from "@/test/server";
import * as sessionModule from "@/lib/session";
import { checkMasterPassword, passwordRuleText, strictest } from "@/lib/policies";
import { RegisterForm } from "@/features/auth/Register";
import { OrgPoliciesSection } from "./OrgPoliciesSection";

// Radix switches inside a form measure themselves; jsdom has no ResizeObserver.
globalThis.ResizeObserver ??= class { observe() {} unobserve() {} disconnect() {} } as never;
const ORG = { id: "o1", name: "Acme", slug: "acme", role: "admin", isDefault: true };
const session = vi.spyOn(sessionModule, "useSession");
session.mockReturnValue({ org: ORG, orgs: [ORG], user: { id: "a1", name: "Ada", role: "admin" }, applyOrgs: vi.fn() } as never);
const wrap = (ui: React.ReactNode) => render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter>{ui}</MemoryRouter></QueryClientProvider>);

describe("master password rule", () => {
  it("checks length and strength and says the rule in words", () => {
    const rule = { minLength: 16, minScore: 3 };
    expect(checkMasterPassword("short", rule)).toBe("Use at least 16 characters.");
    expect(checkMasterPassword("aaaaaaaaaaaaaaaa", rule)).toMatch(/stronger master password/);
    expect(checkMasterPassword("violet anchor tram 42 hedgehog!", rule)).toBeNull();
    expect(passwordRuleText(rule)).toBe("At least 16 characters, rated good or better.");
    expect(passwordRuleText({ minLength: 12, minScore: 0 })).toBe("At least 12 characters.");
    expect(strictest([{ minLength: 14, minScore: 1 }, { minLength: 12, minScore: 3 }])).toEqual({ minLength: 14, minScore: 3 });
  });

  it("the sign-up form shows and enforces the inviting org's rule", async () => {
    const onSubmit = vi.fn();
    render(<RegisterForm email="new@clane.ai" onSubmit={onSubmit} policy={{ minLength: 20, minScore: 0 }} />);
    expect(screen.getByText("At least 20 characters.")).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText("Your name"), "New");
    await userEvent.type(screen.getByLabelText("Master password"), "fifteen chars!!");
    await userEvent.type(screen.getByLabelText("Repeat master password"), "fifteen chars!!");
    await userEvent.click(screen.getByRole("button", { name: "Create account" }));
    expect(screen.getByRole("alert")).toHaveTextContent("Use at least 20 characters.");
    expect(onSubmit).not.toHaveBeenCalled();
  });
});

describe("Org policies section", () => {
  it("loads, edits and saves the policies, then reloads the org list", async () => {
    let put: Record<string, unknown> | null = null;
    let reloaded = false;
    server.use(
      http.put("/api/v1/admin/settings/policies", async ({ request }) => {
        put = (await request.json()) as never;
        return HttpResponse.json({ policies: put, changedAt: new Date().toISOString(), changedBy: { id: "a1", name: "Ada" }, yourIp: "203.0.113.9" });
      }),
      http.get("/api/v1/me/orgs", () => { reloaded = true; return HttpResponse.json({ orgs: [ORG], invitations: [], allowOrgCreation: true, instanceAdmin: false }); }),
    );
    wrap(<OrgPoliciesSection />);
    const lock = await screen.findByLabelText("Auto-lock after (minutes idle)");
    await userEvent.type(lock, "5");
    await userEvent.clear(screen.getByLabelText("Master password: minimum length"));
    await userEvent.type(screen.getByLabelText("Master password: minimum length"), "16");
    await userEvent.click(screen.getByRole("switch", { name: "Offline copies" }));
    await userEvent.click(screen.getByRole("switch", { name: "Require a link password" }));
    await userEvent.type(screen.getByLabelText("IP allowlist"), "203.0.113.0/24\n2001:db8::/32");
    // Only the owner changes break-glass.
    expect(screen.getByRole("switch", { name: "Owner break-glass" })).toBeDisabled();
    await userEvent.click(screen.getByRole("button", { name: "Save policies" }));
    await waitFor(() => expect(put).not.toBeNull());
    expect(put!).toMatchObject({ autoLockMinutes: 5, minPasswordLength: 16, offlineAllowed: false, links: { allowed: true, requirePassword: true }, ipAllowlist: ["203.0.113.0/24", "2001:db8::/32"], ownerBreakGlass: true });
    await waitFor(() => expect(reloaded).toBe(true));
  });

  it("explains an allowlist that would lock the admin out", async () => {
    server.use(http.put("/api/v1/admin/settings/policies", () => HttpResponse.json({ error: "would_lock_out" }, { status: 409 })));
    wrap(<OrgPoliciesSection />);
    await userEvent.type(await screen.findByLabelText("IP allowlist"), "10.9.0.0/16");
    await userEvent.click(screen.getByRole("button", { name: "Save policies" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("leaves out your own address (127.0.0.1)");
  });

  it("is hidden from members", () => {
    session.mockReturnValueOnce({ org: { ...ORG, role: "member" }, orgs: [ORG], user: { id: "m1", name: "Mia", role: "member" } } as never);
    const { container } = wrap(<OrgPoliciesSection />);
    expect(container).toBeEmptyDOMElement();
  });
});
