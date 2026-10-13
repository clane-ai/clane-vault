import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { http, HttpResponse } from "msw";
import { server } from "@/test/server";
import * as sessionModule from "@/lib/session";
import { SsoSettingsSection, type SsoSettingsView } from "./SsoSettings";

const ORG = { id: "aaaaaaaa-0000-4000-8000-000000000001", name: "Acme", slug: "acme-1", role: "owner" as const, isDefault: true };
const wrap = (ui: React.ReactNode) => render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>{ui}</QueryClientProvider>);
beforeEach(() => { vi.spyOn(sessionModule, "useSession").mockReturnValue({ user: { id: "u1", name: "Ann", email: "ann@acme.test", role: "admin" }, org: ORG } as never); });

const base: SsoSettingsView = { config: null, domains: [], redirectUri: "https://vault.acme.test/api/v1/auth/sso/callback", orgSlug: "acme-1", scopes: "openid email profile", linkedAccounts: 0 };

describe("SsoSettingsSection", () => {
  it("sets up the provider (secret write-only), tests the connection, and verifies a domain before Require SSO", async () => {
    let state: SsoSettingsView = { ...base };
    const puts: Record<string, unknown>[] = [];
    const tests: unknown[] = [];
    let txtThere = false;
    server.use(
      http.get("/api/v1/admin/settings/sso", () => HttpResponse.json(state)),
      http.put("/api/v1/admin/settings/sso", async ({ request }) => {
        const b = await request.json() as Record<string, unknown>;
        puts.push(b);
        if (b.requireSso && !state.domains.some((d) => d.verified)) return HttpResponse.json({ error: "domain_not_verified" }, { status: 409 });
        state = { ...state, config: { issuer: String(b.issuer), clientId: String(b.clientId), clientSecret: { set: true, last4: "wxyz" }, requireSso: !!b.requireSso, trustIdpMfa: !!b.trustIdpMfa, autoJoin: !!b.autoJoin, updatedAt: new Date().toISOString(), updatedBy: { id: "u1", name: "Ann" } } };
        return HttpResponse.json(state);
      }),
      http.post("/api/v1/admin/settings/sso/test", async ({ request }) => { tests.push(await request.json()); return HttpResponse.json({ ok: false, checks: [{ name: "discovery", ok: true, detail: "Found https://idp." }, { name: "metadata", ok: true, detail: "ok" }, { name: "client", ok: false, detail: "The provider rejected the client ID or secret." }] }); }),
      http.post("/api/v1/admin/settings/sso/domains", async ({ request }) => {
        const { domain } = await request.json() as { domain: string };
        state = { ...state, domains: [{ domain, verified: false, verifiedAt: null, txtRecord: { name: domain, value: "clane-vault-verify=tok123" } }] };
        return HttpResponse.json(state, { status: 201 });
      }),
      http.post("/api/v1/admin/settings/sso/domains/:d/verify", () => {
        if (!txtThere) return HttpResponse.json({ error: "txt_not_found", detail: "No TXT record \"clane-vault-verify=tok123\" on acme.test yet." }, { status: 409 });
        state = { ...state, domains: state.domains.map((d) => ({ ...d, verified: true, verifiedAt: new Date().toISOString() })) };
        return HttpResponse.json(state);
      }),
    );
    wrap(<SsoSettingsSection />);
    const sec = await screen.findByRole("region", { name: "Single sign-on" });
    expect(await within(sec).findByText("https://vault.acme.test/api/v1/auth/sso/callback")).toBeInTheDocument();
    expect(within(sec).getByText("acme-1")).toBeInTheDocument();
    // Require SSO / auto-join can't be switched on before a domain is verified (and nothing is set up yet).
    expect(within(sec).getByRole("switch", { name: "Require SSO for members" })).toBeDisabled();
    await userEvent.click(within(sec).getByRole("button", { name: "Set up" }));
    await userEvent.type(within(sec).getByLabelText("Issuer URL"), "https://login.microsoftonline.com/tid/v2.0");
    await userEvent.type(within(sec).getByLabelText("Client ID"), "app-id");
    await userEvent.click(within(sec).getByRole("button", { name: "Save" }));
    expect(within(sec).getByRole("alert")).toHaveTextContent("Enter the client secret.");
    await userEvent.type(within(sec).getByLabelText("Client secret"), "very-secret-wxyz");
    await userEvent.click(within(sec).getByRole("button", { name: "Test connection" }));
    const result = await within(sec).findByRole("list", { name: "Connection test" });
    expect(result).toHaveTextContent("Client ID and secret: The provider rejected the client ID or secret.");
    expect(tests).toEqual([{ issuer: "https://login.microsoftonline.com/tid/v2.0", clientId: "app-id", clientSecret: "very-secret-wxyz" }]);
    await userEvent.click(within(sec).getByRole("button", { name: "Save" }));
    expect(await within(sec).findByText(/secret set \(…wxyz\)/)).toBeInTheDocument();
    expect(puts[0]).toMatchObject({ issuer: "https://login.microsoftonline.com/tid/v2.0", clientId: "app-id", clientSecret: "very-secret-wxyz", requireSso: false });
    // Editing again doesn't show or resend the secret.
    await userEvent.click(within(sec).getByRole("button", { name: "Edit" }));
    expect(within(sec).getByLabelText("Client secret")).toHaveValue("");
    await userEvent.click(within(sec).getByRole("button", { name: "Save" }));
    await within(sec).findByRole("button", { name: "Edit" });
    expect(puts[1]).not.toHaveProperty("clientSecret");
    // Domain: add, see the TXT record, verify (first too early).
    await userEvent.type(within(sec).getByLabelText("Domain"), "acme.test");
    await userEvent.click(within(sec).getByRole("button", { name: "Add domain" }));
    const item = await within(sec).findByRole("listitem", { name: "acme.test" });
    expect(within(item).getByText("clane-vault-verify=tok123")).toBeInTheDocument();
    await userEvent.click(within(item).getByRole("button", { name: "Verify" }));
    expect(await within(item).findByRole("alert")).toHaveTextContent("No TXT record");
    txtThere = true;
    await userEvent.click(within(item).getByRole("button", { name: "Verify" }));
    expect(await within(sec).findByText("Verified")).toBeInTheDocument();
    const req = within(sec).getByRole("switch", { name: "Require SSO for members" });
    expect(req).toBeEnabled();
    await userEvent.click(req);
    await vi.waitFor(() => expect(puts.at(-1)).toMatchObject({ requireSso: true, issuer: "https://login.microsoftonline.com/tid/v2.0", clientId: "app-id" }));
    expect(puts.at(-1)).not.toHaveProperty("clientSecret");
    expect(await within(sec).findByText("Required")).toBeInTheDocument();
  });
});

describe("owner-only SSO options", () => {
  it("admins can't switch Require SSO or trusting the IdP's MFA", async () => {
    vi.spyOn(sessionModule, "useSession").mockReturnValue({ user: { id: "u2", name: "Adam", email: "adam@acme.test", role: "admin" }, org: { ...ORG, role: "admin" } } as never);
    server.use(http.get("/api/v1/admin/settings/sso", () => HttpResponse.json({ ...base,
      config: { issuer: "https://idp", clientId: "c", clientSecret: { set: true, last4: null }, requireSso: false, trustIdpMfa: false, autoJoin: false, updatedAt: new Date().toISOString(), updatedBy: null },
      domains: [{ domain: "acme.test", verified: true, verifiedAt: new Date().toISOString(), txtRecord: { name: "acme.test", value: "x" } }] })));
    wrap(<SsoSettingsSection />);
    const sec = await screen.findByRole("region", { name: "Single sign-on" });
    await within(sec).findByText("Verified");
    expect(within(sec).getByRole("switch", { name: "Require SSO for members" })).toBeDisabled();
    expect(within(sec).getByRole("switch", { name: "Trust the identity provider's MFA" })).toBeDisabled();
    expect(within(sec).getByRole("switch", { name: "Auto-join verified domain users" })).toBeEnabled();
  });
});
