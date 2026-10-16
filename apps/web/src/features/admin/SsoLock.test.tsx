import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { http, HttpResponse } from "msw";
import { server } from "@/test/server";
import * as sessionModule from "@/lib/session";
import { SsoSettingsSection } from "@/features/settings/SsoSettings";

const ORG = { id: "o1", name: "Acme", slug: "acme", role: "owner", isDefault: true };
vi.spyOn(sessionModule, "useSession").mockReturnValue({ org: ORG, orgs: [ORG], user: { id: "a1", name: "Ada", role: "admin" } } as never);
const view = { config: null, domains: [], redirectUri: "http://x/cb", orgSlug: "acme", scopes: "openid", linkedAccounts: 0 };
const wrap = () => render(<QueryClientProvider client={new QueryClient()}><MemoryRouter><SsoSettingsSection /></MemoryRouter></QueryClientProvider>);

describe("SSO settings and the plan", () => {
  it("shows the lock line and no form when SSO is off for the plan", async () => {
    server.use(http.get("/api/v1/org/plan", () => HttpResponse.json({ entitlements: { features: { sso: false } } })),
      http.get("/api/v1/admin/settings/sso", () => HttpResponse.json(view)));
    wrap();
    expect(await screen.findByText("Available on the Business plan.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /set up/i })).toBeNull();
  });
  it("shows the page when billing is off (404)", async () => {
    server.use(http.get("/api/v1/org/plan", () => HttpResponse.json({ error: "not_found" }, { status: 404 })),
      http.get("/api/v1/admin/settings/sso", () => HttpResponse.json(view)));
    wrap();
    expect(await screen.findByRole("button", { name: /set up/i })).toBeInTheDocument();
    expect(screen.queryByText("Available on the Business plan.")).toBeNull();
  });
});
