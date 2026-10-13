import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { http, HttpResponse } from "msw";
import { server } from "@/test/server";
import * as sessionModule from "@/lib/session";
import { DomainJoinSection, type DomainJoinView } from "./DomainJoinSection";
import { JoinRequest } from "@/features/auth/Join";

const ORG = { id: "aaaaaaaa-0000-4000-8000-000000000001", name: "Acme", slug: "acme-1", role: "owner" as const, isDefault: true };
const wrap = (ui: React.ReactNode) => render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter>{ui}</MemoryRouter></QueryClientProvider>);
const view = (o: Partial<DomainJoinView> = {}): DomainJoinView => ({ enabled: false, role: "member", groups: [], domains: [], emailConfigured: true, joinUrl: "http://localhost:5173/join", canEdit: true, updatedAt: null, updatedBy: null, ...o });

describe("Email domain auto-join settings", () => {
  it("can't be switched on without a verified domain", async () => {
    vi.spyOn(sessionModule, "useSession").mockReturnValue({ user: { id: "u1" }, org: ORG } as never);
    server.use(http.get("/api/v1/admin/settings/domain-join", () => HttpResponse.json(view({ domains: [{ domain: "acme.test", verified: false }] }))));
    wrap(<DomainJoinSection />);
    const sw = await screen.findByRole("switch", { name: "Let people with a verified work address join" });
    expect(sw).toBeDisabled();
    expect(screen.getByRole("note")).toHaveTextContent("Verify a domain above first");
    vi.restoreAllMocks();
  });

  it("the owner turns it on with groups; the join page link appears", async () => {
    vi.spyOn(sessionModule, "useSession").mockReturnValue({ user: { id: "u1" }, org: ORG } as never);
    let state = view({ domains: [{ domain: "acme.test", verified: true }] });
    const puts: unknown[] = [];
    server.use(
      http.get("/api/v1/admin/settings/domain-join", () => HttpResponse.json(state)),
      http.get("/api/v1/admin/groups", () => HttpResponse.json({ groups: [{ id: "g1", name: "Everyone", members: [] }] })),
      http.put("/api/v1/admin/settings/domain-join", async ({ request }) => {
        const b = await request.json() as { enabled: boolean; groupIds: string[] };
        puts.push(b);
        state = { ...state, enabled: b.enabled, groups: b.groupIds.map((id) => ({ id, name: "Everyone" })) };
        return HttpResponse.json(state);
      }),
    );
    wrap(<DomainJoinSection />);
    const section = await screen.findByRole("region", { name: "Email domain auto-join" });
    expect(within(section).getByRole("list", { name: "Verified domains" })).toHaveTextContent("acme.test");
    await userEvent.click(await within(section).findByRole("checkbox", { name: "Everyone" }));
    await userEvent.click(within(section).getByRole("switch", { name: "Let people with a verified work address join" }));
    await waitFor(() => expect(puts).toEqual([{ enabled: true, groupIds: ["g1"] }]));
    expect(await within(section).findByText("http://localhost:5173/join")).toBeInTheDocument();
    vi.restoreAllMocks();
  });

  it("admins see it but can't change it", async () => {
    vi.spyOn(sessionModule, "useSession").mockReturnValue({ user: { id: "u1" }, org: { ...ORG, role: "admin" } } as never);
    server.use(http.get("/api/v1/admin/settings/domain-join", () => HttpResponse.json(view({ canEdit: false, enabled: true, domains: [{ domain: "acme.test", verified: true }] }))));
    wrap(<DomainJoinSection />);
    expect(await screen.findByRole("switch", { name: "Let people with a verified work address join" })).toBeDisabled();
    expect(screen.getByText("Only the organisation's owner can change this.")).toBeInTheDocument();
    vi.restoreAllMocks();
  });
});

describe("Join with a work email", () => {
  it("asks for a link and gives the same answer whatever happens", async () => {
    let posted: unknown = null;
    server.use(http.post("/api/v1/auth/domain-join", async ({ request }) => { posted = await request.json(); return HttpResponse.json({ ok: true }, { status: 202 }); }));
    wrap(<JoinRequest />);
    await userEvent.type(screen.getByLabelText("Work email"), "new@acme.test");
    await userEvent.click(screen.getByRole("button", { name: "Email me a link" }));
    expect(await screen.findByRole("status")).toHaveTextContent("If your organisation lets people with new@acme.test's domain join, we've emailed you a link.");
    expect(posted).toEqual({ email: "new@acme.test" });
  });
});
