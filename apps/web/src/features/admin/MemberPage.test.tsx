import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, useLocation } from "react-router";
import { describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { http, HttpResponse } from "msw";
import { server } from "@/test/server";
import * as sessionModule from "@/lib/session";
import type { VaultFolder } from "@/features/vault/types";
import MemberPage from "./MemberPage";
import GroupPage from "@/features/groups/GroupPage";

const ORG = { id: "o1", name: "Acme", slug: "acme", role: "admin", isDefault: true };
vi.spyOn(sessionModule, "useSession").mockReturnValue({ org: ORG, orgs: [ORG], user: { id: "a1", name: "Ada", role: "admin" }, generation: () => 0 } as never);
function Where() { const l = useLocation(); return <output data-testid="where">{l.pathname + l.search}</output>; }
const wrap = (ui: React.ReactNode) => render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter initialEntries={["/o/acme/admin"]}>{ui}<Where /></MemoryRouter></QueryClientProvider>);
const folder = (id: string, name: string) => ({ id, name, kind: "team", deleted: false }) as unknown as VaultFolder;

const detail = {
  member: { id: "m1", name: "Mia", email: "mia@acme.test", role: "member", status: "active", joinedAt: "2026-10-01T00:00:00Z", twoFactor: true },
  groups: [{ id: "g1", name: "Ops" }],
  folders: [{ id: "f1", permission: "edit", direct: null, owner: false }, { id: "f2", permission: "view", direct: "view", owner: false }],
  health: { score: 64, total: 20, weak: 3, reused: 4, old: 1, breached: null, reportedAt: "2026-10-07T00:00:00Z" },
  recovery: { enabled: true, acknowledged: true, escrowed: true, pendingRequest: false },
};

describe("Admin → People → member", () => {
  it("shows role, groups, team folders (names when the admin can open them), health and recovery; links to their events", async () => {
    server.use(http.get("/api/v1/admin/members/m1", () => HttpResponse.json(detail)));
    wrap(<MemberPage userId="m1" folders={[folder("f1", "Infrastructure")]} />);
    expect(await screen.findByRole("heading", { level: 1, name: "Mia" })).toBeInTheDocument();
    expect(within(screen.getByRole("region", { name: "Groups" })).getByRole("link", { name: "Ops" })).toHaveAttribute("href", "/o/acme/admin/groups/g1");
    const folders = screen.getByRole("region", { name: "Team folders" });
    expect(folders).toHaveTextContent("Infrastructure");
    expect(folders).toHaveTextContent("via group");
    expect(folders).toHaveTextContent("A folder you aren't in");
    expect(screen.getByRole("region", { name: "Password health" })).toHaveTextContent("64");
    expect(screen.getByRole("region", { name: "Account recovery" })).toHaveTextContent("escrowed to this organisation's admins");
    expect(screen.getByRole("link", { name: "Their events" })).toHaveAttribute("href", "/o/acme/admin/events?actor=m1");
  });

  it("acts on the member after confirming; removing goes back to People", async () => {
    let removed = false;
    server.use(http.get("/api/v1/admin/members/m1", () => HttpResponse.json(detail)), http.delete("/api/v1/admin/members/m1", () => { removed = true; return new HttpResponse(null, { status: 204 }); }));
    wrap(<MemberPage userId="m1" folders={[]} />);
    await userEvent.click(await screen.findByRole("button", { name: "Remove" }));
    await userEvent.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Remove" }));
    await waitFor(() => expect(removed).toBe(true));
    await waitFor(() => expect(screen.getByTestId("where")).toHaveTextContent("/o/acme/admin/people"));
  });

  it("someone not in the organisation: says so", async () => {
    server.use(http.get("/api/v1/admin/members/zz", () => HttpResponse.json({ error: "not_found" }, { status: 404 })));
    wrap(<MemberPage userId="zz" folders={[]} />);
    expect(await screen.findByText(/isn't in this organisation/)).toBeInTheDocument();
  });
});

describe("Admin → Groups → group", () => {
  it("lists members (to their pages), shared folders and who waits for a key; removes a member", async () => {
    let removed = "";
    server.use(
      http.get("/api/v1/admin/groups/g1", () => HttpResponse.json({ group: { id: "g1", name: "Ops", createdAt: "2026-10-01T00:00:00Z" },
        members: [{ id: "m1", name: "Mia", email: "mia@acme.test", addedAt: "2026-10-02T00:00:00Z" }],
        folders: [{ id: "f1", permission: "edit", sharedAt: "2026-10-02T00:00:00Z" }],
        pending: [{ folderId: "f1", userId: "m1", name: "Mia", email: "mia@acme.test", declined: false }] })),
      http.delete("/api/v1/admin/groups/g1/members/:uid", ({ params }) => { removed = String(params.uid); return new HttpResponse(null, { status: 204 }); }),
      http.get("/api/v1/users", () => HttpResponse.json({ users: [] })),
    );
    wrap(<GroupPage groupId="g1" folders={[folder("f1", "Infrastructure")]} />);
    expect(await screen.findByRole("heading", { level: 1, name: "Ops" })).toBeInTheDocument();
    expect(within(screen.getByRole("region", { name: "Members" })).getByRole("link", { name: "Mia" })).toHaveAttribute("href", "/o/acme/admin/people/m1");
    expect(screen.getByRole("region", { name: "Folders shared with this group" })).toHaveTextContent("InfrastructureCan edit");
    expect(screen.getByRole("region", { name: "Waiting for access" })).toHaveTextContent("Waiting");
    await userEvent.click(screen.getByRole("button", { name: "Remove Mia from Ops" }));
    await waitFor(() => expect(removed).toBe("m1"));
  });
});
