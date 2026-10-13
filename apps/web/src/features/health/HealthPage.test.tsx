import { render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { http, HttpResponse } from "msw";
import { server } from "@/test/server";
import * as sessionModule from "@/lib/session";
import type { VaultRecord } from "@/features/vault/types";
import HealthPage, { TeamHealth } from "./HealthPage";

const ORG = { id: "o1", name: "Acme", slug: "acme", role: "admin", isDefault: true, policies: { breachCheckAllowed: false } };
const session = vi.spyOn(sessionModule, "useSession");
session.mockReturnValue({ org: ORG, orgs: [ORG], user: { id: "a1", name: "Ada", role: "admin" } } as never);

const rec = (id: string, title: string, password: string, updatedAt = new Date().toISOString()): VaultRecord => ({
  id, folderId: null, type: "login", revision: 1, updatedAt, deleted: false, permission: "owner", recordKey: null, body: { type: "login", title, username: `${id}@x`, password },
});
// Three records in a team folder of the org, one private ("Bank").
const inTeam = (r: VaultRecord): VaultRecord => ({ ...r, folderId: "tf" });
const RECORDS = [inTeam(rec("r1", "Figma", "figma123")), inTeam(rec("r2", "AWS", "Zq8!vT3#pL6@wX1&")), inTeam(rec("r3", "GCP", "Zq8!vT3#pL6@wX1&")), rec("r4", "Bank", "Mn5$kR9^bH2*yJ7(")];
const FOLDERS = [{ id: "tf", name: "Team", kind: "team" as const, deleted: false }];
const wrap = (ui: React.ReactNode) => render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter>{ui}</MemoryRouter></QueryClientProvider>);

describe("Password health page", () => {
  it("shows the score and filterable lists that open records, and posts only counts", async () => {
    let posted: unknown = null;
    server.use(
      http.post("/api/v1/me/health-report", async ({ request }) => { posted = await request.json(); return new HttpResponse(null, { status: 204 }); }),
      http.get("/api/v1/admin/health", () => HttpResponse.json({ members: [
        { id: "m1", name: "Mia", email: "mia@clane.ai", role: "member", status: "active", report: { score: 64, total: 20, weak: 3, reused: 4, old: 1, breached: null, reportedAt: new Date().toISOString() } },
        { id: "m2", name: "Ben", email: "ben@clane.ai", role: "member", status: "active", report: null },
      ] })),
    );
    const onOpen = vi.fn();
    wrap(<HealthPage records={RECORDS} folders={FOLDERS} onOpen={onOpen} />);
    expect(screen.getByTestId("health-score")).toHaveTextContent("25");
    const list = screen.getByRole("list", { name: "Records with issues" });
    expect(within(list).getAllByRole("button")).toHaveLength(3);
    await userEvent.click(screen.getByRole("button", { name: /^Reused/ }));
    expect(within(screen.getByRole("list", { name: "Records with issues" })).getAllByRole("button").map((b) => b.textContent)).toEqual([expect.stringContaining("AWS"), expect.stringContaining("GCP")]);
    await userEvent.click(screen.getByRole("button", { name: /^Weak/ }));
    await userEvent.click(within(screen.getByRole("list", { name: "Records with issues" })).getByRole("button", { name: /Figma/ }));
    expect(onOpen).toHaveBeenCalledWith("r1");
    // The page covers every record; the admins get the org's part only (the private "Bank" stays out).
    await waitFor(() => expect(posted).toEqual({ score: 0, total: 3, weak: 1, reused: 2, old: 0, breached: null }));
    expect(JSON.stringify(posted)).not.toMatch(/figma|Zq8|AWS|Bank/i);
    // The org turned the breach check off.
    expect(screen.getByRole("switch", { name: "Check against known breaches" })).toBeDisabled();
    // The team table moved to Admin → Password health: this page is the viewer's own vault only, even for admins.
    expect(screen.queryByRole("region", { name: "Team password health" })).not.toBeInTheDocument();
  });

  it("Admin → Password health: each member's counts only, each row opening the member's page", async () => {
    server.use(http.get("/api/v1/admin/health", () => HttpResponse.json({ members: [
      { id: "m1", name: "Mia", email: "mia@clane.ai", role: "member", status: "active", report: { score: 64, total: 20, weak: 3, reused: 4, old: 1, breached: null, reportedAt: new Date().toISOString() } },
      { id: "m2", name: "Ben", email: "ben@clane.ai", role: "member", status: "active", report: null },
    ] })));
    wrap(<TeamHealth />);
    const team = await screen.findByRole("region", { name: "Team password health" });
    await waitFor(() => expect(within(within(team).getByRole("row", { name: "Mia" })).getByText("64")).toBeInTheDocument());
    expect(within(within(team).getByRole("row", { name: "Ben" })).getByText("No report yet")).toBeInTheDocument();
    expect(within(team).getByRole("link", { name: "Mia" })).toHaveAttribute("href", "/o/acme/admin/people/m1");
  });

  it("members don't see the team table", async () => {
    session.mockReturnValue({ org: { ...ORG, role: "member" }, orgs: [ORG], user: { id: "m1", name: "Mia", role: "member" } } as never);
    wrap(<HealthPage records={[]} onOpen={vi.fn()} />);
    expect(await screen.findByText("No issues found. Nice work.")).toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "Team password health" })).not.toBeInTheDocument();
  });
});
