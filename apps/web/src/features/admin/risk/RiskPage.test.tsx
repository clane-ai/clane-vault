import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { MemoryRouter, useLocation } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { http, HttpResponse } from "msw";
import { server } from "@/test/server";
import * as sessionModule from "@/lib/session";
import { toast } from "sonner";
import RiskPage from "./RiskPage";
import type { RiskOverview, RiskMembers } from "./model";

const ORG = { id: "o1", name: "Acme", slug: "acme", role: "owner", isDefault: true };
vi.spyOn(sessionModule, "useSession").mockReturnValue({ org: ORG, orgs: [ORG], user: { id: "a1", name: "Ada", role: "admin" } } as never);
function Where() { const l = useLocation(); return <output data-testid="where">{l.pathname + l.search}</output>; }
const wrap = (at = "/o/acme/admin/risk") => render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter initialEntries={[at]}><RiskPage /><Where /></MemoryRouter></QueryClientProvider>);

const overview = (over: Partial<RiskOverview> = {}): RiskOverview => ({
  generatedAt: "2026-10-12T09:00:00Z", windowDays: 30, instanceAdmin: false,
  score: { value: 62, benchmarks: 55, health: 78, weights: { benchmarks: 0.7, health: 0.3 }, counted: { earned: 11, possible: 20 } },
  utilisation: { members: 4, withRecords: 3, active30d: 2, invitations: { accepted: 4, pending: 2 }, twoFactor: { required: true, members: 4, idpMfaSessions: 1 }, recoveryKit: 1, healthReported30d: 3 },
  benchmarks: [
    { key: "backup_admin", title: "At least two owners or admins", severity: "high", status: "critical", detail: "Only one active owner or admin.", passing: false },
    { key: "auto_lock", title: "Auto-lock after 15 minutes or less", severity: "medium", status: "completed", detail: "Vaults lock after 10 idle minutes.", passing: true },
    { key: "ip_allowlist", title: "IP allowlist (optional)", severity: "low", status: "critical", detail: "Any network.", passing: false },
    { key: "sso", title: "Single sign-on with a verified domain", severity: "medium", status: "ignored", detail: "Not set up.", passing: false },
    { key: "backups", title: "Server backups ran in the last 48 hours", severity: "high", status: "unknown", detail: "Only the server's admins can see backups: ask your server admin.", passing: null },
  ],
  alerts: [
    { action: "admin.reset_2fa", label: "2FA resets", scope: "org", current: 3, previous: 1, trend: 200 },
    { action: "auth.login_failed", label: "Failed sign-ins", scope: "account", current: 5, previous: 0, trend: null },
    { action: "link.create", label: "One-time links created", scope: "org", current: 1, previous: 4, trend: -75 },
    { action: "org.transfer", label: "Ownership transferred", scope: "org", current: 0, previous: 0, trend: 0 },
  ],
  health: { members: 4, reported: 3, reported30d: 3, averageScore: 78, atRisk: 1, atRiskBelow: 60, passwords: 120, weak: 7, reused: 4, old: 9, breached: 2, breachCheckMembers: 2 },
  ...over,
});
const members: RiskMembers = {
  members: [
    { id: "u1", name: "Ada", email: "ada@acme.test", role: "owner", joinedAt: "2026-01-01T00:00:00Z", records: { owned: 3, canOpen: 5 }, lastSeen: new Date().toISOString(), active30d: true, idpMfa: true, recoveryKit: true, health: { score: 90, weak: 0, reused: 0, old: 1, breached: 0, reportedAt: new Date().toISOString(), recent: true } },
    { id: "u2", name: "Bob", email: "bob@acme.test", role: "member", joinedAt: "2026-01-01T00:00:00Z", records: { owned: 0, canOpen: 0 }, lastSeen: null, active30d: false, idpMfa: false, recoveryKit: false, health: null },
  ],
  invites: [{ email: "new@acme.test", role: "member", createdAt: "2026-10-10T00:00:00Z", expiresAt: "2026-10-17T00:00:00Z" }],
};

describe("Risk dashboard", () => {
  it("shows the score with its explanation, utilisation, benchmarks by group, alerts and password health", async () => {
    server.use(http.get("/api/v1/admin/risk", () => HttpResponse.json(overview())));
    wrap();
    expect(await screen.findByTestId("risk-score")).toHaveTextContent("62");
    expect(screen.getByText("How is this computed?")).toBeInTheDocument();
    expect(screen.getByText(/11 of 20 points = 55/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Members with records: 3 of 4" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Two-step sign-in: 100% required" })).toBeInTheDocument();
    const critical = screen.getByRole("group", { name: "Critical (3)" });
    expect(within(critical).getByRole("listitem", { name: "At least two owners or admins" })).toBeInTheDocument();
    expect(within(critical).getByText(/ask your server admin/)).toBeInTheDocument();
    // Not an instance admin: no link to the server's backups.
    expect(within(critical).queryByRole("link", { name: /Server backups/ })).not.toBeInTheDocument();
    expect(within(screen.getByRole("group", { name: "Completed (1)" })).getByText("Auto-lock after 15 minutes or less")).toBeInTheDocument();
    expect(within(screen.getByRole("group", { name: "Ignored (1)" })).getByRole("button", { name: "Restore benchmark: Single sign-on with a verified domain" })).toBeInTheDocument();
    const health = screen.getByRole("region", { name: "Password health summary" });
    expect(within(health).getByText("120")).toBeInTheDocument();
  });

  it("remediation buttons open the exact settings page", async () => {
    server.use(http.get("/api/v1/admin/risk", () => HttpResponse.json(overview())));
    wrap();
    expect(await screen.findByRole("link", { name: "Fix: At least two owners or admins" })).toHaveAttribute("href", "/o/acme/admin/people");
    expect(screen.getByRole("link", { name: "Fix: IP allowlist (optional)" })).toHaveAttribute("href", "/o/acme/admin/org/policies");
    expect(screen.getByRole("link", { name: "Review: Auto-lock after 15 minutes or less" })).toHaveAttribute("href", "/o/acme/admin/org/policies");
    expect(screen.getByRole("link", { name: "Review: Single sign-on with a verified domain" })).toHaveAttribute("href", "/o/acme/admin/org/sso");
  });

  it("ignores and restores a benchmark", async () => {
    let calls: string[] = [];
    server.use(
      http.get("/api/v1/admin/risk", () => HttpResponse.json(overview())),
      http.post("/api/v1/admin/risk/benchmarks/:key/ignore", ({ params }) => {
        calls.push(`ignore ${params.key}`);
        const o = overview();
        return HttpResponse.json({ ...o, benchmarks: o.benchmarks.map((b) => (b.key === params.key ? { ...b, status: "ignored" } : b)) });
      }),
      http.delete("/api/v1/admin/risk/benchmarks/:key/ignore", ({ params }) => { calls.push(`restore ${params.key}`); return new HttpResponse(null, { status: 204 }); }),
    );
    wrap();
    await userEvent.click(await screen.findByRole("button", { name: "Ignore benchmark: IP allowlist (optional)" }));
    await waitFor(() => expect(screen.getByRole("group", { name: "Ignored (2)" })).toBeInTheDocument());
    expect(calls).toEqual(["ignore ip_allowlist"]);
    calls = [];
    await userEvent.click(screen.getByRole("button", { name: "Restore benchmark: Single sign-on with a verified domain" }));
    await waitFor(() => expect(calls).toEqual(["restore sso"]));
  });

  it("drills down from a tile to the members, filters, and exports CSV", async () => {
    let exported = "";
    server.use(
      http.get("/api/v1/admin/risk", () => HttpResponse.json(overview())),
      http.get("/api/v1/admin/risk/members", () => HttpResponse.json(members)),
      http.get("/api/v1/admin/risk/members.csv", ({ request }) => { exported = new URL(request.url).search; return new HttpResponse("name\r\n", { headers: { "content-type": "text/csv" } }); }),
    );
    const createObjectURL = vi.fn(() => "blob:x");
    Object.assign(URL, { createObjectURL, revokeObjectURL: vi.fn() });
    wrap();
    await userEvent.click(await screen.findByRole("button", { name: "Members with records: 3 of 4" }));
    expect(screen.getByTestId("where")).toHaveTextContent("/o/acme/admin/risk?view=records");
    const drill = await screen.findByRole("region", { name: "Members with records: members" });
    expect(await within(drill).findByRole("row", { name: "Ada" })).toBeInTheDocument();
    expect(within(drill).getByRole("row", { name: "Bob" })).toBeInTheDocument();
    expect(within(drill).getByRole("link", { name: "Ada" })).toHaveAttribute("href", "/o/acme/admin/people/u1");
    await userEvent.click(within(drill).getByRole("button", { name: "Without records" }));
    expect(within(drill).queryByRole("row", { name: "Ada" })).not.toBeInTheDocument();
    expect(within(drill).getByRole("row", { name: "Bob" })).toBeInTheDocument();
    await userEvent.type(within(drill).getByRole("textbox", { name: "Search people" }), "zzz");
    expect(within(drill).getByText("No members match.")).toBeInTheDocument();
    await userEvent.click(within(drill).getByRole("button", { name: "Export CSV" }));
    await waitFor(() => expect(createObjectURL).toHaveBeenCalled());
    expect(exported).toBe("?tile=records&has=no");
  });

  it("invitations: lists pending ones and resends them all through People's resend", async () => {
    let resent = 0;
    server.use(
      http.get("/api/v1/admin/risk", () => HttpResponse.json(overview())),
      http.get("/api/v1/admin/risk/members", () => HttpResponse.json(members)),
      http.post("/api/v1/admin/invites/resend-all", () => { resent++; return HttpResponse.json({ resent: 1, skipped: 0, results: [] }); }),
    );
    const ok = vi.spyOn(toast, "success");
    wrap("/o/acme/admin/risk?view=invites");
    const drill = await screen.findByRole("region", { name: "Invitations accepted: members" });
    expect(await within(drill).findByText("new@acme.test")).toBeInTheDocument();
    await userEvent.click(within(drill).getByRole("button", { name: "Resend all pending invites" }));
    await waitFor(() => expect(resent).toBe(1));
    await waitFor(() => expect(ok).toHaveBeenCalledWith("Sent 1 invitation again"));
  });

  it("sorts alerts, links org alerts to the filtered event log, and shows who", async () => {
    server.use(
      http.get("/api/v1/admin/risk", () => HttpResponse.json(overview())),
      http.get("/api/v1/admin/risk/alerts/:action/members", ({ params }) => HttpResponse.json({ action: params.action, label: "2FA resets", scope: "org", windowDays: 30,
        people: [{ user: { id: "u2", name: "Bob", email: "bob@acme.test" }, asActor: 0, asTarget: 3, lastAt: new Date().toISOString() }] })),
    );
    wrap();
    const table = await screen.findByRole("table");
    const labels = () => within(table).getAllByRole("row").slice(1).map((r) => r.getAttribute("aria-label"));
    expect(labels()).toEqual(["Failed sign-ins", "2FA resets", "One-time links created"]);
    await userEvent.click(within(table).getByRole("button", { name: "Trend" }));
    expect(labels()).toEqual(["Failed sign-ins", "2FA resets", "One-time links created"]);
    await userEvent.click(within(table).getByRole("button", { name: "Trend" }));
    expect(labels()).toEqual(["One-time links created", "2FA resets", "Failed sign-ins"]);
    expect(within(table).getByRole("row", { name: "2FA resets" })).toHaveTextContent("+200%");
    expect(within(table).getByRole("row", { name: "Failed sign-ins" })).toHaveTextContent("New");
    expect(within(table).getByRole("link", { name: "2FA resets" })).toHaveAttribute("href", "/o/acme/admin/events?action=admin.reset_2fa");
    // Account-level alerts aren't in the org's event log: no link there.
    expect(within(table).queryByRole("link", { name: "Failed sign-ins" })).not.toBeInTheDocument();
    // Alerts with no events in either window are folded away until asked for.
    expect(within(table).queryByRole("row", { name: "Ownership transferred" })).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Show all 4 alerts (1 with no events)" }));
    expect(within(table).getByRole("row", { name: "Ownership transferred" })).toBeInTheDocument();
    await userEvent.click(within(table).getByRole("button", { name: "People: 2FA resets" }));
    expect(await within(table).findByText("3× to them")).toBeInTheDocument();
  });

  it("Download report prints a plain report", async () => {
    server.use(http.get("/api/v1/admin/risk", () => HttpResponse.json(overview())));
    let seen = "";
    const print = vi.fn(() => { seen = document.querySelector("[data-testid=risk-print]")?.textContent ?? ""; window.dispatchEvent(new Event("afterprint")); });
    Object.assign(window, { print });
    wrap();
    await userEvent.click(await screen.findByRole("button", { name: "Download report" }));
    expect(print).toHaveBeenCalled();
    expect(seen).toContain("Security risk report");
    expect(seen).toContain("Score: 62 / 100");
    await waitFor(() => expect(document.querySelector("[data-testid=risk-print]")).toBeNull());
  });
});
