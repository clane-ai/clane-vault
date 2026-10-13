import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { MemoryRouter, useLocation } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { http, HttpResponse } from "msw";
import { server } from "@/test/server";
import * as sessionModule from "@/lib/session";
import EventLogPage, { eventQuery } from "./EventLogPage";

const ORG = { id: "o1", name: "Acme", slug: "acme", role: "admin", isDefault: true };
vi.spyOn(sessionModule, "useSession").mockReturnValue({ org: ORG, orgs: [ORG], user: { id: "a1", name: "Ada", role: "admin" } } as never);
function Where() { const l = useLocation(); return <output data-testid="where">{l.pathname + l.search}</output>; }
const wrap = (ui: React.ReactNode, at = "/admin/events") => render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter initialEntries={[at]}>{ui}<Where /></MemoryRouter></QueryClientProvider>);
const ev = (id: string, action: string, actor = "Ada") => ({ id, at: "2026-10-08T09:00:00Z", action, actor: { id: "a1", name: actor, email: "ada@clane.ai" }, target: null, recordId: null, folderId: null, ip: "10.0.0.1", meta: null });

describe("Event log", () => {
  it("lists events, filters by action and person, pages, and exports CSV", async () => {
    const queries: string[] = [];
    let exported = "";
    server.use(
      http.get("/api/v1/admin/people", () => HttpResponse.json({ users: [{ id: "a1", name: "Ada", email: "ada@clane.ai" }, { id: "m1", name: "Mia", email: "mia@clane.ai" }], invites: [] })),
      http.get("/api/v1/admin/events/actions", () => HttpResponse.json({ actions: ["group.create", "org.leave"] })),
      http.get("/api/v1/admin/events", ({ request }) => {
        const q = new URL(request.url).searchParams;
        queries.push(q.toString());
        if (q.get("before") === "5") return HttpResponse.json({ events: [ev("4", "org.leave", "Mia")], nextBefore: null });
        return HttpResponse.json({ events: [ev("6", "group.create"), ev("5", "group.create")], nextBefore: q.get("action") ? null : "5" });
      }),
      http.get("/api/v1/admin/events/export.csv", ({ request }) => { exported = new URL(request.url).search; return new HttpResponse("id,at\r\n", { headers: { "content-type": "text/csv" } }); }),
    );
    const createObjectURL = vi.fn(() => "blob:x");
    Object.assign(URL, { createObjectURL, revokeObjectURL: vi.fn() });
    wrap(<EventLogPage />);
    const table = await screen.findByRole("table");
    expect(within(table).getAllByText("group.create")).toHaveLength(2);
    await userEvent.click(screen.getByRole("button", { name: "Load more" }));
    expect(await within(table).findByText("org.leave")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("combobox", { name: "Action" }));
    await userEvent.click(await screen.findByRole("option", { name: "group.*" }));
    await waitFor(() => expect(queries).toContain("action=group."));
    await userEvent.click(screen.getByRole("combobox", { name: "Who" }));
    await userEvent.click(await screen.findByRole("option", { name: "Mia" }));
    await waitFor(() => expect(queries).toContain("actor=m1&action=group."));
    // The filters are in the address, so the view can be bookmarked.
    expect(screen.getByTestId("where")).toHaveTextContent("/admin/events?actor=m1&action=group.");

    await userEvent.click(screen.getByRole("button", { name: "Export CSV" }));
    await waitFor(() => expect(createObjectURL).toHaveBeenCalled());
    expect(exported).toBe("?actor=m1&action=group.");
  });

  it("opens with the filters from the address (a bookmark, or a member's page linking to their events)", async () => {
    const queries: string[] = [];
    server.use(
      http.get("/api/v1/admin/people", () => HttpResponse.json({ users: [{ id: "m1", name: "Mia", email: "mia@clane.ai" }], invites: [] })),
      http.get("/api/v1/admin/events/actions", () => HttpResponse.json({ actions: [] })),
      http.get("/api/v1/admin/events", ({ request }) => { queries.push(new URL(request.url).searchParams.toString()); return HttpResponse.json({ events: [], nextBefore: null }); }),
    );
    wrap(<EventLogPage />, "/admin/events?actor=m1");
    await waitFor(() => expect(queries).toContain("actor=m1"));
    expect(await screen.findByRole("combobox", { name: "Who" })).toHaveTextContent("Mia");
  });

  it("turns date filters into whole days", () => {
    const q = new URLSearchParams(eventQuery({ actor: "", action: "", from: "2026-10-01", to: "2026-10-02" }));
    expect(new Date(q.get("from")!).getDate()).toBe(1);
    expect(new Date(q.get("to")!).getHours()).toBe(23);
  });
});
