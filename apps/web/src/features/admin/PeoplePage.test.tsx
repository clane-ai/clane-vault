import { render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { http, HttpResponse } from "msw";
import { server } from "@/test/server";
import * as sessionModule from "@/lib/session";
import PeoplePage from "./PeoplePage";

vi.mock("@/lib/clipboard", () => ({ copySecret: vi.fn(async () => undefined) }));
import { copySecret } from "@/lib/clipboard";
const ORG = { id: "aaaaaaaa-0000-4000-8000-000000000001", name: "Acme", slug: "acme", role: "admin" as const, isDefault: true };
vi.spyOn(sessionModule, "useSession").mockReturnValue({ user: { id: "a1", name: "Admin", role: "admin" }, org: ORG, orgs: [ORG] } as never);

const render_ = () => render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter><PeoplePage /></MemoryRouter></QueryClientProvider>);
const USERS = [
  { id: "a1", name: "Admin", email: "admin@clane.ai", role: "admin", status: "active", createdAt: "2026-10-01T00:00:00Z", publicKey: "" },
  { id: "m1", name: "Mia", email: "mia@clane.ai", role: "member", status: "active", createdAt: "2026-10-02T00:00:00Z", publicKey: "" },
];
const CAP = { perDay: 50, sentToday: 3, remaining: 47 };
const invite = (o: Partial<{ id: string; email: string; expired: boolean; source: string; groups: { id: string; name: string }[] }>) => ({
  id: "i1", email: "x@clane.ai", role: "member", source: "admin", groups: [], createdAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 6 * 864e5).toISOString(),
  expired: false, lastSentAt: new Date().toISOString(), resendCount: 0, invitedBy: { id: "a1", name: "Admin" }, ...o,
});
const invitesResponse = (invites: ReturnType<typeof invite>[], hostedMode = false) => HttpResponse.json({ invites, cap: CAP,
  counts: { pending: invites.filter((i) => !i.expired).length, expired: invites.filter((i) => i.expired).length }, emailConfigured: hostedMode, hostedMode });

describe("People admin page", () => {
  it("invites one address and offers Copy invite link for it", async () => {
    const invites: ReturnType<typeof invite>[] = [];
    let posted: unknown = null;
    server.use(
      http.get("/api/v1/admin/people", () => HttpResponse.json({ users: USERS })),
      http.get("/api/v1/admin/invites", () => invitesResponse(invites)),
      http.post("/api/v1/admin/invites", async ({ request }) => {
        posted = await request.json();
        invites.push(invite({ id: "i1", email: "new@clane.ai" }));
        return HttpResponse.json({ invited: true, email: "new@clane.ai", role: "member", inviteUrl: "http://localhost:5173/invite/tok123", emailed: false }, { status: 201 });
      }),
    );
    render_();
    expect(await screen.findByText("mia@clane.ai")).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText("Email"), "new@clane.ai");
    await userEvent.click(screen.getByRole("button", { name: "Invite" }));
    await waitFor(() => expect(posted).toEqual({ email: "new@clane.ai", role: "member" }));
    const row = await screen.findByRole("listitem", { name: "new@clane.ai" });
    await userEvent.click(within(row).getByRole("button", { name: "Copy invite link" }));
    expect(copySecret).toHaveBeenCalledWith("http://localhost:5173/invite/tok123", expect.any(Number));
  });

  it("disables a person after confirming", async () => {
    let disabled = "";
    server.use(
      http.get("/api/v1/admin/people", () => HttpResponse.json({ users: USERS })),
      http.post("/api/v1/admin/users/:id/disable", ({ params }) => { disabled = params.id as string; return HttpResponse.json({ ok: true }); }),
    );
    render_();
    const row = await screen.findByRole("listitem", { name: "Mia" });
    expect(within(screen.getByRole("listitem", { name: "Admin" })).queryByRole("button", { name: "Disable" })).not.toBeInTheDocument();
    await userEvent.click(within(row).getByRole("button", { name: "Disable" }));
    expect(await screen.findByText("Disable Mia?")).toBeInTheDocument();
    expect(disabled).toBe("");
    await userEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Disable" }));
    await waitFor(() => expect(disabled).toBe("m1"));
  });
});

describe("Invite people dialog", () => {
  const preview = { dryRun: true, cap: CAP, counts: { valid: 2, member: 1, invalid_email: 1 }, results: [
    { row: 1, email: "ann@clane.ai", name: null, role: "member", groups: ["Engineering"], status: "valid" },
    { row: 2, email: "bob@clane.ai", name: "Bob", role: "admin", groups: ["Engineering"], status: "valid" },
    { row: 3, email: "mia@clane.ai", name: null, role: "member", groups: ["Engineering"], status: "member" },
    { row: 4, email: "nope", name: null, role: "member", groups: [], status: "invalid_email" },
  ] };

  it("previews pasted addresses with a role and groups, sends once, and shows each row's result with its link", async () => {
    const bodies: { rows: { email: string }[]; role: string; groupIds: string[]; dryRun: boolean }[] = [];
    server.use(
      http.get("/api/v1/admin/people", () => HttpResponse.json({ users: USERS })),
      http.get("/api/v1/admin/groups", () => HttpResponse.json({ groups: [{ id: "g1", name: "Engineering", members: [] }, { id: "g2", name: "Sales", members: [] }] })),
      http.post("/api/v1/admin/invites/bulk", async ({ request }) => {
        const b = await request.json() as (typeof bodies)[number];
        bodies.push(b);
        if (b.dryRun) return HttpResponse.json(preview);
        return HttpResponse.json({ dryRun: false, cap: { ...CAP, remaining: 45 }, counts: { invited: 2, member: 1, invalid_email: 1 }, results: [
          { ...preview.results[0], status: "invited", emailed: false, inviteUrl: "http://localhost:5173/invite/tA" },
          { ...preview.results[1], status: "invited", emailed: false, inviteUrl: "http://localhost:5173/invite/tB" },
          preview.results[2], preview.results[3],
        ] });
      }),
    );
    render_();
    await userEvent.click(await screen.findByRole("button", { name: "Invite people" }));
    const dlg = await screen.findByRole("dialog");
    await userEvent.type(within(dlg).getByLabelText("Email addresses"), "ann@clane.ai, Bob <bob@clane.ai>\nmia@clane.ai\nnope");
    expect(within(dlg).getByText(/4 addresses/)).toBeInTheDocument();
    await userEvent.click(await within(dlg).findByRole("checkbox", { name: "Engineering" }));
    await userEvent.click(within(dlg).getByRole("button", { name: "Preview" }));
    expect(await within(dlg).findByText("2 will be invited")).toBeInTheDocument();
    expect(bodies[0]).toEqual({ rows: [{ email: "ann@clane.ai" }, { email: "bob@clane.ai", name: "Bob" }, { email: "mia@clane.ai" }, { email: "nope" }], role: "member", groupIds: ["g1"], dryRun: true });
    expect(within(within(dlg).getByRole("row", { name: "mia@clane.ai" })).getByText("Already a member")).toBeInTheDocument();
    expect(within(within(dlg).getByRole("row", { name: "nope" })).getByText("Invalid address")).toBeInTheDocument();
    expect(within(dlg).getByText(/47 of 50 invitations left today/)).toBeInTheDocument();
    await userEvent.click(within(dlg).getByRole("button", { name: "Send 2 invitations" }));
    expect(await within(dlg).findByText("2 invited")).toBeInTheDocument();
    expect(bodies).toHaveLength(2);
    expect(bodies[1]!.dryRun).toBe(false);
    await userEvent.click(within(dlg).getByRole("button", { name: "Copy invite link for bob@clane.ai" }));
    expect(copySecret).toHaveBeenCalledWith("http://localhost:5173/invite/tB", expect.any(Number));
    await userEvent.click(within(dlg).getByRole("button", { name: "Copy all links" }));
    expect(copySecret).toHaveBeenCalledWith("ann@clane.ai,http://localhost:5173/invite/tA\nbob@clane.ai,http://localhost:5173/invite/tB", expect.any(Number));
  });

  it("reads a CSV file and explains a refusal", async () => {
    let body: { rows: unknown[] } | null = null;
    server.use(
      http.get("/api/v1/admin/people", () => HttpResponse.json({ users: USERS })),
      http.post("/api/v1/admin/invites/bulk", async ({ request }) => { body = await request.json() as { rows: unknown[] }; return HttpResponse.json({ error: "email_required" }, { status: 409 }); }),
    );
    render_();
    await userEvent.click(await screen.findByRole("button", { name: "Invite people" }));
    const dlg = await screen.findByRole("dialog");
    await userEvent.click(within(dlg).getByRole("tab", { name: "Upload CSV" }));
    const file = new File(["email,name,role,groups\nann@clane.ai,Ann,admin,Engineering;Sales\nbob@clane.ai,,,\n"], "people.csv", { type: "text/csv" });
    await userEvent.upload(within(dlg).getByLabelText("CSV file"), file);
    expect(await within(dlg).findByText(/2 rows/)).toBeInTheDocument();
    await userEvent.click(within(dlg).getByRole("button", { name: "Preview" }));
    expect(await within(dlg).findByRole("alert")).toHaveTextContent("email isn't set up");
    expect(body!.rows).toEqual([{ email: "ann@clane.ai", name: "Ann", role: "admin", groups: "Engineering;Sales" }, { email: "bob@clane.ai" }]);
  });
});

describe("Invitations list", () => {
  it("filters, resends one, resends all pending and revokes", async () => {
    const calls: string[] = [];
    server.use(
      http.get("/api/v1/admin/people", () => HttpResponse.json({ users: USERS })),
      http.get("/api/v1/admin/invites", () => invitesResponse([
        invite({ id: "i1", email: "ann@clane.ai", groups: [{ id: "g1", name: "Engineering" }] }),
        invite({ id: "i2", email: "bob@clane.ai", source: "domain" }),
        invite({ id: "i3", email: "old@clane.ai", expired: true }),
      ])),
      http.post("/api/v1/admin/invites/:id/resend", ({ params }) => { calls.push(`resend:${params.id}`); return HttpResponse.json({ id: params.id, email: "ann@clane.ai", emailed: false, inviteUrl: "http://localhost:5173/invite/new" }); }),
      http.post("/api/v1/admin/invites/resend-all", () => { calls.push("all"); return HttpResponse.json({ resent: 1, skipped: 1, cap: CAP, results: [{ id: "i1", email: "ann@clane.ai", status: "resent" }, { id: "i2", email: "bob@clane.ai", status: "too_soon" }] }); }),
      http.delete("/api/v1/admin/invites/:id", ({ params }) => { calls.push(`revoke:${params.id}`); return new HttpResponse(null, { status: 204 }); }),
    );
    render_();
    const list = await screen.findByRole("region", { name: "Invitations" });
    expect(within(list).getByRole("listitem", { name: "ann@clane.ai" })).toHaveTextContent("Groups when they join: Engineering");
    expect(within(list).getByRole("listitem", { name: "bob@clane.ai" })).toHaveTextContent("Domain auto-join");
    expect(within(list).queryByRole("listitem", { name: "old@clane.ai" })).not.toBeInTheDocument();
    await userEvent.type(within(list).getByLabelText("Filter invitations"), "bob");
    expect(within(list).queryByRole("listitem", { name: "ann@clane.ai" })).not.toBeInTheDocument();
    await userEvent.clear(within(list).getByLabelText("Filter invitations"));
    await userEvent.click(within(list).getByRole("button", { name: "Resend invitation to ann@clane.ai" }));
    await waitFor(() => expect(calls).toEqual(["resend:i1"]));
    // The new link can be copied.
    await userEvent.click(await within(within(list).getByRole("listitem", { name: "ann@clane.ai" })).findByRole("button", { name: "Copy invite link" }));
    expect(copySecret).toHaveBeenCalledWith("http://localhost:5173/invite/new", expect.any(Number));
    await userEvent.click(within(list).getByRole("button", { name: "Resend all pending" }));
    await userEvent.click(within(list).getByRole("button", { name: "Resend all" }));
    await waitFor(() => expect(calls).toContain("all"));
    await userEvent.click(within(within(list).getByRole("listitem", { name: "bob@clane.ai" })).getByRole("button", { name: "Revoke" }));
    await userEvent.click(within(within(list).getByRole("listitem", { name: "bob@clane.ai" })).getByRole("button", { name: "Revoke" }));
    await waitFor(() => expect(calls).toContain("revoke:i2"));
  });
});

describe("Onboarding checklist", () => {
  it("shows what's left from the server's state, links each step, and can be dismissed", async () => {
    let dismissed: unknown = null;
    server.use(
      http.get("/api/v1/admin/people", () => HttpResponse.json({ users: USERS })),
      http.get("/api/v1/admin/onboarding", () => HttpResponse.json({ show: true, dismissed: false, done: 2, total: 5,
        steps: [{ id: "invite", done: true }, { id: "group", done: true }, { id: "policies", done: false }, { id: "recovery", done: false }, { id: "sso", done: false }] })),
      http.put("/api/v1/admin/onboarding", async ({ request }) => { dismissed = await request.json(); return HttpResponse.json({ dismissed: true }); }),
    );
    render_();
    const card = await screen.findByRole("region", { name: "Set up your organisation" });
    expect(card).toHaveTextContent("2/5 done");
    expect(within(card).getByRole("listitem", { name: "Invite your people" })).toHaveTextContent("(done)");
    expect(within(card).getByRole("link", { name: "Open Policies" })).toHaveAttribute("href", "/o/acme/admin/org/policies");
    expect(within(card).getByRole("link", { name: "Open Single sign-on" })).toHaveAttribute("href", "/o/acme/admin/org/sso");
    await userEvent.click(within(card).getByRole("button", { name: "Dismiss checklist" }));
    await waitFor(() => expect(dismissed).toEqual({ dismissed: true }));
    await waitFor(() => expect(screen.queryByRole("region", { name: "Set up your organisation" })).not.toBeInTheDocument());
  });
});
