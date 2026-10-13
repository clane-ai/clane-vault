import { MemoryRouter } from "react-router";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { http, HttpResponse } from "msw";
import { server } from "@/test/server";
import { api, forOrg } from "@/lib/api";
import * as sessionModule from "@/lib/session";
import { RegisterForm } from "@/features/auth/Register";
import PeoplePage from "@/features/admin/PeoplePage";
import { OrgSwitcher } from "./OrgSwitcher";

// Security review of multi-org: pinned org per operation, hosted sign-up code, generic invites, and the
// "joining another org turns admin recovery off" confirmation.
const ORG_A = { id: "aaaaaaaa-0000-4000-8000-000000000001", name: "Alpha", slug: "alpha", role: "admin" as const, isDefault: true };
const wrap = (ui: React.ReactNode) => render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter>{ui}</MemoryRouter></QueryClientProvider>);

describe("pinned org per operation", () => {
  it("a request pinned to org A keeps X-Org-Id A after the active org changes", async () => {
    const seen: (string | null)[] = [];
    server.use(http.get("/api/v1/sync", ({ request }) => { seen.push(request.headers.get("x-org-id")); return HttpResponse.json({}); }));
    api.setOrg("org-a");
    const pinned = api.pinned();
    api.setOrg("org-b");
    await pinned.get("/sync");
    await api.get("/sync");
    await forOrg(null).get("/sync");
    expect(seen).toEqual(["org-a", "org-b", null]);
    api.setOrg(null);
  });
});

describe("hosted sign-up", () => {
  it("asks for the emailed code and sends it with the account", async () => {
    const onSubmit = vi.fn();
    const onSendCode = vi.fn(async () => undefined);
    render(<RegisterForm email="sara@x.io" onSubmit={onSubmit} onSendCode={onSendCode} />);
    await userEvent.type(screen.getByLabelText("Your name"), "Sara");
    await userEvent.type(screen.getByLabelText("Master password"), "a long master password");
    await userEvent.type(screen.getByLabelText("Repeat master password"), "a long master password");
    await userEvent.click(screen.getByRole("button", { name: "Create account" }));
    expect(screen.getByRole("alert")).toHaveTextContent("6-digit code");
    expect(onSubmit).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole("button", { name: "Email me a code" }));
    expect(onSendCode).toHaveBeenCalledOnce();
    expect(await screen.findByText(/Sent to sara@x.io/)).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText("Code from your email"), "123456");
    await userEvent.click(screen.getByRole("button", { name: "Create account" }));
    expect(onSubmit).toHaveBeenCalledWith({ name: "Sara", password: "a long master password", emailCode: "123456" });
  });
});

describe("invites", () => {
  it("hosted: an invite shows only that it was emailed (no link), whoever the address is", async () => {
    vi.spyOn(sessionModule, "useSession").mockReturnValue({ user: { id: "a1", name: "Admin", role: "admin" }, org: ORG_A, applyOrgs: vi.fn() } as never);
    const invites: { id: string; email: string; role: string; expiresAt: string; createdAt: string }[] = [];
    server.use(
      http.get("/api/v1/me/orgs", () => HttpResponse.json({ orgs: [ORG_A], invitations: [], allowOrgCreation: false, instanceAdmin: false, hostedMode: true })),
      http.get("/api/v1/admin/people", () => HttpResponse.json({ users: [], invites })),
      // The invitations list (docs/provisioning.md) says the server is hosted.
      http.get("/api/v1/admin/invites", () => HttpResponse.json({ invites: invites.map((i) => ({ ...i, source: "admin", groups: [], expired: false, lastSentAt: i.createdAt, resendCount: 0, invitedBy: null })),
        cap: { perDay: 50, sentToday: invites.length, remaining: 50 - invites.length }, counts: { pending: invites.length, expired: 0 }, emailConfigured: true, hostedMode: true })),
      http.post("/api/v1/admin/invites", async ({ request }) => {
        const b = await request.json() as { email: string };
        invites.push({ id: crypto.randomUUID(), email: b.email, role: "member", expiresAt: new Date(Date.now() + 6e8).toISOString(), createdAt: new Date().toISOString() });
        return HttpResponse.json({ invited: true, email: b.email, role: "member", emailed: true }, { status: 201 });
      }),
    );
    wrap(<PeoplePage />);
    await userEvent.type(await screen.findByLabelText("Email"), "someone@x.io");
    await userEvent.click(screen.getByRole("button", { name: "Invite" }));
    const row = await screen.findByRole("listitem", { name: "someone@x.io" });
    expect(within(row).getByText("Sent by email")).toBeInTheDocument();
    expect(within(row).queryByRole("button", { name: "Copy invite link" })).not.toBeInTheDocument();
    vi.restoreAllMocks();
  });

  it("explains a cooldown after a decline", async () => {
    vi.spyOn(sessionModule, "useSession").mockReturnValue({ user: { id: "a1", name: "Admin", role: "admin" }, org: ORG_A, applyOrgs: vi.fn() } as never);
    server.use(
      http.get("/api/v1/admin/people", () => HttpResponse.json({ users: [], invites: [] })),
      http.post("/api/v1/admin/invites", () => HttpResponse.json({ error: "invite_cooldown" }, { status: 409 })),
    );
    wrap(<PeoplePage />);
    await userEvent.type(await screen.findByLabelText("Email"), "no@x.io");
    await userEvent.click(screen.getByRole("button", { name: "Invite" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("declined");
    vi.restoreAllMocks();
  });
});

describe("joining a second organisation", () => {
  it("accepts right away: admin recovery is per organisation, so joining another changes nothing in this one", async () => {
    vi.spyOn(sessionModule, "useSession").mockReturnValue({ user: { id: "u1", name: "Sara", role: "member" }, org: { ...ORG_A, role: "member" }, orgs: [{ ...ORG_A, role: "member" }], switchOrg: vi.fn(), applyOrgs: vi.fn() } as never);
    let accepted = 0;
    server.use(
      http.get("/api/v1/me/orgs", () => HttpResponse.json({ orgs: [{ ...ORG_A, role: "member" }], invitations: [{ orgId: "bbbbbbbb-0000-4000-8000-000000000002", orgName: "Beta", role: "member", invitedBy: "Bo", invitedAt: new Date().toISOString() }], allowOrgCreation: false, instanceAdmin: false })),
      http.get("/api/v1/me/security", () => HttpResponse.json({ recoveryKit: { createdAt: "2026-01-01T00:00:00Z" }, adminRecoveryEnabled: true, adminRecoveryAckRequired: false,
        orgs: [{ orgId: ORG_A.id, orgName: "Alpha", adminRecoveryEnabled: true, ackRequired: false, recoverable: true, escrowHolders: [] }] })),
      http.post("/api/v1/me/invitations/:id/accept", () => { accepted++; return HttpResponse.json({ orgs: [] }); }),
    );
    wrap(<OrgSwitcher onSettings={() => undefined} />);
    await userEvent.click(await screen.findByRole("button", { name: /1 invitation/ }));
    await waitFor(() => expect(screen.getByRole("menu")).toHaveTextContent("Beta"));
    await userEvent.click(screen.getByRole("menuitem", { name: "Accept and switch" }));
    await waitFor(() => expect(accepted).toBe(1));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    vi.restoreAllMocks();
  });
});
