import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { toast } from "sonner";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { http, HttpResponse } from "msw";
import { server } from "@/test/server";
import { CustomerOrgsSection, type CustomerOrg } from "./CustomerOrgs";

const wrap = (ui: React.ReactNode) => render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>{ui}</QueryClientProvider>);

const org = (o: Partial<CustomerOrg>): CustomerOrg => ({ id: crypto.randomUUID(), name: "Globex", ownerEmail: "ceo@globex.test", createdAt: "2026-10-10T09:00:00.000Z", status: "pending", expiresAt: "2026-10-17T09:00:00.000Z", ...o });

describe("Server → Customer organisations", () => {
  it("creates an organisation with an owner invitation and shows the link to pass on (self-hosted)", async () => {
    let orgs: CustomerOrg[] = [];
    const posts: unknown[] = [];
    server.use(
      http.get("/api/v1/admin/instance/orgs", () => HttpResponse.json({ orgs, hostedMode: false, emailConfigured: false })),
      http.post("/api/v1/admin/instance/orgs", async ({ request }) => {
        const b = await request.json() as { name: string; ownerEmail: string };
        posts.push(b);
        const o = org({ name: b.name, ownerEmail: b.ownerEmail });
        orgs = [o];
        return HttpResponse.json({ org: o, emailed: false, inviteUrl: "http://localhost:5173/invite/tok123456789012345678901" }, { status: 201 });
      }),
    );
    wrap(<CustomerOrgsSection />);
    expect(await screen.findByText("No organisations created for customers yet.")).toBeInTheDocument();
    const form = screen.getByRole("form", { name: "Create an organisation for a customer" });
    await userEvent.click(within(form).getByRole("button", { name: "Create and invite owner" }));
    expect(within(form).getByRole("alert")).toHaveTextContent("Enter the organisation's name and its owner's email address.");
    await userEvent.type(within(form).getByLabelText("Organisation name"), "Globex");
    await userEvent.type(within(form).getByLabelText("Owner's email address"), "ceo@globex.test");
    await userEvent.click(within(form).getByRole("button", { name: "Create and invite owner" }));
    const done = await within(form).findByRole("status");
    expect(done).toHaveTextContent("Globex was created.");
    expect(done).toHaveTextContent("Send this link to ceo@globex.test yourself");
    expect(within(done).getByText("http://localhost:5173/invite/tok123456789012345678901")).toBeInTheDocument();
    expect(posts).toEqual([{ name: "Globex", ownerEmail: "ceo@globex.test" }]);
    const row = await screen.findByRole("row", { name: "Globex" });
    expect(within(row).getByText("ceo@globex.test")).toBeInTheDocument();
    expect(within(row).getByText("Pending")).toBeInTheDocument();
  });

  it("lists status per organisation; resends and cancels (with a confirmation) only what isn't accepted", async () => {
    const pending = org({ name: "Globex" }), expired = org({ name: "Initech", ownerEmail: "bill@initech.test", status: "expired" }), accepted = org({ name: "Umbrella", ownerEmail: "al@umbrella.test", status: "accepted", expiresAt: null });
    let orgs = [pending, expired, accepted];
    const calls: string[] = [];
    server.use(
      http.get("/api/v1/admin/instance/orgs", () => HttpResponse.json({ orgs, hostedMode: true, emailConfigured: true })),
      http.post("/api/v1/admin/instance/orgs/:id/resend", ({ params }) => {
        calls.push(`resend ${params.id}`);
        if (params.id === pending.id) return HttpResponse.json({ error: "too_soon" }, { status: 429 });
        orgs = orgs.map((o) => (o.id === params.id ? { ...o, status: "pending" } : o));
        return HttpResponse.json({ org: { ...expired, status: "pending" }, emailed: true });
      }),
      http.delete("/api/v1/admin/instance/orgs/:id", ({ params }) => { calls.push(`delete ${params.id}`); orgs = orgs.filter((o) => o.id !== params.id); return new HttpResponse(null, { status: 204 }); }),
    );
    wrap(<CustomerOrgsSection />);
    const rowOf = (name: string) => screen.findByRole("row", { name });
    expect(within(await rowOf("Initech")).getByText("Expired")).toBeInTheDocument();
    const um = await rowOf("Umbrella");
    expect(within(um).getByText("Accepted")).toBeInTheDocument();
    expect(within(um).queryByRole("button")).not.toBeInTheDocument();
    // No member lists or anything else from inside the organisations.
    expect(screen.getAllByRole("columnheader").map((h) => h.textContent)).toEqual(["Organisation", "Created", "Owner", "Invitation", "Actions"]);

    await userEvent.click(within(await rowOf("Initech")).getByRole("button", { name: "Resend invite for Initech" }));
    await waitFor(async () => expect(within(await rowOf("Initech")).getByText("Pending")).toBeInTheDocument());
    const failed = vi.spyOn(toast, "error");
    await userEvent.click(within(await rowOf("Globex")).getByRole("button", { name: "Resend invite for Globex" }));
    await waitFor(() => expect(failed).toHaveBeenCalledWith("It was sent less than 5 minutes ago. Try again in a few minutes."));

    await userEvent.click(within(await rowOf("Globex")).getByRole("button", { name: "Cancel Globex" }));
    const dialog = await screen.findByRole("dialog", { name: "Cancel the invitation and delete Globex?" });
    expect(dialog).toHaveTextContent("The invitation link to ceo@globex.test stops working.");
    await userEvent.click(within(dialog).getByRole("button", { name: "Cancel and delete" }));
    await waitFor(() => expect(screen.queryByRole("row", { name: "Globex" })).not.toBeInTheDocument());
    expect(calls).toEqual([`resend ${expired.id}`, `resend ${pending.id}`, `delete ${pending.id}`]);
  });

  it("explains a refused create (HOSTED_MODE without email)", async () => {
    server.use(
      http.get("/api/v1/admin/instance/orgs", () => HttpResponse.json({ orgs: [], hostedMode: true, emailConfigured: false })),
      http.post("/api/v1/admin/instance/orgs", () => HttpResponse.json({ error: "email_required" }, { status: 409 })),
    );
    wrap(<CustomerOrgsSection />);
    expect(await screen.findByText(/Email isn't set up on this server/)).toBeInTheDocument();
    const form = screen.getByRole("form", { name: "Create an organisation for a customer" });
    await userEvent.type(within(form).getByLabelText("Organisation name"), "Hooli");
    await userEvent.type(within(form).getByLabelText("Owner's email address"), "gavin@hooli.test");
    await userEvent.click(within(form).getByRole("button", { name: "Create and invite owner" }));
    expect(await within(form).findByRole("alert")).toHaveTextContent("Set up email first (Server → Email)");
  });
});
