import { render, screen } from "@testing-library/react";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { http, HttpResponse } from "msw";
import { server } from "@/test/server";
import * as sessionModule from "@/lib/session";
import { AdminArea } from "./AdminArea";
import { TrialLine } from "./PlanLock";

const ORG = { id: "o1", name: "Acme", slug: "acme", role: "owner", isDefault: true };
let spy: ReturnType<typeof vi.spyOn>;
beforeAll(() => { spy = vi.spyOn(sessionModule, "useSession").mockReturnValue({ org: ORG, orgs: [ORG], user: { id: "a1", name: "Ada", role: "admin" } } as never); });
afterAll(() => spy.mockRestore());
const days = (d: number) => new Date(Date.now() + d * 86_400_000).toISOString();
const plan = (trial: boolean, trialEndsAt: string | null) => http.get("/api/v1/org/plan", () => HttpResponse.json({ plan: "team", trialEndsAt, entitlements: { trial, features: {} } }));
const wrap = (ui: React.ReactNode) => render(<QueryClientProvider client={new QueryClient()}><MemoryRouter>{ui}</MemoryRouter></QueryClientProvider>);
const area = (isAdmin: boolean) => <AdminArea section="events" detailId={null} mobile={false} isAdmin={isAdmin} isInstanceAdmin={false} loading={false} folders={[]} records={[]} vaultLoading={false} pendingReady={0} recoveryPending={0} />;

describe("trial line", () => {
  it("counts whole days, rounding up", async () => {
    server.use(plan(true, days(13.2)));
    wrap(<TrialLine />);
    expect(await screen.findByText("Business trial: 14 days left")).toBeInTheDocument();
  });
  it("says 1 day left", async () => {
    server.use(plan(true, days(0.5)));
    wrap(<TrialLine />);
    expect(await screen.findByText("Business trial: 1 day left")).toBeInTheDocument();
  });
  it("is hidden once the trial has ended, even if the cached plan still says trial", async () => {
    let asked = false;
    server.use(http.get("/api/v1/org/plan", () => { asked = true; return HttpResponse.json({ trialEndsAt: days(-0.1), entitlements: { trial: true, features: {} } }); }));
    wrap(<TrialLine />);
    await vi.waitFor(() => expect(asked).toBe(true));
    await new Promise((r) => setTimeout(r, 50));
    expect(screen.queryByText(/Business trial/)).toBeNull();
  });
  it("shows in the admin area for an admin", async () => {
    server.use(plan(true, days(3)));
    wrap(area(true));
    expect(await screen.findByText("Business trial: 3 days left")).toBeInTheDocument();
  });
  it("shows nothing to a member, and never asks for the plan", async () => {
    let asked = false;
    server.use(http.get("/api/v1/org/plan", () => { asked = true; return HttpResponse.json({ trialEndsAt: days(3), entitlements: { trial: true, features: {} } }); }));
    wrap(area(false));
    expect(await screen.findByLabelText("No access")).toBeInTheDocument();
    expect(screen.queryByText(/Business trial/)).toBeNull();
    expect(screen.queryByText("Available on the Business plan.")).toBeNull();
    expect(asked).toBe(false);
  });
  it("shows nothing when billing is off", async () => {
    wrap(area(true));
    expect(await screen.findByRole("region", { name: "Event log" })).toBeInTheDocument();
    expect(screen.queryByText(/Business trial/)).toBeNull();
    expect(screen.queryByText("Available on the Business plan.")).toBeNull();
  });
});
