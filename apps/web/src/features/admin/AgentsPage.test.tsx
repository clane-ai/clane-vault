import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { http, HttpResponse } from "msw";
import { b64url, gatewayKeyId, generateIdentityKeyPair, generateKeyPair, signAgentKey } from "@clane-vault/crypto";
import { server } from "@/test/server";
import * as sessionModule from "@/lib/session";
import { fingerprintOf, gatewayPinStatus, pinGateway, pinStatus, type GatewayIdentity } from "@/lib/orgKeys";
import type { VaultFolder } from "@/features/vault/types";
import AgentsPage from "./AgentsPage";
import type { Agent } from "./agents";

vi.mock("@/lib/clipboard", () => ({ copySecret: vi.fn(async () => undefined) }));
const ORG = { id: "aaaaaaaa-0000-4000-8000-000000000001", name: "Acme", slug: "acme", role: "admin" as const, isDefault: true };
const ME = "a1";
vi.spyOn(sessionModule, "useSession").mockReturnValue({ user: { id: ME, name: "Admin", role: "admin" }, org: ORG, orgs: [ORG] } as never);
const AGENT_ID = "bbbbbbbb-0000-4000-8000-000000000002";
const URL_ = "https://gw.test/mcp";
const FOLDERS = [{ id: "f1", name: "Payments", kind: "team", deleted: false }] as VaultFolder[];

async function newGateway() {
  const kp = await generateIdentityKeyPair();
  const identity: GatewayIdentity = { keyId: await gatewayKeyId(kp.publicKey), publicKey: b64url.encode(kp.publicKey) };
  const attest = async (agentId: string, publicKey: string) => signAgentKey(kp.privateKey, identity.keyId, { orgId: ORG.id, agentId, publicKey });
  return { identity, attest };
}
const agentKey = async () => b64url.encode((await generateKeyPair()).publicKey);
const row = (o: Partial<Agent>): Agent => ({ id: AGENT_ID, name: "Billing bot", status: "active", publicKey: "", attestation: "", expiresAt: null, lastUsedAt: null,
  createdAt: "2026-10-17T00:00:00Z", verifiedAt: "2026-10-17T00:00:00Z", folders: [], groups: [], tokens: [], grants: [], ...o });

let agents: Agent[];
const served = (g: GatewayIdentity) => http.get("/api/v1/org/agents/gateway", () => HttpResponse.json({ url: URL_, identityKeyId: g.keyId, identityPublicKey: g.publicKey }));
beforeEach(() => {
  try { localStorage.clear(); } catch { /* none */ }
  agents = [];
  server.use(
    http.get("/api/v1/admin/agents", () => HttpResponse.json({ agents })),
    http.get("/api/v1/org/plan", () => HttpResponse.json({ error: "not_found" }, { status: 404 })),
  );
});
let qc: QueryClient;
const renderPage = () => { qc = new QueryClient({ defaultOptions: { queries: { retry: false } } }); return render(<QueryClientProvider client={qc}><AgentsPage folders={FOLDERS} /></QueryClientProvider>); };

describe("Admin → Agents", () => {
  it("creates an agent, shows both fingerprints as New, and Matches pins both", async () => {
    const gw = await newGateway();
    const pub = await agentKey();
    const attestation = await gw.attest(AGENT_ID, pub);
    let created: unknown = null, verified: unknown = null;
    server.use(served(gw.identity),
      http.post("/api/v1/admin/agents", async ({ request }) => {
        created = await request.json();
        agents = [row({ status: "awaiting_verification", verifiedAt: null, publicKey: pub, attestation })];
        return HttpResponse.json({ id: AGENT_ID, name: "Billing bot", publicKey: pub, attestation, fingerprint: "x", gateway: { keyId: gw.identity.keyId, fingerprint: "x" } }, { status: 201 });
      }),
      http.post(`/api/v1/admin/agents/${AGENT_ID}/verify`, async ({ request }) => { verified = await request.json(); agents = [row({ publicKey: pub, attestation })]; return HttpResponse.json({ ok: true }); }),
    );
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: "New agent" }));
    await userEvent.type(screen.getByLabelText("Name"), "Billing bot");
    await userEvent.click(screen.getByRole("button", { name: "Create" }));
    await waitFor(() => expect(created).toEqual({ name: "Billing bot", expiresAt: null }));
    const dialog = await screen.findByRole("dialog", { name: "Verify Billing bot" });
    expect(await within(dialog).findByText(await fingerprintOf(pub))).toBeInTheDocument();
    expect(await within(dialog).findByText(await fingerprintOf(gw.identity.publicKey))).toBeInTheDocument();
    expect(within(dialog).getByText("New")).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole("button", { name: "Matches" }));
    await waitFor(() => expect(verified).toEqual({ publicKey: pub }));
    await waitFor(() => expect(gatewayPinStatus(ME, ORG.id, gw.identity).status).toBe("same"));
    expect(pinStatus(ME, ORG.id, AGENT_ID, pub).status).toBe("same");
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  });

  it("a changed gateway shows Changed, and Matches waits for the comparison to be confirmed, then repins", async () => {
    const old = await newGateway(), gw = await newGateway();
    await pinGateway(ME, ORG.id, old.identity);
    const pub = await agentKey();
    agents = [row({ status: "awaiting_verification", verifiedAt: null, publicKey: pub, attestation: await gw.attest(AGENT_ID, pub) })];
    server.use(served(gw.identity), http.post(`/api/v1/admin/agents/${AGENT_ID}/verify`, () => HttpResponse.json({ ok: true })));
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: "Verify Billing bot" }));
    const dialog = await screen.findByRole("dialog", { name: "Verify Billing bot" });
    expect(await within(dialog).findByText("Changed — compare it with the published fingerprint")).toBeInTheDocument();
    const matches = within(dialog).getByRole("button", { name: "Matches" });
    expect(matches).toBeDisabled();
    await userEvent.click(within(dialog).getByLabelText("I compared the gateway fingerprint with the published one"));
    expect(matches).toBeEnabled();
    // A refetch that serves another identity unticks the box, even if the first one comes back.
    const third = await newGateway();
    server.use(served(third.identity));
    await qc.invalidateQueries({ queryKey: ["agent-gateway"] });
    expect(await within(dialog).findByText("The gateway did not sign this key")).toBeInTheDocument();
    server.use(served(gw.identity));
    await qc.invalidateQueries({ queryKey: ["agent-gateway"] });
    const box = await within(dialog).findByLabelText("I compared the gateway fingerprint with the published one");
    expect(box).not.toBeChecked();
    expect(within(dialog).getByRole("button", { name: "Matches" })).toBeDisabled();
    await userEvent.click(box);
    await userEvent.click(within(dialog).getByRole("button", { name: "Matches" }));
    await waitFor(() => expect(gatewayPinStatus(ME, ORG.id, gw.identity).status).toBe("same"));
  });

  it("a key the gateway didn't sign: no Matches, only Revoke with reason attestation_failed", async () => {
    const gw = await newGateway();
    const pub = await agentKey(), tampered = await agentKey();
    const attestation = await gw.attest(AGENT_ID, pub);
    let revoked: unknown = null;
    server.use(served(gw.identity),
      http.post("/api/v1/admin/agents", () => {
        agents = [row({ status: "awaiting_verification", verifiedAt: null, publicKey: tampered, attestation })];
        return HttpResponse.json({ id: AGENT_ID, name: "Billing bot", publicKey: tampered, attestation }, { status: 201 });
      }),
      http.delete(`/api/v1/admin/agents/${AGENT_ID}`, async ({ request }) => { revoked = await request.json(); return HttpResponse.json({ rotate: { folders: [], records: 0 } }); }),
    );
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: "New agent" }));
    await userEvent.type(screen.getByLabelText("Name"), "Billing bot");
    await userEvent.click(screen.getByRole("button", { name: "Create" }));
    const dialog = await screen.findByRole("dialog", { name: "Verify Billing bot" });
    expect(await within(dialog).findByText("The gateway did not sign this key")).toBeInTheDocument();
    expect(within(dialog).queryByRole("button", { name: "Matches" })).not.toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole("button", { name: "Revoke" }));
    await waitFor(() => expect(revoked).toEqual({ reason: "attestation_failed" }));
    expect(gatewayPinStatus(ME, ORG.id, gw.identity).status).toBe("new");
  });

  it("connect: the URL in every snippet, the Claude API beta header; a token is shown once", async () => {
    const gw = await newGateway();
    await pinGateway(ME, ORG.id, gw.identity);
    const pub = await agentKey();
    agents = [row({ publicKey: pub, attestation: await gw.attest(AGENT_ID, pub),
      grants: [{ id: "g1", clientName: "Claude", grantedBy: { id: ME, name: "Admin" }, createdAt: new Date().toISOString() }] })];
    let grantRevoked = false;
    server.use(http.delete(`/api/v1/admin/agents/${AGENT_ID}/grants/g1`, () => { grantRevoked = true; return new HttpResponse(null, { status: 204 }); }));
    let tokenBody: unknown = null;
    server.use(served(gw.identity), http.post(`/api/v1/admin/agents/${AGENT_ID}/tokens`, async ({ request }) => {
      tokenBody = await request.json();
      return HttpResponse.json({ id: "t1", token: "cvat_t1_secretsecret" }, { status: 201 });
    }));
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: "Connect Billing bot" }));
    let sheet = await screen.findByRole("dialog", { name: "Connect Billing bot" });
    const snippets = await within(sheet).findAllByRole("region", { name: /snippet$/ });
    expect(snippets).toHaveLength(6);
    for (const s of snippets) expect(s.textContent).toContain(URL_);
    expect(within(sheet).getByRole("region", { name: "Claude API (MCP connector) snippet" }).textContent).toContain("mcp-client-2025-11-20");
    const grant = within(sheet).getByRole("listitem", { name: "Claude" });
    expect(within(grant).getByText(/Admin, /)).toBeInTheDocument();
    await userEvent.click(within(grant).getByRole("button", { name: "Revoke Claude" }));
    await waitFor(() => expect(grantRevoked).toBe(true));
    await userEvent.click(within(sheet).getByRole("button", { name: "Create API token" }));
    await waitFor(() => expect(tokenBody).toEqual({ label: "API token" }));
    expect(await within(sheet).findByText("cvat_t1_secretsecret")).toBeInTheDocument();
    await userEvent.click(within(sheet).getByRole("button", { name: "Close" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    // Nothing keeps the token once the sheet is closed: not the mutation cache either.
    await waitFor(() => expect(JSON.stringify(qc.getMutationCache().getAll().map((m) => m.state.data ?? null))).not.toContain("cvat_"));
    await userEvent.click(screen.getByRole("button", { name: "Connect Billing bot" }));
    sheet = await screen.findByRole("dialog", { name: "Connect Billing bot" });
    expect(within(sheet).queryByText(/cvat_t1_secretsecret/)).not.toBeInTheDocument();
  });

  it("revoke: a confirmation, then the folders to rotate by their vault names", async () => {
    const gw = await newGateway();
    await pinGateway(ME, ORG.id, gw.identity);
    const pub = await agentKey();
    agents = [row({ publicKey: pub, attestation: await gw.attest(AGENT_ID, pub), folders: [{ id: "f1" }] })];
    let revoked = false;
    server.use(served(gw.identity), http.delete(`/api/v1/admin/agents/${AGENT_ID}`, () => { revoked = true; return HttpResponse.json({ rotate: { folders: [{ id: "f1" }, { id: "f9" }], records: 4 } }); }));
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: "Revoke Billing bot" }));
    const dialog = await screen.findByRole("dialog", { name: "Revoke Billing bot?" });
    expect(revoked).toBe(false);
    await userEvent.click(within(dialog).getByRole("button", { name: "Revoke" }));
    expect(await within(dialog).findByText("The gateway could open these folders for this agent. Rotate the credentials in them.")).toBeInTheDocument();
    expect(within(dialog).getByText("Payments")).toBeInTheDocument();
    expect(within(dialog).getByText("A folder you can't open")).toBeInTheDocument();
  });

  it("an agent attested by another gateway than the pinned one needs re-enrolment", async () => {
    const old = await newGateway(), gw = await newGateway();
    await pinGateway(ME, ORG.id, gw.identity);
    const pub = await agentKey();
    agents = [row({ publicKey: pub, attestation: await old.attest(AGENT_ID, pub) })];
    server.use(served(gw.identity));
    renderPage();
    const item = await screen.findByRole("listitem", { name: "Billing bot" });
    expect(await within(item).findByText("Needs re-enrolment")).toBeInTheDocument();
  });

  it("edit: a rename sends no expiry, and the expiry's day survives the round trip west of UTC", async () => {
    const tz = process.env.TZ;
    process.env.TZ = "America/Los_Angeles";
    try {
      const gw = await newGateway();
      await pinGateway(ME, ORG.id, gw.identity);
      const pub = await agentKey();
      agents = [row({ publicKey: pub, attestation: await gw.attest(AGENT_ID, pub), expiresAt: new Date("2026-12-31T23:59:59").toISOString() })];
      expect(agents[0]!.expiresAt).toBe("2027-01-01T07:59:59.000Z");
      const patches: unknown[] = [];
      server.use(served(gw.identity), http.patch(`/api/v1/admin/agents/${AGENT_ID}`, async ({ request }) => { patches.push(await request.json()); return HttpResponse.json({ ok: true }); }));
      renderPage();
      await userEvent.click(await screen.findByRole("button", { name: "Edit Billing bot" }));
      const dialog = await screen.findByRole("dialog", { name: "Edit Billing bot" });
      expect(within(dialog).getByLabelText("Expires (optional)")).toHaveValue("2026-12-31");
      await userEvent.clear(within(dialog).getByLabelText("Name"));
      await userEvent.type(within(dialog).getByLabelText("Name"), "Payments bot");
      await userEvent.click(within(dialog).getByRole("button", { name: "Save" }));
      await waitFor(() => expect(patches).toEqual([{ name: "Payments bot" }]));
    } finally { process.env.TZ = tz; }
  });

  it("agents off on this server: one line, no actions", async () => {
    server.use(http.get("/api/v1/admin/agents", () => HttpResponse.json({ error: "not_found" }, { status: 404 })),
      http.get("/api/v1/org/agents/gateway", () => HttpResponse.json({ error: "not_found" }, { status: 404 })));
    renderPage();
    expect(await screen.findByText("Agent access isn't turned on for this server.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "New agent" })).not.toBeInTheDocument();
    expect(screen.queryByText(/no longer exists/)).not.toBeInTheDocument();
  });

  it("at the Team plan's agent limit, New agent is replaced by the upgrade line", async () => {
    server.use(served((await newGateway()).identity), http.get("/api/v1/org/plan", () => HttpResponse.json({
      plan: "team", billingStatus: "active", seatsPaid: 5, currentPeriodEnd: null, trialEndsAt: null,
      entitlements: { plan: "team", trial: false, features: {}, seatsAllowed: 5, storageBytesPerSeat: null, activeLinkLimit: null, eventLogDays: 30 },
      seats: { used: 2, allowed: 5 }, storage: { used: 0, limit: null }, agents: { used: 3, allowed: 3 },
    })));
    renderPage();
    expect(await screen.findByText("Available on the Business plan.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "New agent" })).not.toBeInTheDocument();
  });
});
