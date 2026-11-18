import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router";
import { http, HttpResponse } from "msw";
import { b64url, gatewayKeyId, generateIdentityKeyPair, generateKeyPair, signPersonalAgentKey } from "@clane-vault/crypto";
import { server } from "@/test/server";
import * as sessionModule from "@/lib/session";
import { AgentAttestationError, fingerprintOf, PERSONAL_SLOT, pinnedGateway, pinGateway, pinStatus, type GatewayIdentity } from "@/lib/orgKeys";
import type { VaultRecord } from "@/features/vault/types";
import { MyAgentsSection } from "./MyAgentsSection";
import { SettingsArea } from "./SettingsPage";
import type { MyAgent, MyAgents } from "./myAgents";
import { agentErrorText } from "@/features/admin/agents";

vi.mock("@/lib/clipboard", () => ({ copySecret: vi.fn(async () => undefined) }));
const ME = "11111111-0000-4000-8000-000000000001";
const ORG = { id: "aaaaaaaa-0000-4000-8000-000000000001", name: "Acme", slug: "acme", role: "member" as const, isDefault: true };
const AGENT_ID = "bbbbbbbb-0000-4000-8000-000000000002";
const URL_ = "https://gw.test/mcp";
const RECORDS = [{ id: "r1", folderId: null, type: "login", body: { type: "login", title: "Stripe live key" }, revision: 1, updatedAt: "", deleted: false, permission: "owner", recordKey: null }] as unknown as VaultRecord[];

let owner: { publicKey: Uint8Array; privateKey: Uint8Array };
let ownerPublicKey: string;
let agents: MyAgent[];
let rest: Omit<MyAgents, "agents" | "gateway">;
let gwIdentity: GatewayIdentity | null;

async function newGateway() {
  const kp = await generateIdentityKeyPair();
  const identity: GatewayIdentity = { keyId: await gatewayKeyId(kp.publicKey), publicKey: b64url.encode(kp.publicKey) };
  const attest = (agentId: string, publicKey: string, ownerKey = ownerPublicKey) => signPersonalAgentKey(kp.privateKey, identity.keyId, { ownerUserId: ME, ownerPublicKey: ownerKey, agentId, publicKey });
  return { identity, attest };
}
const agentKey = async () => b64url.encode((await generateKeyPair()).publicKey);
const row = (o: Partial<MyAgent>): MyAgent => ({ id: AGENT_ID, name: "My bot", status: "active", publicKey: "", attestation: "", expiresAt: null, lastUsedAt: null,
  createdAt: "2026-11-15T00:00:00Z", verifiedAt: "2026-11-15T00:00:00Z", items: 0, owner: { userId: ME, publicKey: ownerPublicKey }, tokens: [], grants: [], ...o });
const gatewayBody = (g: GatewayIdentity) => ({ url: URL_, identityKeyId: g.keyId, identityPublicKey: g.publicKey });

beforeEach(async () => {
  try { localStorage.clear(); } catch { /* none */ }
  owner = await generateKeyPair();
  ownerPublicKey = b64url.encode(owner.publicKey);
  vi.spyOn(sessionModule, "useSession").mockReturnValue({ user: { id: ME, name: "Me", role: "member" }, org: ORG, orgs: [ORG], keys: { privateKey: owner.privateKey } } as never);
  agents = [];
  gwIdentity = null;
  rest = { allowance: { used: 0, allowed: 2 }, rules: { allowed: true, blockedByOrgId: null, write: false, reveal: "off" }, revealEmail: true };
  server.use(
    http.get("/api/v1/me/agents", () => HttpResponse.json({ agents, ...rest, gateway: gwIdentity && gatewayBody(gwIdentity) })),
    http.get("/api/v1/me/agents/gateway", () => (gwIdentity ? HttpResponse.json(gatewayBody(gwIdentity)) : HttpResponse.json({ error: "gateway_unavailable" }, { status: 503 }))),
  );
});
const wrap = (ui: React.ReactNode) => <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter>{ui}</MemoryRouter></QueryClientProvider>;
const renderSection = () => render(wrap(<MyAgentsSection records={RECORDS} />));

async function createAgent() {
  await userEvent.click(await screen.findByRole("button", { name: "New agent" }));
  await userEvent.type(screen.getByLabelText("Name"), "My bot");
  await userEvent.click(screen.getByRole("button", { name: "Create" }));
  return screen.findByRole("dialog", { name: "Verify My bot" });
}

describe("Settings → My agents", () => {
  it("creating opens the verify dialog with both fingerprints; Matches verifies and pins the personal slot", async () => {
    const gw = await newGateway();
    gwIdentity = gw.identity;
    const pub = await agentKey();
    const attestation = await gw.attest(AGENT_ID, pub);
    let created: unknown = null, verified: unknown = null;
    server.use(
      http.post("/api/v1/me/agents", async ({ request }) => {
        created = await request.json();
        agents = [row({ status: "awaiting_verification", verifiedAt: null, publicKey: pub, attestation })];
        return HttpResponse.json({ id: AGENT_ID, name: "My bot", publicKey: pub, fingerprint: "x", attestation, owner: { userId: ME, publicKey: ownerPublicKey },
          gateway: { keyId: gw.identity.keyId, publicKey: gw.identity.publicKey, fingerprint: "x" } }, { status: 201 });
      }),
      http.post(`/api/v1/me/agents/${AGENT_ID}/verify`, async ({ request }) => { verified = await request.json(); agents = [row({ publicKey: pub, attestation })]; return HttpResponse.json({ ok: true }); }),
    );
    renderSection();
    const dialog = await createAgent();
    expect(created).toEqual({ name: "My bot", expiresAt: null });
    expect(await within(dialog).findByText(await fingerprintOf(pub))).toBeInTheDocument();
    expect(within(dialog).getByText(await fingerprintOf(gw.identity.publicKey))).toBeInTheDocument();
    expect(within(dialog).getByText("Compare this with the fingerprint your server's operator published. A wrong gateway could read everything you give this agent.")).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole("button", { name: "Matches" }));
    await waitFor(() => expect(verified).toEqual({ publicKey: pub }));
    await waitFor(() => expect(pinnedGateway(ME, PERSONAL_SLOT)).toEqual(gw.identity));
    expect(pinStatus(ME, PERSONAL_SLOT, AGENT_ID, pub).status).toBe("same");
  });

  it("an attestation for another owner key: The gateway did not sign this key, and no Matches", async () => {
    const gw = await newGateway();
    gwIdentity = gw.identity;
    const pub = await agentKey();
    const attestation = await gw.attest(AGENT_ID, pub, await agentKey());
    server.use(http.post("/api/v1/me/agents", () => HttpResponse.json({ id: AGENT_ID, name: "My bot", publicKey: pub, attestation, owner: { userId: ME, publicKey: ownerPublicKey },
      gateway: { keyId: gw.identity.keyId, publicKey: gw.identity.publicKey, fingerprint: "x" } }, { status: 201 })));
    renderSection();
    const dialog = await createAgent();
    expect(await within(dialog).findByText("The gateway did not sign this key")).toBeInTheDocument();
    expect(within(dialog).queryByRole("button", { name: "Matches" })).not.toBeInTheDocument();
  });

  it("a gateway that differs from an organisation pin shows Changed with both fingerprints and repins only after the tick", async () => {
    const old = await newGateway(), gw = await newGateway();
    await pinGateway(ME, ORG.id, old.identity);
    gwIdentity = gw.identity;
    const pub = await agentKey();
    agents = [row({ status: "awaiting_verification", verifiedAt: null, publicKey: pub, attestation: await gw.attest(AGENT_ID, pub) })];
    server.use(http.post(`/api/v1/me/agents/${AGENT_ID}/verify`, () => HttpResponse.json({ ok: true })));
    renderSection();
    await userEvent.click(await screen.findByRole("button", { name: "Verify My bot" }));
    const dialog = await screen.findByRole("dialog", { name: "Verify My bot" });
    expect(await within(dialog).findByText("Changed — compare it with the published fingerprint")).toBeInTheDocument();
    expect(within(dialog).getByText(await fingerprintOf(old.identity.publicKey))).toBeInTheDocument();
    expect(within(dialog).getByRole("link", { name: "The published fingerprint" })).toHaveAttribute("href", expect.stringContaining("docs/agents.md"));
    expect(within(dialog).getByRole("button", { name: "Matches" })).toBeDisabled();
    await userEvent.click(within(dialog).getByLabelText("I compared the gateway fingerprint with the published one"));
    await userEvent.click(within(dialog).getByRole("button", { name: "Matches" }));
    await waitFor(() => expect(pinnedGateway(ME, PERSONAL_SLOT)).toEqual(gw.identity));
    expect(pinnedGateway(ME, ORG.id)).toEqual(old.identity);
  });

  it("at the allowance: New agent is disabled with 2 of 2 agents", async () => {
    rest.allowance = { used: 2, allowed: 2 };
    renderSection();
    expect(await screen.findByText("2 of 2 agents")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "New agent" })).toBeDisabled();
  });

  it("turned off by an organisation: names it, and no New agent", async () => {
    rest.rules = { allowed: false, blockedByOrgId: ORG.id, write: false, reveal: "off" };
    renderSection();
    expect(await screen.findByText("Acme doesn't allow personal agents, so you can't add one.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "New agent" })).not.toBeInTheDocument();
  });

  it("a create refused with personal_agents_disabled names the organisation", async () => {
    server.use(http.post("/api/v1/me/agents", () => HttpResponse.json({ error: "personal_agents_disabled", orgId: ORG.id }, { status: 403 })));
    renderSection();
    await userEvent.click(await screen.findByRole("button", { name: "New agent" }));
    await userEvent.type(screen.getByLabelText("Name"), "My bot");
    await userEvent.click(screen.getByRole("button", { name: "Create" }));
    expect(await screen.findByText("Acme doesn't allow personal agents, so you can't add one.")).toBeInTheDocument();
  });

  it("an attestation over my previous account key: Needs re-enrolment, no Connect", async () => {
    const gw = await newGateway();
    gwIdentity = gw.identity;
    await pinGateway(ME, PERSONAL_SLOT, gw.identity);
    const pub = await agentKey();
    agents = [row({ publicKey: pub, attestation: await gw.attest(AGENT_ID, pub, await agentKey()) }), row({ id: "cccccccc-0000-4000-8000-000000000003", name: "Good bot", publicKey: pub, attestation: await gw.attest("cccccccc-0000-4000-8000-000000000003", pub) })];
    renderSection();
    const bad = await screen.findByRole("listitem", { name: "My bot" });
    expect(await within(bad).findByText("Needs re-enrolment")).toBeInTheDocument();
    expect(within(bad).queryByRole("button", { name: "Connect My bot" })).not.toBeInTheDocument();
    const good = screen.getByRole("listitem", { name: "Good bot" });
    expect(within(good).getByText("Active")).toBeInTheDocument();
    expect(within(good).getByRole("button", { name: "Connect Good bot" })).toBeInTheDocument();
  });

  it("revoke lists the items to rotate by title", async () => {
    agents = [row({ publicKey: await agentKey() })];
    server.use(http.delete(`/api/v1/me/agents/${AGENT_ID}`, () => HttpResponse.json({ rotate: { records: [{ id: "r1" }, { id: "r2" }], revealed: [] } })));
    renderSection();
    await userEvent.click(await screen.findByRole("button", { name: "Revoke My bot" }));
    const dialog = await screen.findByRole("dialog", { name: "Revoke My bot?" });
    await userEvent.click(within(dialog).getByRole("button", { name: "Revoke" }));
    expect(await within(dialog).findByText("The gateway could open these items. Change the credentials in them.")).toBeInTheDocument();
    expect(within(dialog).getByText("Stripe live key")).toBeInTheDocument();
    expect(within(dialog).getByText("An item you can't open")).toBeInTheDocument();
  });

  it("revoke also lists the fields shown to the model; the reveal email switch saves", async () => {
    agents = [row({ publicKey: await agentKey() })];
    rest = { ...rest, rules: { ...rest.rules, reveal: "approval" } };
    let patched: unknown = null;
    server.use(
      http.get("/api/v1/me/agents", () => HttpResponse.json({ agents, ...rest, gateway: { url: "https://gw.test/mcp", identityKeyId: "k", identityPublicKey: "p", reveal: "approval" } })),
      http.patch("/api/v1/me/agents/settings", async ({ request }) => { patched = await request.json(); return HttpResponse.json({ ok: true }); }),
      http.delete(`/api/v1/me/agents/${AGENT_ID}`, () => HttpResponse.json({ rotate: { records: [], revealed: [{ id: "r1", fields: ["username"] }] } })),
    );
    renderSection();
    await userEvent.click(await screen.findByRole("checkbox", { name: "Email me when an agent asks for a secret" }));
    await waitFor(() => expect(patched).toEqual({ revealEmail: false }));
    await userEvent.click(await screen.findByRole("button", { name: "Revoke My bot" }));
    const dialog = await screen.findByRole("dialog", { name: "Revoke My bot?" });
    await userEvent.click(within(dialog).getByRole("button", { name: "Revoke" }));
    expect(await within(dialog).findByText("These fields were shown to the AI model. Change them.")).toBeInTheDocument();
    expect(within(dialog).getByText("Stripe live key: username")).toBeInTheDocument();
  });

  it("a 404 from /me/agents hides My agents from the settings menu", async () => {
    const health = <p>health</p>;
    const { unmount } = render(wrap(<SettingsArea section="health" mobile={false} health={health} records={[]} />));
    expect(await screen.findByRole("link", { name: /My agents/ })).toBeInTheDocument();
    unmount();
    let asked = false;
    server.use(http.get("/api/v1/me/agents", () => { asked = true; return HttpResponse.json({ error: "not_found" }, { status: 404 }); }));
    render(wrap(<SettingsArea section="health" mobile={false} health={health} records={[]} />));
    await waitFor(() => expect(asked).toBe(true));
    await new Promise((r) => setTimeout(r, 50));
    expect(screen.getByRole("link", { name: /Security/ })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /My agents/ })).not.toBeInTheDocument();
  });

  it("an owner key from another key pair: the owner alert, and no Matches", async () => {
    const gw = await newGateway();
    gwIdentity = gw.identity;
    const pub = await agentKey(), other = await agentKey();
    const attestation = await gw.attest(AGENT_ID, pub, other); // signed for the key the server claims, which isn't mine
    server.use(http.post("/api/v1/me/agents", () => HttpResponse.json({ id: AGENT_ID, name: "My bot", publicKey: pub, attestation, owner: { userId: ME, publicKey: other },
      gateway: { keyId: gw.identity.keyId, publicKey: gw.identity.publicKey, fingerprint: "x" } }, { status: 201 })));
    renderSection();
    const dialog = await createAgent();
    expect(await within(dialog).findByText("This agent's key is bound to a different account key than yours, so nothing was shared. Revoke the agent and create it again.")).toBeInTheDocument();
    expect(within(dialog).queryByRole("button", { name: "Matches" })).not.toBeInTheDocument();
    expect(pinnedGateway(ME, PERSONAL_SLOT)).toBeNull();
  });

  it("a server listing the stale owner key the attestation was made over still shows Needs re-enrolment", async () => {
    const gw = await newGateway();
    gwIdentity = gw.identity;
    await pinGateway(ME, PERSONAL_SLOT, gw.identity);
    const pub = await agentKey(), stale = await agentKey();
    agents = [row({ publicKey: pub, attestation: await gw.attest(AGENT_ID, pub, stale), owner: { userId: ME, publicKey: stale } })];
    renderSection();
    const bad = await screen.findByRole("listitem", { name: "My bot" });
    expect(await within(bad).findByText("Needs re-enrolment")).toBeInTheDocument();
  });

  it("a step-up 403 shows the authenticator step-up in the section", async () => {
    server.use(http.get("/api/v1/me/agents", () => HttpResponse.json({ error: "totp_step_up_required" }, { status: 403 })));
    renderSection();
    expect(await screen.findByRole("heading", { name: "Confirm with your authenticator" })).toBeInTheDocument();
    expect(screen.queryByText("Couldn't do that. Try again.")).not.toBeInTheDocument();
  });

  it("a private-locked session doesn't ask /me/agents (no app-wide step-up), and shows the step-up", async () => {
    let asked = false;
    server.use(http.get("/api/v1/me/agents", () => { asked = true; return HttpResponse.json({ error: "totp_step_up_required" }, { status: 403 }); }));
    render(wrap(<MyAgentsSection records={RECORDS} privateLocked />));
    expect(await screen.findByRole("heading", { name: "Confirm with your authenticator" })).toBeInTheDocument();
    render(wrap(<SettingsArea section="health" mobile={false} health={<p>health</p>} records={[]} privateLocked />));
    await new Promise((r) => setTimeout(r, 50));
    expect(asked).toBe(false);
  });

  it("personal wording: gateway_changed is something the owner can act on", () => {
    expect(agentErrorText(new AgentAttestationError("gateway_changed"), { personal: true })).toBe("The gateway's identity changed. Verify the agent again.");
    expect(agentErrorText(new AgentAttestationError("gateway_changed"))).toContain("Revoke the agent and create it again");
  });
});
