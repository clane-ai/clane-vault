import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { http, HttpResponse } from "msw";
import {
  agentRevealRequestMessage, b64url, encryptNewRecord, gatewayKeyId, generateIdentityKeyPair, generateKeyPair, openReveal, randomBytes, signGatewayMessage,
} from "@clane-vault/crypto";
import { server } from "@/test/server";
import * as sessionModule from "@/lib/session";
import { PERSONAL_SLOT, pinGateway } from "@/lib/orgKeys";
import { RevealApproval } from "./RevealApproval";

const ME = "11111111-0000-4000-8000-000000000001";
const AGENT_ID = "bbbbbbbb-0000-4000-8000-000000000002";
const RECORD_ID = "cccccccc-0000-4000-8000-000000000003";
const SEED = "JBSWY3DPEHPK3PXP";
const me = { userKey: randomBytes(32), ...(await generateKeyPair()) };
const session = { org: null, orgs: [], user: { id: ME, name: "Sara", role: "member" }, generation: () => 0, lock: vi.fn(), signOut: vi.fn(), keys: me };
vi.spyOn(sessionModule, "useSession").mockImplementation(() => session as never);

let sign: (m: string) => Promise<string>;
let pending: object[];
let approved: { sealed: string } | null, denied: number, polls: number;
let oneTime: { publicKey: Uint8Array; privateKey: Uint8Array };

async function request(o: { swapKey?: boolean; recordId?: string; fields?: string[]; expiresIn?: number } = {}) {
  oneTime = await generateKeyPair();
  const requestPublicKey = b64url.encode(oneTime.publicKey);
  const id = crypto.randomUUID(), recordId = o.recordId ?? RECORD_ID, fields = o.fields ?? ["username"];
  const expiresAt = new Date(Date.now() + (o.expiresIn ?? 300e3)).toISOString();
  const signature = await sign(agentRevealRequestMessage({ requestId: id, ownerUserId: ME, agentId: AGENT_ID, recordId, fields, requestPublicKey, expiresAt }));
  // A malicious API replacing the key after signing: the browser would seal to the API's own key.
  const shown = o.swapKey ? b64url.encode((await generateKeyPair()).publicKey) : requestPublicKey;
  return { id, agentId: AGENT_ID, agentName: "My bot", app: "Claude", recordId, fields, reason: "I need to log in", requestPublicKey: shown, signature, expiresAt, createdAt: new Date().toISOString() };
}

beforeEach(async () => {
  try { localStorage.clear(); } catch { /* none */ }
  const kp = await generateIdentityKeyPair();
  const identity = { keyId: await gatewayKeyId(kp.publicKey), publicKey: b64url.encode(kp.publicKey) };
  sign = (m) => signGatewayMessage(kp.privateKey, identity.keyId, "q1", m);
  await pinGateway(ME, PERSONAL_SLOT, identity);
  pending = []; approved = null; denied = 0; polls = 0;
  const enc = await encryptNewRecord(RECORD_ID, { type: "login", title: "Stripe login", username: "u", password: "pw", totpSecret: SEED }, me.userKey);
  server.use(
    http.get("/api/v1/me/agent-reveals", () => { polls++; return HttpResponse.json({ requests: pending, paused: [] }); }),
    http.get("/api/v1/sync", () => HttpResponse.json({ serverTime: "", folders: [], records: [{ id: RECORD_ID, folderId: null, type: "login", encBody: enc.encBody,
      wrappedRecordKey: enc.wrappedRecordKey, revision: 1, updatedAt: "", deletedAt: null, permission: "owner", holderType: "user", ownerId: ME, ownerName: "Sara", sharedWith: [],
      agentGrants: [{ agentId: AGENT_ID, use: false, write: false, reveal: ["username"] }] }] })),
    http.post("/api/v1/me/agent-reveals/:id/approve", async ({ request: r }) => { approved = (await r.json()) as never; pending = []; return HttpResponse.json({ ok: true }); }),
    http.post("/api/v1/me/agent-reveals/:id/deny", () => { denied++; pending = []; return HttpResponse.json({ ok: true }); }),
  );
});
const show = () => render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><RevealApproval /></QueryClientProvider>);

describe("the reveal approval sheet", () => {
  it("shows my vault's title and the reason label; Allow once seals exactly the asked field to the request's key", async () => {
    const r = await request();
    pending = [r];
    show();
    const sheet = await screen.findByRole("dialog");
    expect(await screen.findByText("Stripe login")).toBeInTheDocument();
    expect(sheet).toHaveTextContent("Written by the agent. It may not be true.");
    expect(sheet).toHaveTextContent("I need to log in");
    expect(sheet).toHaveTextContent("Username");
    await userEvent.click(await screen.findByRole("button", { name: "Allow once" }));
    await waitFor(() => expect(approved).not.toBeNull());
    const out = await openReveal(approved!.sealed, { requestId: r.id, recordId: RECORD_ID, agentId: AGENT_ID }, oneTime, me.publicKey, r.fields);
    expect(out).toEqual({ username: "u" });
    expect(JSON.stringify(out)).not.toContain(SEED);
  });

  it("a key swapped after signing: no Allow button, the unsigned line, nothing approved", async () => {
    pending = [await request({ swapKey: true })];
    show();
    expect(await screen.findByText("This request was not signed by your gateway.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Allow once" })).toBeNull();
    expect(approved).toBeNull();
  });

  it("an item not in my vault, or a field I did not allow: no Allow button", async () => {
    pending = [await request({ recordId: crypto.randomUUID() })];
    const v = show();
    expect(await screen.findByText("This asks for an item or fields you did not allow.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Allow once" })).toBeNull();
    v.unmount();
    pending = [await request({ fields: ["password"] })];
    show();
    expect(await screen.findByText("This asks for an item or fields you did not allow.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Allow once" })).toBeNull();
  });

  it("no personal gateway pinned on this device: verify first, no Allow button (F6)", async () => {
    localStorage.clear();
    pending = [await request()];
    show();
    expect(await screen.findByText("Verify your gateway on this device first")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Allow once" })).toBeNull();
    expect(screen.queryByText("This request was not signed by your gateway.")).toBeNull();
  });

  it("Deny posts deny; an expired request leaves the sheet", async () => {
    pending = [await request()];
    const v = show();
    await userEvent.click(await screen.findByRole("button", { name: "Deny" }));
    await waitFor(() => expect(denied).toBe(1));
    v.unmount();
    pending = [await request({ expiresIn: 1500 })];
    show();
    expect(await screen.findByRole("dialog")).toBeInTheDocument();
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull(), { timeout: 4000 });
  });

  it("polling stops after a 404 and after a 403", async () => {
    for (const status of [404, 403]) {
      polls = 0;
      server.use(http.get("/api/v1/me/agent-reveals", () => { polls++; return HttpResponse.json({ error: status === 404 ? "not_found" : "totp_step_up_required" }, { status }); }));
      vi.useFakeTimers({ shouldAdvanceTime: true });
      const v = show();
      await waitFor(() => expect(polls).toBe(1));
      await vi.advanceTimersByTimeAsync(20_000);
      expect(polls).toBe(1);
      vi.useRealTimers();
      v.unmount();
    }
  });

  it("a paused agent shows the notice", async () => {
    server.use(http.get("/api/v1/me/agent-reveals", () => HttpResponse.json({ requests: [], paused: [{ agentId: AGENT_ID, agentName: "My bot", until: "2026-11-18T12:00:00.000Z" }] })));
    show();
    expect(await screen.findByText(/My bot was denied three times\. Its requests are paused until /)).toBeInTheDocument();
  });
});
