import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router";
import { http, HttpResponse } from "msw";
import {
  configureKdfFloor, createAccount, createRecoveryKit, recoveryAuthFor, parseRecoveryCode, adminRecoveryProof, createMembershipKeys, createMembershipRecoveryGrant,
  openMembershipRecoveryGrant, sealMembershipEscrow, unlockMembershipKeys, type KdfParams,
} from "@clane-vault/crypto";
import { server } from "@/test/server";
import * as sessionModule from "@/lib/session";
import { RecoveryKitPanel } from "./RecoveryKit";
import { AdminRecoveryLinkPage, RecoverWithKitPage } from "./RecoverPages";
import { KitBanner } from "./KitBanner";
import { AdminRecoveryNotice } from "./AdminRecoveryNotice";
import { ResetBanner } from "./ResetBanner";
import { AccountSettings, AdminRecoverySection, SecuritySettings } from "@/features/settings/SettingsPage";
import { RecoveryRequestsSection } from "@/features/admin/RecoveryRequests";

const FAST: KdfParams = { alg: "argon2id", m: 1024, t: 2, p: 1 };
configureKdfFloor({ m: 1024, t: 1 });
// New master passwords use the real (slow) KDF in the app; tests use fast parameters.
vi.mock("@clane-vault/crypto", async (orig) => {
  const m = await orig<typeof import("@clane-vault/crypto")>();
  const fast = { alg: "argon2id", m: 1024, t: 2, p: 1 } as const;
  return { ...m, changeMasterPassword: (p: string, k: never, mat: never) => m.changeMasterPassword(p, k, mat, fast), createAccount: (p: string, params?: never) => m.createAccount(p, params ?? fast) };
});
vi.mock("@/lib/clipboard", () => ({ copySecret: vi.fn(async () => undefined) }));

const CODE_RE = /^[0-9A-Z]{4}(-[0-9A-Z]{4}){13}$/;
const wrap = (ui: React.ReactNode, path = "/") =>
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter initialEntries={[path]}>{ui}</MemoryRouter></QueryClientProvider>);

type Session = ReturnType<typeof sessionModule.useSession>;
function mockSession(over: Partial<Session>) {
  const s = { user: null, keys: null, kitProof: () => null, kitCreated: vi.fn(), proveMaster: vi.fn(), completeRecovery: vi.fn(), ...over } as unknown as Session;
  vi.spyOn(sessionModule, "useSession").mockReturnValue(s);
  return s;
}

beforeEach(() => { vi.restoreAllMocks(); });

describe("recovery kit screen", () => {
  it("shows the code once, needs the last group typed (or the box ticked) before saving, and sends the sign-up proof", async () => {
    const acct = await createAccount("pw pw pw pw pw", FAST);
    const s = mockSession({ user: { id: "u1", email: "sara@clane.ai", name: "Sara", role: "member" }, keys: acct.keys, kitProof: () => "PROOF" });
    let posted: { authKey: string; recoveryWrap: string; recoveryAuth: string } | null = null;
    server.use(http.post("/api/v1/me/recovery-kit", async ({ request }) => { posted = (await request.json()) as never; return HttpResponse.json({ createdAt: new Date().toISOString() }, { status: 201 }); }));
    const done = vi.fn();
    wrap(<RecoveryKitPanel mode="signup" onDone={done} />);
    const code = (await screen.findByTestId("recovery-code")).textContent!;
    expect(code).toMatch(CODE_RE);
    const save = screen.getByRole("button", { name: "Save recovery kit" });
    expect(save).toBeDisabled();
    await userEvent.type(screen.getByLabelText(/Type the last group/), "ZZZZ");
    expect(save).toBeDisabled();
    await userEvent.clear(screen.getByLabelText(/Type the last group/));
    await userEvent.type(screen.getByLabelText(/Type the last group/), code.slice(-4).toLowerCase());
    expect(save).toBeEnabled();
    await userEvent.click(save);
    await waitFor(() => expect(done).toHaveBeenCalled());
    expect(s.kitCreated).toHaveBeenCalled();
    expect(posted!.authKey).toBe("PROOF");
    // what was stored matches the code that was shown
    expect(posted!.recoveryAuth).toBe(await recoveryAuthFor(await parseRecoveryCode(code)));
    expect(JSON.stringify(posted)).not.toContain(code);
  });

  it("the tick box also confirms; Download saves a text file with the code", async () => {
    const acct = await createAccount("pw pw pw pw pw", FAST);
    mockSession({ user: { id: "u1", email: "sara@clane.ai", name: "Sara", role: "member" }, keys: acct.keys, kitProof: () => "PROOF" });
    const blobs: Blob[] = [];
    URL.createObjectURL = vi.fn((b: Blob) => { blobs.push(b); return "blob:x"; }) as never;
    URL.revokeObjectURL = vi.fn();
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);
    wrap(<RecoveryKitPanel mode="signup" onDone={vi.fn()} />);
    const code = (await screen.findByTestId("recovery-code")).textContent!;
    await userEvent.click(screen.getByRole("button", { name: "Download recovery kit" }));
    expect(click).toHaveBeenCalled();
    const text = await blobs[0]!.text();
    expect(text).toContain(code);
    expect(text).toContain("sara@clane.ai");
    expect(text).toMatch(/recovery kit/i);
    await userEvent.click(screen.getByLabelText("I saved my recovery kit somewhere safe"));
    expect(screen.getByRole("button", { name: "Save recovery kit" })).toBeEnabled();
  });

  it("regenerating asks for the master password first", async () => {
    const acct = await createAccount("pw pw pw pw pw", FAST);
    const s = mockSession({ user: { id: "u1", email: "sara@clane.ai", name: "Sara", role: "member" }, keys: acct.keys, proveMaster: vi.fn(async () => "P2") });
    wrap(<RecoveryKitPanel mode="regenerate" onDone={vi.fn()} onCancel={vi.fn()} />);
    expect(screen.queryByTestId("recovery-code")).not.toBeInTheDocument();
    await userEvent.type(screen.getByLabelText("Master password"), "my password");
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));
    expect(s.proveMaster).toHaveBeenCalledWith("my password");
    expect(await screen.findByTestId("recovery-code")).toBeInTheDocument();
    expect(screen.getByText(/current kit stops working/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Replace my recovery kit" })).toBeDisabled();
  });
});

describe("recover with the kit", () => {
  it("catches a typo in the code before asking the server", async () => {
    mockSession({});
    let called = false;
    server.use(http.post("/api/v1/auth/recovery/kit", () => { called = true; return HttpResponse.json({ error: "invalid_recovery" }, { status: 401 }); }));
    const kit = await createRecoveryKit("u1", new Uint8Array(32).fill(1));
    const typo = kit.code.slice(0, 5) + (kit.code[5] === "A" ? "B" : "A") + kit.code.slice(6);
    wrap(<Routes><Route path="/recover" element={<RecoverWithKitPage />} /></Routes>, "/recover?email=sara%40clane.ai");
    expect(screen.getByLabelText("Email address")).toHaveValue("sara@clane.ai");
    await userEvent.type(screen.getByLabelText("Recovery code"), typo);
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/typo|complete recovery code/);
    expect(called).toBe(false);
  });

  it("email + code → 2FA → new password → signed in with the same keys, and the kit screen next", async () => {
    const acct = await createAccount("old password!!", FAST);
    const kit = await createRecoveryKit("u1", acct.keys.userKey);
    const s = mockSession({});
    const bodies: Record<string, unknown>[] = [];
    let finishAuth = "";
    server.use(
      http.post("/api/v1/auth/recovery/kit", async ({ request }) => {
        const b = (await request.json()) as { email: string; recoveryAuth: string; code?: string };
        bodies.push(b);
        if (b.recoveryAuth !== kit.recoveryAuth) return HttpResponse.json({ error: "invalid_recovery" }, { status: 401 });
        if (!b.code) return HttpResponse.json({ error: "totp_required" }, { status: 401 });
        return HttpResponse.json({ recoveryToken: "RT", userId: "u1", recoveryWrap: kit.recoveryWrap, material: acct.material });
      }),
      http.post("/api/v1/auth/recovery/finish", async ({ request }) => {
        finishAuth = request.headers.get("authorization") ?? "";
        const b = (await request.json()) as { material: typeof acct.material };
        return HttpResponse.json({ accessToken: "AT", user: { id: "u1", email: "sara@clane.ai", name: "Sara", role: "member", recoveryKit: false }, material: b.material });
      }),
    );
    wrap(<Routes><Route path="/recover" element={<RecoverWithKitPage />} /><Route path="/" element={<p>home</p>} /></Routes>, "/recover");
    await userEvent.type(screen.getByLabelText("Email address"), "sara@clane.ai");
    await userEvent.type(screen.getByLabelText("Recovery code"), kit.code.toLowerCase().replace(/-/g, " "));
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));
    await userEvent.type(await screen.findByLabelText("6-digit code from your authenticator app"), "123456");
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));
    await userEvent.type(await screen.findByLabelText("New master password"), "a new long password");
    await userEvent.type(screen.getByLabelText("Repeat new master password"), "a new long password");
    await userEvent.click(screen.getByRole("button", { name: "Set new master password" }));
    expect(await screen.findByText("home")).toBeInTheDocument();
    expect(finishAuth).toBe("Bearer RT");
    expect(bodies.every((b) => !JSON.stringify(b).includes(kit.code))).toBe(true);
    const [res, keys, , opts] = vi.mocked(s.completeRecovery).mock.calls[0]!;
    expect(res.accessToken).toBe("AT");
    expect(keys.userKey).toEqual(acct.keys.userKey);
    expect(opts).toEqual({ requireKit: true });
  });

  it("says the same thing for a wrong email or code", async () => {
    mockSession({});
    server.use(http.post("/api/v1/auth/recovery/kit", () => HttpResponse.json({ error: "invalid_recovery" }, { status: 401 })));
    const kit = await createRecoveryKit("u1", new Uint8Array(32).fill(1));
    wrap(<Routes><Route path="/recover" element={<RecoverWithKitPage />} /></Routes>, "/recover");
    await userEvent.type(screen.getByLabelText("Email address"), "x@clane.ai");
    await userEvent.type(screen.getByLabelText("Recovery code"), kit.code);
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Email or recovery code is not right.");
  });
});

describe("admin recovery link", () => {
  const ID = "6f1f8a8e-1b7c-4c55-9d1e-0c0f3b0e2a11";
  const ORG = "0e0e0e0e-1111-4222-8333-444455556666";

  async function grantFor(userKey: Uint8Array, userId = "u1") {
    const made = await createMembershipKeys(userKey, { orgId: ORG, userId });
    const g = await createMembershipRecoveryGrant(ID, { orgId: ORG, userId }, made.keys);
    return { made, g };
  }

  it("explains the waiting period and the two-person rule after a 2FA reset", async () => {
    mockSession({});
    const { g } = await grantFor(new Uint8Array(32).fill(3));
    server.use(http.post(`/api/v1/auth/recovery/admin/${ID}`, () => HttpResponse.json({ error: "reset_delay", retryAfterSeconds: 7200 }, { status: 423 })));
    window.history.replaceState(null, "", `/recover/${ID}#${g.fragment}`);
    wrap(<Routes><Route path="/recover/:id" element={<AdminRecoveryLinkPage />} /></Routes>, `/recover/${ID}`);
    expect(await screen.findByRole("alert")).toHaveTextContent(/about 2 hours/);
  });

  it("a link without its secret, or one the server refuses, says it doesn't work", async () => {
    mockSession({});
    window.history.replaceState(null, "", `/recover/${ID}`);
    wrap(<Routes><Route path="/recover/:id" element={<AdminRecoveryLinkPage />} /></Routes>, `/recover/${ID}`);
    expect(await screen.findByRole("heading", { name: "This recovery link doesn't work" })).toBeInTheDocument();
  });

  it("proof + 2FA → new password and new account keys; only that org comes back; the secret never goes to the server", async () => {
    const acct = await createAccount("old password!!", FAST);
    const { made, g } = await grantFor(acct.keys.userKey);
    const s = mockSession({});
    const sent: string[] = [];
    let finish = null as { authKey: string; material: typeof acct.material; membership: { publicKey: string; wrappedPrivateKey: string } } | null;
    server.use(
      http.post(`/api/v1/auth/recovery/admin/${ID}`, async ({ request }) => {
        const raw = await request.text(); sent.push(raw);
        const b = JSON.parse(raw) as { proof: string; code?: string };
        if (b.proof !== (await adminRecoveryProof(g.fragment))) return HttpResponse.json({ error: "invalid_link" }, { status: 401 });
        if (!b.code) return HttpResponse.json({ error: "totp_required", email: "mia@clane.ai" }, { status: 401 });
        return HttpResponse.json({ recoveryToken: "RT", userId: "u1", email: "mia@clane.ai", mode: "reset", orgId: ORG, orgName: "Acme",
          memberPublicKey: made.material.publicKey, wrappedMembershipKey: g.wrappedMembershipKey });
      }),
      http.post("/api/v1/auth/recovery/finish", async ({ request }) => {
        const b = (await request.json()) as NonNullable<typeof finish>;
        finish = b;
        return HttpResponse.json({ accessToken: "AT", user: { id: "u1", email: "mia@clane.ai", name: "Mia", role: "member", recoveryKit: false }, material: b.material });
      }),
    );
    window.history.replaceState(null, "", `/recover/${ID}#${g.fragment}`);
    wrap(<Routes><Route path="/recover/:id" element={<AdminRecoveryLinkPage />} /><Route path="/" element={<p>home</p>} /></Routes>, `/recover/${ID}`);
    expect(await screen.findByText(/Admin-approved recovery for mia@clane.ai/)).toBeInTheDocument();
    expect(window.location.hash).toBe("");
    await userEvent.type(screen.getByLabelText("6-digit code from your authenticator app"), "123456");
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));
    expect(await screen.findByText(/This restores what you have in/)).toHaveTextContent("Acme");
    await userEvent.type(screen.getByLabelText("New master password"), "a new long password");
    await userEvent.type(screen.getByLabelText("Repeat new master password"), "a new long password");
    await userEvent.click(screen.getByRole("button", { name: "Set new master password" }));
    expect(await screen.findByText("home")).toBeInTheDocument();
    expect(sent.join("")).not.toContain(g.fragment);
    // New account keys; the membership key re-wrapped under the new user key, same key pair.
    expect(finish!.material.publicKey).not.toBe(acct.material.publicKey);
    expect(finish!.membership.publicKey).toBe(made.material.publicKey);
    const [, keys, , opts] = vi.mocked(s.completeRecovery).mock.calls[0]!;
    expect(keys.userKey).not.toEqual(acct.keys.userKey);
    expect((await unlockMembershipKeys(keys.userKey, { orgId: ORG, userId: "u1" }, finish!.membership)).privateKey).toEqual(made.keys.privateKey);
    expect(opts).toEqual({ requireKit: true }); // the old kit went to the archive
  });

  it("restore mode (already reset): the current master password brings this org back, without a reset", async () => {
    const acct = await createAccount("current password", FAST);
    const { made, g } = await grantFor(new Uint8Array(32).fill(9));
    mockSession({});
    let body = null as { authKey: string; publicKey: string; wrappedPrivateKey: string } | null;
    let materialAsked = 0;
    server.use(
      // The link never carries the wrapped user key: only the KDF parameters, to derive the auth key.
      http.post(`/api/v1/auth/recovery/admin/${ID}`, () => HttpResponse.json({ recoveryToken: "RT", userId: "u1", email: "mia@clane.ai", mode: "restore", orgId: ORG, orgName: "Beta",
        memberPublicKey: made.material.publicKey, wrappedMembershipKey: g.wrappedMembershipKey, kdf: { kdfSalt: acct.material.kdfSalt, kdfParams: acct.material.kdfParams } })),
      http.post("/api/v1/auth/recovery/restore-membership/material", async ({ request }) => {
        materialAsked++;
        const b = (await request.json()) as { authKey: string };
        return b.authKey === acct.authKey ? HttpResponse.json({ material: acct.material }) : HttpResponse.json({ error: "invalid_credentials" }, { status: 401 });
      }),
      http.post("/api/v1/auth/recovery/restore-membership", async ({ request }) => { body = (await request.json()) as never; return HttpResponse.json({ ok: true, orgId: ORG }); }),
    );
    window.history.replaceState(null, "", `/recover/${ID}#${g.fragment}`);
    wrap(<Routes><Route path="/recover/:id" element={<AdminRecoveryLinkPage />} /></Routes>, `/recover/${ID}`);
    await userEvent.type(await screen.findByLabelText("Current master password"), "wrong password");
    await userEvent.click(screen.getByRole("button", { name: "Restore Beta" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("That master password is not right.");
    await userEvent.type(screen.getByLabelText("Current master password"), "current password");
    await userEvent.click(screen.getByRole("button", { name: "Restore Beta" }));
    expect(await screen.findByText(/Your access to Beta is back/)).toBeInTheDocument();
    expect(materialAsked).toBe(2);
    expect(body!.publicKey).toBe(made.material.publicKey);
    expect((await unlockMembershipKeys(acct.keys.userKey, { orgId: ORG, userId: "u1" }, body!)).privateKey).toEqual(made.keys.privateKey);
  });

  it("refuses a grant that doesn't open to the key the server names", async () => {
    mockSession({});
    const { g } = await grantFor(new Uint8Array(32).fill(3));
    const other = await createMembershipKeys(new Uint8Array(32).fill(4), { orgId: ORG, userId: "u1" });
    server.use(http.post(`/api/v1/auth/recovery/admin/${ID}`, () => HttpResponse.json({ recoveryToken: "RT", userId: "u1", mode: "reset", orgId: ORG, orgName: "Acme",
      memberPublicKey: other.material.publicKey, wrappedMembershipKey: g.wrappedMembershipKey })));
    window.history.replaceState(null, "", `/recover/${ID}#${g.fragment}`);
    wrap(<Routes><Route path="/recover/:id" element={<AdminRecoveryLinkPage />} /></Routes>, `/recover/${ID}`);
    expect(await screen.findByRole("heading", { name: "This recovery link doesn't work" })).toBeInTheDocument();
  });
});

describe("disclosure and prompts", () => {
  const member = { id: "u1", email: "sara@clane.ai", name: "Sara", role: "member" as const };

  it("Settings → Security says which admins can restore which organisation, and never private items", async () => {
    mockSession({ user: member });
    server.use(http.get("/api/v1/me/security", () => HttpResponse.json({ recoveryKit: null, adminRecoveryEnabled: true,
      orgs: [{ orgId: "o1", orgName: "Acme", adminRecoveryEnabled: true, ackRequired: false, recoverable: true, escrowHolders: [{ adminId: "a1", name: "Ann", email: "ann@acme.io", since: "2026-10-01T00:00:00Z" }] }] })));
    wrap(<><SecuritySettings /><AccountSettings /></>);
    const note = await screen.findByRole("note", { name: "Who can recover your vault" });
    await waitFor(() => expect(note).toHaveTextContent("Admins of Acme can recover your account"));
    expect(note).toHaveTextContent("They can't open your private items or other organisations' items");
    expect(within(note).getByRole("list", { name: "Who holds your escrow" })).toHaveTextContent("Acme: held by Ann (ann@acme.io)");
    expect(screen.getByRole("button", { name: "Create recovery kit" })).toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "Organisation" })).not.toBeInTheDocument();
  });

  it("Settings → Security says only you can open the vault when the policy is off", async () => {
    mockSession({ user: member });
    wrap(<><SecuritySettings /><AccountSettings /></>);
    const note = await screen.findByRole("note", { name: "Who can recover your vault" });
    await waitFor(() => expect(note).toHaveTextContent("Only you can open your vault"));
    expect(await screen.findByRole("button", { name: "Regenerate recovery kit" })).toBeInTheDocument();
  });

  it("admins switch the policy on only after an explicit warning, their master password and a 2FA code", async () => {
    const s = mockSession({ user: { ...member, role: "admin" }, proveMaster: vi.fn(async () => "AK") });
    let put: unknown = null;
    const view = (enabled: boolean) => ({ adminRecovery: { enabled, changedAt: null, changedBy: null }, escrows: { total: 0, members: 0 } });
    server.use(
      http.get("/api/v1/admin/settings", () => HttpResponse.json(view(false))),
      http.put("/api/v1/admin/settings/admin-recovery", async ({ request }) => { put = await request.json(); return HttpResponse.json(view(true)); }),
    );
    wrap(<AdminRecoverySection />);
    const sw = await screen.findByRole("switch", { name: "Admin account recovery" });
    await waitFor(() => expect(sw).toBeEnabled());
    await userEvent.click(sw);
    const dialog = await screen.findByRole("dialog");
    expect(dialog).toHaveTextContent("restore what they hold in this organisation. Never their private items");
    expect(put).toBeNull();
    expect(within(dialog).getByRole("button", { name: "Turn on" })).toBeDisabled();
    await userEvent.type(within(dialog).getByLabelText("Your master password"), "admin pw");
    await userEvent.type(within(dialog).getByLabelText("6-digit code from your authenticator app"), "123456");
    await userEvent.click(within(dialog).getByRole("button", { name: "Turn on" }));
    await waitFor(() => expect(put).toEqual({ enabled: true, authKey: "AK", code: "123456" }));
    expect(s.proveMaster).toHaveBeenCalledWith("admin pw");
    await waitFor(() => expect(screen.getByRole("switch", { name: "Admin account recovery" })).toBeChecked());
  });

  it("on Team admins get the lock line and a turn-off, never the switch", async () => {
    mockSession({ user: { ...member, role: "admin" } });
    let put: unknown = null;
    server.use(
      http.get("/api/v1/org/plan", () => HttpResponse.json({ entitlements: { features: { adminRecovery: false } } })),
      http.get("/api/v1/admin/settings", () => HttpResponse.json({ adminRecovery: { enabled: false, changedAt: null, changedBy: null }, escrows: { total: 0, members: 0 } })),
      http.put("/api/v1/admin/settings/admin-recovery", async ({ request }) => { put = await request.json(); return HttpResponse.json({ adminRecovery: { enabled: false, changedAt: null, changedBy: null }, escrows: { total: 0, members: 0 } }); }),
    );
    wrap(<AdminRecoverySection />);
    expect(await screen.findByText("Available on the Business plan.")).toBeInTheDocument();
    expect(screen.queryByRole("switch")).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: "Turn off admin recovery" }));
    await waitFor(() => expect(put).toEqual({ enabled: false }));
  });

  it("a blocking notice asks members to acknowledge admin recovery per organisation, and says what it covers", async () => {
    mockSession({ user: member });
    let acked = false;
    let ackBody: unknown = null;
    server.use(
      http.get("/api/v1/me/security", () => HttpResponse.json({ recoveryKit: null, adminRecoveryEnabled: true, adminRecoveryAckRequired: !acked,
        orgs: [{ orgId: "o1", orgName: "Acme", adminRecoveryEnabled: true, ackRequired: !acked }] })),
      http.post("/api/v1/me/admin-recovery-ack", async ({ request }) => { ackBody = await request.json(); acked = true; return HttpResponse.json({ ok: true }); }),
    );
    wrap(<AdminRecoveryNotice />);
    const dialog = await screen.findByRole("dialog");
    expect(dialog).toHaveTextContent("Acme turned on admin recovery");
    expect(dialog).toHaveTextContent("They can't open your private items or other organisations' items");
    await userEvent.click(within(dialog).getByRole("button", { name: "Continue" }));
    await waitFor(() => expect(ackBody).toEqual({ orgId: "o1" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  });

  it("after a reset, a banner says what stayed locked; none when nothing did", async () => {
    mockSession({ user: member });
    let arch = { id: "k1", archivedAt: "2026-10-08T00:00:00Z", privateItems: 3, otherOrgs: 1 };
    server.use(http.get("/api/v1/me/security", () => HttpResponse.json({ recoveryKit: null, adminRecoveryEnabled: false, keyArchive: arch })));
    const onOpen = vi.fn();
    const { unmount } = wrap(<ResetBanner onOpen={onOpen} />);
    const banner = await screen.findByRole("status", { name: "Items from before your reset" });
    expect(banner).toHaveTextContent("3 private items and your access in 1 other organisation are locked");
    await userEvent.click(within(banner).getByRole("button", { name: "Restore" }));
    expect(onOpen).toHaveBeenCalled();
    unmount();
    arch = { ...arch, privateItems: 0, otherOrgs: 0 };
    wrap(<ResetBanner onOpen={onOpen} />);
    await new Promise((r) => setTimeout(r, 50));
    expect(screen.queryByRole("status", { name: "Items from before your reset" })).not.toBeInTheDocument();
  });

  it("the vault shows a dismissible kit prompt when there is no kit", async () => {
    mockSession({ user: member });
    server.use(http.get("/api/v1/me/security", () => HttpResponse.json({ recoveryKit: null, adminRecoveryEnabled: false })));
    wrap(<KitBanner />);
    const banner = await screen.findByRole("status", { name: "Recovery kit" });
    expect(banner).toHaveTextContent("Create your recovery kit");
    await userEvent.click(within(banner).getByRole("button", { name: "Remind me later" }));
    expect(screen.queryByRole("status", { name: "Recovery kit" })).not.toBeInTheDocument();
  });

  it("no prompt when a kit exists", async () => {
    mockSession({ user: member });
    wrap(<KitBanner />);
    await new Promise((r) => setTimeout(r, 50));
    expect(screen.queryByRole("status", { name: "Recovery kit" })).not.toBeInTheDocument();
  });
});

describe("admin approves a reset request", () => {
  it("fresh 2FA → own escrow opened with my membership key → one-time link with the secret only in the fragment", async () => {
    const ORG = "0e0e0e0e-1111-4222-8333-444455556666";
    const admin = await createAccount("admin pw pw pw", FAST);
    const RID = "1b2c3d4e-5f60-4718-9a0b-1c2d3e4f5a6b";
    mockSession({ user: { id: "a1", email: "admin@clane.ai", name: "Admin", role: "admin" }, keys: admin.keys, org: { id: ORG, name: "Acme", slug: "acme", role: "admin", isDefault: true } as never });
    const adminKey = await createMembershipKeys(admin.keys.userKey, { orgId: ORG, userId: "a1" });
    const memberKey = await createMembershipKeys(new Uint8Array(32).fill(5), { orgId: ORG, userId: "m1" });
    const sealed = await sealMembershipEscrow(adminKey.keys.publicKey, memberKey.keys, { userId: "m1", adminId: "a1" });
    let approved = null as { approvalToken: string; memberPublicKey: string; wrappedMembershipKey: string; proof: string } | null;
    let escrowCode: unknown = null;
    server.use(
      http.get("/api/v1/admin/recovery-requests", () => HttpResponse.json({ requests: [{ id: RID, status: approved ? "approved" : "pending", createdAt: new Date().toISOString(), approvedAt: null, approvedBy: null, expiresAt: null, user: { id: "m1", name: "Mia", email: "mia@clane.ai" }, canApprove: !approved }] })),
      http.post(`/api/v1/admin/recovery-requests/${RID}/escrow`, async ({ request }) => {
        escrowCode = await request.json();
        return HttpResponse.json({ sealedKey: sealed, memberPublicKey: memberKey.material.publicKey, adminPublicKey: adminKey.material.publicKey, member: { id: "m1" }, approvalToken: "AP" });
      }),
      http.get("/api/v1/membership-key", () => HttpResponse.json({ keys: [{ ...adminKey.material, state: "current", escrowOpenedAt: null }] })),
      http.post(`/api/v1/admin/recovery-requests/${RID}/approve`, async ({ request }) => {
        approved = (await request.json()) as never;
        return HttpResponse.json({ linkBase: `http://localhost/recover/${RID}`, expiresAt: new Date(Date.now() + 864e5).toISOString() });
      }),
    );
    wrap(<RecoveryRequestsSection />);
    const row = await screen.findByRole("listitem", { name: "Reset request from mia@clane.ai" });
    await userEvent.click(within(row).getByRole("button", { name: "Approve" }));
    const dialog = await screen.findByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Your 6-digit authenticator code"), "654321");
    await userEvent.click(within(dialog).getByRole("button", { name: "Approve and create link" }));
    const link = (await within(dialog).findByTestId("recovery-link")).textContent!;
    expect(escrowCode).toEqual({ code: "654321" });
    expect(approved!.approvalToken).toBe("AP");
    expect(approved!.memberPublicKey).toBe(memberKey.material.publicKey);
    const [base, fragment] = link.split("#");
    expect(base).toBe(`http://localhost/recover/${RID}`);
    expect(JSON.stringify(approved)).not.toContain(fragment!);
    expect(await adminRecoveryProof(fragment!)).toBe(approved!.proof);
    const back = await openMembershipRecoveryGrant(RID, { orgId: ORG, userId: "m1" }, fragment!, approved!.wrappedMembershipKey, memberKey.material.publicKey);
    expect(back.privateKey).toEqual(memberKey.keys.privateKey);
  });
});

describe("restoring from before a reset (key archive)", () => {
  it("proves the old kit to the server before it hands out the old key material (never on a 2FA code alone)", async () => {
    const { KeyArchiveSection } = await import("./KeyArchive");
    const old = await createAccount("old password!!", FAST);
    const now = await createAccount("new password!!", FAST);
    const kit = await createRecoveryKit("u1", old.keys.userKey);
    mockSession({ user: { id: "u1", email: "mia@clane.ai", name: "Mia", role: "member" } as never, keys: now.keys, orgs: [], generation: () => 1 } as never);
    const ARCH = "aaaaaaaa-1111-4222-8333-444455556666";
    let openBody = null as null | Record<string, string>;
    let restored = false;
    server.use(
      http.get("/api/v1/me/security", () => HttpResponse.json({ recoveryKit: null, adminRecoveryEnabled: false, keyArchive: { id: ARCH, archivedAt: "2026-10-08T00:00:00Z", privateItems: 1, otherOrgs: 0 } })),
      http.get("/api/v1/me/key-archive", () => HttpResponse.json({ archives: [{ id: ARCH, hasKit: true, kdfSalt: old.material.kdfSalt, kdfParams: old.material.kdfParams }] })),
      http.post("/api/v1/me/key-archive/open", async ({ request }) => {
        openBody = (await request.json()) as Record<string, string>;
        if (openBody?.recoveryAuth !== kit.recoveryAuth) return HttpResponse.json({ error: "invalid_credentials" }, { status: 401 });
        return HttpResponse.json({ archives: [{ id: ARCH, userKeyGen: 1, ...old.material, recoveryWrap: kit.recoveryWrap, membershipKeys: [] }] });
      }),
      http.get("/api/v1/me/owner-rows", () => HttpResponse.json({ rows: [], after: null })),
      http.get("/api/v1/me/private-folders", () => HttpResponse.json({ folders: [] })),
      http.post(`/api/v1/me/key-archive/${ARCH}/restored`, () => { restored = true; return HttpResponse.json({ ok: true }); }),
    );
    wrap(<KeyArchiveSection />);
    await userEvent.type(await screen.findByLabelText("Recovery code from before the reset"), kit.code);
    await userEvent.type(screen.getByLabelText("6-digit code from your authenticator app"), "123456");
    await userEvent.click(screen.getByRole("button", { name: "Restore" }));
    await waitFor(() => expect(restored).toBe(true));
    expect(openBody).toEqual({ code: "123456", id: ARCH, recoveryAuth: await recoveryAuthFor(await parseRecoveryCode(kit.code)) });
  });
});
