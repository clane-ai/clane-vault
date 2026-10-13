import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter, Route, Routes, useLocation } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { http, HttpResponse } from "msw";
import { server } from "@/test/server";
import { api } from "@/lib/api";
import * as sessionModule from "@/lib/session";
import { SignInForm } from "./SignIn";
import SsoComplete from "./SsoComplete";
import { SsoRequiredPanel } from "./SsoRequired";
import { TotpStepUpPanel } from "./TotpStepUp";
import { safeReturnTo } from "./sso";

afterEach(() => { vi.restoreAllMocks(); window.location.hash = ""; });

async function enterEmail(email: string) {
  await userEvent.type(screen.getByLabelText("Email address"), email);
  await userEvent.click(screen.getByRole("button", { name: "Next" }));
}

describe("sign-in with SSO", () => {
  it("offers the org's SSO for a verified domain above the password, and starts it with the email", async () => {
    const started: unknown[] = [];
    server.use(
      http.post("/api/v1/auth/sso/discover", async ({ request }) => HttpResponse.json({ orgs: (await request.json() as { email: string }).email.endsWith("@acme.test") ? [{ slug: "acme-1", name: "Acme" }] : [] })),
      http.post("/api/v1/auth/sso/start", async ({ request }) => { started.push(await request.json()); return HttpResponse.json({ url: "https://idp.example/authorize?x=1" }); }),
    );
    const go = vi.fn(async (org: string, email?: string) => { await api.post("/auth/sso/start", { org, email }); });
    render(<MemoryRouter><SignInForm signIn={vi.fn()} onDone={vi.fn()} onNeedsSetup={vi.fn()} onSso={go} /></MemoryRouter>);
    await enterEmail("sara@acme.test");
    const btn = await screen.findByRole("button", { name: "Continue with Acme SSO" });
    expect(screen.getByLabelText("Master password")).toBeInTheDocument();
    await userEvent.click(btn);
    expect(go).toHaveBeenCalledWith("acme-1", "sara@acme.test");
    expect(started).toEqual([{ org: "acme-1", email: "sara@acme.test" }]);
  });

  it("no SSO for other domains; \"Sign in with SSO\" takes an organisation ID", async () => {
    server.use(http.post("/api/v1/auth/sso/discover", () => HttpResponse.json({ orgs: [] })));
    const go = vi.fn(async () => undefined);
    render(<MemoryRouter><SignInForm signIn={vi.fn()} onDone={vi.fn()} onNeedsSetup={vi.fn()} onSso={go} /></MemoryRouter>);
    await userEvent.click(screen.getByRole("button", { name: "Sign in with SSO" }));
    await userEvent.type(screen.getByLabelText("Organisation ID for single sign-on"), " Acme-1 ");
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));
    expect(go).toHaveBeenCalledWith("acme-1", undefined);
    await enterEmail("bob@gmail.test");
    await screen.findByLabelText("Master password");
    expect(screen.queryByRole("group", { name: "Single sign-on" })).not.toBeInTheDocument();
  });

  it("explains an SSO error and an unknown organisation", async () => {
    const go = vi.fn(async () => { throw new (await import("@/lib/api")).ApiError(404, "sso_not_configured", null); });
    render(<MemoryRouter><SignInForm signIn={vi.fn()} onDone={vi.fn()} onNeedsSetup={vi.fn()} onSso={go} ssoError="sso_identity_mismatch" /></MemoryRouter>);
    expect(screen.getByRole("alert")).toHaveTextContent("linked to a different account");
    await userEvent.click(screen.getByRole("button", { name: "Sign in with SSO" }));
    await userEvent.type(screen.getByLabelText("Organisation ID for single sign-on"), "nope");
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("doesn't use single sign-on");
  });

  it("returnTo never leaves the app", () => {
    for (const bad of ["https://evil.example", "//evil.example", "/\\evil.example", "javascript:alert(1)", null]) expect(safeReturnTo(bad)).toBe("/");
    expect(safeReturnTo("/settings")).toBe("/settings");
  });
});

function Where() { const l = useLocation(); return <p data-testid="where">{l.pathname}</p>; }
function renderComplete(session: Partial<ReturnType<typeof sessionModule.useSession>>) {
  vi.spyOn(sessionModule, "useSession").mockReturnValue({ beginTwoFactor: vi.fn(), ...session } as never);
  render(<QueryClientProvider client={new QueryClient()}><MemoryRouter initialEntries={["/sso/complete"]}><Routes>
    <Route path="/sso/complete" element={<SsoComplete />} />
    <Route path="*" element={<Where />} />
  </Routes></MemoryRouter></QueryClientProvider>);
}

describe("after the identity provider", () => {
  it("reads the proof from the fragment, clears it, then asks for the master password and the 2FA code", async () => {
    window.location.hash = "#proof=proof-token-0123456789abcdef&returnTo=%2Fsettings";
    const proofs: unknown[] = [];
    server.use(http.post("/api/v1/auth/sso/proof", async ({ request }) => { proofs.push(await request.json()); return HttpResponse.json({ mode: "login", email: "sara@idp-renamed.test", accountEmail: "sara@acme.test", kdf: { kdfSalt: "salt-1", kdfParams: { alg: "argon2id", m: 1024, t: 1, p: 1 } }, org: { name: "Acme", slug: "acme-1" }, returnTo: "/settings", totpSkipped: false, joins: null }); }));
    const signInWithSso = vi.fn().mockResolvedValueOnce({ kind: "error", code: "totp_required" }).mockResolvedValueOnce({ kind: "ok" });
    renderComplete({ signInWithSso });
    expect(await screen.findByRole("status")).toHaveTextContent("Acme confirmed you as sara@idp-renamed.test");
    expect(window.location.hash).toBe("");
    expect(proofs).toEqual([{ proof: "proof-token-0123456789abcdef" }]);
    await userEvent.type(screen.getByLabelText("Master password"), "my master password");
    await userEvent.click(screen.getByRole("button", { name: "Unlock" }));
    // The account's own email and KDF parameters from the proof (the IdP's address may differ).
    const kdf = { kdfSalt: "salt-1", kdfParams: { alg: "argon2id", m: 1024, t: 1, p: 1 } };
    expect(signInWithSso).toHaveBeenLastCalledWith("proof-token-0123456789abcdef", "sara@acme.test", "my master password", undefined, kdf);
    await userEvent.type(await screen.findByLabelText("6-digit code from your authenticator app"), "123456");
    await userEvent.click(screen.getByRole("button", { name: "Unlock" }));
    expect(signInWithSso).toHaveBeenLastCalledWith("proof-token-0123456789abcdef", "sara@acme.test", "my master password", "123456", kdf);
    expect(await screen.findByTestId("where")).toHaveTextContent("/settings");
  });

  it("trusted IdP MFA: says so and needs only the master password", async () => {
    window.location.hash = "#proof=proof-token-0123456789abcdef";
    server.use(http.post("/api/v1/auth/sso/proof", () => HttpResponse.json({ mode: "login", email: "sara@acme.test", accountEmail: "sara@acme.test", kdf: { kdfSalt: "salt-1", kdfParams: { alg: "argon2id", m: 1024, t: 1, p: 1 } }, org: { name: "Acme", slug: "acme-1" }, returnTo: "/", totpSkipped: true, joins: null })));
    const signInWithSso = vi.fn().mockResolvedValue({ kind: "ok" });
    renderComplete({ signInWithSso });
    expect(await screen.findByText(/already checked your second factor/)).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText("Master password"), "pw");
    await userEvent.click(screen.getByRole("button", { name: "Unlock" }));
    expect(await screen.findByTestId("where")).toHaveTextContent("/");
    expect(signInWithSso).toHaveBeenCalledOnce();
  });

  it("new account: name from the IdP, master password, then 2FA setup (no email code)", async () => {
    window.location.hash = "#proof=proof-token-0123456789abcdef";
    const regs: { proof: string; name: string }[] = [];
    server.use(
      http.post("/api/v1/auth/sso/proof", () => HttpResponse.json({ mode: "register", email: "new@acme.test", org: { name: "Acme", slug: "acme-1" }, returnTo: "/", name: "New Person", adminRecoveryEnabled: false, joins: "member" })),
      http.post("/api/v1/auth/sso/register", async ({ request }) => { regs.push(await request.json() as { proof: string; name: string }); return HttpResponse.json({ setupToken: "setup-1" }, { status: 201 }); }),
    );
    const beginTwoFactor = vi.fn();
    renderComplete({ beginTwoFactor });
    expect(await screen.findByLabelText("Your name")).toHaveValue("New Person");
    expect(screen.queryByLabelText("Code from your email")).not.toBeInTheDocument();
    await userEvent.type(screen.getByLabelText("Master password"), "a long master password");
    await userEvent.type(screen.getByLabelText("Repeat master password"), "a long master password");
    await userEvent.click(screen.getByRole("button", { name: "Create account" }));
    expect(await screen.findByTestId("where", {}, { timeout: 15_000 })).toHaveTextContent("/setup-2fa");
    expect(regs[0]).toMatchObject({ proof: "proof-token-0123456789abcdef", name: "New Person" });
    expect(beginTwoFactor).toHaveBeenCalledWith("setup-1", "a long master password");
  });

  it("an expired or foreign proof shows a way back", async () => {
    window.location.hash = "#proof=proof-token-0123456789abcdef";
    server.use(http.post("/api/v1/auth/sso/proof", () => HttpResponse.json({ error: "sso_proof_invalid" }, { status: 410 })));
    renderComplete({});
    expect(await screen.findByText("Single sign-on expired")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Back to sign in" })).toBeInTheDocument();
  });
});

describe("Require SSO", () => {
  it("a 403 sso_required is reported to the session", async () => {
    const seen: string[] = [];
    api.onSsoRequired((id) => seen.push(id));
    server.use(http.get("/api/v1/sync", () => HttpResponse.json({ error: "sso_required", orgId: "org-1" }, { status: 403 })));
    await expect(api.get("/sync")).rejects.toMatchObject({ code: "sso_required" });
    expect(seen).toEqual(["org-1"]);
    api.onSsoRequired(() => {});
  });

  it("the panel starts the org's SSO with the account's email", async () => {
    const org = { id: "org-1", name: "Acme", slug: "acme-1", role: "member" as const, isDefault: false };
    vi.spyOn(sessionModule, "useSession").mockReturnValue({ user: { id: "u", email: "sara@acme.test", name: "Sara", role: "member" }, orgs: [org, { ...org, id: "org-2", name: "Other", slug: "o" }], switchOrg: vi.fn() } as never);
    const starts: unknown[] = [];
    server.use(http.post("/api/v1/auth/sso/start", async ({ request }) => { starts.push(await request.json()); return HttpResponse.json({ url: "https://idp.example/a" }); }));
    const go = vi.fn();
    render(<MemoryRouter><SsoRequiredPanel org={org} go={go} /></MemoryRouter>);
    const panel = screen.getByRole("region", { name: "Single sign-on required" });
    expect(within(panel).getByText("Acme requires single sign-on")).toBeInTheDocument();
    expect(within(panel).getByRole("button", { name: "Go to your Personal vault" })).toBeInTheDocument();
    await userEvent.click(within(panel).getByRole("button", { name: "Sign in with Acme SSO" }));
    await waitFor(() => expect(go).toHaveBeenCalledWith("https://idp.example/a"));
    expect(starts).toEqual([{ org: "acme-1", email: "sara@acme.test", returnTo: "/o/acme-1/vault" }]);
  });
});

describe("TOTP step-up after a trusted-MFA SSO sign-in", () => {
  it("a 403 totp_step_up_required is reported, and the panel sends the code", async () => {
    let asked = 0;
    api.onStepUpRequired(() => { asked++; });
    server.use(http.get("/api/v1/sync", () => HttpResponse.json({ error: "totp_step_up_required" }, { status: 403 })));
    await expect(api.get("/sync")).rejects.toMatchObject({ code: "totp_step_up_required" });
    expect(asked).toBe(1);
    api.onStepUpRequired(() => {});
    const stepUp = vi.fn().mockRejectedValueOnce(new (await import("@/lib/api")).ApiError(401, "totp_invalid", null)).mockResolvedValueOnce(undefined);
    vi.spyOn(sessionModule, "useSession").mockReturnValue({ stepUp } as never);
    render(<TotpStepUpPanel />);
    await userEvent.type(screen.getByLabelText("6-digit code from your authenticator app"), "111111");
    await userEvent.click(screen.getByRole("button", { name: "Confirm" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("didn't work");
    await userEvent.type(screen.getByLabelText("6-digit code from your authenticator app"), "222222");
    await userEvent.click(screen.getByRole("button", { name: "Confirm" }));
    await waitFor(() => expect(stepUp).toHaveBeenLastCalledWith("222222"));
  });
});
