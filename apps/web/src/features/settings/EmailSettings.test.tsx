import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { http, HttpResponse } from "msw";
import { server } from "@/test/server";
import * as sessionModule from "@/lib/session";
import { EmailSettingsSection, type EmailSettingsView, type M365Delegated } from "./EmailSettings";
import { browser } from "./m365Connect";

const ORG = { id: "aaaaaaaa-0000-4000-8000-000000000001", name: "Alpha", slug: "alpha", role: "owner" as const, isDefault: true };
const wrap = (ui: React.ReactNode) => render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>{ui}</QueryClientProvider>);
beforeEach(() => { vi.spyOn(sessionModule, "useSession").mockReturnValue({ user: { id: "u1", name: "Ann", email: "ann@alpha.test", role: "admin" }, org: ORG } as never); });

const saved: EmailSettingsView["settings"] = {
  provider: "resend", fromName: "Vault", fromAddress: "vault@alpha.test", smtp: null, secret: { set: true, last4: "9876" },
  updatedAt: new Date().toISOString(), updatedBy: { id: "u1", name: "Ann" },
};

describe("EmailSettingsSection", () => {
  it("instance: sets up SMTP; the password is sent only when typed, never shown", async () => {
    let state: EmailSettingsView = { scope: "instance", settings: null, fallback: "env", env: { from: "x@y.z" } };
    const puts: unknown[] = [];
    server.use(
      http.get("/api/v1/admin/instance/email", () => HttpResponse.json(state)),
      http.put("/api/v1/admin/instance/email", async ({ request }) => {
        const b = await request.json() as { provider: "smtp"; fromAddress: string; fromName: string; smtp: { host: string; port: number; security: "starttls"; username: string } };
        puts.push(b);
        state = { ...state, settings: { provider: b.provider, fromName: b.fromName, fromAddress: b.fromAddress, smtp: b.smtp, secret: { set: true, last4: null }, updatedAt: new Date().toISOString(), updatedBy: { id: "u1", name: "Ann" } } };
        return HttpResponse.json(state);
      }),
    );
    wrap(<EmailSettingsSection scope="instance" />);
    expect(await screen.findByText(/RESEND_API_KEY and EMAIL_FROM/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Set up" }));
    await userEvent.click(screen.getByRole("radio", { name: "SMTP server" }));
    await userEvent.type(screen.getByLabelText("From name"), "Clane Vault");
    await userEvent.type(screen.getByLabelText("From address"), "vault@clane.test");
    await userEvent.type(screen.getByLabelText("SMTP host"), "smtp.clane.test");
    await userEvent.click(screen.getByRole("radio", { name: "TLS" }));
    expect(screen.getByLabelText("Port")).toHaveValue("465");
    expect(screen.getByLabelText("Password")).toBeDisabled();
    await userEvent.type(screen.getByLabelText("Username"), "mailer");
    await userEvent.type(screen.getByLabelText("Password"), "hunter22");
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(await screen.findByText("SMTP · smtp.clane.test:465")).toBeInTheDocument();
    expect(puts).toEqual([{ provider: "smtp", fromName: "Clane Vault", fromAddress: "vault@clane.test", smtp: { host: "smtp.clane.test", port: 465, security: "tls", username: "mailer" }, secret: "hunter22" }]);
    // Editing again: the password field is empty (write-only), says it's set, and is not sent unless retyped.
    await userEvent.click(screen.getByRole("button", { name: "Edit" }));
    expect(screen.getByLabelText("Password")).toHaveValue("");
    expect(screen.getByText("Set. Leave empty to keep it.")).toBeInTheDocument();
    await userEvent.clear(screen.getByLabelText("From name"));
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    await screen.findByRole("button", { name: "Edit" });
    expect(puts[1]).not.toHaveProperty("secret");
    expect(puts[1]).toMatchObject({ fromName: null });
  });

  it("org: shows the override, its masked key, and test email success and failure", async () => {
    let fail = false;
    const sentWith: (string | null)[] = [];
    server.use(
      http.get("/api/v1/admin/settings/email", () => HttpResponse.json({ scope: "org", settings: saved, fallback: "instance" })),
      http.post("/api/v1/admin/settings/email/test", ({ request }) => {
        sentWith.push(request.headers.get("x-org-id"));
        return fail ? HttpResponse.json({ error: "email_test_failed", detail: "Resend refused the email: the API key was rejected." }, { status: 502 }) : HttpResponse.json({ ok: true, to: "ann@alpha.test" });
      }),
    );
    wrap(<EmailSettingsSection scope="org" />);
    const section = await screen.findByRole("region", { name: "Email for this organisation" });
    expect(await within(section).findByText("Resend")).toBeInTheDocument();
    expect(within(section).getByText(/From Vault <vault@alpha.test>/)).toBeInTheDocument();
    await userEvent.click(within(section).getByRole("button", { name: "Edit" }));
    expect(within(section).getByLabelText("Resend API key")).toHaveValue("");
    expect(within(section).getByText("Set (ends in 9876). Leave empty to keep it.")).toBeInTheDocument();
    await userEvent.click(within(section).getByRole("button", { name: "Cancel" }));
    await userEvent.click(within(section).getByRole("button", { name: "Send test email" }));
    expect(await within(section).findByRole("status")).toHaveTextContent("Test email sent to ann@alpha.test");
    fail = true;
    await userEvent.click(within(section).getByRole("button", { name: "Send test email" }));
    expect(await within(section).findByRole("alert")).toHaveTextContent("Test email failed: Resend refused the email: the API key was rejected.");
    expect(sentWith).toEqual([ORG.id, ORG.id]);
  });

  it("Resend needs an API key the first time", async () => {
    server.use(http.get("/api/v1/admin/settings/email", () => HttpResponse.json({ scope: "org", settings: null, fallback: "none" })));
    wrap(<EmailSettingsSection scope="org" />);
    expect(await screen.findByText(/Email isn't set up/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Set up" }));
    await userEvent.type(screen.getByLabelText("From address"), "it@alpha.test");
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(screen.getByRole("alert")).toHaveTextContent("Enter the Resend API key.");
  });

  it("Microsoft 365: guides the Entra setup, validates IDs, sends tenant, client and secret; the secret is write-only", async () => {
    let state: EmailSettingsView = { scope: "org", settings: null, fallback: "instance" };
    const puts: Record<string, unknown>[] = [];
    server.use(
      http.get("/api/v1/admin/settings/email", () => HttpResponse.json(state)),
      http.put("/api/v1/admin/settings/email", async ({ request }) => {
        const b = await request.json() as { provider: "m365"; fromName: string | null; fromAddress: string; m365: { tenantId: string; clientId: string }; secret?: string };
        puts.push(b);
        state = { ...state, settings: { provider: b.provider, fromName: b.fromName, fromAddress: b.fromAddress, smtp: null, m365: { tenantId: b.m365.tenantId.toLowerCase(), clientId: b.m365.clientId.toLowerCase() },
          secret: { set: true, last4: "wxyz" }, updatedAt: new Date().toISOString(), updatedBy: { id: "u1", name: "Ann" } } };
        return HttpResponse.json(state);
      }),
    );
    wrap(<EmailSettingsSection scope="org" />);
    await userEvent.click(await screen.findByRole("button", { name: "Set up" }));
    await userEvent.click(screen.getByRole("radio", { name: "Microsoft 365 (recommended for Office 365)" }));
    // The Entra steps and the mailbox restriction are right there.
    expect(screen.getByText("How to set this up in Microsoft Entra")).toBeInTheDocument();
    expect(screen.getByText(/New-ApplicationAccessPolicy -AppId <clientId> -PolicyScopeGroupId vault-senders@yourdomain.com -AccessRight RestrictAccess/)).toBeInTheDocument();
    expect(screen.getByText(/RBAC for Applications/)).toBeInTheDocument();
    expect(screen.getAllByText("Mail.Send").length).toBeGreaterThan(0);
    expect(screen.getByText("Grant admin consent")).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText("Sender mailbox"), "vault@northwind.test");
    await userEvent.type(screen.getByLabelText("Directory (tenant) ID"), "not a tenant");
    await userEvent.type(screen.getByLabelText("Application (client) ID"), "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee");
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(screen.getByRole("alert")).toHaveTextContent("Enter the Directory (tenant) ID: a GUID or a verified domain");
    await userEvent.clear(screen.getByLabelText("Directory (tenant) ID"));
    await userEvent.type(screen.getByLabelText("Directory (tenant) ID"), "northwind.onmicrosoft.com");
    await userEvent.clear(screen.getByLabelText("Application (client) ID"));
    await userEvent.type(screen.getByLabelText("Application (client) ID"), "northwind-vault");
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(screen.getByRole("alert")).toHaveTextContent("Enter the Application (client) ID: a GUID.");
    await userEvent.clear(screen.getByLabelText("Application (client) ID"));
    await userEvent.type(screen.getByLabelText("Application (client) ID"), "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE");
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(screen.getByRole("alert")).toHaveTextContent("Enter the client secret.");
    await userEvent.type(screen.getByLabelText("Client secret"), "Abc8Q~secret");
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(await screen.findByText("Microsoft 365 · vault@northwind.test")).toBeInTheDocument();
    expect(puts).toEqual([{ provider: "m365", fromName: null, fromAddress: "vault@northwind.test", m365: { tenantId: "northwind.onmicrosoft.com", clientId: "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE", authMode: "app" }, secret: "Abc8Q~secret" }]);
    // Editing: the secret field is empty and says it's set; it isn't sent unless retyped.
    await userEvent.click(screen.getByRole("button", { name: "Edit" }));
    expect(screen.getByLabelText("Directory (tenant) ID")).toHaveValue("northwind.onmicrosoft.com");
    expect(screen.getByLabelText("Client secret")).toHaveValue("");
    expect(screen.getByText("Set (ends in wxyz). Leave empty to keep it.")).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText("From name"), "Northwind Vault");
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    await screen.findByRole("button", { name: "Edit" });
    expect(puts[1]).not.toHaveProperty("secret");
    expect(puts[1]).toMatchObject({ fromName: "Northwind Vault", m365: { tenantId: "northwind.onmicrosoft.com" } });
    // A different tenant needs the secret again.
    await userEvent.click(screen.getByRole("button", { name: "Edit" }));
    await userEvent.clear(screen.getByLabelText("Directory (tenant) ID"));
    await userEvent.type(screen.getByLabelText("Directory (tenant) ID"), "11111111-2222-4333-8444-555555555555");
    expect(screen.queryByText(/Leave empty to keep it/)).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(screen.getByRole("alert")).toHaveTextContent("Enter the client secret.");
    expect(puts).toHaveLength(2);
  }, 30_000);

  it("SMTP with smtp.office365.com points to the Microsoft 365 provider", async () => {
    server.use(http.get("/api/v1/admin/instance/email", () => HttpResponse.json({ scope: "instance", settings: null, fallback: "none" })));
    wrap(<EmailSettingsSection scope="instance" />);
    await userEvent.click(await screen.findByRole("button", { name: "Set up" }));
    await userEvent.click(screen.getByRole("radio", { name: "SMTP server" }));
    await userEvent.type(screen.getByLabelText("SMTP host"), "smtp.example.com");
    expect(screen.queryByText(/retired password sign-in/)).not.toBeInTheDocument();
    await userEvent.clear(screen.getByLabelText("SMTP host"));
    await userEvent.type(screen.getByLabelText("SMTP host"), "smtp.office365.com");
    expect(screen.getByRole("note")).toHaveTextContent("Microsoft has retired password sign-in for SMTP — use Microsoft 365 instead");
    await userEvent.click(screen.getByRole("button", { name: "Switch to Microsoft 365" }));
    expect(screen.getByRole("radio", { name: "Microsoft 365 (recommended for Office 365)" })).toBeChecked();
    expect(screen.getByLabelText("Directory (tenant) ID")).toBeInTheDocument();
  }, 15_000);

  it("Microsoft 365: shows the server's validation and test errors", async () => {
    server.use(
      http.get("/api/v1/admin/settings/email", () => HttpResponse.json({ scope: "org", settings: { ...saved, provider: "m365", m365: { tenantId: "11111111-2222-4333-8444-555555555555", clientId: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee" }, secret: { set: true, last4: "wxyz" } }, fallback: "instance" })),
      http.post("/api/v1/admin/settings/email/test", () => HttpResponse.json({ error: "email_test_failed", detail: "Microsoft 365 rejected the client secret (AADSTS7000215)." }, { status: 502 })),
    );
    wrap(<EmailSettingsSection scope="org" />);
    expect(await screen.findByText("Microsoft 365 · vault@alpha.test")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Send test email" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Test email failed: Microsoft 365 rejected the client secret (AADSTS7000215).");
  });
});

describe("EmailSettingsSection: Microsoft 365 delegated sign-in", () => {
  const REDIRECT = "https://vault.northwind.test/vault/api/v1/admin/email/m365/callback";
  const m365Settings = (delegated: M365Delegated | null, fromAddress = ""): EmailSettingsView["settings"] => ({
    provider: "m365", fromName: null, fromAddress, smtp: null, secret: { set: true, last4: "wxyz" },
    m365: { tenantId: "11111111-2222-4333-8444-555555555555", clientId: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", authMode: "delegated", delegated },
    updatedAt: new Date().toISOString(), updatedBy: { id: "u1", name: "Ann" },
  });
  const none: M365Delegated = { account: null, connectedAt: null, connectedBy: null, reconnect: null, sharedScopeMissing: false };
  beforeEach(() => { window.history.replaceState(null, "", "/server/email"); });

  it("set up: Connection choice, optional sender, the redirect URI to copy and the Entra steps; then Sign in with Microsoft", async () => {
    let state: EmailSettingsView = { scope: "instance", settings: null, fallback: "none", m365RedirectUri: REDIRECT };
    const puts: Record<string, unknown>[] = [];
    let connects = 0;
    server.use(
      http.get("/api/v1/admin/instance/email", () => HttpResponse.json(state)),
      http.put("/api/v1/admin/instance/email", async ({ request }) => {
        const b = await request.json() as Record<string, unknown>;
        puts.push(b);
        state = { ...state, settings: m365Settings(none) };
        return HttpResponse.json(state);
      }),
      http.post("/api/v1/admin/instance/email/m365/connect", () => { connects++; return HttpResponse.json({ url: "https://login.microsoftonline.com/x/oauth2/v2.0/authorize?state=s" }); }),
    );
    const go = vi.spyOn(browser, "go").mockImplementation(() => undefined);
    wrap(<EmailSettingsSection scope="instance" />);
    await userEvent.click(await screen.findByRole("button", { name: "Set up" }));
    await userEvent.click(screen.getByRole("radio", { name: "Microsoft 365 (recommended for Office 365)" }));
    await userEvent.click(screen.getByRole("radio", { name: "Sign in with Microsoft (delegated)" }));
    expect(screen.getByRole("radio", { name: "App-only (client credentials)" })).not.toBeChecked();
    expect(screen.getByLabelText("Redirect URI (register it in Entra as a Web platform)")).toHaveValue(REDIRECT);
    expect(screen.getByText("How to set up delegated sign-in in Microsoft Entra")).toBeInTheDocument();
    expect(screen.getByText("Mail.Send.Shared")).toBeInTheDocument();
    expect(screen.getByText("offline_access")).toBeInTheDocument();
    expect(screen.getByText(REDIRECT)).toBeInTheDocument();
    expect(screen.queryByText(/New-ApplicationAccessPolicy/)).not.toBeInTheDocument();
    await userEvent.type(screen.getByLabelText("Directory (tenant) ID"), "11111111-2222-4333-8444-555555555555");
    await userEvent.type(screen.getByLabelText("Application (client) ID"), "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee");
    await userEvent.type(screen.getByLabelText("Client secret"), "Abc8Q~secret");
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(await screen.findByText("Microsoft 365 · not connected")).toBeInTheDocument();
    expect(puts).toEqual([{ provider: "m365", fromName: null, fromAddress: "", secret: "Abc8Q~secret",
      m365: { tenantId: "11111111-2222-4333-8444-555555555555", clientId: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", authMode: "delegated" } }]);
    expect(screen.getByText("Not connected")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Sign in with Microsoft" }));
    await vi.waitFor(() => expect(go).toHaveBeenCalledWith("https://login.microsoftonline.com/x/oauth2/v2.0/authorize?state=s"));
    expect(connects).toBe(1);
  }, 30_000);

  it("connected: Connected as … · Reconnect · Disconnect; the shared-mailbox scope hint", async () => {
    let state: EmailSettingsView = { scope: "instance", fallback: "env", m365RedirectUri: REDIRECT,
      settings: m365Settings({ account: "admin@northwind.test", connectedAt: new Date().toISOString(), connectedBy: { id: "u1", name: "Ann" }, reconnect: null, sharedScopeMissing: true }, "shared@northwind.test") };
    let deletes = 0;
    server.use(
      http.get("/api/v1/admin/instance/email", () => HttpResponse.json(state)),
      http.delete("/api/v1/admin/instance/email/m365/connection", () => { deletes++; state = { ...state, settings: m365Settings(none, "shared@northwind.test") }; return HttpResponse.json(state); }),
      http.post("/api/v1/admin/instance/email/m365/connect", () => HttpResponse.json({ url: "https://login.microsoftonline.com/r" })),
    );
    const go = vi.spyOn(browser, "go").mockImplementation(() => undefined);
    wrap(<EmailSettingsSection scope="instance" />);
    expect(await screen.findByText("Microsoft 365 · shared@northwind.test")).toBeInTheDocument();
    expect(screen.getByText(/Connected as/)).toHaveTextContent("Connected as admin@northwind.test");
    expect(screen.getByRole("note")).toHaveTextContent("reconnect to grant Mail.Send.Shared");
    await userEvent.click(screen.getByRole("button", { name: "Reconnect" }));
    await vi.waitFor(() => expect(go).toHaveBeenCalledWith("https://login.microsoftonline.com/r"));
    await userEvent.click(screen.getByRole("button", { name: "Disconnect" }));
    expect(await screen.findByRole("button", { name: "Sign in with Microsoft" })).toBeInTheDocument();
    expect(deletes).toBe(1);
  });

  it("needs reconnect: says why and offers Reconnect", async () => {
    server.use(http.get("/api/v1/admin/settings/email", () => HttpResponse.json({ scope: "org", fallback: "instance", m365RedirectUri: REDIRECT,
      settings: m365Settings({ account: "admin@northwind.test", connectedAt: new Date().toISOString(), connectedBy: null, sharedScopeMissing: false,
        reconnect: { at: new Date().toISOString(), reason: "The account's password changed or its sign-ins were revoked (AADSTS50173)." } }) })));
    wrap(<EmailSettingsSection scope="org" />);
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Microsoft 365 sign-in needs reconnecting. Email can't be sent as admin@northwind.test: The account's password changed or its sign-ins were revoked (AADSTS50173).");
    expect(within(alert).getByRole("button", { name: "Reconnect" })).toBeInTheDocument();
    expect(screen.getByText("Reconnect", { selector: "span" })).toBeInTheDocument(); // the status chip
  });

  it("back from Microsoft: explains the error (the exact redirect URI for AADSTS50011) and cleans the URL; success says so", async () => {
    server.use(http.get("/api/v1/admin/instance/email", () => HttpResponse.json({ scope: "instance", fallback: "none", m365RedirectUri: REDIRECT, settings: m365Settings(none) })));
    window.history.replaceState(null, "", "/server/email?m365_error=redirect_uri_mismatch&aadsts=50011");
    const { unmount } = wrap(<EmailSettingsSection scope="instance" />);
    await vi.waitFor(() => expect(screen.getByText(/Microsoft sign-in failed/)).toHaveTextContent(`The redirect URI isn't registered for this app (AADSTS50011). In the app registration → Authentication → Web, add exactly: ${REDIRECT}`));
    await vi.waitFor(() => expect(window.location.search).toBe(""));
    unmount();
    for (const [code, text] of [["consent_required", "Grant admin consent"], ["app_not_found", "(client) ID wasn't found"], ["bad_secret", "not its Secret ID"], ["access_denied", "cancelled or consent was declined"]] as const) {
      window.history.replaceState(null, "", `/server/email?m365_error=${code}`);
      const r = wrap(<EmailSettingsSection scope="instance" />);
      expect(await screen.findByText(/Microsoft sign-in failed/)).toHaveTextContent(text);
      r.unmount();
    }
    window.history.replaceState(null, "", "/server/email?m365=connected");
    wrap(<EmailSettingsSection scope="instance" />);
    expect(await screen.findByRole("status")).toHaveTextContent("Signed in with Microsoft. Send a test email to check.");
    expect(window.location.search).toBe("");
  });
});
