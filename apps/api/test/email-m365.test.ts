import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { makeTestApp, resetDb, createActiveUser } from "./helpers.js";
import { secretAad } from "../src/lib/mailer.js";
import { invalidateM365Token, M365_GRAPH_HOST, M365_LOGIN_HOST, setM365FetchForTests } from "../src/lib/m365.js";
import { settingsBox } from "../src/lib/settingsBox.js";

// Microsoft 365 email through Microsoft Graph (docs/email.md, "Microsoft 365 (Graph)"): client-credentials tokens,
// cached per settings row, sendMail as the sender mailbox, clear error messages, secrets never returned, both scopes.
const t = await makeTestApp();
afterAll(async () => { setM365FetchForTests(null); await t.app.close(); });

type U = Awaited<ReturnType<typeof createActiveUser>>;
let ipSeq = 0;
const call = (u: U, method: "GET" | "PUT" | "POST" | "DELETE", url: string, payload?: unknown, org: string | null = u.orgId) =>
  t.app.inject({ method, url: `/api/v1${url}`, payload: payload as object, remoteAddress: `10.170.${(++ipSeq >> 8) & 255}.${ipSeq & 255}`,
    headers: { authorization: `Bearer ${u.accessToken}`, ...(org ? { "x-org-id": org } : {}) } });

// ---- a fake Microsoft Entra token endpoint and Graph sendMail, behind the m365 test seam ----
interface App { secret: string; consent: boolean; mailboxes: string[] }
interface Tenant { id: string; domain: string; apps: Record<string, App> }
interface Sent { tenant: string; sender: string; body: { message: { subject: string; body: { contentType: string; content: string }; toRecipients: { emailAddress: { address: string } }[]; from?: { emailAddress: { address: string; name: string } } }; saveToSentItems: boolean } }
const fake = {
  tenants: [] as Tenant[],
  tokens: new Map<string, { tenant: string; clientId: string }>(),
  tokenCalls: [] as { tenant: string; form: Record<string, string> }[],
  sent: [] as Sent[],
  urls: [] as string[],
  expiresIn: 3599,
  /** Overrides the next responses of an endpoint. */
  tokenOverride: null as null | (() => Response),
  graphOverride: null as null | (() => Response),
};
const jsonRes = (status: number, body: unknown) => new Response(status === 202 ? null : JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
let tokenSeq = 0;
setM365FetchForTests(async (url, init) => {
  fake.urls.push(url);
  if (url.startsWith(`${M365_LOGIN_HOST}/`)) {
    const tenant = decodeURIComponent(/^https:\/\/login\.microsoftonline\.com\/([^/]+)\/oauth2\/v2\.0\/token$/.exec(url)![1]!);
    const form = Object.fromEntries(new URLSearchParams(String(init.body)));
    fake.tokenCalls.push({ tenant, form });
    if (fake.tokenOverride) return fake.tokenOverride();
    const ten = fake.tenants.find((x) => x.id === tenant || x.domain === tenant);
    if (!ten) return jsonRes(400, { error: "invalid_request", error_description: `AADSTS90002: Tenant '${tenant}' not found.`, error_codes: [90002] });
    const app = ten.apps[form.client_id!];
    if (!app) return jsonRes(400, { error: "unauthorized_client", error_description: `AADSTS700016: Application with identifier '${form.client_id}' was not found in the directory.`, error_codes: [700016] });
    if (app.secret !== form.client_secret) return jsonRes(401, { error: "invalid_client", error_description: `AADSTS7000215: Invalid client secret provided. ${form.client_secret}`, error_codes: [7000215] });
    expect(form).toMatchObject({ grant_type: "client_credentials", scope: "https://graph.microsoft.com/.default" });
    const token = `eyJ0eXAi.fake-token-${++tokenSeq}`;
    fake.tokens.set(token, { tenant: ten.id, clientId: form.client_id! });
    return jsonRes(200, { token_type: "Bearer", expires_in: fake.expiresIn, access_token: token });
  }
  if (url.startsWith(`${M365_GRAPH_HOST}/`)) {
    const sender = decodeURIComponent(/^https:\/\/graph\.microsoft\.com\/v1\.0\/users\/([^/]+)\/sendMail$/.exec(url)![1]!);
    if (fake.graphOverride) return fake.graphOverride();
    const auth = new Headers(init.headers).get("authorization") ?? "";
    const tok = fake.tokens.get(auth.replace(/^Bearer /, ""));
    if (!tok) return jsonRes(401, { error: { code: "InvalidAuthenticationToken", message: "Access token is empty." } });
    const ten = fake.tenants.find((x) => x.id === tok.tenant)!;
    const app = ten.apps[tok.clientId]!;
    if (!app.consent) return jsonRes(403, { error: { code: "ErrorAccessDenied", message: "Access is denied. Check credentials and try again." } });
    if (!app.mailboxes.includes(sender)) return jsonRes(404, { error: { code: "ErrorInvalidUser", message: `The requested user '${sender}' is invalid.` } });
    fake.sent.push({ tenant: ten.id, sender, body: JSON.parse(String(init.body)) as Sent["body"] });
    return jsonRes(202, null);
  }
  throw new Error(`unexpected fetch ${url}`);
});

const TENANT = "11111111-2222-4333-8444-555555555555";
const CLIENT = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
const SECRET = "Abc8Q~fakeClientSecretValue1234567890wxyz";
const OTHER_TENANT = "99999999-8888-4777-8666-555555555555";
const OTHER_CLIENT = "12345678-1234-4123-8123-123456789abc";
const OTHER_SECRET = "Zyx8Q~otherOrgSecretValue000000000000qrst";
const m365 = (over: Record<string, unknown> = {}) => ({ provider: "m365", fromName: "Northwind Vault", fromAddress: "vault@northwind.test", m365: { tenantId: TENANT, clientId: CLIENT }, secret: SECRET, ...over });

beforeEach(async () => {
  await resetDb(t.prisma);
  invalidateM365Token();
  fake.tenants = [
    { id: TENANT, domain: "northwind.onmicrosoft.com", apps: { [CLIENT]: { secret: SECRET, consent: true, mailboxes: ["vault@northwind.test"] } } },
    { id: OTHER_TENANT, domain: "beta.onmicrosoft.com", apps: { [OTHER_CLIENT]: { secret: OTHER_SECRET, consent: true, mailboxes: ["it@beta.test"] } } },
  ];
  fake.tokens.clear(); fake.tokenCalls.length = 0; fake.sent.length = 0; fake.urls.length = 0; fake.expiresIn = 3599;
  fake.tokenOverride = null; fake.graphOverride = null;
});
afterEach(() => { vi.restoreAllMocks(); delete t.config.hostedMode; });

async function instanceAdmin(): Promise<U> {
  const u = await createActiveUser(t, { role: "owner" });
  await t.prisma.user.update({ where: { id: u.id }, data: { instanceAdmin: true } });
  return u;
}
const newOrg = (name: string) => t.prisma.organization.create({ data: { name, slug: `${name.toLowerCase()}-${crypto.randomUUID().slice(0, 8)}` } });
const log = { warn: vi.fn() };
const sendInstance = (to: string) => t.app.mail.send(to, { subject: "Hello", text: "Body" }, log);

describe("settings", () => {
  it("saves tenant, client and sender; the client secret is sealed, bound to the row and never returned", async () => {
    const ia = await instanceAdmin();
    const r = await call(ia, "PUT", "/admin/instance/email", m365({ m365: { tenantId: ` ${TENANT.toUpperCase()} `, clientId: CLIENT.toUpperCase() } }), null);
    expect(r.statusCode).toBe(200);
    expect(r.json().settings).toMatchObject({ provider: "m365", fromName: "Northwind Vault", fromAddress: "vault@northwind.test", smtp: null,
      m365: { tenantId: TENANT, clientId: CLIENT }, secret: { set: true, last4: "wxyz" } });
    const row = await t.prisma.emailSettings.findUniqueOrThrow({ where: { scope: "instance" } });
    expect(row.secretEnc).toMatch(/^v1\./);
    expect(row.secretEnc).not.toContain(SECRET);
    expect(settingsBox(t.config.serverSecret).open(row.secretEnc!, secretAad(row))).toBe(SECRET);
    const g = await call(ia, "GET", "/admin/instance/email", undefined, null);
    for (const res of [r, g]) { expect(res.body).not.toContain(SECRET); expect(res.body).not.toContain(row.secretEnc!); }
    // Audit: which fields, never the secret.
    const ev = await t.prisma.event.findMany({ where: { action: { startsWith: "email." } } });
    expect(JSON.stringify(ev.map((e) => e.meta))).not.toContain(SECRET);
  });

  it("validates the tenant (GUID or domain) and client ID (GUID), and needs a client secret", async () => {
    const ia = await instanceAdmin();
    for (const tenantId of ["not a tenant", "https://evil.test/x", "evil.test/../x", "localhost", "a".repeat(300) + ".com", "common/oauth"]) {
      const r = await call(ia, "PUT", "/admin/instance/email", m365({ m365: { tenantId, clientId: CLIENT } }), null);
      expect(r.statusCode, tenantId).toBe(400);
      expect(r.json()).toMatchObject({ error: "invalid_request", issues: ["m365.tenantId"] });
    }
    for (const clientId of ["northwind-vault", `${CLIENT}x`, ""]) {
      expect((await call(ia, "PUT", "/admin/instance/email", m365({ m365: { tenantId: TENANT, clientId } }), null)).json()).toMatchObject({ issues: ["m365.clientId"] });
    }
    expect((await call(ia, "PUT", "/admin/instance/email", m365({ m365: undefined }), null)).json()).toEqual({ error: "invalid_request", issues: ["m365"] });
    expect((await call(ia, "PUT", "/admin/instance/email", m365({ secret: undefined }), null)).json()).toEqual({ error: "secret_required" });
    expect((await call(ia, "PUT", "/admin/instance/email", m365({ m365: { tenantId: "northwind.onmicrosoft.com", clientId: CLIENT } }), null)).statusCode).toBe(200);
  });

  it("keeps the secret only for the same tenant and app; switching provider drops it", async () => {
    const ia = await instanceAdmin();
    await call(ia, "PUT", "/admin/instance/email", m365(), null);
    const kept = await call(ia, "PUT", "/admin/instance/email", m365({ secret: undefined, fromName: "Other" }), null);
    expect(kept.json().settings.secret).toEqual({ set: true, last4: "wxyz" });
    expect((await call(ia, "PUT", "/admin/instance/email", m365({ secret: undefined, m365: { tenantId: OTHER_TENANT, clientId: CLIENT } }), null)).json()).toEqual({ error: "secret_required" });
    expect((await call(ia, "PUT", "/admin/instance/email", m365({ secret: undefined, m365: { tenantId: TENANT, clientId: OTHER_CLIENT } }), null)).json()).toEqual({ error: "secret_required" });
    await call(ia, "PUT", "/admin/instance/email", { provider: "resend", fromAddress: "a@northwind.test", secret: "re_live_ABCDEFGHIJKL_9876" }, null);
    expect((await call(ia, "PUT", "/admin/instance/email", m365({ secret: undefined }), null)).json()).toEqual({ error: "secret_required" });
    const row = await t.prisma.emailSettings.findUniqueOrThrow({ where: { scope: "instance" } });
    expect([row.m365TenantId, row.m365ClientId]).toEqual([null, null]);
  });

  it("instance settings: instance admins only; org settings: that org's owners and admins only", async () => {
    const ia = await instanceAdmin();
    const admin = await createActiveUser(t, { role: "admin" });
    const member = await createActiveUser(t, { role: "member" });
    for (const u of [admin, member]) {
      expect((await call(u, "PUT", "/admin/instance/email", m365(), null)).statusCode).toBe(403);
      expect((await call(u, "POST", "/admin/instance/email/test", {}, null)).statusCode).toBe(403);
    }
    expect((await call(member, "PUT", "/admin/settings/email", m365())).statusCode).toBe(403);
    expect((await call(member, "POST", "/admin/settings/email/test", {})).statusCode).toBe(403);
    expect((await call(admin, "PUT", "/admin/settings/email", m365())).statusCode).toBe(200);
    expect((await call(ia, "PUT", "/admin/instance/email", m365(), null)).statusCode).toBe(200);
    const other = await newOrg("Other");
    const otherOwner = await createActiveUser(t, { role: "owner", orgId: other.id });
    expect((await call(otherOwner, "GET", "/admin/settings/email", undefined, admin.orgId)).statusCode).toBe(403);
    expect((await call(otherOwner, "POST", "/admin/settings/email/test", {}, admin.orgId)).statusCode).toBe(403);
    expect(fake.urls).toEqual([]);
  });
});

describe("sending", () => {
  it("test email: client-credentials token, then sendMail as the sender mailbox", async () => {
    const ia = await instanceAdmin();
    await call(ia, "PUT", "/admin/instance/email", m365(), null);
    const r = await call(ia, "POST", "/admin/instance/email/test", {}, null);
    expect(r.json()).toEqual({ ok: true, to: ia.email });
    expect(fake.tokenCalls).toEqual([{ tenant: TENANT, form: { grant_type: "client_credentials", client_id: CLIENT, client_secret: SECRET, scope: "https://graph.microsoft.com/.default" } }]);
    expect(fake.urls).toEqual([`${M365_LOGIN_HOST}/${TENANT}/oauth2/v2.0/token`, `${M365_GRAPH_HOST}/v1.0/users/vault%40northwind.test/sendMail`]);
    expect(fake.sent).toHaveLength(1);
    expect(fake.sent[0]).toMatchObject({ tenant: TENANT, sender: "vault@northwind.test", body: {
      message: { subject: "Clane Vault: test email", body: { contentType: "Text", content: expect.stringContaining("Microsoft 365 (vault@northwind.test)") },
        toRecipients: [{ emailAddress: { address: ia.email } }], from: { emailAddress: { address: "vault@northwind.test", name: "Northwind Vault" } } },
      saveToSentItems: false } });
    expect((await t.prisma.event.findFirstOrThrow({ where: { action: "email.test" } })).meta).toMatchObject({ ok: true, provider: "m365" });
  });

  it("caches the token per settings row until about 5 minutes before it expires, and on settings change gets a new one", async () => {
    const ia = await instanceAdmin();
    await call(ia, "PUT", "/admin/instance/email", m365(), null);
    const t0 = Date.now();
    const now = vi.spyOn(Date, "now").mockReturnValue(t0);
    expect(await sendInstance("a@x.test")).toBe(true);
    expect(await sendInstance("b@x.test")).toBe(true);
    expect(fake.tokenCalls).toHaveLength(1);
    now.mockReturnValue(t0 + (3599 - 301) * 1000); // still more than 5 minutes left
    expect(await sendInstance("c@x.test")).toBe(true);
    expect(fake.tokenCalls).toHaveLength(1);
    now.mockReturnValue(t0 + (3599 - 299) * 1000); // within 5 minutes of expiry: refresh
    expect(await sendInstance("d@x.test")).toBe(true);
    expect(fake.tokenCalls).toHaveLength(2);
    now.mockRestore();
    // Concurrent sends share one token request.
    invalidateM365Token();
    await Promise.all([sendInstance("e@x.test"), sendInstance("f@x.test"), sendInstance("g@x.test")]);
    expect(fake.tokenCalls).toHaveLength(3);
    // A settings change (even without a new secret) drops the cached token.
    await call(ia, "PUT", "/admin/instance/email", m365({ secret: undefined, fromName: "Renamed" }), null);
    expect(await sendInstance("h@x.test")).toBe(true);
    expect(fake.tokenCalls).toHaveLength(4);
    // e, f and g went out concurrently, in no defined order.
    expect(fake.sent.map((s) => s.body.message.toRecipients[0]!.emailAddress.address).sort()).toEqual(["a@x.test", "b@x.test", "c@x.test", "d@x.test", "e@x.test", "f@x.test", "g@x.test", "h@x.test"]);
  });

  it("a revoked cached token is replaced once and the email still goes out", async () => {
    const ia = await instanceAdmin();
    await call(ia, "PUT", "/admin/instance/email", m365(), null);
    expect(await sendInstance("a@x.test")).toBe(true);
    fake.tokens.clear(); // Microsoft no longer accepts the cached token
    expect(await sendInstance("b@x.test")).toBe(true);
    expect(fake.tokenCalls).toHaveLength(2);
    expect(fake.sent).toHaveLength(2);
  });

  it("maps Microsoft errors to clear messages without secrets or tokens", async () => {
    const ia = await instanceAdmin();
    const test = async () => {
      invalidateM365Token();
      const r = await call(ia, "POST", "/admin/instance/email/test", {}, null);
      expect(r.statusCode).toBe(502);
      expect(r.json().error).toBe("email_test_failed");
      for (const s of [SECRET, "fake-token", "eyJ0eXAi", "Access is denied", "requested user"]) expect(r.body).not.toContain(s);
      return r.json().detail as string;
    };
    await call(ia, "PUT", "/admin/instance/email", m365({ secret: "Wrong8Q~notTheRightSecret00000000000000abcd" }), null);
    expect(await test()).toMatch(/rejected the client secret \(AADSTS7000215\).*Value \(not its Secret ID\)/);
    await call(ia, "PUT", "/admin/instance/email", m365({ m365: { tenantId: TENANT, clientId: OTHER_CLIENT } }), null);
    expect(await test()).toMatch(/application \(client\) ID wasn't found in this tenant \(AADSTS700016\)/);
    await call(ia, "PUT", "/admin/instance/email", m365({ m365: { tenantId: "nowhere.onmicrosoft.com", clientId: CLIENT } }), null);
    expect(await test()).toMatch(/can't find that tenant \(AADSTS90002\)/);
    await call(ia, "PUT", "/admin/instance/email", m365(), null);
    fake.tokenOverride = () => jsonRes(401, { error: "invalid_client", error_description: "AADSTS7000222: The provided client secret keys for app are expired.", error_codes: [7000222] });
    expect(await test()).toMatch(/client secret has expired \(AADSTS7000222\)/);
    fake.tokenOverride = () => jsonRes(400, { error: "invalid_request", error_description: "AADSTS12345: Something else." });
    expect(await test()).toBe("Microsoft 365 sign-in failed (AADSTS12345). Check the tenant ID, client ID and secret.");
    fake.tokenOverride = () => { throw Object.assign(new Error("timed out"), { name: "TimeoutError" }); };
    expect(await test()).toBe("No answer from login.microsoftonline.com within 10 s.");
    fake.tokenOverride = null;
    // Graph: no Mail.Send consent (or a policy excluding the mailbox) → 403 ErrorAccessDenied.
    fake.tenants[0]!.apps[CLIENT]!.consent = false;
    expect(await test()).toMatch(/denied sending as vault@northwind\.test \(ErrorAccessDenied\): the app needs the Microsoft Graph Mail\.Send application permission with admin consent.*Application Access Policy/);
    fake.tenants[0]!.apps[CLIENT]!.consent = true;
    // The sender mailbox doesn't exist (or has no Exchange Online mailbox).
    await call(ia, "PUT", "/admin/instance/email", m365({ secret: undefined, fromAddress: "nobody@northwind.test" }), null);
    expect(await test()).toMatch(/sender mailbox nobody@northwind\.test wasn't found.*Exchange Online.*\(ErrorInvalidUser\)/);
    for (const code of ["ResourceNotFound", "MailboxNotEnabledForRESTAPI"]) {
      fake.graphOverride = () => jsonRes(404, { error: { code, message: "whatever" } });
      expect(await test()).toMatch(new RegExp(`wasn't found.*\\(${code}\\)`));
    }
    fake.graphOverride = () => jsonRes(403, { error: { code: "ErrorAccessDenied", message: "Access to OData is disabled: [RAOP] : Blocked by tenant configured AppOnly AccessPolicy settings." } });
    expect(await test()).toMatch(/Application Access Policy/);
    fake.graphOverride = () => jsonRes(429, { error: { code: "TooManyRequests" } });
    expect(await test()).toMatch(/throttling/);
    fake.graphOverride = () => jsonRes(500, { error: { code: "<script>", message: SECRET } });
    expect(await test()).toBe("Microsoft 365 refused the email (HTTP 500).");
    // Nothing but the two Microsoft hosts was ever called.
    expect(fake.urls.every((u) => u.startsWith(`${M365_LOGIN_HOST}/`) || u.startsWith(`${M365_GRAPH_HOST}/`))).toBe(true);
    expect(JSON.stringify(log.warn.mock.calls)).not.toContain(SECRET);
  });
});

describe("scopes", () => {
  it("each organisation sends with its own app and tenant; tokens and settings never cross organisations", async () => {
    const ia = await instanceAdmin();
    const beta = await newOrg("Beta");
    const betaOwner = await createActiveUser(t, { role: "owner", orgId: beta.id });
    await call(ia, "PUT", "/admin/settings/email", m365());
    await call(betaOwner, "PUT", "/admin/settings/email", m365({ fromName: "Beta IT", fromAddress: "it@beta.test", m365: { tenantId: OTHER_TENANT, clientId: OTHER_CLIENT }, secret: OTHER_SECRET }));
    // Beta's owner sees only Beta's settings.
    const g = await call(betaOwner, "GET", "/admin/settings/email");
    expect(g.json().settings.m365).toEqual({ tenantId: OTHER_TENANT, clientId: OTHER_CLIENT, authMode: "app", delegated: null });
    expect(g.body).not.toContain(TENANT);
    expect(g.body).not.toContain(OTHER_SECRET);
    expect((await call(ia, "POST", "/admin/invites", { email: "one@x.test" })).json()).toMatchObject({ emailed: true });
    expect((await call(betaOwner, "POST", "/admin/invites", { email: "two@x.test" })).json()).toMatchObject({ emailed: true });
    await vi.waitFor(() => expect(fake.sent).toHaveLength(2));
    const by = (to: string) => fake.sent.find((s) => s.body.message.toRecipients[0]!.emailAddress.address === to)!;
    expect(by("one@x.test")).toMatchObject({ tenant: TENANT, sender: "vault@northwind.test" });
    expect(by("two@x.test")).toMatchObject({ tenant: OTHER_TENANT, sender: "it@beta.test" });
    expect(by("two@x.test").body.message.subject).toMatch(/Beta/);
    expect(fake.tokenCalls.map((c) => [c.tenant, c.form.client_id])).toEqual(expect.arrayContaining([[TENANT, CLIENT], [OTHER_TENANT, OTHER_CLIENT]]));
    // Removing Beta's override drops its token; Beta then uses the instance's settings (none here: the environment's, none).
    await call(betaOwner, "DELETE", "/admin/settings/email");
    expect(await t.app.mail.resolve(beta.id)).toBeNull();
  });

  it("security notices use the instance's Microsoft 365 settings even when the organisation has its own", async () => {
    const ia = await instanceAdmin();
    await call(ia, "PUT", "/admin/instance/email", m365({ fromName: "Server" }), null);
    await call(ia, "PUT", "/admin/settings/email", m365({ fromAddress: "it@beta.test", m365: { tenantId: OTHER_TENANT, clientId: OTHER_CLIENT }, secret: OTHER_SECRET }));
    expect(await t.app.mail.resolve(null)).toMatchObject({ source: "instance", provider: "m365", tenantId: TENANT });
    const { recoveryAdminActionEmail, sendEmail } = await import("../src/lib/email.js");
    expect(await sendEmail(t.app.mail, ia.email, recoveryAdminActionEmail(t.config.productName, "approved", "Admin", "Test org"), t.app.log)).toBe(true);
    expect(fake.sent).toHaveLength(1);
    expect(fake.sent[0]).toMatchObject({ tenant: TENANT, sender: "vault@northwind.test", body: { message: { from: { emailAddress: { name: "Server" } } } } });
    expect(fake.tokenCalls.map((c) => c.tenant)).toEqual([TENANT]);
  });

  it("works in hosted mode for organisations (the Microsoft hosts are fixed, nothing to resolve)", async () => {
    const ia = await instanceAdmin();
    t.config.hostedMode = true;
    expect((await call(ia, "PUT", "/admin/settings/email", m365())).statusCode).toBe(200);
    expect((await call(ia, "POST", "/admin/settings/email/test", {})).json()).toEqual({ ok: true, to: ia.email });
  });
});
