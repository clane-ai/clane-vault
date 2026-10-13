import { createHash, randomUUID } from "node:crypto";
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createActiveUser, makeTestApp, resetDb } from "./helpers.js";
import { refreshAad, secretAad } from "../src/lib/mailer.js";
import { invalidateM365Token, M365_GRAPH_HOST, M365_LOGIN_HOST, setM365FetchForTests } from "../src/lib/m365.js";
import { m365RedirectUri } from "../src/routes/emailSettings.js";
import { redactInviteUrl } from "../src/app.js";
import { settingsBox } from "../src/lib/settingsBox.js";

// Microsoft 365 delegated sign-in (docs/email.md, "Microsoft 365 — delegated sign-in"): authorization code flow with
// PKCE, state and nonce; the refresh token sealed, rotated on every refresh; invalid_grant → needs reconnect; sending
// with /me/sendMail (from = shared mailbox); authorisation and cross-org isolation.
const t = await makeTestApp();
const box = settingsBox(t.config.serverSecret);
afterAll(async () => { setM365FetchForTests(null); await t.app.close(); });

type U = Awaited<ReturnType<typeof createActiveUser>>;
let ipSeq = 0;
const call = (u: U, method: "GET" | "PUT" | "POST" | "DELETE", url: string, payload?: unknown, org: string | null = u.orgId) =>
  t.app.inject({ method, url: `/api/v1${url}`, payload: payload as object, remoteAddress: `10.171.${(++ipSeq >> 8) & 255}.${ipSeq & 255}`,
    headers: { authorization: `Bearer ${u.accessToken}`, ...(org ? { "x-org-id": org } : {}) } });

const TENANT = "11111111-2222-4333-8444-555555555555";
const CLIENT = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
const SECRET = "Abc8Q~fakeClientSecretValue1234567890wxyz";
const REDIRECT = "http://localhost:5173/api/v1/admin/email/m365/callback";

// ---- a fake Microsoft identity platform (authorize, token) and Graph (/me, /me/sendMail), behind the m365 test seam ----
interface Person { id: string; upn: string; sendAs: string[] }
interface Grant { tenant: string; clientId: string; redirectUri: string; challenge: string; nonce: string; scope: string; person: Person }
interface Sent { url: string; token: string; body: { message: { from?: { emailAddress: { address: string; name?: string } }; toRecipients: { emailAddress: { address: string } }[]; subject: string }; saveToSentItems: boolean } }
const b64u = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
const jsonRes = (status: number, body: unknown) => new Response(status === 202 ? null : JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
const fake = {
  people: [] as Person[],
  codes: new Map<string, Grant>(),
  access: new Map<string, { person: Person; scope: string }>(),
  refresh: new Map<string, { person: Person; scope: string; clientId: string }>(),
  tokenCalls: [] as Record<string, string>[],
  sent: [] as Sent[],
  urls: [] as string[],
  /** Scope the token endpoint says it granted (null: what was asked). */
  grantedScope: null as string | null,
  idTokenOver: {} as Record<string, unknown>,
  tokenOverride: null as null | (() => Response),
  noRefreshToken: false,
};
let seq = 0;
function issue(person: Person, scope: string, clientId: string) {
  const access = `eyJ0eXAi.delegated-access-${++seq}`;
  const refresh = `0.AXoA-refresh-token-${seq}-${randomUUID()}`;
  fake.access.set(access, { person, scope });
  fake.refresh.set(refresh, { person, scope, clientId });
  return { access, refresh };
}
const fakeFetch = async (url: string, init: RequestInit): Promise<Response> => {
  fake.urls.push(url);
  if (url === `${M365_LOGIN_HOST}/${TENANT}/oauth2/v2.0/token`) {
    const form = Object.fromEntries(new URLSearchParams(String(init.body)));
    fake.tokenCalls.push(form);
    if (fake.tokenOverride) return fake.tokenOverride();
    if (form.client_id !== CLIENT) return jsonRes(400, { error: "unauthorized_client", error_description: "AADSTS700016: Application not found.", error_codes: [700016] });
    if (form.client_secret !== SECRET) return jsonRes(401, { error: "invalid_client", error_description: "AADSTS7000215: Invalid client secret provided.", error_codes: [7000215] });
    if (form.grant_type === "authorization_code") {
      const g = fake.codes.get(form.code!);
      fake.codes.delete(form.code!);
      if (!g) return jsonRes(400, { error: "invalid_grant", error_description: "AADSTS54005: OAuth2 Authorization code was already redeemed.", error_codes: [54005] });
      if (g.redirectUri !== form.redirect_uri) return jsonRes(400, { error: "invalid_grant", error_description: "AADSTS50011: redirect URI mismatch.", error_codes: [50011] });
      if (createHash("sha256").update(form.code_verifier ?? "").digest("base64url") !== g.challenge)
        return jsonRes(400, { error: "invalid_grant", error_description: "AADSTS501481: The Code_Verifier does not match the code_challenge supplied in the authorization request.", error_codes: [501481] });
      const scope = fake.grantedScope ?? g.scope.split(" ").filter((s) => s.startsWith("https://")).join(" ");
      const { access, refresh } = issue(g.person, scope, form.client_id!);
      const id = { aud: CLIENT, tid: TENANT, oid: g.person.id, nonce: g.nonce, exp: Math.floor(Date.now() / 1000) + 3600, preferred_username: g.person.upn, ...fake.idTokenOver };
      return jsonRes(200, { token_type: "Bearer", scope, expires_in: 3599, access_token: access, ...(fake.noRefreshToken ? {} : { refresh_token: refresh }), id_token: `${b64u({ alg: "RS256" })}.${b64u(id)}.sig` });
    }
    if (form.grant_type === "refresh_token") {
      const r = fake.refresh.get(form.refresh_token!);
      if (!r) return jsonRes(400, { error: "invalid_grant", error_description: "AADSTS50173: The provided grant has expired due to it being revoked.", error_codes: [50173] });
      fake.refresh.delete(form.refresh_token!); // rotation: the old one is used up
      const { access, refresh } = issue(r.person, r.scope, r.clientId);
      return jsonRes(200, { token_type: "Bearer", scope: r.scope, expires_in: 3599, access_token: access, refresh_token: refresh });
    }
    throw new Error(`unexpected grant ${form.grant_type}`);
  }
  if (url.startsWith(`${M365_GRAPH_HOST}/v1.0/me`)) {
    const token = (new Headers(init.headers).get("authorization") ?? "").replace(/^Bearer /, "");
    const a = fake.access.get(token);
    if (!a) return jsonRes(401, { error: { code: "InvalidAuthenticationToken" } });
    if (url === `${M365_GRAPH_HOST}/v1.0/me?$select=id,userPrincipalName`) return jsonRes(200, { id: a.person.id, userPrincipalName: a.person.upn.toUpperCase() });
    if (url === `${M365_GRAPH_HOST}/v1.0/me/sendMail`) {
      const body = JSON.parse(String(init.body)) as Sent["body"];
      const from = body.message.from?.emailAddress.address;
      if (from && from !== a.person.upn) {
        if (!a.scope.includes("Mail.Send.Shared")) return jsonRes(403, { error: { code: "ErrorAccessDenied" } });
        if (!a.person.sendAs.includes(from)) return jsonRes(403, { error: { code: "ErrorSendAsDenied", message: "The user account which was used to submit this request does not have the right to send mail on behalf of the specified sending account." } });
      }
      fake.sent.push({ url, token, body });
      return jsonRes(202, null);
    }
  }
  throw new Error(`unexpected fetch ${url}`);
};
setM365FetchForTests(fakeFetch);

/** The browser at Microsoft: checks the authorize request and comes back with a code (or an error). */
function authorize(urlStr: string, person: Person) {
  const u = new URL(urlStr);
  expect(u.origin).toBe(M365_LOGIN_HOST);
  expect(u.pathname).toBe(`/${TENANT}/oauth2/v2.0/authorize`);
  const p = Object.fromEntries(u.searchParams);
  expect(p).toMatchObject({ client_id: CLIENT, response_type: "code", redirect_uri: REDIRECT, response_mode: "query", code_challenge_method: "S256" });
  expect(p.state!.length).toBeGreaterThanOrEqual(40);
  expect(p.nonce!.length).toBeGreaterThanOrEqual(40);
  const code = `M.C5_BAY.2.U.code-${randomUUID()}`;
  fake.codes.set(code, { tenant: TENANT, clientId: p.client_id!, redirectUri: p.redirect_uri!, challenge: p.code_challenge!, nonce: p.nonce!, scope: p.scope!, person });
  return { code, state: p.state!, scope: p.scope!.split(" ") };
}

const cookieOf = (res: { cookies: { name: string; value: string; path?: string; httpOnly?: boolean; sameSite?: string }[] }) => res.cookies.find((c) => c.name === "cv_m365");
const callback = (query: Record<string, string>, cookie?: string) =>
  t.app.inject({ method: "GET", url: `/api/v1/admin/email/m365/callback?${new URLSearchParams(query)}`, remoteAddress: `10.172.${(++ipSeq >> 8) & 255}.${ipSeq & 255}`, headers: cookie ? { cookie: `cv_m365=${cookie}` } : {} });

/** POST connect → Microsoft → callback. Returns the callback's response and the redirect target. */
async function signIn(u: U, base: string, person: Person, org: string | null = u.orgId, tweak?: (q: Record<string, string>) => void) {
  const c = await call(u, "POST", `${base}/m365/connect`, undefined, org);
  expect(c.statusCode).toBe(200);
  const cookie = cookieOf(c)!;
  const a = authorize(c.json().url as string, person);
  const q = { code: a.code, state: a.state, session_state: "abc" };
  tweak?.(q);
  const r = await callback(q, cookie.value);
  return { r, location: new URL(String(r.headers.location ?? "http://x.invalid/")), cookie, scope: a.scope, state: a.state, code: a.code };
}

const delegated = (over: Record<string, unknown> = {}) => ({ provider: "m365", fromName: null, fromAddress: "", m365: { tenantId: TENANT, clientId: CLIENT, authMode: "delegated" }, secret: SECRET, ...over });
let admin: Person, other: Person;

beforeEach(async () => {
  await resetDb(t.prisma);
  await t.prisma.emailSettings.deleteMany({});
  await t.prisma.m365Connect.deleteMany({});
  invalidateM365Token();
  admin = { id: randomUUID(), upn: "admin@northwind.test", sendAs: ["shared@northwind.test"] };
  other = { id: randomUUID(), upn: "helpdesk@northwind.test", sendAs: [] };
  fake.people = [admin, other];
  fake.codes.clear(); fake.access.clear(); fake.refresh.clear();
  fake.tokenCalls.length = 0; fake.sent.length = 0; fake.urls.length = 0;
  fake.grantedScope = null; fake.idTokenOver = {}; fake.tokenOverride = null; fake.noRefreshToken = false;
});
afterEach(() => { vi.restoreAllMocks(); delete t.config.resendApiKey; delete t.config.emailFrom; });

async function instanceAdmin(): Promise<U> {
  const u = await createActiveUser(t, { role: "owner" });
  await t.prisma.user.update({ where: { id: u.id }, data: { instanceAdmin: true } });
  return u;
}
const newOrg = (name: string) => t.prisma.organization.create({ data: { name, slug: `${name.toLowerCase()}-${randomUUID().slice(0, 8)}` } });
const log = { warn: vi.fn() };
const instanceRow = () => t.prisma.emailSettings.findUniqueOrThrow({ where: { scope: "instance" } });

describe("delegated sign-in: settings", () => {
  it("saves delegated mode with an empty sender (the signed-in account) and shows the redirect URI to register", async () => {
    const ia = await instanceAdmin();
    const r = await call(ia, "PUT", "/admin/instance/email", delegated(), null);
    expect(r.statusCode).toBe(200);
    expect(r.json()).toMatchObject({ m365RedirectUri: REDIRECT, settings: { provider: "m365", fromAddress: "",
      m365: { tenantId: TENANT, clientId: CLIENT, authMode: "delegated", delegated: { account: null, connectedAt: null, reconnect: null } } } });
    // An empty sender is only for delegated.
    const app = await call(ia, "PUT", "/admin/instance/email", delegated({ m365: { tenantId: TENANT, clientId: CLIENT, authMode: "app" } }), null);
    expect(app.statusCode).toBe(400);
    expect(app.json().issues).toEqual(["fromAddress"]);
    // Existing app-only rows read as "app".
    await call(ia, "PUT", "/admin/instance/email", { provider: "m365", fromAddress: "vault@northwind.test", m365: { tenantId: TENANT, clientId: CLIENT }, secret: SECRET }, null);
    expect((await call(ia, "GET", "/admin/instance/email", undefined, null)).json().settings.m365).toMatchObject({ authMode: "app", delegated: null });
  });

  it("the redirect URI follows PUBLIC_URL, base path included", () => {
    expect(m365RedirectUri({ publicUrl: "https://h.test/vault" })).toBe("https://h.test/vault/api/v1/admin/email/m365/callback");
    expect(redactInviteUrl("/vault/api/v1/admin/email/m365/callback?code=SECRETCODE&state=s")).toBe("/vault/api/v1/admin/email/m365/callback?[redacted]");
  });
});

describe("delegated sign-in: the code flow", () => {
  it("connects: PKCE, state and nonce, the refresh token sealed and never returned, then sends with /me/sendMail", async () => {
    const ia = await instanceAdmin();
    await call(ia, "PUT", "/admin/instance/email", delegated({ fromName: "Northwind Vault" }), null);
    const { r, location, cookie, scope } = await signIn(ia, "/admin/instance/email", admin, null);
    expect(cookie).toMatchObject({ httpOnly: true, sameSite: "Lax", path: "/api/v1/admin/email/m365" });
    expect(scope).toEqual(expect.arrayContaining(["offline_access", "openid", "email", "profile", "https://graph.microsoft.com/Mail.Send", "https://graph.microsoft.com/User.Read"]));
    expect(scope).not.toContain("https://graph.microsoft.com/Mail.Send.Shared");
    expect(r.statusCode).toBe(302);
    expect(`${location.origin}${location.pathname}${location.search}`).toBe("http://localhost:5173/server/email?m365=connected");
    // The code was redeemed server-side with the client secret, the PKCE verifier and the same redirect URI.
    const redeem = fake.tokenCalls.find((f) => f.grant_type === "authorization_code")!;
    expect(redeem).toMatchObject({ client_id: CLIENT, client_secret: SECRET, redirect_uri: REDIRECT });
    expect(redeem.code_verifier!.length).toBeGreaterThanOrEqual(43);

    const row = await instanceRow();
    const rt = [...fake.refresh.keys()][0]!;
    expect(row).toMatchObject({ m365Account: "admin@northwind.test", m365ConnectedById: ia.id, m365ReconnectAt: null });
    expect(row.m365RefreshEnc).toMatch(/^v1\./);
    expect(row.m365RefreshEnc).not.toContain(rt);
    expect(box.open(row.m365RefreshEnc!, refreshAad(row))).toBe(rt);
    // Bound to its purpose: it doesn't open as the row's secret.
    expect(() => box.open(row.m365RefreshEnc!, secretAad(row))).toThrow();
    const g = await call(ia, "GET", "/admin/instance/email", undefined, null);
    expect(g.json().settings.m365.delegated).toMatchObject({ account: "admin@northwind.test", connectedBy: { id: ia.id }, reconnect: null, sharedScopeMissing: false });
    for (const res of [g, r]) { expect(res.body).not.toContain(rt); expect(res.body).not.toContain(row.m365RefreshEnc!); }
    const ev = await t.prisma.event.findMany({ where: { action: "email.m365_connected" } });
    expect(ev).toHaveLength(1);
    expect(ev[0]!.meta).toMatchObject({ scope: "instance", account: "admin@northwind.test" });
    expect(JSON.stringify((await t.prisma.event.findMany()).map((e) => e.meta))).not.toContain(rt);
    // The request is single use and gone from the table's live set.
    expect((await t.prisma.m365Connect.findFirstOrThrow()).usedAt).not.toBeNull();

    // Sending: refresh (rotating the refresh token, persisted), then /me/sendMail as the signed-in account.
    expect(await t.app.mail.send("bob@else.test", { subject: "Hi", text: "Body" }, log)).toBe(true);
    expect(fake.sent).toHaveLength(1);
    expect(fake.sent[0]!.url).toBe(`${M365_GRAPH_HOST}/v1.0/me/sendMail`);
    expect(fake.sent[0]!.body.message.from).toEqual({ emailAddress: { address: "admin@northwind.test", name: "Northwind Vault" } });
    const after = await instanceRow();
    const rt2 = [...fake.refresh.keys()][0]!;
    expect(rt2).not.toBe(rt);
    expect(after.m365RefreshVersion).toBe(row.m365RefreshVersion + 1);
    expect(box.open(after.m365RefreshEnc!, refreshAad(after))).toBe(rt2);
    expect(fake.tokenCalls.at(-1)).toMatchObject({ grant_type: "refresh_token", client_secret: SECRET, refresh_token: rt });
    // The access token is cached: a second email doesn't refresh again.
    const calls = fake.tokenCalls.length;
    expect(await t.app.mail.send("bob@else.test", { subject: "Hi", text: "Body" }, log)).toBe(true);
    expect(fake.tokenCalls.length).toBe(calls);
    // The test email works too.
    const te = await call(ia, "POST", "/admin/instance/email/test", undefined, null);
    expect(te.statusCode).toBe(200);
    // Only the two Microsoft hosts were called.
    expect(fake.urls.every((u) => u.startsWith(`${M365_LOGIN_HOST}/`) || u.startsWith(`${M365_GRAPH_HOST}/`))).toBe(true);
  });

  it("rejects a bad PKCE verifier, a wrong nonce, audience or tenant in the id_token, and a missing refresh token", async () => {
    const ia = await instanceAdmin();
    await call(ia, "PUT", "/admin/instance/email", delegated(), null);
    // PKCE: the verifier stored for the request no longer matches the challenge sent to Microsoft.
    const c = await call(ia, "POST", "/admin/instance/email/m365/connect", undefined, null);
    await t.prisma.m365Connect.updateMany({ data: { codeVerifier: "x".repeat(64) } });
    const a = authorize(c.json().url, admin);
    const r = await callback({ code: a.code, state: a.state }, cookieOf(c)!.value);
    expect(Object.fromEntries(new URL(r.headers.location as string).searchParams)).toEqual({ m365_error: "failed", aadsts: "501481" });
    for (const over of [{ nonce: "another-nonce" }, { aud: "12345678-1234-4123-8123-123456789abc" }, { tid: "99999999-8888-4777-8666-555555555555" }, { exp: 1000 }]) {
      fake.idTokenOver = over;
      const { location } = await signIn(ia, "/admin/instance/email", admin, null);
      expect(location.searchParams.get("m365_error"), JSON.stringify(over)).toBe("id_token");
    }
    fake.idTokenOver = {};
    fake.noRefreshToken = true;
    expect((await signIn(ia, "/admin/instance/email", admin, null)).location.searchParams.get("m365_error")).toBe("no_refresh_token");
    expect((await instanceRow()).m365RefreshEnc).toBeNull();
    expect(await t.prisma.event.count({ where: { action: "email.m365_connect_failed" } })).toBe(6);
  });

  it("state: another browser, no cookie, a replay, an expired or unknown state are refused", async () => {
    const ia = await instanceAdmin();
    await call(ia, "PUT", "/admin/instance/email", delegated(), null);
    const c = await call(ia, "POST", "/admin/instance/email/m365/connect", undefined, null);
    const a = authorize(c.json().url, admin);
    const err = (r: { headers: Record<string, unknown> }) => new URL(r.headers.location as string).searchParams.get("m365_error");
    expect(err(await callback({ code: a.code, state: a.state }, "someone-elses-cookie-value-xxxxxxxxxxxx"))).toBe("state");
    expect(err(await callback({ code: a.code, state: a.state }))).toBe("state");
    const ok = await callback({ code: a.code, state: a.state }, cookieOf(c)!.value);
    expect(new URL(ok.headers.location as string).searchParams.get("m365")).toBe("connected");
    expect(err(await callback({ code: a.code, state: a.state }, cookieOf(c)!.value))).toBe("state"); // replay
    const c2 = await call(ia, "POST", "/admin/instance/email/m365/connect", undefined, null);
    const a2 = authorize(c2.json().url, admin);
    await t.prisma.m365Connect.updateMany({ where: { usedAt: null }, data: { expiresAt: new Date(Date.now() - 1000) } });
    expect(err(await callback({ code: a2.code, state: a2.state }, cookieOf(c2)!.value))).toBe("state");
    const unknown = await callback({ code: "x", state: "not-a-state" }, cookieOf(c2)!.value);
    expect(unknown.statusCode).toBe(400);
    expect(unknown.headers.location).toBeUndefined();
  });

  it("only the admin who started it, still an admin, from a live session, for unchanged settings", async () => {
    const ia = await instanceAdmin();
    await call(ia, "PUT", "/admin/instance/email", delegated(), null);
    expect((await signIn(ia, "/admin/instance/email", admin, null)).location.searchParams.get("m365")).toBe("connected");
    // No longer an instance admin by the time Microsoft redirects back.
    const c = await call(ia, "POST", "/admin/instance/email/m365/connect", undefined, null);
    await t.prisma.user.update({ where: { id: ia.id }, data: { instanceAdmin: false } });
    const a = authorize(c.json().url, admin);
    expect(new URL((await callback({ code: a.code, state: a.state }, cookieOf(c)!.value)).headers.location as string).searchParams.get("m365_error")).toBe("forbidden");
    await t.prisma.user.update({ where: { id: ia.id }, data: { instanceAdmin: true } });
    // Session signed out meanwhile.
    const c2 = await call(ia, "POST", "/admin/instance/email/m365/connect", undefined, null);
    await t.prisma.session.updateMany({ where: { userId: ia.id }, data: { revokedAt: new Date() } });
    const a2 = authorize(c2.json().url, admin);
    expect(new URL((await callback({ code: a2.code, state: a2.state }, cookieOf(c2)!.value)).headers.location as string).searchParams.get("m365_error")).toBe("forbidden");
    expect(fake.tokenCalls.filter((f) => f.grant_type === "authorization_code")).toHaveLength(1); // only the first one redeemed a code
  });

  it("settings changed between sign-in and callback: refused", async () => {
    const ia = await instanceAdmin();
    await call(ia, "PUT", "/admin/instance/email", delegated(), null);
    const c = await call(ia, "POST", "/admin/instance/email/m365/connect", undefined, null);
    await call(ia, "PUT", "/admin/instance/email", delegated({ m365: { tenantId: TENANT, clientId: "12345678-1234-4123-8123-123456789abc", authMode: "delegated" } }), null);
    const a = authorize(c.json().url, admin);
    expect(new URL((await callback({ code: a.code, state: a.state }, cookieOf(c)!.value)).headers.location as string).searchParams.get("m365_error")).toBe("settings_changed");
  });

  it("maps Microsoft's errors: access_denied, consent (AADSTS65001), redirect URI (AADSTS50011), secret (AADSTS7000215), app (AADSTS700016)", async () => {
    const ia = await instanceAdmin();
    await call(ia, "PUT", "/admin/instance/email", delegated(), null);
    const viaRedirect = async (error: string, description?: string) => {
      const { location } = await signIn(ia, "/admin/instance/email", admin, null, (q) => { delete q.code; q.error = error; if (description) q.error_description = description; });
      return Object.fromEntries(location.searchParams);
    };
    expect(await viaRedirect("access_denied", "AADSTS65004: User declined to consent to access the app.")).toEqual({ m365_error: "access_denied", aadsts: "65004" });
    expect(await viaRedirect("invalid_client", "AADSTS65001: The user or administrator has not consented to use the application.")).toEqual({ m365_error: "consent_required", aadsts: "65001" });
    expect(await viaRedirect("invalid_request", "AADSTS50011: The redirect URI specified in the request does not match.")).toEqual({ m365_error: "redirect_uri_mismatch", aadsts: "50011" });
    fake.tokenOverride = () => jsonRes(401, { error: "invalid_client", error_description: "AADSTS7000215: Invalid client secret provided.", error_codes: [7000215] });
    expect(Object.fromEntries((await signIn(ia, "/admin/instance/email", admin, null)).location.searchParams)).toEqual({ m365_error: "bad_secret", aadsts: "7000215" });
    fake.tokenOverride = () => jsonRes(400, { error: "unauthorized_client", error_description: "AADSTS700016: Application not found in the directory.", error_codes: [700016] });
    expect(Object.fromEntries((await signIn(ia, "/admin/instance/email", admin, null)).location.searchParams)).toEqual({ m365_error: "app_not_found", aadsts: "700016" });
    // The error text from Microsoft never reaches the event log verbatim.
    const ev = await t.prisma.event.findMany({ where: { action: "email.m365_connect_failed" } });
    expect(ev.map((e) => (e.meta as { error: string }).error)).toEqual(["access_denied", "consent_required", "redirect_uri_mismatch", "bad_secret", "app_not_found"]);
  });
});

describe("delegated sign-in: sending", () => {
  it("a shared mailbox: Mail.Send.Shared is asked for, /me/sendMail with from; no Send As is explained", async () => {
    const ia = await instanceAdmin();
    await call(ia, "PUT", "/admin/instance/email", delegated({ fromAddress: "shared@northwind.test", fromName: "IT" }), null);
    const { scope } = await signIn(ia, "/admin/instance/email", admin, null);
    expect(scope).toContain("https://graph.microsoft.com/Mail.Send.Shared");
    expect(await t.app.mail.send("bob@else.test", { subject: "Hi", text: "Body" }, log)).toBe(true);
    expect(fake.sent[0]).toMatchObject({ url: `${M365_GRAPH_HOST}/v1.0/me/sendMail`, body: { message: { from: { emailAddress: { address: "shared@northwind.test", name: "IT" } } }, saveToSentItems: false } });
    // Signed in as someone without Send As on the mailbox.
    await signIn(ia, "/admin/instance/email", other, null);
    const te = await call(ia, "POST", "/admin/instance/email/test", undefined, null);
    expect(te.statusCode).toBe(502);
    expect(te.json().detail).toMatch(/^helpdesk@northwind\.test has no Send As permission on shared@northwind\.test \(ErrorSendAsDenied\)/);
    expect(JSON.stringify((await t.prisma.event.findMany({ where: { action: "email.m365_connected" } })).map((e) => e.meta))).toContain("\"reconnect\":true");
  });

  it("a shared mailbox without Mail.Send.Shared granted: sign-in refused; a sender changed later shows sharedScopeMissing", async () => {
    const ia = await instanceAdmin();
    await call(ia, "PUT", "/admin/instance/email", delegated({ fromAddress: "shared@northwind.test" }), null);
    fake.grantedScope = "https://graph.microsoft.com/Mail.Send https://graph.microsoft.com/User.Read";
    expect((await signIn(ia, "/admin/instance/email", admin, null)).location.searchParams.get("m365_error")).toBe("shared_scope_missing");
    await call(ia, "PUT", "/admin/instance/email", delegated({ secret: undefined }), null);
    expect((await signIn(ia, "/admin/instance/email", admin, null)).location.searchParams.get("m365")).toBe("connected");
    const r = await call(ia, "PUT", "/admin/instance/email", delegated({ fromAddress: "shared@northwind.test", secret: undefined }), null);
    expect(r.json().settings.m365.delegated).toMatchObject({ account: "admin@northwind.test", sharedScopeMissing: true });
    // Graph refuses without the permission, with a message saying what to add.
    const te = await call(ia, "POST", "/admin/instance/email/test", undefined, null);
    expect(te.json().detail).toMatch(/Mail\.Send delegated permission and Mail\.Send\.Shared/);
  });

  it("concurrent refreshes: rotation is a compare-and-swap; a stale writer never overwrites the newer token", async () => {
    const ia = await instanceAdmin();
    await call(ia, "PUT", "/admin/instance/email", delegated(), null);
    await signIn(ia, "/admin/instance/email", admin, null);
    const row = await instanceRow();
    const tr = t.app.mail.transportOf(row, "instance");
    expect(tr).toMatchObject({ provider: "m365", mode: "delegated", account: "admin@northwind.test", sender: "admin@northwind.test" });
    const store = (tr as { store: { load: () => Promise<{ refreshToken: string; version: number }>; rotate: (v: number, s: string) => Promise<boolean> } }).store;
    const cur = await store.load();
    expect(await store.rotate(cur.version, "rt-new-1")).toBe(true);
    expect(await store.rotate(cur.version, "rt-stale")).toBe(false);
    const now = await instanceRow();
    expect(box.open(now.m365RefreshEnc!, refreshAad(now))).toBe("rt-new-1");
    // Parallel sends share one refresh.
    await t.prisma.emailSettings.update({ where: { id: row.id }, data: { m365RefreshEnc: box.seal(cur.refreshToken, refreshAad(row)) } });
    fake.refresh.set(cur.refreshToken, { person: admin, scope: "https://graph.microsoft.com/Mail.Send", clientId: CLIENT });
    invalidateM365Token();
    const before = fake.tokenCalls.length;
    expect(await Promise.all([1, 2, 3].map(() => t.app.mail.send("x@else.test", { subject: "s", text: "t" }, log)))).toEqual([true, true, true]);
    expect(fake.tokenCalls.length - before).toBe(1);
  });

  it("invalid_grant: the connection needs reconnecting, admins are told through a non-Microsoft path, the UI and benchmark show it", async () => {
    const ia = await instanceAdmin();
    const org = ia.orgId;
    t.config.resendApiKey = "re_env_key_0000000000"; t.config.emailFrom = "env@clane.test";
    const resend = vi.spyOn(globalThis, "fetch").mockImplementation(async () => new Response("{}", { status: 200 }));
    await call(ia, "PUT", "/admin/settings/email", delegated(), org);
    expect((await signIn(ia, "/admin/settings/email", admin, org)).location.pathname).toMatch(/^\/o\/[^/]+\/admin\/org\/email$/);
    fake.refresh.clear(); // revoked at Microsoft (password reset, consent removed, 90 days unused…)
    const te = await call(ia, "POST", "/admin/settings/email/test", undefined, org);
    expect(te.statusCode).toBe(502);
    expect(te.json().detail).toMatch(/sign-in for admin@northwind\.test stopped working: The account's password changed or its sign-ins were revoked \(AADSTS50173\)\. An admin needs to reconnect it/);
    const row = await t.prisma.emailSettings.findUniqueOrThrow({ where: { orgId: org! } });
    expect(row).toMatchObject({ m365RefreshEnc: null, m365Account: "admin@northwind.test" });
    expect(row.m365ReconnectAt).not.toBeNull();
    const g = await call(ia, "GET", "/admin/settings/email", undefined, org);
    expect(g.json().settings.m365.delegated.reconnect).toMatchObject({ reason: expect.stringMatching(/AADSTS50173/) });
    // Logged once; later emails fall back to the next source (here the environment) instead of retrying Microsoft.
    expect(await t.app.mail.send("x@else.test", { subject: "s", text: "t" }, log, org)).toBe(true);
    expect(await t.prisma.event.count({ where: { action: "email.m365_reconnect_needed", orgId: org! } })).toBe(1);
    expect((await call(ia, "POST", "/admin/settings/email/test", undefined, org)).json()).toEqual({ error: "m365_reconnect" });
    // The org's owners and admins were emailed through Resend (the environment), not Microsoft 365.
    const notices = resend.mock.calls.filter(([, init]) => String((init as RequestInit).body).includes("needs signing in again"));
    expect(notices).toHaveLength(1);
    expect(JSON.parse(String((notices[0]![1] as RequestInit).body))).toMatchObject({ to: [ia.email], from: "env@clane.test" });
    // Risk dashboard: the org email benchmark is critical and the alert counts it.
    const risk = (await call(ia, "GET", "/admin/risk", undefined, org)).json();
    expect(risk.benchmarks.find((b: { key: string }) => b.key === "org_email")).toMatchObject({ status: "critical", detail: expect.stringMatching(/stopped working/) });
    // Reconnect clears it.
    expect((await signIn(ia, "/admin/settings/email", admin, org)).location.searchParams.get("m365")).toBe("connected");
    expect((await call(ia, "GET", "/admin/settings/email", undefined, org)).json().settings.m365.delegated.reconnect).toBeNull();
  });

  it("disconnect deletes the refresh token; switching to app-only or another app drops the connection", async () => {
    const ia = await instanceAdmin();
    await call(ia, "PUT", "/admin/instance/email", delegated(), null);
    await signIn(ia, "/admin/instance/email", admin, null);
    const d = await call(ia, "DELETE", "/admin/instance/email/m365/connection", undefined, null);
    expect(d.statusCode).toBe(200);
    expect(d.json().settings.m365.delegated).toMatchObject({ account: null, connectedAt: null });
    expect(await instanceRow()).toMatchObject({ m365RefreshEnc: null, m365Account: null });
    expect((await call(ia, "POST", "/admin/instance/email/test", undefined, null)).json()).toEqual({ error: "m365_not_connected" });
    await signIn(ia, "/admin/instance/email", admin, null);
    await call(ia, "PUT", "/admin/instance/email", { provider: "m365", fromAddress: "vault@northwind.test", m365: { tenantId: TENANT, clientId: CLIENT, authMode: "app" } }, null);
    expect(await instanceRow()).toMatchObject({ m365RefreshEnc: null, m365Account: null, m365AuthMode: "app" });
    expect((await t.prisma.event.findMany({ where: { action: "email.m365_disconnected" }, orderBy: { at: "asc" } })).map((e) => (e.meta as { why?: string }).why ?? "button"))
      .toEqual(["button", "settings_changed"]);
    // The client secret stayed (same app).
    expect((await instanceRow()).secretEnc).not.toBeNull();
  });

  it("app-only ErrorAccessDenied suggests delegated sign-in", async () => {
    const ia = await instanceAdmin();
    await call(ia, "PUT", "/admin/instance/email", { provider: "m365", fromAddress: "vault@northwind.test", m365: { tenantId: TENANT, clientId: CLIENT }, secret: SECRET }, null);
    setM365FetchForTests(async (url) => url.includes("/oauth2/") ? jsonRes(200, { access_token: "app-token", expires_in: 3599 }) : jsonRes(403, { error: { code: "ErrorAccessDenied" } }));
    try {
      const te = await call(ia, "POST", "/admin/instance/email/test", undefined, null);
      expect(te.json().detail).toMatch(/Mail\.Send application permission.*Or use delegated sign-in \(Sign in with Microsoft\) instead\./);
    } finally {
      // Back to the fake Microsoft for the other tests.
      setM365FetchForTests(fakeFetch);
    }
  });
});

describe("delegated sign-in: who may", () => {
  it("members and other orgs' admins can't start or finish it; each org's connection is its own", async () => {
    const ia = await instanceAdmin();
    const orgA = ia.orgId!;
    const b = await newOrg("Beta");
    const bOwner = await createActiveUser(t, { role: "owner", orgId: b.id });
    const member = await createActiveUser(t, { role: "member", orgId: orgA });
    await call(ia, "PUT", "/admin/settings/email", delegated(), orgA);
    await call(bOwner, "PUT", "/admin/settings/email", delegated(), b.id);
    expect((await call(member, "POST", "/admin/settings/email/m365/connect", undefined, orgA)).statusCode).toBe(403);
    expect((await call(bOwner, "POST", "/admin/settings/email/m365/connect", undefined, orgA)).statusCode).toBe(403);
    expect((await call(bOwner, "POST", "/admin/instance/email/m365/connect", undefined, null)).statusCode).toBe(403);
    expect((await call(member, "DELETE", "/admin/settings/email/m365/connection", undefined, orgA)).statusCode).toBe(403);
    // Org A's request finished with org B's browser cookie: refused.
    const ca = await call(ia, "POST", "/admin/settings/email/m365/connect", undefined, orgA);
    const cb = await call(bOwner, "POST", "/admin/settings/email/m365/connect", undefined, b.id);
    const a = authorize(ca.json().url, admin);
    expect(new URL((await callback({ code: a.code, state: a.state }, cookieOf(cb)!.value)).headers.location as string).searchParams.get("m365_error")).toBe("state");
    // Org B connects its own; org A, the instance and B are separate rows.
    const bb = authorize(cb.json().url, other);
    expect(new URL((await callback({ code: bb.code, state: bb.state }, cookieOf(cb)!.value)).headers.location as string).searchParams.get("m365")).toBe("connected");
    expect((await t.prisma.emailSettings.findUniqueOrThrow({ where: { orgId: b.id } })).m365Account).toBe("helpdesk@northwind.test");
    expect((await t.prisma.emailSettings.findUniqueOrThrow({ where: { orgId: orgA } })).m365Account).toBeNull();
    expect((await call(ia, "GET", "/admin/settings/email", undefined, orgA)).body).not.toContain("helpdesk@northwind.test");
    // B's connection sends B's email only.
    expect(await t.app.mail.send("x@else.test", { subject: "s", text: "t" }, log, b.id)).toBe(true);
    expect(await t.app.mail.send("x@else.test", { subject: "s", text: "t" }, log, orgA)).toBe(false);
  });

  it("connect needs delegated settings with a client secret", async () => {
    const ia = await instanceAdmin();
    expect((await call(ia, "POST", "/admin/instance/email/m365/connect", undefined, null)).json()).toEqual({ error: "not_delegated" });
    await call(ia, "PUT", "/admin/instance/email", { provider: "m365", fromAddress: "vault@northwind.test", m365: { tenantId: TENANT, clientId: CLIENT }, secret: SECRET }, null);
    expect((await call(ia, "POST", "/admin/instance/email/m365/connect", undefined, null)).json()).toEqual({ error: "not_delegated" });
    expect((await call(ia, "PUT", "/admin/instance/email", delegated({ m365: { tenantId: TENANT, clientId: "12345678-1234-4123-8123-123456789abc", authMode: "delegated" }, secret: undefined }), null)).json()).toEqual({ error: "secret_required" });
  });
});
