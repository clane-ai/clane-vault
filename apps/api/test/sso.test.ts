import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { createAccount, deriveLoginKeys, encryptNewRecord, type KdfParams } from "@clane-vault/crypto";
import { makeTestApp, resetDb, createActiveUser, createInvite, FAST_KDF, freshTotp, defaultOrgId } from "./helpers.js";
import { MockOidc } from "./mockOidc.js";
import { clientSecretAad, safeReturnTo } from "../src/lib/sso.js";
import { settingsBox } from "../src/lib/settingsBox.js";
import { redactInviteUrl } from "../src/app.js";

// Single sign-on through OpenID Connect (docs/sso.md), against an in-process mock identity provider.
const t = await makeTestApp();
t.config.ssoAllowHttpIssuer = true;
const idp = await new MockOidc().start();
const CLIENT = idp.addClient({ id: "clane-vault", secret: "idp-client-secret-1234", redirectUris: [`${t.config.publicUrl}/api/v1/auth/sso/callback`] });
afterAll(async () => { await t.app.close(); await idp.stop(); });
let txt: Record<string, string[]> = {};
beforeAll(() => { t.app.ssoDeps.resolveTxt = async (d) => { if (!txt[d]) throw Object.assign(new Error("no data"), { code: "ENODATA" }); return txt[d]!.map((r) => [r]); }; });
beforeEach(async () => { await resetDb(t.prisma); idp.users.clear(); idp.next = null; idp.tamper = null; txt = {}; });

type U = Awaited<ReturnType<typeof createActiveUser>>;
type M = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
let ipSeq = 0;
const ip = () => `10.170.${(++ipSeq >> 8) & 255}.${ipSeq & 255}`;
const call = (u: { accessToken: string; orgId?: string | null }, method: M, url: string, payload?: unknown, org: string | null | undefined = u.orgId) =>
  t.app.inject({ method, url: `/api/v1${url}`, payload: payload as object, remoteAddress: ip(), headers: { authorization: `Bearer ${u.accessToken}`, ...(org ? { "x-org-id": org } : {}) } });
const pub = (method: M, url: string, payload?: unknown, cookies?: Record<string, string>) =>
  t.app.inject({ method, url: `/api/v1${url}`, payload: payload as object, remoteAddress: ip(), ...(cookies ? { cookies } : {}) });

const authKeyOf = async (u: U) => (await deriveLoginKeys(u.password, u.material.kdfSalt, u.material.kdfParams as KdfParams)).authKey;

/** The org's owner configures SSO (and verifies acme.test unless told otherwise). */
async function setupSso(owner: U, opts: { verify?: boolean; requireSso?: boolean; trustIdpMfa?: boolean; autoJoin?: boolean; domain?: string } = {}) {
  const domain = opts.domain ?? "acme.test";
  expect((await call(owner, "PUT", "/admin/settings/sso", { issuer: idp.issuer, clientId: CLIENT.id, clientSecret: CLIENT.secret })).statusCode).toBe(200);
  const added = await call(owner, "POST", "/admin/settings/sso/domains", { domain });
  expect(added.statusCode).toBe(201);
  if (opts.verify !== false) {
    const rec = added.json().domains.find((d: { domain: string }) => d.domain === domain).txtRecord;
    txt[domain] = ["v=spf1 -all", rec.value];
    expect((await call(owner, "POST", `/admin/settings/sso/domains/${domain}/verify`)).statusCode).toBe(200);
  }
  if (opts.requireSso || opts.trustIdpMfa || opts.autoJoin)
    expect((await call(owner, "PUT", "/admin/settings/sso", { issuer: idp.issuer, clientId: CLIENT.id, requireSso: !!opts.requireSso, trustIdpMfa: !!opts.trustIdpMfa, autoJoin: !!opts.autoJoin })).statusCode).toBe(200);
}
const slugOf = async (orgId: string) => (await t.prisma.organization.findUniqueOrThrow({ where: { id: orgId } })).slug;

/** Browser side: start, follow the IdP's redirect, hit the callback with the cookie; returns where the callback sent us. */
async function ssoFlow(slug: string, opts: { email?: string; returnTo?: string; cookie?: string } = {}) {
  const start = await pub("POST", "/auth/sso/start", { org: slug, ...(opts.email ? { email: opts.email } : {}), ...(opts.returnTo ? { returnTo: opts.returnTo } : {}) });
  expect(start.statusCode).toBe(200);
  const c = start.cookies.find((x) => x.name === "cv_sso")!;
  expect(c).toMatchObject({ httpOnly: true, sameSite: "Lax", path: "/api/v1/auth/sso" });
  const auth = new URL(start.json().url);
  const r = await fetch(auth, { redirect: "manual" });
  const back = new URL(r.headers.get("location")!);
  const cb = await pub("GET", `${back.pathname.replace("/api/v1", "")}${back.search}`, undefined, { cv_sso: opts.cookie ?? c.value });
  const to = String(cb.headers.location ?? "");
  const frag = new URLSearchParams(to.split("#")[1] ?? "");
  return { auth, back, cb, to, cookie: c.value, proof: frag.get("proof"), returnTo: frag.get("returnTo"), error: new URL(to, "http://x").searchParams.get("sso_error") };
}
const proofCall = (path: string, body: object, cookie: string) => pub("POST", `/auth/sso/${path}`, body, { cv_sso: cookie });

async function sessionOf(accessToken: string) {
  const sid = JSON.parse(Buffer.from(accessToken.split(".")[1]!, "base64url").toString()).sid as string;
  return t.prisma.session.findUniqueOrThrow({ where: { id: sid } });
}

describe("settings", () => {
  it("owners/admins only; client secret sealed at rest and never returned; domains verified by DNS TXT", async () => {
    const owner = await createActiveUser(t, { role: "owner", email: "own@acme.test" });
    const member = await createActiveUser(t, { role: "member" });
    expect((await call(member, "GET", "/admin/settings/sso")).statusCode).toBe(403);
    expect((await call(member, "PUT", "/admin/settings/sso", { issuer: idp.issuer, clientId: "x", clientSecret: "y" })).statusCode).toBe(403);
    expect((await call(owner, "PUT", "/admin/settings/sso", { issuer: idp.issuer, clientId: CLIENT.id })).json()).toEqual({ error: "secret_required" });
    const r = await call(owner, "PUT", "/admin/settings/sso", { issuer: `${idp.issuer}/`, clientId: CLIENT.id, clientSecret: CLIENT.secret });
    expect(r.statusCode).toBe(200);
    expect(r.body).not.toContain(CLIENT.secret);
    expect(r.json()).toMatchObject({ config: { issuer: idp.issuer, clientId: CLIENT.id, clientSecret: { set: true, last4: "1234" }, requireSso: false }, redirectUri: "http://localhost:5173/api/v1/auth/sso/callback", orgSlug: "default" });
    const row = await t.prisma.orgSso.findUniqueOrThrow({ where: { orgId: owner.orgId } });
    expect(row.clientSecretEnc).not.toContain(CLIENT.secret);
    expect(settingsBox(t.config.serverSecret).open(row.clientSecretEnc!, clientSecretAad(row))).toBe(CLIENT.secret);
    expect(() => settingsBox(t.config.serverSecret).open(row.clientSecretEnc!, clientSecretAad({ id: row.id, orgId: crypto.randomUUID() }))).toThrow();
    expect((await call(owner, "GET", "/admin/settings/sso")).body).not.toContain(CLIENT.secret);
    // Require SSO / JIT need a verified domain.
    expect((await call(owner, "PUT", "/admin/settings/sso", { issuer: idp.issuer, clientId: CLIENT.id, requireSso: true })).json()).toEqual({ error: "domain_not_verified" });
    const added = await call(owner, "POST", "/admin/settings/sso/domains", { domain: "https://ACME.test/" });
    const d = added.json().domains[0];
    expect(d).toMatchObject({ domain: "acme.test", verified: false, txtRecord: { name: "acme.test", value: expect.stringMatching(/^clane-vault-verify=/) } });
    expect((await call(owner, "POST", "/admin/settings/sso/domains", { domain: "not a domain" })).json()).toEqual({ error: "invalid_domain" });
    expect((await call(owner, "POST", "/admin/settings/sso/domains/acme.test/verify")).json()).toMatchObject({ error: "txt_not_found" });
    txt["acme.test"] = ["clane-vault-verify=someone-elses-token"];
    expect((await call(owner, "POST", "/admin/settings/sso/domains/acme.test/verify")).json()).toMatchObject({ error: "txt_not_found" });
    txt["acme.test"] = [d.txtRecord.value];
    expect((await call(owner, "POST", "/admin/settings/sso/domains/acme.test/verify")).json().domains[0]).toMatchObject({ verified: true });
    expect((await call(owner, "PUT", "/admin/settings/sso", { issuer: idp.issuer, clientId: CLIENT.id, requireSso: true, autoJoin: true })).json().config).toMatchObject({ requireSso: true, autoJoin: true, clientSecret: { set: true } });
    // Removing the last verified domain switches them off.
    expect((await call(owner, "DELETE", "/admin/settings/sso/domains/acme.test")).json().config).toMatchObject({ requireSso: false, autoJoin: false });
    // Non-https issuers are refused unless allowed (development).
    t.config.ssoAllowHttpIssuer = false;
    expect((await call(owner, "PUT", "/admin/settings/sso", { issuer: idp.issuer, clientId: CLIENT.id })).json()).toEqual({ error: "issuer_insecure" });
    t.config.ssoAllowHttpIssuer = true;
    const ev = (await t.prisma.event.findMany({ where: { action: { startsWith: "sso." } }, orderBy: { id: "asc" } })).map((e) => e.action);
    expect(ev).toEqual(expect.arrayContaining(["sso.settings_updated", "sso.domain_added", "sso.domain_verify_failed", "sso.domain_verified", "sso.domain_removed"]));
    expect(JSON.stringify(await t.prisma.event.findMany({ select: { meta: true } }))).not.toContain(CLIENT.secret);
  });

  it("test connection: discovery, metadata and the client credentials", async () => {
    const owner = await createActiveUser(t, { role: "owner" });
    await call(owner, "PUT", "/admin/settings/sso", { issuer: idp.issuer, clientId: CLIENT.id, clientSecret: CLIENT.secret });
    const ok = await call(owner, "POST", "/admin/settings/sso/test", {});
    expect(ok.json()).toMatchObject({ ok: true, checks: [{ name: "discovery", ok: true }, { name: "metadata", ok: true }, { name: "client", ok: true }] });
    const bad = await call(owner, "POST", "/admin/settings/sso/test", { clientSecret: "wrong-secret" });
    expect(bad.json()).toMatchObject({ ok: false, checks: [{ ok: true }, { ok: true }, { name: "client", ok: false, detail: "The provider rejected the client ID or secret." }] });
    expect(bad.body).not.toContain("wrong-secret");
    const none = await call(owner, "POST", "/admin/settings/sso/test", { issuer: "http://127.0.0.1:1", clientSecret: "x" });
    expect(none.json()).toMatchObject({ ok: false, checks: [{ name: "discovery", ok: false }] });
  });

  it("hosted mode: issuers on private addresses are refused", async () => {
    const owner = await createActiveUser(t, { role: "owner" });
    t.config.hostedMode = true;
    try {
      expect((await call(owner, "PUT", "/admin/settings/sso", { issuer: idp.issuer, clientId: CLIENT.id, clientSecret: CLIENT.secret })).json()).toEqual({ error: "private_host" });
      expect((await call(owner, "POST", "/admin/settings/sso/test", { issuer: idp.issuer, clientId: CLIENT.id, clientSecret: CLIENT.secret })).json()).toMatchObject({ ok: false, checks: [{ name: "discovery", detail: expect.stringMatching(/private network address/) }] });
    } finally { delete t.config.hostedMode; }
  });
});

describe("sign-in", () => {
  it("happy path: IdP, then master password and TOTP; identity linked; the session counts as the org's SSO", async () => {
    const owner = await createActiveUser(t, { role: "owner", email: "boss@acme.test" });
    const m = await createActiveUser(t, { email: "sara@acme.test" });
    await setupSso(owner);
    idp.addUser({ sub: "idp-sara", email: "sara@acme.test", email_verified: true, name: "Sara" });
    expect((await pub("POST", "/auth/sso/discover", { email: "Sara@ACME.test" })).json()).toEqual({ orgs: [{ slug: "default", name: "Test org" }] });
    expect((await pub("POST", "/auth/sso/discover", { email: "sara@other.test" })).json()).toEqual({ orgs: [] });
    const f = await ssoFlow("default", { email: "sara@acme.test", returnTo: "/settings" });
    // The authorization request: code flow, PKCE S256, state, nonce, our redirect URI and scopes.
    expect(Object.fromEntries(f.auth.searchParams)).toMatchObject({ response_type: "code", client_id: CLIENT.id, code_challenge_method: "S256", scope: "openid email profile",
      redirect_uri: "http://localhost:5173/api/v1/auth/sso/callback", login_hint: "sara@acme.test", state: expect.any(String), nonce: expect.any(String), code_challenge: expect.any(String) });
    expect(f.to).toMatch(/^http:\/\/localhost:5173\/sso\/complete#proof=/);
    expect(f.returnTo).toBe("/settings");
    const info = await proofCall("proof", { proof: f.proof }, f.cookie);
    expect(info.json()).toEqual({ mode: "login", email: "sara@acme.test", accountEmail: "sara@acme.test", kdf: { kdfSalt: m.material.kdfSalt, kdfParams: m.material.kdfParams },
      org: { name: "Test org", slug: "default" }, returnTo: "/settings", totpSkipped: false, joins: null });
    const authKey = await authKeyOf(m);
    expect((await proofCall("login", { proof: f.proof, authKey }, f.cookie)).json()).toEqual({ error: "totp_required" });
    const ok = await proofCall("login", { proof: f.proof, authKey, code: await freshTotp(m.totpSecret) }, f.cookie);
    expect(ok.statusCode).toBe(200);
    expect(ok.json()).toMatchObject({ user: { id: m.id }, returnTo: "/settings", orgs: [{ slug: "default" }] });
    expect(ok.cookies.find((c) => c.name === "cv_refresh")).toBeTruthy();
    expect((await sessionOf(ok.json().accessToken)).ssoOrgIds).toEqual([m.orgId]);
    expect(await t.prisma.ssoIdentity.findMany({ select: { userId: true, subject: true, issuer: true } })).toEqual([{ userId: m.id, subject: "idp-sara", issuer: idp.issuer }]);
    // Single use.
    expect((await proofCall("login", { proof: f.proof, authKey, code: await freshTotp(m.totpSecret) }, f.cookie)).json()).toEqual({ error: "sso_proof_invalid" });
    const ev = await t.prisma.event.findMany({ where: { actorId: m.id, action: "auth.login" } });
    expect(ev.at(-1)!.meta).toMatchObject({ via: "sso", totpSkipped: false });
    // No token, code or secret in events.
    expect(JSON.stringify(await t.prisma.event.findMany({ select: { action: true, meta: true } }))).not.toMatch(/id_token|access_token|idp-client-secret/);
  });

  it("the proof is bound to the browser's cookie and burned after 5 wrong passwords", async () => {
    const owner = await createActiveUser(t, { role: "owner", email: "boss@acme.test" });
    const m = await createActiveUser(t, { email: "sara@acme.test" });
    await setupSso(owner);
    idp.addUser({ sub: "s1", email: "sara@acme.test", email_verified: true });
    const f = await ssoFlow("default", { email: "sara@acme.test" });
    expect((await proofCall("proof", { proof: f.proof }, "another-browser-cookie-value-xxxx")).statusCode).toBe(410);
    expect((await pub("POST", "/auth/sso/proof", { proof: f.proof })).statusCode).toBe(410);
    const wrong = (await createAccount("not the password", FAST_KDF)).authKey;
    for (let i = 0; i < 5; i++) expect((await proofCall("login", { proof: f.proof, authKey: wrong }, f.cookie)).json()).toEqual({ error: "invalid_credentials" });
    expect((await proofCall("login", { proof: f.proof, authKey: await authKeyOf(m), code: await freshTotp(m.totpSecret) }, f.cookie)).json()).toEqual({ error: "sso_proof_invalid" });
  });

  it("bad state: unknown, another browser's, or replayed", async () => {
    const owner = await createActiveUser(t, { role: "owner", email: "boss@acme.test" });
    await createActiveUser(t, { email: "sara@acme.test" });
    await setupSso(owner);
    idp.addUser({ sub: "s1", email: "sara@acme.test", email_verified: true });
    expect((await pub("GET", "/auth/sso/callback?code=x&state=nope", undefined, { cv_sso: "a".repeat(43) })).headers.location).toBe("http://localhost:5173/sign-in?sso_error=sso_state");
    const other = await ssoFlow("default", { email: "sara@acme.test", cookie: "b".repeat(43) });
    expect(other.error).toBe("sso_state");
    const f = await ssoFlow("default", { email: "sara@acme.test" });
    expect(f.proof).toBeTruthy();
    const replay = await pub("GET", `/auth/sso/callback${f.back.search}`, undefined, { cv_sso: f.cookie });
    expect(replay.headers.location).toBe("http://localhost:5173/sign-in?sso_error=sso_state");
    const fails = await t.prisma.event.findMany({ where: { action: "sso.callback_failed" } });
    expect(fails.map((e) => (e.meta as { reason: string }).reason)).toEqual(["sso_state", "sso_state", "sso_state"]);
  });

  it.each([
    ["bad nonce", { nonce: "someone-elses-nonce" }],
    ["wrong audience", { aud: "another-client" }],
    ["wrong issuer", { iss: "https://evil.example" }],
    ["expired id_token", { expired: true }],
    ["signature by a key not in the JWKS", { badKey: true }],
  ])("%s: refused", async (_n, tamper) => {
    const owner = await createActiveUser(t, { role: "owner", email: "boss@acme.test" });
    await createActiveUser(t, { email: "sara@acme.test" });
    await setupSso(owner);
    idp.addUser({ sub: "s1", email: "sara@acme.test", email_verified: true });
    idp.tamper = tamper;
    const f = await ssoFlow("default", { email: "sara@acme.test" });
    expect(f.error).toBe("sso_failed");
    expect(f.proof).toBeNull();
    expect(await t.prisma.ssoProof.count()).toBe(0);
  });

  it("an unverified email is refused (Entra's xms_edov counts only for Entra issuers)", async () => {
    const owner = await createActiveUser(t, { role: "owner", email: "boss@acme.test" });
    await createActiveUser(t, { email: "sara@acme.test" });
    await setupSso(owner);
    idp.addUser({ sub: "s1", email: "sara@acme.test", email_verified: false, xms_edov: true });
    expect((await ssoFlow("default", { email: "sara@acme.test" })).error).toBe("sso_email_unverified");
    idp.addUser({ sub: "s1", email: "sara@acme.test" });
    expect((await ssoFlow("default", { email: "sara@acme.test" })).error).toBe("sso_email_unverified");
  });

  it("an address outside the org's domains is refused", async () => {
    const owner = await createActiveUser(t, { role: "owner", email: "boss@acme.test" });
    await createActiveUser(t, { email: "sara@else.test" });
    await setupSso(owner);
    idp.addUser({ sub: "s1", email: "sara@else.test", email_verified: true });
    expect((await ssoFlow("default", { email: "sara@else.test" })).error).toBe("sso_domain");
  });

  it("once linked, the subject must match: another IdP account can't take over by using the same email; a renamed one still maps to its owner", async () => {
    const owner = await createActiveUser(t, { role: "owner", email: "boss@acme.test" });
    const sara = await createActiveUser(t, { email: "sara@acme.test" });
    const bob = await createActiveUser(t, { email: "bob@acme.test" });
    await setupSso(owner, { trustIdpMfa: true });
    idp.addUser({ sub: "sara-sub", email: "sara@acme.test", email_verified: true });
    const f1 = await ssoFlow("default", { email: "sara@acme.test" });
    expect((await proofCall("login", { proof: f1.proof, authKey: await authKeyOf(sara) }, f1.cookie)).statusCode).toBe(200);
    // A different IdP account now claims Sara's address.
    idp.addUser({ sub: "attacker-sub", email: "sara@acme.test", email_verified: true });
    expect((await ssoFlow("default", { email: "sara@acme.test" })).error).toBe("sso_identity_mismatch");
    // Sara's IdP account is renamed to Bob's address: it still maps to Sara (by subject), never to Bob.
    idp.users.clear();
    idp.addUser({ sub: "sara-sub", email: "bob@acme.test", email_verified: true });
    const f3 = await ssoFlow("default", { email: "bob@acme.test" });
    expect((await proofCall("login", { proof: f3.proof, authKey: await authKeyOf(bob) }, f3.cookie)).json()).toEqual({ error: "invalid_credentials" });
    const f4 = await ssoFlow("default", { email: "bob@acme.test" });
    // The proof names Sara's account (and her KDF salt), so the browser derives the right key.
    expect((await proofCall("proof", { proof: f4.proof }, f4.cookie)).json()).toMatchObject({ email: "bob@acme.test", accountEmail: "sara@acme.test", kdf: { kdfSalt: sara.material.kdfSalt } });
    const ok = await proofCall("login", { proof: f4.proof, authKey: await authKeyOf(sara) }, f4.cookie);
    expect(ok.json().user.id).toBe(sara.id);
  });

  it("trust IdP MFA skips TOTP for verified-domain members only; otherwise TOTP as usual", async () => {
    const owner = await createActiveUser(t, { role: "owner", email: "boss@acme.test" });
    const m = await createActiveUser(t, { email: "sara@acme.test" });
    const ext = await createActiveUser(t, { email: "ext@partner.test" });
    await setupSso(owner, { trustIdpMfa: true });
    await call(owner, "POST", "/admin/settings/sso/domains", { domain: "partner.test" }); // listed but not verified
    idp.addUser({ sub: "s1", email: "sara@acme.test", email_verified: true });
    idp.addUser({ sub: "s2", email: "ext@partner.test", email_verified: true });
    const f = await ssoFlow("default", { email: "sara@acme.test" });
    expect((await proofCall("proof", { proof: f.proof }, f.cookie)).json()).toMatchObject({ totpSkipped: true });
    const ok = await proofCall("login", { proof: f.proof, authKey: await authKeyOf(m) }, f.cookie);
    expect(ok.statusCode).toBe(200);
    expect((await t.prisma.event.findMany({ where: { actorId: m.id, action: "auth.login" } })).at(-1)!.meta).toMatchObject({ totpSkipped: true });
    // Unverified domain: TOTP still needed.
    const g = await ssoFlow("default", { email: "ext@partner.test" });
    expect((await proofCall("proof", { proof: g.proof }, g.cookie)).json()).toMatchObject({ totpSkipped: false });
    expect((await proofCall("login", { proof: g.proof, authKey: await authKeyOf(ext) }, g.cookie)).json()).toEqual({ error: "totp_required" });
    // Trust off: TOTP again.
    await call(owner, "PUT", "/admin/settings/sso", { issuer: idp.issuer, clientId: CLIENT.id, trustIdpMfa: false });
    const h = await ssoFlow("default", { email: "sara@acme.test" });
    expect((await proofCall("login", { proof: h.proof, authKey: await authKeyOf(m) }, h.cookie)).json()).toEqual({ error: "totp_required" });
  });

  it("returnTo can't leave the app", async () => {
    const owner = await createActiveUser(t, { role: "owner", email: "boss@acme.test" });
    await createActiveUser(t, { email: "sara@acme.test" });
    await setupSso(owner);
    idp.addUser({ sub: "s1", email: "sara@acme.test", email_verified: true });
    for (const bad of ["https://evil.example/x", "//evil.example", "/\\evil.example", "javascript:alert(1)", "/ok\nx"]) {
      const f = await ssoFlow("default", { email: "sara@acme.test", returnTo: bad });
      expect(f.to.startsWith("http://localhost:5173/sso/complete#")).toBe(true);
      expect(f.returnTo).toBeNull();
    }
    expect(safeReturnTo("/vault?x=1#y")).toBe("/vault?x=1#y");
    expect(safeReturnTo("/%2F%2Fevil.example")).toBe("/%2F%2Fevil.example");
  });

  it("the callback URL (code, state) is redacted from request logs", () => {
    expect(redactInviteUrl("/api/v1/auth/sso/callback?code=SECRET&state=S")).toBe("/api/v1/auth/sso/callback?[redacted]");
  });
});

describe("new accounts and just-in-time", () => {
  it("domain not verified: no JIT, no sign-up; existing non-members are refused", async () => {
    const owner = await createActiveUser(t, { role: "owner", email: "boss@acme.test" });
    const other = await t.prisma.organization.create({ data: { name: "Other", slug: "other-1" } });
    await createActiveUser(t, { email: "out@acme.test", orgId: other.id });
    await setupSso(owner, { verify: false });
    idp.addUser({ sub: "n1", email: "new@acme.test", email_verified: true });
    idp.addUser({ sub: "o1", email: "out@acme.test", email_verified: true });
    expect((await ssoFlow("default", { email: "new@acme.test" })).error).toBe("sso_no_account");
    await createInvite(t.prisma, "new@acme.test", "member", owner.orgId);
    expect((await ssoFlow("default", { email: "new@acme.test" })).error).toBe("sso_no_account");
    expect((await ssoFlow("default", { email: "out@acme.test" })).error).toBe("sso_not_member");
    expect(await t.prisma.user.count({ where: { email: "new@acme.test" } })).toBe(0);
  });

  it("verified domain + JIT: a new person signs up (no email code), sets up TOTP and lands in the org with an SSO session", async () => {
    const owner = await createActiveUser(t, { role: "owner", email: "boss@acme.test" });
    await setupSso(owner, { autoJoin: true });
    try {
      idp.addUser({ sub: "n1", email: "new@acme.test", email_verified: true, name: "New Person" });
      const f = await ssoFlow("default", { email: "new@acme.test" });
      // Hosted mode needs an emailed code for invite sign-ups; SSO sign-ups don't (the IdP verified the address).
      t.config.hostedMode = true;
      expect((await proofCall("proof", { proof: f.proof }, f.cookie)).json()).toEqual({ mode: "register", email: "new@acme.test", org: { name: "Test org", slug: "default" }, returnTo: "/", name: "New Person", adminRecoveryEnabled: false, joins: "member" });
      const acct = await createAccount("a new master password", FAST_KDF);
      const reg = await proofCall("register", { proof: f.proof, name: "New Person", authKey: acct.authKey, material: acct.material }, f.cookie);
      expect(reg.statusCode).toBe(201);
      const auth = { authorization: `Bearer ${reg.json().setupToken}` };
      const setup = await t.app.inject({ method: "POST", url: "/api/v1/auth/totp/setup", headers: auth, payload: {}, remoteAddress: ip() });
      const done = await t.app.inject({ method: "POST", url: "/api/v1/auth/totp/verify", headers: auth, payload: { code: await freshTotp(setup.json().secret) }, remoteAddress: ip() });
      expect(done.statusCode).toBe(200);
      const u = await t.prisma.user.findUniqueOrThrow({ where: { email: "new@acme.test" }, include: { memberships: true, ssoIdentities: true } });
      expect(u.memberships.map((m) => [m.orgId, m.role, m.status])).toEqual([[owner.orgId, "member", "active"]]);
      expect(u.ssoIdentities.map((i) => i.subject)).toEqual(["n1"]);
      expect((await sessionOf(done.json().accessToken)).ssoOrgIds).toEqual([owner.orgId]);
      expect((await proofCall("register", { proof: f.proof, name: "Again", authKey: acct.authKey, material: acct.material }, f.cookie)).statusCode).toBe(410);
    } finally { delete t.config.hostedMode; }
  });

  it("verified domain + JIT: an existing account outside the org joins it on SSO sign-in", async () => {
    const owner = await createActiveUser(t, { role: "owner", email: "boss@acme.test" });
    const other = await t.prisma.organization.create({ data: { name: "Other", slug: "other-2" } });
    const u = await createActiveUser(t, { email: "out@acme.test", orgId: other.id });
    await setupSso(owner, { autoJoin: true });
    idp.addUser({ sub: "o1", email: "out@acme.test", email_verified: true });
    const f = await ssoFlow("default", { email: "out@acme.test" });
    expect((await proofCall("proof", { proof: f.proof }, f.cookie)).json()).toMatchObject({ mode: "login", joins: "member" });
    const ok = await proofCall("login", { proof: f.proof, authKey: await authKeyOf(u), code: await freshTotp(u.totpSecret) }, f.cookie);
    expect(ok.statusCode).toBe(200);
    expect(ok.json().orgs.map((o: { id: string }) => o.id).sort()).toEqual([owner.orgId, other.id].sort());
    expect(await t.prisma.event.count({ where: { action: "sso.jit_join", targetUserId: u.id } })).toBe(1);
  });

  it("an open invite (verified domain) signs up through SSO with the invite's role", async () => {
    const owner = await createActiveUser(t, { role: "owner", email: "boss@acme.test" });
    await setupSso(owner);
    await createInvite(t.prisma, "inv@acme.test", "admin", owner.orgId);
    idp.addUser({ sub: "i1", email: "inv@acme.test", email_verified: true });
    const f = await ssoFlow("default", { email: "inv@acme.test" });
    expect((await proofCall("proof", { proof: f.proof }, f.cookie)).json()).toMatchObject({ mode: "register", joins: "invite" });
    const acct = await createAccount("pw pw pw pw", FAST_KDF);
    expect((await proofCall("register", { proof: f.proof, name: "Inv", authKey: acct.authKey, material: acct.material }, f.cookie)).statusCode).toBe(201);
    const m = await t.prisma.membership.findFirstOrThrow({ where: { user: { email: "inv@acme.test" } } });
    expect(m.role).toBe("admin");
    expect(await t.prisma.invite.count({ where: { email: "inv@acme.test", acceptedAt: null } })).toBe(0);
  });
});

describe("Require SSO for members", () => {
  it("verified-domain members reach the org only from a session that org's SSO established; others and other orgs are unaffected", async () => {
    const owner = await createActiveUser(t, { role: "owner", email: "boss@acme.test" });
    const m = await createActiveUser(t, { email: "sara@acme.test" });
    const ext = await createActiveUser(t, { email: "ext@partner.test" });
    const other = await t.prisma.organization.create({ data: { name: "Other", slug: "other-3" } });
    await t.prisma.membership.create({ data: { orgId: other.id, userId: m.id, role: "member", status: "active", joinedAt: new Date() } });
    await setupSso(owner, { requireSso: true });
    // Password session: 403 sso_required in this org; private vault and the other org work.
    const r = await call(m, "GET", "/sync");
    expect(r.statusCode).toBe(403);
    expect(r.json()).toEqual({ error: "sso_required", orgId: m.orgId });
    expect((await call(m, "GET", "/sync", undefined, null)).statusCode).toBe(200);
    expect((await call(m, "GET", "/sync", undefined, other.id)).statusCode).toBe(200);
    expect((await call(m, "GET", "/me/orgs", undefined, null)).statusCode).toBe(200);
    // The owner (break-glass) and people outside the verified domains aren't affected.
    expect((await call(owner, "GET", "/sync")).statusCode).toBe(200);
    expect((await call(ext, "GET", "/sync")).statusCode).toBe(200);
    // After SSO: allowed, and it survives a token refresh (same session).
    idp.addUser({ sub: "s1", email: "sara@acme.test", email_verified: true });
    const f = await ssoFlow("default", { email: "sara@acme.test" });
    const ok = await proofCall("login", { proof: f.proof, authKey: await authKeyOf(m), code: await freshTotp(m.totpSecret) }, f.cookie);
    const s = { accessToken: ok.json().accessToken as string, orgId: m.orgId };
    expect((await call(s, "GET", "/sync")).statusCode).toBe(200);
    const c = ok.cookies.find((x) => x.name === "cv_refresh")!;
    const refreshed = await t.app.inject({ method: "POST", url: "/api/v1/auth/refresh", cookies: { cv_refresh: c.value }, remoteAddress: ip() });
    expect((await call({ accessToken: refreshed.json().accessToken, orgId: m.orgId }, "GET", "/sync")).statusCode).toBe(200);
    // The old password session is still not good enough.
    expect((await call(m, "GET", "/sync")).statusCode).toBe(403);
    // Turning it off lifts it at once.
    await call(owner, "PUT", "/admin/settings/sso", { issuer: idp.issuer, clientId: CLIENT.id, requireSso: false });
    expect((await call(m, "GET", "/sync")).statusCode).toBe(200);
    expect(await defaultOrgId(t.prisma)).toBe(m.orgId);
  });
});

describe("security review fixes", () => {
  const sessionsFlag = async (accessToken: string) => (await sessionOf(accessToken)).totpSkippedForOrg;

  it("I1: trusted IdP MFA skips TOTP only for a single-org member, confines the session to that org until a step-up, and needs an MFA amr when amr is sent", async () => {
    const owner = await createActiveUser(t, { role: "owner", email: "boss@acme.test" });
    const m = await createActiveUser(t, { email: "sara@acme.test" });
    const two = await createActiveUser(t, { email: "two@acme.test" });
    const other = await t.prisma.organization.create({ data: { name: "Other", slug: "other-i1" } });
    await t.prisma.membership.create({ data: { orgId: other.id, userId: two.id, role: "member", status: "active", joinedAt: new Date() } });
    await setupSso(owner, { trustIdpMfa: true });
    idp.addUser({ sub: "s1", email: "sara@acme.test", email_verified: true, amr: ["pwd", "mfa"] });
    idp.addUser({ sub: "s2", email: "two@acme.test", email_verified: true });
    // Single-org member: skipped, but the session reaches this org only.
    const f = await ssoFlow("default", { email: "sara@acme.test" });
    const ok = await proofCall("login", { proof: f.proof, authKey: await authKeyOf(m) }, f.cookie);
    expect(ok.statusCode).toBe(200);
    const s = { accessToken: ok.json().accessToken as string, orgId: m.orgId };
    expect(await sessionsFlag(s.accessToken)).toBe(m.orgId);
    expect((await call(s, "GET", "/sync")).statusCode).toBe(200);
    expect((await call(s, "GET", "/sync", undefined, null)).json()).toEqual({ error: "totp_step_up_required" });
    expect((await call(s, "GET", "/sync", undefined, other.id)).json()).toEqual({ error: "org_forbidden" });
    // Joining another org doesn't widen the session.
    await t.prisma.membership.create({ data: { orgId: other.id, userId: m.id, role: "member", status: "active", joinedAt: new Date() } });
    expect((await call(s, "GET", "/sync", undefined, other.id)).json()).toEqual({ error: "totp_step_up_required" });
    // Step-up with a fresh code lifts it (a wrong code doesn't).
    expect((await call(s, "POST", "/auth/totp/step-up", { code: "000000" }, null)).statusCode).toBe(401);
    expect((await call(s, "POST", "/auth/totp/step-up", { code: await freshTotp(m.totpSecret) }, null)).json()).toEqual({ ok: true });
    expect((await call(s, "GET", "/sync", undefined, null)).statusCode).toBe(200);
    expect((await call(s, "GET", "/sync", undefined, other.id)).statusCode).toBe(200);
    // A member of two orgs: no skip.
    const g = await ssoFlow("default", { email: "two@acme.test" });
    expect((await proofCall("proof", { proof: g.proof }, g.cookie)).json()).toMatchObject({ totpSkipped: false });
    expect((await proofCall("login", { proof: g.proof, authKey: await authKeyOf(two) }, g.cookie)).json()).toEqual({ error: "totp_required" });
    // amr without a second factor: no skip.
    const solo = await createActiveUser(t, { email: "solo@acme.test" });
    idp.addUser({ sub: "s3", email: "solo@acme.test", email_verified: true, amr: ["pwd"] });
    const h = await ssoFlow("default", { email: "solo@acme.test" });
    expect((await proofCall("login", { proof: h.proof, authKey: await authKeyOf(solo) }, h.cookie)).json()).toEqual({ error: "totp_required" });
    // A sign-in with the code has no confinement.
    const okFull = await proofCall("login", { proof: h.proof, authKey: await authKeyOf(solo), code: await freshTotp(solo.totpSecret) }, h.cookie);
    expect(await sessionsFlag(okFull.json().accessToken)).toBeNull();
  });

  it("I1: no TOTP skip on a just-in-time join", async () => {
    const owner = await createActiveUser(t, { role: "owner", email: "boss@acme.test" });
    const outside = await t.prisma.organization.create({ data: { name: "Outside", slug: "outside-i1" } });
    const u = await createActiveUser(t, { email: "new@acme.test", orgId: outside.id });
    await t.prisma.membership.deleteMany({ where: { userId: u.id } });
    await setupSso(owner, { trustIdpMfa: true, autoJoin: true });
    idp.addUser({ sub: "j1", email: "new@acme.test", email_verified: true, amr: ["mfa"] });
    const f = await ssoFlow("default", { email: "new@acme.test" });
    expect((await proofCall("proof", { proof: f.proof }, f.cookie)).json()).toMatchObject({ joins: "member", totpSkipped: false });
    expect((await proofCall("login", { proof: f.proof, authKey: await authKeyOf(u) }, f.cookie)).json()).toEqual({ error: "totp_required" });
  });

  it("I2: test connection never sends the stored secret to another issuer or client", async () => {
    const owner = await createActiveUser(t, { role: "owner" });
    await call(owner, "PUT", "/admin/settings/sso", { issuer: idp.issuer, clientId: CLIENT.id, clientSecret: CLIENT.secret });
    const evil = await new MockOidc().start();
    try {
      expect((await call(owner, "POST", "/admin/settings/sso/test", { issuer: evil.issuer })).json()).toEqual({ error: "secret_required" });
      expect((await call(owner, "POST", "/admin/settings/sso/test", { clientId: "other-client" })).json()).toEqual({ error: "secret_required" });
      expect(evil.tokenRequests).toEqual([]);
      expect((await call(owner, "POST", "/admin/settings/sso/test", {})).json()).toMatchObject({ ok: true });
    } finally { await evil.stop(); }
  });

  it("I5: http issuers can't be allowed in hosted mode or production", async () => {
    const { loadConfig } = await import("../src/config.js");
    const env = { DATABASE_URL: "postgresql://a:b@localhost/x", JWT_SECRET: "x".repeat(40), SERVER_SECRET: "y".repeat(40), PUBLIC_URL: "https://v.example", SSO_ALLOW_HTTP_ISSUER: "true" };
    expect(() => loadConfig({ ...env, HOSTED_MODE: "true" })).toThrow(/SSO_ALLOW_HTTP_ISSUER/);
    expect(() => loadConfig({ ...env, NODE_ENV: "production" })).toThrow(/SSO_ALLOW_HTTP_ISSUER/);
    expect(loadConfig(env).ssoAllowHttpIssuer).toBe(true);
  });

  it("settings: sensitive changes are owner-only and emailed to owners and admins with the server's email", async () => {
    const owner = await createActiveUser(t, { role: "owner", email: "boss@acme.test" });
    const admin = await createActiveUser(t, { role: "admin", email: "adm@acme.test" });
    expect((await call(admin, "PUT", "/admin/settings/sso", { issuer: idp.issuer, clientId: CLIENT.id, clientSecret: CLIENT.secret })).json()).toEqual({ error: "owner_only" });
    // The org's own (unreachable) SMTP override must not carry this notice.
    await t.prisma.emailSettings.create({ data: { id: crypto.randomUUID(), scope: `org:${owner.orgId}`, orgId: owner.orgId, provider: "smtp", fromAddress: "it@acme.test", smtpHost: "127.0.0.1", smtpPort: 1, smtpSecurity: "none" } });
    t.config.resendApiKey = "re_env_key"; t.config.emailFrom = "vault@server.test";
    const real = globalThis.fetch;
    const sent: { to: string[]; subject: string }[] = [];
    const spy = vi.spyOn(globalThis, "fetch").mockImplementation(async (u, init) => {
      if (String(u).includes("api.resend.com")) { sent.push(JSON.parse(String(init!.body))); return new Response("{}", { status: 200 }); }
      return real(u, init);
    });
    try {
      await setupSso(owner);
      expect((await call(admin, "PUT", "/admin/settings/sso", { issuer: idp.issuer, clientId: CLIENT.id, trustIdpMfa: true })).json()).toEqual({ error: "owner_only" });
      expect((await call(admin, "PUT", "/admin/settings/sso", { issuer: idp.issuer, clientId: CLIENT.id, autoJoin: true })).statusCode).toBe(200);
      expect((await call(admin, "DELETE", "/admin/settings/sso")).json()).toEqual({ error: "owner_only" });
      await call(owner, "PUT", "/admin/settings/sso", { issuer: idp.issuer, clientId: CLIENT.id, trustIdpMfa: true, autoJoin: true });
      await vi.waitFor(() => expect(sent.filter((x) => /single sign-on settings changed/.test(x.subject)).length).toBeGreaterThanOrEqual(6));
      expect(new Set(sent.flatMap((x) => x.to))).toEqual(new Set(["boss@acme.test", "adm@acme.test"]));
    } finally { spy.mockRestore(); delete t.config.resendApiKey; delete t.config.emailFrom; }
  });

  it("domains: no public mail providers; one org per verified domain; re-checked before a JIT join after 24 h", async () => {
    const owner = await createActiveUser(t, { role: "owner", email: "boss@acme.test" });
    for (const d of ["gmail.com", "Outlook.com", "gmx.de", "yandex.ru", "mail.ru", "proton.me"]) expect((await call(owner, "POST", "/admin/settings/sso/domains", { domain: d })).json()).toEqual({ error: "public_domain" });
    await setupSso(owner, { autoJoin: true });
    const other = await t.prisma.organization.create({ data: { name: "Squatter", slug: "squat-1" } });
    const squatter = await createActiveUser(t, { role: "owner", orgId: other.id });
    const added = await call(squatter, "POST", "/admin/settings/sso/domains", { domain: "acme.test" });
    txt["acme.test"]!.push(added.json().domains[0].txtRecord.value);
    expect((await call(squatter, "POST", "/admin/settings/sso/domains/acme.test/verify")).json()).toEqual({ error: "domain_taken" });
    // TXT record gone and last seen over 24 h ago: the JIT join is refused and the domain un-verified.
    await t.prisma.ssoDomain.updateMany({ where: { orgId: owner.orgId }, data: { checkedAt: new Date(Date.now() - 25 * 3600e3), verifiedAt: new Date(Date.now() - 25 * 3600e3) } });
    txt["acme.test"] = [];
    idp.addUser({ sub: "n1", email: "new@acme.test", email_verified: true });
    expect((await ssoFlow("default", { email: "new@acme.test" })).error).toBe("sso_no_account");
    expect((await t.prisma.ssoDomain.findFirstOrThrow({ where: { orgId: owner.orgId } })).verifiedAt).toBeNull();
    expect((await t.prisma.orgSso.findFirstOrThrow({ where: { orgId: owner.orgId } })).autoJoin).toBe(false);
    expect(await t.prisma.event.count({ where: { action: "sso.domain_unverified" } })).toBe(1);
  });

  it("use-time checks: JIT sign-up refused when auto-join was switched off after the callback; a duplicate sign-up is 409", async () => {
    const owner = await createActiveUser(t, { role: "owner", email: "boss@acme.test" });
    await setupSso(owner, { autoJoin: true });
    idp.addUser({ sub: "n1", email: "new@acme.test", email_verified: true });
    const f = await ssoFlow("default", { email: "new@acme.test" });
    const g = await ssoFlow("default", { email: "new@acme.test" });
    const acct = await createAccount("a new master password", FAST_KDF);
    await t.prisma.orgSso.updateMany({ data: { autoJoin: false } });
    expect((await proofCall("register", { proof: f.proof, name: "N", authKey: acct.authKey, material: acct.material }, f.cookie)).json()).toEqual({ error: "sso_no_account" });
    await t.prisma.orgSso.updateMany({ data: { autoJoin: true } });
    expect((await proofCall("register", { proof: f.proof, name: "N", authKey: acct.authKey, material: acct.material }, f.cookie)).statusCode).toBe(201);
    expect((await proofCall("register", { proof: g.proof, name: "N", authKey: acct.authKey, material: acct.material }, g.cookie)).json()).toEqual({ error: "account_exists" });
  });

  it("pending 2FA: the identity link waits until the new authenticator is set up", async () => {
    const owner = await createActiveUser(t, { role: "owner", email: "boss@acme.test" });
    const m = await createActiveUser(t, { email: "sara@acme.test" });
    await setupSso(owner);
    await t.prisma.user.update({ where: { id: m.id }, data: { status: "pending_2fa", totpSecretEnc: null, totpLastStep: null } });
    idp.addUser({ sub: "s1", email: "sara@acme.test", email_verified: true });
    const f = await ssoFlow("default", { email: "sara@acme.test" });
    const r = await proofCall("login", { proof: f.proof, authKey: await authKeyOf(m) }, f.cookie);
    expect(r.json()).toMatchObject({ needsTotpSetup: true });
    expect(await t.prisma.ssoIdentity.count()).toBe(0);
    const auth = { authorization: `Bearer ${r.json().setupToken}` };
    const setup = await t.app.inject({ method: "POST", url: "/api/v1/auth/totp/setup", headers: auth, payload: {}, remoteAddress: ip() });
    const done = await t.app.inject({ method: "POST", url: "/api/v1/auth/totp/verify", headers: auth, payload: { code: await freshTotp(setup.json().secret) }, remoteAddress: ip() });
    expect(done.statusCode).toBe(200);
    expect(await t.prisma.ssoIdentity.findMany({ select: { userId: true, subject: true } })).toEqual([{ userId: m.id, subject: "s1" }]);
    expect((await sessionOf(done.json().accessToken)).ssoOrgIds).toEqual([m.orgId]);
  });

  it("owner bypass of Require SSO is logged once per session; /start is limited per org and not logged; IdP error text is cleaned", async () => {
    const owner = await createActiveUser(t, { role: "owner", email: "boss@acme.test" });
    await setupSso(owner, { requireSso: true });
    for (let i = 0; i < 3; i++) expect((await call(owner, "GET", "/sync")).statusCode).toBe(200);
    expect(await t.prisma.event.count({ where: { action: "sso.bypass_owner", actorId: owner.id } })).toBe(1);
    // An IdP error with control characters: stored without them.
    const start = await pub("POST", "/auth/sso/start", { org: "default" });
    const c = start.cookies.find((x) => x.name === "cv_sso")!.value;
    const state = new URL(start.json().url).searchParams.get("state")!;
    await pub("GET", `/auth/sso/callback?state=${state}&error=bad%0Ainjected%1Bline`, undefined, { cv_sso: c });
    const ev = await t.prisma.event.findFirstOrThrow({ where: { action: "sso.callback_failed" } });
    expect((ev.meta as { detail: string }).detail).toBe("bad injected line");
    let last = 0;
    for (let i = 0; i < 61; i++) last = (await pub("POST", "/auth/sso/start", { org: "default" })).statusCode;
    expect(last).toBe(429);
    expect(await t.prisma.event.count({ where: { action: "sso.start" } })).toBe(0);
  });
});

describe("a session that skipped TOTP doesn't reach the private vault", () => {
  it("sync leaves out own private folders and records; private routes answer totp_step_up_required until a step-up", async () => {
    const owner = await createActiveUser(t, { role: "owner", email: "boss@acme.test" });
    const m = await createActiveUser(t, { email: "sara@acme.test" });
    // Made with a full (password + TOTP) session: a private folder and record, and a link on the record.
    const folderId = crypto.randomUUID(), recId = crypto.randomUUID();
    expect((await call(m, "POST", "/folders", { id: folderId, encName: "v1.name" }, null)).statusCode).toBe(201);
    const enc = await encryptNewRecord(recId, { type: "login", title: "Mine", password: "pw" }, m.keys.userKey);
    expect((await call(m, "POST", "/records", { id: recId, folderId: null, type: "login", encBody: enc.encBody, wrappedRecordKey: enc.wrappedRecordKey }, null)).statusCode).toBe(201);
    await setupSso(owner, { trustIdpMfa: true });
    idp.addUser({ sub: "s1", email: "sara@acme.test", email_verified: true });
    const f = await ssoFlow("default", { email: "sara@acme.test" });
    const ok = await proofCall("login", { proof: f.proof, authKey: await authKeyOf(m) }, f.cookie);
    const s = { accessToken: ok.json().accessToken as string, orgId: m.orgId };
    const sync = (await call(s, "GET", "/sync")).json();
    expect(sync.privateLocked).toBe(true);
    expect(sync.folders.map((x: { id: string }) => x.id)).not.toContain(folderId);
    expect(sync.records.map((x: { id: string }) => x.id)).not.toContain(recId);
    const locked = { error: "totp_step_up_required" };
    const newId = crypto.randomUUID();
    const enc2 = await encryptNewRecord(newId, { type: "note", title: "x" }, m.keys.userKey);
    expect((await call(s, "GET", `/records/${recId}/activity`)).json()).toEqual(locked);
    expect((await call(s, "PUT", `/records/${recId}`, { encBody: enc.encBody, revision: 1 })).json()).toEqual(locked);
    expect((await call(s, "DELETE", `/records/${recId}`)).json()).toEqual(locked);
    expect((await call(s, "GET", `/records/${recId}/links`)).json()).toEqual(locked);
    expect((await call(s, "POST", "/records", { id: newId, folderId: null, type: "note", encBody: enc2.encBody, wrappedRecordKey: enc2.wrappedRecordKey })).json()).toEqual(locked);
    expect((await call(s, "POST", "/records/batch", { records: [{ id: newId, folderId, type: "note", encBody: enc2.encBody, wrappedRecordKey: enc2.wrappedRecordKey }] })).json()).toEqual(locked);
    expect((await call(s, "POST", "/folders", { id: crypto.randomUUID(), encName: "v1.x" })).json()).toEqual(locked);
    expect((await call(s, "PATCH", `/folders/${folderId}`, { encName: "v1.y" })).json()).toEqual(locked);
    expect((await call(s, "POST", "/links", { id: crypto.randomUUID(), recordId: recId, encPayload: "v1.x", expiresInHours: 1, maxOpens: 1 })).json()).toEqual(locked);
    // After the authenticator code: everything is back.
    expect((await call(s, "POST", "/auth/totp/step-up", { code: await freshTotp(m.totpSecret) }, null)).json()).toEqual({ ok: true });
    const after = (await call(s, "GET", "/sync")).json();
    expect(after.privateLocked).toBeUndefined();
    expect(after.records.map((x: { id: string }) => x.id)).toContain(recId);
    expect(after.folders.map((x: { id: string }) => x.id)).toContain(folderId);
    expect((await call(s, "GET", `/records/${recId}/activity`)).statusCode).toBe(200);
  });
});
