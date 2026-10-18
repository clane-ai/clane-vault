import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { AddressInfo } from "node:net";
import { SMTPServer } from "smtp-server";
import { makeTestApp, resetDb, createActiveUser } from "./helpers.js";
import { secretAad } from "../src/lib/mailer.js";
import { settingsBox } from "../src/lib/settingsBox.js";

// Email settings in the admin GUI (docs/email.md): instance-wide and per-org overrides, secrets sealed at rest and
// never returned, test emails, and which settings an email goes out with.
const t = await makeTestApp();
const saved = { ...t.config };
afterAll(() => t.app.close());
beforeEach(() => resetDb(t.prisma));
afterEach(() => { vi.restoreAllMocks(); Object.assign(t.config, saved); delete t.config.resendApiKey; delete t.config.emailFrom; delete t.config.hostedMode; });

type U = Awaited<ReturnType<typeof createActiveUser>>;
let ipSeq = 0;
const call = (u: U, method: "GET" | "PUT" | "POST" | "DELETE", url: string, payload?: unknown, org: string | null = u.orgId) =>
  t.app.inject({ method, url: `/api/v1${url}`, payload: payload as object, remoteAddress: `10.160.${(++ipSeq >> 8) & 255}.${ipSeq & 255}`,
    headers: { authorization: `Bearer ${u.accessToken}`, ...(org ? { "x-org-id": org } : {}) } });

// ---- a local SMTP server (smtp-server, in-process) ----
interface Got { from: string; to: string[]; data: string; user?: string }
const got: Got[] = [];
let smtp: SMTPServer;
let smtpPort = 0;
beforeAll(async () => {
  smtp = new SMTPServer({
    secure: false, disabledCommands: ["STARTTLS"], allowInsecureAuth: true, authOptional: true, logger: false,
    onAuth(auth, _s, cb) { if (auth.username === "mailer" && auth.password === "smtp-Password-123") cb(null, { user: "mailer" }); else cb(new Error("Invalid username or password")); },
    onData(stream, session, cb) {
      let data = "";
      stream.on("data", (c: Buffer) => { data += c.toString("utf8"); });
      stream.on("end", () => { got.push({ from: session.envelope.mailFrom ? session.envelope.mailFrom.address : "", to: session.envelope.rcptTo.map((r) => r.address), data, user: session.user as string | undefined }); cb(); });
    },
  });
  await new Promise<void>((r) => smtp.listen(0, "127.0.0.1", r));
  smtpPort = (smtp.server.address() as AddressInfo).port;
});
afterAll(() => new Promise<void>((r) => smtp.close(() => r())));
beforeEach(() => { got.length = 0; });

/** Resend stub: every Resend call is captured with its API key. */
function resendStub(status = 200, body: object = { id: "x" }) {
  const spy = vi.spyOn(globalThis, "fetch").mockImplementation(async (u) => {
    if (String(u).includes("api.resend.com")) return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    throw new Error(`unexpected fetch ${String(u)}`);
  });
  return () => spy.mock.calls.filter(([u]) => String(u).includes("resend.com")).map(([, init]) => ({
    key: String((init as RequestInit).headers && ((init as RequestInit).headers as Record<string, string>).authorization),
    ...(JSON.parse(String((init as RequestInit).body)) as { from: string; to: string[]; subject: string; text: string }),
  }));
}

const RESEND_KEY = "re_live_ABCDEFGHIJKL_9876";
const SMTP_PASSWORD = "smtp-Password-123";
const smtpSettings = (over: Record<string, unknown> = {}) => ({ provider: "smtp", fromName: "Acme Vault", fromAddress: "vault@acme.test",
  smtp: { host: "127.0.0.1", port: smtpPort, security: "none", username: "mailer" }, secret: SMTP_PASSWORD, ...over });

async function instanceAdmin(): Promise<U> {
  const u = await createActiveUser(t, { role: "owner" });
  await t.prisma.user.update({ where: { id: u.id }, data: { instanceAdmin: true } });
  return u;
}
const newOrg = (name: string) => t.prisma.organization.create({ data: { name, slug: `${name.toLowerCase()}-${crypto.randomUUID().slice(0, 8)}` } });

describe("permissions", () => {
  it("instance settings: instance admins only; org settings: that org's owners and admins only", async () => {
    const ia = await instanceAdmin();
    const admin = await createActiveUser(t, { role: "admin" });
    const member = await createActiveUser(t, { role: "member" });
    expect((await call(ia, "GET", "/admin/instance/email", undefined, null)).statusCode).toBe(200);
    for (const u of [admin, member]) {
      expect((await call(u, "GET", "/admin/instance/email", undefined, null)).statusCode).toBe(403);
      expect((await call(u, "PUT", "/admin/instance/email", { provider: "resend", fromAddress: "a@b.co", secret: RESEND_KEY }, null)).statusCode).toBe(403);
      expect((await call(u, "POST", "/admin/instance/email/test", {}, null)).statusCode).toBe(403);
    }
    expect((await call(admin, "GET", "/admin/settings/email")).statusCode).toBe(200);
    expect((await call(admin, "PUT", "/admin/settings/email", smtpSettings())).statusCode).toBe(200);
    expect((await call(member, "GET", "/admin/settings/email")).statusCode).toBe(403);
    expect((await call(member, "PUT", "/admin/settings/email", smtpSettings())).statusCode).toBe(403);
    expect((await call(member, "DELETE", "/admin/settings/email")).statusCode).toBe(403);
    // An admin of another org can't touch this org's settings (X-Org-Id is checked against their memberships).
    const other = await newOrg("Other");
    const otherAdmin = await createActiveUser(t, { role: "owner", orgId: other.id });
    expect((await call(otherAdmin, "GET", "/admin/settings/email", undefined, admin.orgId)).statusCode).toBe(403);
    expect((await call(admin, "GET", "/admin/settings/email", undefined, null)).statusCode).toBe(403);
  });
});

describe("secrets", () => {
  it("are sealed at rest (bound to the row) and never returned; replace-only", async () => {
    const ia = await instanceAdmin();
    const r = await call(ia, "PUT", "/admin/instance/email", { provider: "resend", fromName: "Clane Vault", fromAddress: "vault@clane.test", secret: RESEND_KEY }, null);
    expect(r.statusCode).toBe(200);
    expect(r.body).not.toContain(RESEND_KEY);
    expect(r.json().settings).toMatchObject({ provider: "resend", fromAddress: "vault@clane.test", secret: { set: true, last4: "9876" } });
    const row = await t.prisma.emailSettings.findUniqueOrThrow({ where: { scope: "instance" } });
    expect(row.secretEnc).toMatch(/^v1\./);
    expect(row.secretEnc).not.toContain(RESEND_KEY);
    const box = settingsBox(t.config.serverSecret);
    expect(box.open(row.secretEnc!, secretAad(row))).toBe(RESEND_KEY);
    // Bound to its row: the same ciphertext doesn't open as another row's secret, nor with another server secret.
    expect(() => box.open(row.secretEnc!, secretAad({ id: crypto.randomUUID(), scope: "instance" }))).toThrow();
    expect(() => settingsBox("another-server-secret-another-server-secret").open(row.secretEnc!, secretAad(row))).toThrow();
    // GET never has it either.
    const g = await call(ia, "GET", "/admin/instance/email", undefined, null);
    expect(g.body).not.toContain(RESEND_KEY);
    expect(g.body).not.toContain(row.secretEnc!);
    // Saving without a secret keeps the stored one; a new one replaces it.
    await call(ia, "PUT", "/admin/instance/email", { provider: "resend", fromAddress: "other@clane.test" }, null);
    const kept = await t.prisma.emailSettings.findUniqueOrThrow({ where: { scope: "instance" } });
    expect(kept.secretEnc).toBe(row.secretEnc);
    await call(ia, "PUT", "/admin/instance/email", { provider: "resend", fromAddress: "other@clane.test", secret: "re_new_key_000000001234" }, null);
    expect((await call(ia, "GET", "/admin/instance/email", undefined, null)).json().settings.secret).toEqual({ set: true, last4: "1234" });
    // Resend needs a key; switching provider drops the old secret.
    await call(ia, "DELETE", "/admin/instance/email", undefined, null);
    expect((await call(ia, "PUT", "/admin/instance/email", { provider: "resend", fromAddress: "a@clane.test" }, null)).json()).toEqual({ error: "secret_required" });
    await call(ia, "PUT", "/admin/instance/email", { provider: "resend", fromAddress: "a@clane.test", secret: RESEND_KEY }, null);
    const s = await call(ia, "PUT", "/admin/instance/email", smtpSettings({ secret: undefined, smtp: { host: "127.0.0.1", port: smtpPort, security: "none", username: null } }), null);
    expect(s.json().settings).toMatchObject({ provider: "smtp", secret: { set: false, last4: null }, smtp: { host: "127.0.0.1", security: "none", username: null } });
    // SMTP passwords show as set, never with characters.
    const p = await call(ia, "PUT", "/admin/instance/email", smtpSettings(), null);
    expect(p.json().settings.secret).toEqual({ set: true, last4: null });
    expect(p.body).not.toContain(SMTP_PASSWORD);
  });

  it("audit events say who changed what, never secrets", async () => {
    const ia = await instanceAdmin();
    await call(ia, "PUT", "/admin/instance/email", { provider: "resend", fromAddress: "vault@clane.test", secret: RESEND_KEY }, null);
    await call(ia, "PUT", "/admin/instance/email", { provider: "resend", fromAddress: "new@clane.test", secret: "re_other_000000000000" }, null);
    await call(ia, "PUT", "/admin/settings/email", smtpSettings());
    await call(ia, "DELETE", "/admin/settings/email");
    const ev = await t.prisma.event.findMany({ where: { action: { startsWith: "email." } }, orderBy: { id: "asc" } });
    expect(ev.map((e) => [e.action, e.actorId, e.orgId])).toEqual([
      ["email.settings_updated", ia.id, null], ["email.settings_updated", ia.id, null], ["email.settings_updated", ia.id, ia.orgId], ["email.settings_removed", ia.id, ia.orgId],
    ]);
    expect(ev[1]!.meta).toMatchObject({ scope: "instance", provider: "resend", changed: expect.arrayContaining(["fromAddress", "secret"]) });
    const all = JSON.stringify(ev.map((e) => e.meta));
    for (const s of [RESEND_KEY, "re_other_000000000000", SMTP_PASSWORD]) expect(all).not.toContain(s);
  });
});

describe("test email", () => {
  it("SMTP: delivers to the admin's own address through a real SMTP conversation", async () => {
    const ia = await instanceAdmin();
    await call(ia, "PUT", "/admin/instance/email", smtpSettings(), null);
    const r = await call(ia, "POST", "/admin/instance/email/test", {}, null);
    expect(r.json()).toEqual({ ok: true, to: ia.email });
    expect(got).toHaveLength(1);
    expect(got[0]).toMatchObject({ from: "vault@acme.test", to: [ia.email], user: "mailer" });
    expect(got[0]!.data).toMatch(/From: Acme Vault <vault@acme.test>/);
    expect(got[0]!.data).toMatch(/Subject: Clane Vault: test email/);
    expect((await t.prisma.event.findFirstOrThrow({ where: { action: "email.test" } })).meta).toMatchObject({ ok: true, provider: "smtp" });
  });

  it("SMTP errors are summarised without credentials", async () => {
    const ia = await instanceAdmin();
    await call(ia, "PUT", "/admin/instance/email", smtpSettings({ secret: "wrong-Password-999" }), null);
    const bad = await call(ia, "POST", "/admin/instance/email/test", {}, null);
    expect(bad.statusCode).toBe(502);
    expect(bad.json().error).toBe("email_test_failed");
    expect(bad.json().detail).toMatch(/rejected the username or password/);
    expect(bad.body).not.toContain("wrong-Password-999");
    // Nothing listens on this port.
    const closed = await new Promise<number>((res) => { const s = new SMTPServer({ logger: false }); s.listen(0, "127.0.0.1", () => { const p = (s.server.address() as AddressInfo).port; s.close(() => res(p)); }); });
    await call(ia, "PUT", "/admin/instance/email", smtpSettings({ smtp: { host: "127.0.0.1", port: closed, security: "none", username: "mailer" } }), null);
    const refused = await call(ia, "POST", "/admin/instance/email/test", {}, null);
    expect(refused.statusCode).toBe(502);
    expect(refused.json().detail).toBe(`Couldn't connect to 127.0.0.1:${closed}: connection refused.`);
    expect(refused.body).not.toContain(SMTP_PASSWORD);
    expect((await t.prisma.event.findMany({ where: { action: "email.test" } })).map((e) => (e.meta as { ok: boolean }).ok)).toEqual([false, false]);
  });

  it("Resend: sends with the stored key; a refused key gives a clear error", async () => {
    const ia = await instanceAdmin();
    await call(ia, "PUT", "/admin/instance/email", { provider: "resend", fromName: "Vault", fromAddress: "vault@clane.test", secret: RESEND_KEY }, null);
    const sent = resendStub();
    expect((await call(ia, "POST", "/admin/instance/email/test", {}, null)).json()).toEqual({ ok: true, to: ia.email });
    expect(sent()).toEqual([expect.objectContaining({ key: `Bearer ${RESEND_KEY}`, from: "Vault <vault@clane.test>", to: [ia.email] })]);
    vi.restoreAllMocks();
    resendStub(401, { name: "validation_error", message: `API key is invalid: ${RESEND_KEY}` });
    const r = await call(ia, "POST", "/admin/instance/email/test", {}, null);
    expect(r.statusCode).toBe(502);
    expect(r.json().detail).toMatch(/API key was rejected/);
    expect(r.body).not.toContain(RESEND_KEY);
  });

  it("needs saved settings of its own scope", async () => {
    const ia = await instanceAdmin();
    t.config.resendApiKey = "re_env"; t.config.emailFrom = "env@clane.test";
    expect((await call(ia, "POST", "/admin/instance/email/test", {}, null)).json()).toEqual({ error: "not_configured" });
    expect((await call(ia, "POST", "/admin/settings/email/test", {})).json()).toEqual({ error: "not_configured" });
  });
});

describe("which settings an email uses", () => {
  it("org override for that org's invites, else instance settings, else RESEND_API_KEY / EMAIL_FROM", async () => {
    const ia = await instanceAdmin();
    const other = await newOrg("Beta");
    const betaOwner = await createActiveUser(t, { role: "owner", orgId: other.id });
    const sent = resendStub();
    // Env only.
    t.config.resendApiKey = "re_env_key_0000000000"; t.config.emailFrom = "Env <env@clane.test>";
    expect((await call(ia, "GET", "/admin/settings/email")).json()).toMatchObject({ settings: null, fallback: "env" });
    await call(ia, "POST", "/admin/invites", { email: "one@x.test" });
    expect(sent().at(-1)).toMatchObject({ key: "Bearer re_env_key_0000000000", from: "Env <env@clane.test>", to: ["one@x.test"] });
    // Instance settings beat the environment, for every org.
    await call(ia, "PUT", "/admin/instance/email", { provider: "resend", fromName: "Instance", fromAddress: "inst@clane.test", secret: RESEND_KEY }, null);
    expect((await call(ia, "GET", "/admin/settings/email")).json()).toMatchObject({ settings: null, fallback: "instance" });
    await call(betaOwner, "POST", "/admin/invites", { email: "two@x.test" });
    expect(sent().at(-1)).toMatchObject({ key: `Bearer ${RESEND_KEY}`, from: "Instance <inst@clane.test>", to: ["two@x.test"] });
    // Beta's own SMTP server for Beta's invites only.
    expect((await call(betaOwner, "PUT", "/admin/settings/email", smtpSettings({ fromName: "Beta Team", fromAddress: "it@beta.test" }))).statusCode).toBe(200);
    const inv = await call(betaOwner, "POST", "/admin/invites", { email: "three@x.test" });
    expect(inv.json().emailed).toBe(true);
    await vi.waitFor(() => expect(got).toHaveLength(1));
    expect(got[0]).toMatchObject({ from: "it@beta.test", to: ["three@x.test"] });
    expect(got[0]!.data).toMatch(/Subject: You're invited to Beta on Clane Vault/);
    const before = sent().length;
    await call(ia, "POST", "/admin/invites", { email: "four@x.test" });
    expect(sent()).toHaveLength(before + 1);
    expect(sent().at(-1)).toMatchObject({ from: "Instance <inst@clane.test>", to: ["four@x.test"] });
    // Account emails (not about one org) use the instance settings even for Beta's people.
    expect((await t.app.mail.resolve(null))?.source).toBe("instance");
    expect((await t.app.mail.resolve(other.id))?.source).toBe("org");
    // Removing the override falls back again; deleting the org removes its settings.
    await call(betaOwner, "DELETE", "/admin/settings/email");
    expect((await t.app.mail.resolve(other.id))?.source).toBe("instance");
    await call(betaOwner, "PUT", "/admin/settings/email", smtpSettings());
    await t.prisma.organization.delete({ where: { id: other.id } });
    expect(await t.prisma.emailSettings.count({ where: { orgId: other.id } })).toBe(0);
  });

  it("hosted mode: invites need some email set up (an org's own settings count); org SMTP may not point at private addresses", async () => {
    const ia = await instanceAdmin();
    const org = await newOrg("Gamma");
    const owner = await createActiveUser(t, { role: "owner", orgId: org.id });
    t.config.hostedMode = true;
    expect((await call(ia, "POST", "/admin/invites", { email: "x@y.test" })).json()).toEqual({ error: "email_required" });
    // No password over an unencrypted connection (any scope); only the usual ports for organisations; no private hosts.
    expect((await call(owner, "PUT", "/admin/settings/email", smtpSettings())).json()).toEqual({ error: "insecure_auth" });
    expect((await call(ia, "PUT", "/admin/instance/email", smtpSettings(), null)).json()).toEqual({ error: "insecure_auth" });
    expect((await call(owner, "PUT", "/admin/settings/email", smtpSettings({ smtp: { host: "127.0.0.1", port: 2526, security: "starttls", username: "mailer" } }))).json()).toEqual({ error: "port_not_allowed" });
    const r = await call(owner, "PUT", "/admin/settings/email", smtpSettings({ smtp: { host: "127.0.0.1", port: 587, security: "starttls", username: "mailer" } }));
    expect(r.statusCode).toBe(400);
    expect(r.json()).toEqual({ error: "private_host" });
    for (const host of ["::ffff:169.254.169.254", "[::ffff:a9fe:a9fe]", "64:ff9b::a9fe:a9fe", "0:0:0:0:0:0:0:1"])
      expect((await call(owner, "PUT", "/admin/settings/email", smtpSettings({ smtp: { host, port: 587, security: "starttls", username: "mailer" } }))).json(), host).toEqual({ error: "private_host" });
    // Instance admins are trusted with the network (a relay without a password on a private address).
    expect((await call(ia, "PUT", "/admin/instance/email", smtpSettings({ secret: undefined, smtp: { host: "127.0.0.1", port: smtpPort, security: "none", username: null } }), null)).statusCode).toBe(200);
    expect((await call(ia, "POST", "/admin/invites", { email: "x@y.test" })).json()).toMatchObject({ invited: true, emailed: true });
  });

  it("security notices go out with the server's settings even when the org has its own", async () => {
    const ia = await instanceAdmin();
    await call(ia, "PUT", "/admin/settings/email", smtpSettings());
    const sent = resendStub();
    t.config.resendApiKey = "re_env_key_0000000000"; t.config.emailFrom = "Env <env@clane.test>";
    const { recoveryAdminActionEmail, sendEmail } = await import("../src/lib/email.js");
    void sendEmail(t.app.mail, ia.email, recoveryAdminActionEmail(t.config.productName, "approved", "Admin", "Test org"), t.app.log);
    await vi.waitFor(() => expect(sent().length).toBeGreaterThan(0));
    expect(got).toHaveLength(0);
  });
});

describe("SMTP password and server changes", () => {
  it("a kept password is dropped when the host, port or security changes", async () => {
    const ia = await instanceAdmin();
    await call(ia, "PUT", "/admin/instance/email", smtpSettings(), null);
    const same = await call(ia, "PUT", "/admin/instance/email", smtpSettings({ secret: undefined }), null);
    expect(same.json().settings.secret.set).toBe(true);
    for (const smtp of [{ host: "localhost", port: smtpPort, security: "none" }, { host: "127.0.0.1", port: smtpPort + 1, security: "none" }, { host: "127.0.0.1", port: smtpPort, security: "starttls" }]) {
      await call(ia, "PUT", "/admin/instance/email", smtpSettings(), null);
      const moved = await call(ia, "PUT", "/admin/instance/email", smtpSettings({ secret: undefined, smtp: { ...smtp, username: "mailer" } }), null);
      expect(moved.json().settings.secret).toEqual({ set: false, last4: null });
    }
  });

  it("error details are generic (no raw server or system messages)", async () => {
    const { smtpErrorSummary } = await import("../src/lib/mailer.js");
    expect(smtpErrorSummary(Object.assign(new Error("weird 10.1.2.3 thing"), { code: "ESOCKET" }), { host: "h", port: 1 }, [])).not.toMatch(/10\.1\.2\.3/);
    expect(smtpErrorSummary(Object.assign(new Error("x"), { code: "EWHATEVER", responseCode: 550 }), { host: "h", port: 1 }, [])).toBe("Sending failed (server said 550).");
  });
});
