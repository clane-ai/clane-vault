import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { authenticator } from "otplib";
import { createAccount } from "@clane-vault/crypto";
import { makeTestApp, resetDb, createActiveUser, FAST_KDF , freshTotp, orgHeader } from "./helpers.js";

const t = await makeTestApp();
afterAll(() => t.app.close());
beforeEach(() => resetDb(t.prisma));
afterEach(() => { vi.restoreAllMocks(); delete t.config.resendApiKey; delete t.config.emailFrom; });

type U = Awaited<ReturnType<typeof createActiveUser>>;
const call = (u: U, method: "GET" | "POST" | "DELETE" | "PATCH", url: string, payload?: unknown) =>
  t.app.inject({ method, url: `/api/v1${url}`, payload: payload as object, headers: { authorization: `Bearer ${u.accessToken}`, ...orgHeader(u) } });

describe("admin", () => {
  it("guards every admin endpoint by role (read from the database)", async () => {
    const m = await createActiveUser(t);
    const id = crypto.randomUUID();
    for (const [method, url] of [["POST", "/admin/invites"], ["GET", "/admin/people"], ["DELETE", `/admin/invites/${id}`], ["POST", `/admin/users/${id}/disable`], ["POST", `/admin/users/${id}/enable`], ["POST", `/admin/users/${id}/reset-2fa`]] as const) {
      expect((await call(m, method, url, method === "POST" ? { email: "x@clane.ai" } : undefined)).statusCode, url).toBe(403);
      expect((await t.app.inject({ method, url: `/api/v1${url}` })).statusCode, url).toBe(401);
    }
    // A demoted admin loses access immediately, even with a token minted while admin.
    const a = await createActiveUser(t, { role: "admin" });
    expect((await call(a, "GET", "/admin/people")).statusCode).toBe(200);
    await t.prisma.membership.updateMany({ where: { userId: a.id }, data: { role: "member" } });
    expect((await call(a, "GET", "/admin/people")).statusCode).toBe(403);
  });

  it("invites by email: returns the link once, stores only a hash, lists it as pending, and registration works with a normalised email", async () => {
    const a = await createActiveUser(t, { role: "admin" });
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const res = await call(a, "POST", "/admin/invites", { email: "  New.Person@Clane.AI ", role: "member" });
    expect(res.statusCode).toBe(201);
    const { inviteUrl, emailed } = res.json();
    expect(res.json()).toEqual({ invited: true, email: "new.person@clane.ai", role: "member", emailed: false, inviteUrl });
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(inviteUrl).toMatch(/^http:\/\/localhost:5173\/invite\/[A-Za-z0-9_-]{20,}$/);
    const token = inviteUrl.split("/invite/")[1];
    const row = await t.prisma.invite.findFirstOrThrow({ where: { email: "new.person@clane.ai" } });
    const id = row.id;
    expect(row.expiresAt.getTime() - Date.now()).toBeGreaterThan(6.9 * 864e5);
    expect(row.email).toBe("new.person@clane.ai");
    expect(JSON.stringify(row)).not.toContain(token);

    const people = (await call(a, "GET", "/admin/people")).json();
    expect(people.invites).toEqual([expect.objectContaining({ id, email: "new.person@clane.ai", role: "member" })]);
    expect(JSON.stringify(people)).not.toContain(token);
    expect(people.users[0]).toMatchObject({ id: a.id, role: "admin", status: "active" });

    // Re-inviting replaces the pending invite.
    const again = (await call(a, "POST", "/admin/invites", { email: "new.person@clane.ai" })).json();
    expect((await t.app.inject({ method: "GET", url: `/api/v1/auth/invite/${token}` })).statusCode).toBe(404);
    const token2 = again.inviteUrl.split("/invite/")[1];
    expect((await t.app.inject({ method: "GET", url: `/api/v1/auth/invite/${token2}` })).json()).toEqual({ email: "new.person@clane.ai", orgName: "Test org", adminRecoveryEnabled: false, emailVerification: false, passwordPolicy: { minLength: 12, minScore: 0 } });
    const acct = await createAccount("pw for new person", FAST_KDF);
    const reg = await t.app.inject({ method: "POST", url: "/api/v1/auth/register", payload: { inviteToken: token2, name: "New", authKey: acct.authKey, material: acct.material } });
    expect(reg.statusCode).toBe(201);
    const created = await t.prisma.user.findUniqueOrThrow({ where: { email: "new.person@clane.ai" }, include: { memberships: true } });
    expect(created.memberships).toEqual([expect.objectContaining({ orgId: a.orgId, role: "member", status: "active" })]);
    expect((await call(a, "GET", "/admin/people")).json().invites).toEqual([]);
    // Inviting a member again answers like any invite (no "already a member" oracle) and changes nothing.
    const dup = await call(a, "POST", "/admin/invites", { email: "NEW.person@clane.ai" });
    expect(dup.statusCode).toBe(201);
    expect(Object.keys(dup.json()).sort()).toEqual(["email", "emailed", "invited", "inviteUrl", "role"].sort());
    expect((await call(a, "GET", "/admin/people")).json().invites).toEqual([]);
  });

  it("sends the invite through Resend when configured", async () => {
    const a = await createActiveUser(t, { role: "admin" });
    t.config.resendApiKey = "re_test"; t.config.emailFrom = "Vault <vault@clane.ai>";
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("{}", { status: 200 }));
    const res = (await call(a, "POST", "/admin/invites", { email: "x@clane.ai" })).json();
    expect(res.emailed).toBe(true);
    expect(fetchSpy).toHaveBeenCalledOnce();
    const [url, init] = fetchSpy.mock.calls[0]!;
    expect(url).toBe("https://api.resend.com/emails");
    expect((init!.headers as Record<string, string>).authorization).toBe("Bearer re_test");
    expect(JSON.parse(init!.body as string)).toMatchObject({ from: "Vault <vault@clane.ai>", to: ["x@clane.ai"] });
    expect(init!.body as string).toContain(res.inviteUrl);
    fetchSpy.mockResolvedValue(new Response("{}", { status: 500 }));
    expect((await call(a, "POST", "/admin/invites", { email: "y@clane.ai" })).json().emailed).toBe(false);
  });

  it("revokes invites", async () => {
    const a = await createActiveUser(t, { role: "admin" });
    const { inviteUrl } = (await call(a, "POST", "/admin/invites", { email: "x@clane.ai" })).json();
    const id = (await call(a, "GET", "/admin/people")).json().invites[0].id;
    expect((await call(a, "DELETE", `/admin/invites/${id}`)).statusCode).toBe(204);
    expect((await call(a, "DELETE", `/admin/invites/${id}`)).statusCode).toBe(404);
    expect((await t.app.inject({ method: "GET", url: `/api/v1/auth/invite/${inviteUrl.split("/invite/")[1]}` })).statusCode).toBe(404);
  });

  it("disable shuts the member out of the org (not out of their account); enable restores", async () => {
    const a = await createActiveUser(t, { role: "admin" }), m = await createActiveUser(t);
    expect((await call(a, "POST", `/admin/users/${a.id}/disable`)).statusCode).toBe(400);
    expect((await call(a, "POST", `/admin/users/${m.id}/disable`)).statusCode).toBe(200);
    // The org is gone for them at once; their account and private vault are not.
    expect((await call(m, "GET", "/sync")).json()).toEqual({ error: "org_forbidden" });
    expect((await t.app.inject({ method: "GET", url: "/api/v1/sync", headers: { authorization: `Bearer ${m.accessToken}` } })).statusCode).toBe(200);
    expect((await t.app.inject({ method: "POST", url: "/api/v1/auth/refresh", headers: { cookie: m.cookie } })).json().orgs).toEqual([]);
    const people = (await call(a, "GET", "/admin/people")).json();
    expect(people.users.find((u: { id: string }) => u.id === m.id).status).toBe("disabled");
    expect((await call(a, "GET", "/users")).json().users.map((u: { id: string }) => u.id)).toEqual([a.id]);
    expect((await call(a, "POST", `/admin/users/${m.id}/enable`)).statusCode).toBe(200);
    expect((await call(m, "GET", "/sync")).statusCode).toBe(200);
    expect((await call(a, "POST", `/admin/users/${m.id}/enable`)).statusCode).toBe(409);
  });

  it("a globally disabled account (from before organisations) can't sign in until an admin of all its orgs enables it", async () => {
    const a = await createActiveUser(t, { role: "admin" }), m = await createActiveUser(t);
    await t.prisma.user.update({ where: { id: m.id }, data: { status: "disabled" } });
    await t.prisma.membership.updateMany({ where: { userId: m.id }, data: { status: "disabled" } });
    expect((await t.app.inject({ method: "POST", url: "/api/v1/auth/refresh", headers: { cookie: m.cookie } })).statusCode).toBe(401);
    expect((await call(a, "POST", `/admin/users/${m.id}/enable`)).statusCode).toBe(200);
    expect((await t.prisma.user.findUniqueOrThrow({ where: { id: m.id } })).status).toBe("active");
  });

  it("the owner can't be disabled, reset or removed by admins", async () => {
    const o = await createActiveUser(t, { role: "owner" }), a = await createActiveUser(t, { role: "admin" });
    for (const [method, url] of [["POST", `/admin/users/${o.id}/disable`], ["POST", `/admin/users/${o.id}/reset-2fa`], ["DELETE", `/admin/members/${o.id}`]] as const)
      expect((await call(a, method, url)).json(), url).toEqual({ error: "owner" });
  });

  it("changes roles: a promoted member gets admin power and an admin age, a demoted admin loses it and its escrows", async () => {
    const a = await createActiveUser(t, { role: "admin" }), m = await createActiveUser(t);
    expect((await call(m, "GET", "/admin/people")).statusCode).toBe(403);
    expect((await call(a, "PATCH", `/admin/members/${m.id}`, { role: "admin" })).statusCode).toBe(200);
    expect((await call(m, "GET", "/admin/people")).statusCode).toBe(200);
    expect((await t.prisma.membership.findFirstOrThrow({ where: { userId: m.id } })).adminSince).not.toBeNull();
    await t.prisma.membershipEscrow.create({ data: { orgId: a.orgId, userId: a.id, adminId: m.id, memberPublicKey: "k1", adminPublicKey: "k2", sealedKey: "s1.x" } });
    expect((await call(a, "PATCH", `/admin/members/${m.id}`, { role: "member" })).statusCode).toBe(200);
    expect((await call(m, "GET", "/admin/people")).statusCode).toBe(403);
    expect(await t.prisma.membershipEscrow.count({ where: { adminId: m.id } })).toBe(0);
  });

  it("reset-2fa clears the authenticator, revokes sessions and sends the user back through 2FA setup", async () => {
    const a = await createActiveUser(t, { role: "admin" }), m = await createActiveUser(t);
    expect((await call(a, "POST", `/admin/users/${m.id}/reset-2fa`)).statusCode).toBe(200);
    const u = await t.prisma.user.findUniqueOrThrow({ where: { id: m.id } });
    expect(u.status).toBe("pending_2fa");
    expect(u.totpSecretEnc).toBeNull();
    expect((await call(m, "GET", "/sync")).statusCode).toBe(401);
    const { deriveLoginKeys } = await import("@clane-vault/crypto");
    const { authKey } = await deriveLoginKeys(m.password, m.material.kdfSalt, m.material.kdfParams);
    const login = (await t.app.inject({ method: "POST", url: "/api/v1/auth/login", payload: { email: m.email, authKey } })).json();
    expect(login.needsTotpSetup).toBe(true);
    const auth = { authorization: `Bearer ${login.setupToken}` };
    const secret = (await t.app.inject({ method: "POST", url: "/api/v1/auth/totp/setup", headers: auth, payload: {} })).json().secret;
    expect(secret).not.toBe(m.totpSecret);
    const v = await t.app.inject({ method: "POST", url: "/api/v1/auth/totp/verify", headers: auth, payload: { code: await freshTotp(secret) } });
    expect(v.statusCode).toBe(200);
  });
});
