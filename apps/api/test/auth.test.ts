import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { authenticator } from "otplib";
import { createAccount, deriveLoginKeys, type KdfParams } from "@clane-vault/crypto";
import { makeTestApp, resetDb, createInvite, createActiveUser, FAST_KDF , freshTotp } from "./helpers.js";

const t = await makeTestApp();
afterAll(() => t.app.close());
beforeEach(() => resetDb(t.prisma));

const post = (url: string, payload: object, token?: string) =>
  t.app.inject({ method: "POST", url: `/api/v1/auth${url}`, payload, headers: token ? { authorization: `Bearer ${token}` } : {} });

describe("registration and 2FA", () => {
  it("registers from an invite, sets up TOTP and gets a session", async () => {
    const token = await createInvite(t.prisma, "sara@clane.ai");
    expect((await t.app.inject({ method: "GET", url: `/api/v1/auth/invite/${token}` })).json()).toEqual({ email: "sara@clane.ai", orgName: "Test org", adminRecoveryEnabled: false, emailVerification: false, passwordPolicy: { minLength: 12, minScore: 0 } });
    const acct = await createAccount("sara master password", FAST_KDF);
    const reg = await post("/register", { inviteToken: token, name: "Sara", authKey: acct.authKey, material: acct.material });
    expect(reg.statusCode).toBe(201);
    const { setupToken } = reg.json();
    const setup = await post("/totp/setup", {}, setupToken);
    expect(setup.json().otpauthUrl).toMatch(/^otpauth:\/\/totp\/Clane%20Vault:sara%40clane\.ai\?secret=/);
    const verify = await post("/totp/verify", { code: await freshTotp(setup.json().secret) }, setupToken);
    expect(verify.statusCode).toBe(200);
    expect(verify.json().user).toMatchObject({ email: "sara@clane.ai", name: "Sara" });
    expect(verify.json().orgs).toEqual([expect.objectContaining({ name: "Test org", role: "member", isDefault: true })]);
    expect(verify.json().material.wrappedUserKey).toBe(acct.material.wrappedUserKey);
    expect(verify.cookies.find((c) => c.name === "cv_refresh")).toMatchObject({ httpOnly: true, sameSite: "Strict", path: "/api/v1/auth" });
  });

  it("refuses a used or unknown invite", async () => {
    const token = await createInvite(t.prisma, "a@clane.ai");
    const acct = await createAccount("pw pw pw pw pw", FAST_KDF);
    expect((await post("/register", { inviteToken: token, name: "A", authKey: acct.authKey, material: acct.material })).statusCode).toBe(201);
    expect((await post("/register", { inviteToken: token, name: "A", authKey: acct.authKey, material: acct.material })).json()).toEqual({ error: "invite_invalid" });
    expect((await t.app.inject({ method: "GET", url: "/api/v1/auth/invite/nope" })).statusCode).toBe(404);
  });

  it("rejects a wrong TOTP code during setup", async () => {
    const token = await createInvite(t.prisma, "b@clane.ai");
    const acct = await createAccount("pw pw pw pw pw", FAST_KDF);
    const { setupToken } = (await post("/register", { inviteToken: token, name: "B", authKey: acct.authKey, material: acct.material })).json();
    await post("/totp/setup", {}, setupToken);
    expect((await post("/totp/verify", { code: "000000" }, setupToken)).json()).toEqual({ error: "totp_invalid" });
  });

  it("never stores the auth key in clear", async () => {
    const u = await createActiveUser(t);
    const row = await t.prisma.user.findUniqueOrThrow({ where: { id: u.id } });
    expect(row.authHash.startsWith("$argon2id$")).toBe(true);
    expect(row.totpSecretEnc).not.toContain(u.totpSecret);
  });
});

describe("sign-in", () => {
  it("returns the same prelogin salt every time, also for unknown emails", async () => {
    const u = await createActiveUser(t);
    const known = (await post("/prelogin", { email: u.email })).json();
    expect(known.kdfSalt).toBe(u.material.kdfSalt);
    const a = (await post("/prelogin", { email: "ghost@clane.ai" })).json();
    const b = (await post("/prelogin", { email: "GHOST@clane.ai" })).json();
    expect(a).toEqual(b);
    expect(Object.keys(a).sort()).toEqual(["kdfParams", "kdfSalt"]);
  });

  it("signs in with password and TOTP", async () => {
    const u = await createActiveUser(t);
    const { authKey } = await deriveLoginKeys(u.password, u.material.kdfSalt, u.material.kdfParams as KdfParams);
    const res = await post("/login", { email: u.email, authKey, code: await freshTotp(u.totpSecret) });
    expect(res.statusCode).toBe(200);
    expect(res.json().accessToken).toBeTruthy();
  });

  it("gives the same error for unknown email and wrong password", async () => {
    const u = await createActiveUser(t);
    const wrong = await post("/login", { email: u.email, authKey: "AAAA", code: "123456" });
    const ghost = await post("/login", { email: "ghost@clane.ai", authKey: "AAAA", code: "123456" });
    expect(wrong.statusCode).toBe(401); expect(ghost.statusCode).toBe(401);
    expect(wrong.json()).toEqual({ error: "invalid_credentials" });
    expect(ghost.json()).toEqual({ error: "invalid_credentials" });
  });

  it("asks for a TOTP code when missing, and rejects a wrong one", async () => {
    const u = await createActiveUser(t);
    const { authKey } = await deriveLoginKeys(u.password, u.material.kdfSalt, u.material.kdfParams as KdfParams);
    expect((await post("/login", { email: u.email, authKey })).json()).toEqual({ error: "totp_required" });
    expect((await post("/login", { email: u.email, authKey, code: "000000" })).json()).toEqual({ error: "totp_invalid" });
  });

  it("locks the account after 10 failures", async () => {
    const u = await createActiveUser(t);
    for (let i = 0; i < 10; i++) await post("/login", { email: u.email, authKey: "AAAA", code: "000000" });
    const res = await post("/login", { email: u.email, authKey: "AAAA", code: "000000" });
    expect(res.statusCode).toBe(423);
    expect(res.json().error).toBe("locked");
  });

  it("sends pending users back to TOTP setup", async () => {
    const token = await createInvite(t.prisma, "c@clane.ai");
    const acct = await createAccount("pw pw pw pw pw", FAST_KDF);
    await post("/register", { inviteToken: token, name: "C", authKey: acct.authKey, material: acct.material });
    const res = await post("/login", { email: "c@clane.ai", authKey: acct.authKey });
    expect(res.json()).toMatchObject({ needsTotpSetup: true });
  });

  it("writes login events", async () => {
    const u = await createActiveUser(t);
    await post("/login", { email: u.email, authKey: "AAAA", code: "1" });
    const actions = (await t.prisma.event.findMany({ where: { actorId: u.id } })).map((e) => e.action);
    expect(actions).toContain("auth.login_failed");
  });
});

describe("hardening", () => {
  it("prelogin kdfParams have the same key order for known and unknown emails", async () => {
    const u = await createActiveUser(t);
    const known = (await post("/prelogin", { email: u.email })).json();
    const ghost = (await post("/prelogin", { email: "ghost@clane.ai" })).json();
    expect(Object.keys(known.kdfParams)).toEqual(["alg", "m", "t", "p"]);
    expect(Object.keys(ghost.kdfParams)).toEqual(["alg", "m", "t", "p"]);
    expect(JSON.stringify(Object.keys(known.kdfParams))).toBe(JSON.stringify(Object.keys(ghost.kdfParams)));
  });

  it("locks even when wrong logins arrive in parallel", async () => {
    const t2 = await makeTestApp();
    try {
      const u = await createActiveUser(t2);
      const attempt = () => t2.app.inject({ method: "POST", url: "/api/v1/auth/login", payload: { email: u.email, authKey: "AAAA", code: "000000" } });
      await Promise.all(Array.from({ length: 15 }, attempt));
      expect((await attempt()).statusCode).toBe(423);
    } finally { await t2.app.close(); }
  });

  it("answers malformed JSON with 400 invalid_request", async () => {
    const res = await t.app.inject({ method: "POST", url: "/api/v1/auth/prelogin", payload: "{not json", headers: { "content-type": "application/json" } });
    expect(res.statusCode).toBe(400);
    expect(res.json()).toEqual({ error: "invalid_request" });
  });
});
