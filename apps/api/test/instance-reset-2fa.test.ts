import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { deriveLoginKeys } from "@clane-vault/crypto";
import { makeTestApp, resetDb, createActiveUser, freshTotp, wrongTotp } from "./helpers.js";
import { LOCK_AFTER } from "../src/lib/lockout.js";
import { resetTwoFactorByEmail } from "../src/lib/twoFactor.js";

// The instance-level authenticator reset by email address, which reaches organisation owners (docs/recovery.md), and
// its core function, which the operator's reset-2fa CLI runs.
const t = await makeTestApp();
afterAll(() => t.app.close());
beforeEach(() => resetDb(t.prisma));
const saved = { ...t.config };
afterEach(() => { vi.restoreAllMocks(); Object.assign(t.config, saved); delete t.config.resendApiKey; delete t.config.emailFrom; delete t.config.hostedMode; delete t.config.maxOwnedOrgs; });

type U = Awaited<ReturnType<typeof createActiveUser>>;
type M = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
let ipSeq = 0;
const ip = () => `10.171.${(++ipSeq >> 8) & 255}.${ipSeq & 255}`;
const call = (u: U, method: M, url: string, payload?: unknown, org?: string | null) => {
  const o = org === undefined ? u.orgId : org;
  return t.app.inject({ method, url: `/api/v1${url}`, payload: payload as object, remoteAddress: ip(), headers: { authorization: `Bearer ${u.accessToken}`, ...(o ? { "x-org-id": o } : {}) } });
};
const pub = (method: M, url: string, payload?: unknown) => t.app.inject({ method, url: `/api/v1${url}`, payload: payload as object, remoteAddress: ip() });

/** Resend stub: every email is captured. */
function mailbox() {
  t.config.resendApiKey = "re_test"; t.config.emailFrom = "vault@clane.ai";
  const spy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("{}", { status: 200 }));
  return () => spy.mock.calls.filter(([u]) => String(u).includes("resend.com")).map(([, init]) => JSON.parse(String((init as RequestInit).body)) as { to: string[]; subject: string; text: string });
}

async function instanceAdmin(): Promise<U> {
  const a = await createActiveUser(t, { role: "owner" });
  await t.prisma.user.update({ where: { id: a.id }, data: { instanceAdmin: true } });
  return a;
}

/** The instance admin's reset, with their own fresh authenticator code unless `code` is given. */
const reset = async (ia: U, email: string, code?: string) => call(ia, "POST", "/admin/instance/users/reset-2fa", { email, code: code ?? await freshTotp(ia.totpSecret) }, null);

/** An account that owns its own organisation (not the default one). */
async function ownerOfNewOrg(name = "Customer"): Promise<U> {
  const org = await t.prisma.organization.create({ data: { name, slug: `${name.toLowerCase()}-${crypto.randomUUID().slice(0, 8)}` } });
  return createActiveUser(t, { role: "owner", orgId: org.id });
}

describe("resetting someone's authenticator by email address (instance admins)", () => {
  it("resets an organisation owner's: back to setup, signed out everywhere, emailed and logged at instance level", async () => {
    const ia = await instanceAdmin();
    const owner = await ownerOfNewOrg();
    const sent = mailbox();
    const r = await reset(ia, ` ${owner.email.toUpperCase()} `);
    expect(r.statusCode, r.body).toBe(200);
    expect(r.json()).toEqual({ ok: true, email: owner.email, emailed: true });
    const u = await t.prisma.user.findUniqueOrThrow({ where: { id: owner.id } });
    expect(u).toMatchObject({ status: "pending_2fa", totpSecretEnc: null, totpEnabledAt: null, totpResetBy: ia.id });
    expect(u.totpResetAt).not.toBeNull();
    expect((await call(owner, "GET", "/sync")).statusCode).toBe(401);
    expect(sent().map((m) => [m.to[0], m.subject])).toEqual([[owner.email, "Clane Vault: your two-step sign-in was reset"]]);
    const ev = await t.prisma.event.findFirstOrThrow({ where: { action: "instance.reset_2fa" } });
    expect(ev).toMatchObject({ orgId: null, actorId: ia.id, targetUserId: owner.id, meta: { via: "app" } });
    // The owner signs in again and sets up a new authenticator.
    const { authKey } = await deriveLoginKeys(owner.password, owner.material.kdfSalt, owner.material.kdfParams);
    expect((await pub("POST", "/auth/login", { email: owner.email, authKey })).json().needsTotpSetup).toBe(true);
  });

  it("is refused for anyone else, for the instance admin's own account, and for unknown or disabled accounts", async () => {
    const ia = await instanceAdmin();
    const owner = await ownerOfNewOrg();
    const admin = await createActiveUser(t, { role: "admin" });
    // The default org's owner and admins aren't instance admins by role: only the flag counts.
    expect((await call(admin, "POST", "/admin/instance/users/reset-2fa", { email: owner.email }, null)).statusCode).toBe(403);
    expect((await call(owner, "POST", "/admin/instance/users/reset-2fa", { email: admin.email }, null)).statusCode).toBe(403);
    expect((await reset(ia, ia.email)).json()).toEqual({ error: "self" });
    expect((await reset(ia, "nobody@clane.ai")).statusCode).toBe(404);
    // The organisation route still never touches an owner.
    expect((await call(admin, "POST", `/admin/users/${ia.id}/reset-2fa`)).json()).toEqual({ error: "owner" });
    await t.prisma.user.update({ where: { id: admin.id }, data: { status: "disabled" } });
    expect((await reset(ia, admin.email)).json()).toEqual({ error: "disabled" });
    for (const id of [owner.id, ia.id]) expect((await t.prisma.user.findUniqueOrThrow({ where: { id } })).status).toBe("active");
    expect(await t.prisma.event.count({ where: { action: "instance.reset_2fa" } })).toBe(0);
  });

  it("needs the instance admin's own fresh authenticator code, checked before the address and counted toward their lockout", async () => {
    const ia = await instanceAdmin();
    const owner = await ownerOfNewOrg();
    // No code: refused before anything else.
    expect((await call(ia, "POST", "/admin/instance/users/reset-2fa", { email: owner.email }, null)).statusCode).toBe(400);
    // A wrong code gets the same answer for a real and an unknown address: no probing which addresses exist.
    for (const email of [owner.email, "nobody@clane.ai"]) expect((await reset(ia, email, wrongTotp(ia.totpSecret))).json()).toEqual({ error: "totp_invalid" });
    expect((await t.prisma.user.findUniqueOrThrow({ where: { id: ia.id } })).failedLogins).toBe(2);
    expect(await t.prisma.event.count({ where: { actorId: ia.id, action: "auth.reauth_failed" } })).toBe(2);
    // A code used once doesn't work again (the target is untouched until a good code).
    const code = await freshTotp(ia.totpSecret);
    expect((await reset(ia, "nobody@clane.ai", code)).statusCode).toBe(404);
    expect((await reset(ia, owner.email, code)).json()).toEqual({ error: "totp_invalid" });
    expect((await t.prisma.user.findUniqueOrThrow({ where: { id: owner.id } })).status).toBe("active");
    // Enough wrong codes lock the instance admin's account: then even a right code gets 423.
    for (let i = 3; i < LOCK_AFTER; i++) await reset(ia, owner.email, wrongTotp(ia.totpSecret));
    const locked = await reset(ia, owner.email);
    expect(locked.statusCode).toBe(423);
    expect(locked.json()).toMatchObject({ error: "locked" });
    expect((await t.prisma.user.findUniqueOrThrow({ where: { id: owner.id } })).status).toBe("active");
    expect(await t.prisma.event.count({ where: { action: "instance.reset_2fa" } })).toBe(0);
  });

  it("CLI core: resets by email with no actor, records no resetter and logs the CLI as the source", async () => {
    const ia = await instanceAdmin();
    const sent = mailbox();
    const deps = { prisma: t.prisma, mail: t.app.mail, productName: () => t.app.brand.productName() };
    const r = await resetTwoFactorByEmail(deps, { email: ia.email, actorId: null, log: t.app.log });
    expect(r).toMatchObject({ ok: true, user: { id: ia.id, email: ia.email }, emailed: true });
    expect(await t.prisma.user.findUniqueOrThrow({ where: { id: ia.id } })).toMatchObject({ status: "pending_2fa", totpSecretEnc: null, totpResetBy: null, instanceAdmin: true });
    expect(await t.prisma.session.count({ where: { userId: ia.id, revokedAt: null } })).toBe(0);
    expect(await t.prisma.event.findFirstOrThrow({ where: { action: "instance.reset_2fa" } })).toMatchObject({ actorId: null, targetUserId: ia.id, meta: { via: "cli" } });
    expect(sent()[0]!.text).toContain("The Clane Vault server's operator reset the two-step sign-in");
    expect(await resetTwoFactorByEmail(deps, { email: "nobody@clane.ai", actorId: null, log: t.app.log })).toEqual({ ok: false, error: "not_found" });
  });
});
