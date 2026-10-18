import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";
import { authenticator } from "otplib";
import {
  createRecoveryKit, parseRecoveryCode, recoveryAuthFor, openRecoveryWrap, keysFromUserKey, changeMasterPassword, deriveLoginKeys,
  adminRecoveryProof, b64url, generateKeyPair, unlockAccount, unlockMembershipKeys, openMembershipEscrow, createMembershipRecoveryGrant, createMembershipKeys,
  sealMembershipEscrow, createTeamFolder, sealOrgFolderKey, sealFolderKeyFor, resealFolderKeyToMembership, type AccountMaterial,
} from "@clane-vault/crypto";
import { anyScopedPayload, approveScoped, escrowKey, keyUp, keysOf, scopedReset } from "./keys.js";
import { makeTestApp, resetDb, createActiveUser, FAST_KDF, freshTotp, wrongTotp as wrongCode, orgHeader } from "./helpers.js";
import { sweepRecoveryRequests } from "../src/lib/recovery.js";
import { createTestAgent } from "./agentHelpers.js";

const t = await makeTestApp();
afterAll(() => t.app.close());
beforeEach(() => resetDb(t.prisma));

type U = Awaited<ReturnType<typeof createActiveUser>>;
let ip = 0;
// A fresh client address per call, so the per-route rate limits don't interfere (one test checks them on purpose).
const addr = () => `10.9.${(++ip >> 8) & 255}.${ip & 255}`;
const pub = (method: "GET" | "POST", url: string, payload?: object, headers: Record<string, string> = {}, remoteAddress = addr()) =>
  t.app.inject({ method, url: `/api/v1${url}`, payload, headers, remoteAddress });
const call = (u: { accessToken: string; orgId?: string }, method: "GET" | "POST" | "PUT" | "DELETE", url: string, payload?: object) =>
  t.app.inject({ method, url: `/api/v1${url}`, payload, headers: { authorization: `Bearer ${u.accessToken}`, ...orgHeader(u) }, remoteAddress: addr() });
const authKeyOf = async (u: U) => (await deriveLoginKeys(u.password, u.material.kdfSalt, u.material.kdfParams)).authKey;
/**
 * The current code for this user. The server accepts each time step once; tests that don't test replays clear the
 * user's last step first instead of waiting 30 s for the next code.
 */
const totp = async (u: U) => { await t.prisma.user.update({ where: { id: u.id }, data: { totpLastStep: null } }); return authenticator.generate(u.totpSecret); };
const wrongTotp = (u: U) => wrongCode(u.totpSecret);
const events = async (action: string) => t.prisma.event.findMany({ where: { action } });

async function makeKit(u: U) {
  const kit = await createRecoveryKit(u.id, u.keys.userKey);
  const res = await call(u, "POST", "/me/recovery-kit", { authKey: await authKeyOf(u), recoveryWrap: kit.recoveryWrap, recoveryAuth: kit.recoveryAuth });
  expect(res.statusCode).toBe(201);
  return kit;
}

async function newPasswordFor(material: AccountMaterial, userKey: Uint8Array, password = "a brand new master password") {
  const keys = await keysFromUserKey(userKey, material);
  const changed = await changeMasterPassword(password, keys, material, FAST_KDF);
  return { password, authKey: changed.authKey, material: changed.material };
}

describe("recovery kit: create and regenerate", () => {
  it("needs the master password; the server stores only a hash of the auth value", async () => {
    const u = await createActiveUser(t);
    expect((await call(u, "GET", "/me/security")).json()).toEqual({ recoveryKit: null, adminRecoveryEnabled: false, adminRecoveryAckRequired: false, orgs: [], keyArchive: null });
    const kit = await createRecoveryKit(u.id, u.keys.userKey);
    const bad = await call(u, "POST", "/me/recovery-kit", { authKey: "AAAA", recoveryWrap: kit.recoveryWrap, recoveryAuth: kit.recoveryAuth });
    expect(bad.statusCode).toBe(401);
    expect((await t.prisma.user.findUniqueOrThrow({ where: { id: u.id } })).failedLogins).toBe(1);
    expect((await t.app.inject({ method: "POST", url: "/api/v1/me/recovery-kit", payload: { authKey: "x", recoveryWrap: kit.recoveryWrap, recoveryAuth: kit.recoveryAuth } })).statusCode).toBe(401);
    await makeKit(u);
    const row = await t.prisma.user.findUniqueOrThrow({ where: { id: u.id } });
    expect(row.recoveryAuthHash).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(row)).not.toContain(kit.recoveryAuth);
    expect(row.failedLogins).toBe(0);
    const sec = (await call(u, "GET", "/me/security")).json();
    expect(sec.recoveryKit.createdAt).toEqual(expect.any(String));
    expect((await events("auth.recovery_kit_created"))).toHaveLength(1);
    // The session views say whether a kit exists.
    expect((await call(u, "GET", "/me")).json().user.recoveryKit).toBe(true);
  });

  it("rejects malformed kit material", async () => {
    const u = await createActiveUser(t);
    const authKey = await authKeyOf(u);
    for (const p of [{ recoveryWrap: "plain", recoveryAuth: "A".repeat(43) }, { recoveryWrap: "v1.abc", recoveryAuth: "short" }])
      expect((await call(u, "POST", "/me/recovery-kit", { authKey, ...p })).statusCode).toBe(400);
  });

  it("regenerating invalidates the old kit", async () => {
    const u = await createActiveUser(t);
    const old = await makeKit(u);
    await makeKit(u);
    expect(await events("auth.recovery_kit_regenerated")).toHaveLength(1);
    const res = await pub("POST", "/auth/recovery/kit", { email: u.email, recoveryAuth: old.recoveryAuth, code: await totp(u) });
    expect(res.json()).toEqual({ error: "invalid_recovery" });
  });
});

describe("recovery with the kit", () => {
  it("answers the same for unknown emails, accounts without a kit and wrong codes", async () => {
    const withKit = await createActiveUser(t), noKit = await createActiveUser(t);
    await makeKit(withKit);
    const wrong = await recoveryAuthFor(crypto.getRandomValues(new Uint8Array(32)));
    const r = await Promise.all([
      pub("POST", "/auth/recovery/kit", { email: "ghost@clane.ai", recoveryAuth: wrong, code: "123456" }),
      pub("POST", "/auth/recovery/kit", { email: noKit.email, recoveryAuth: wrong, code: "123456" }),
      pub("POST", "/auth/recovery/kit", { email: withKit.email, recoveryAuth: wrong, code: "123456" }),
      pub("POST", "/auth/recovery/kit", { email: withKit.email, recoveryAuth: wrong }),
    ]);
    for (const x of r) { expect(x.statusCode).toBe(401); expect(x.json()).toEqual({ error: "invalid_recovery" }); }
  });

  it("wrong codes count toward the sign-in lockout", async () => {
    const u = await createActiveUser(t);
    await makeKit(u);
    const wrong = await recoveryAuthFor(crypto.getRandomValues(new Uint8Array(32)));
    for (let i = 0; i < 9; i++) expect((await pub("POST", "/auth/recovery/kit", { email: u.email, recoveryAuth: wrong })).statusCode).toBe(401);
    // the 10th failure can be a wrong password: the counter is shared
    expect((await pub("POST", "/auth/login", { email: u.email, authKey: "AAAA", code: "123456" })).statusCode).toBe(401);
    const locked = await pub("POST", "/auth/recovery/kit", { email: u.email, recoveryAuth: wrong });
    expect(locked.statusCode).toBe(423);
    expect(locked.json().error).toBe("locked");
    expect((await events("auth.recovery_failed")).length).toBe(9);
  });

  it("is rate limited per client", async () => {
    const wrong = await recoveryAuthFor(crypto.getRandomValues(new Uint8Array(32)));
    const codes: number[] = [];
    for (let i = 0; i < 12; i++) codes.push((await pub("POST", "/auth/recovery/kit", { email: "ghost@clane.ai", recoveryAuth: wrong }, {}, "10.200.0.1")).statusCode);
    expect(codes.slice(0, 10).every((c) => c === 401)).toBe(true);
    expect(codes.at(-1)).toBe(429);
  });

  it("needs fresh 2FA, then sets a new password, signs out everywhere and consumes the kit", async () => {
    const u = await createActiveUser(t);
    const other = await createActiveUser(t);
    const kit = await makeKit(u);
    const recoveryAuth = await recoveryAuthFor(await parseRecoveryCode(kit.code));
    expect((await pub("POST", "/auth/recovery/kit", { email: u.email, recoveryAuth })).json()).toEqual({ error: "totp_required" });
    const bad = await pub("POST", "/auth/recovery/kit", { email: u.email, recoveryAuth, code: wrongTotp(u) });
    expect(bad.json()).toEqual({ error: "totp_invalid" });
    expect((await t.prisma.user.findUniqueOrThrow({ where: { id: u.id } })).failedLogins).toBe(1);

    const ok = await pub("POST", "/auth/recovery/kit", { email: u.email.toUpperCase(), recoveryAuth, code: await totp(u) });
    expect(ok.statusCode).toBe(200);
    const body = ok.json();
    expect(Object.keys(body).sort()).toEqual(["material", "recoveryToken", "recoveryWrap", "userId"]);
    // The client unwraps the user key with the code and picks a new password.
    const userKey = await openRecoveryWrap(body.userId, await parseRecoveryCode(kit.code), body.recoveryWrap);
    expect(userKey).toEqual(u.keys.userKey);
    const next = await newPasswordFor(body.material, userKey);

    // An access token is not a recovery token, and the other user's token can't finish this user's recovery.
    expect((await pub("POST", "/auth/recovery/finish", { authKey: next.authKey, material: next.material }, { authorization: `Bearer ${u.accessToken}` })).statusCode).toBe(401);
    const fin = await pub("POST", "/auth/recovery/finish", { authKey: next.authKey, material: next.material }, { authorization: `Bearer ${body.recoveryToken}` });
    expect(fin.statusCode).toBe(200);
    expect(fin.json().user).toMatchObject({ id: u.id, recoveryKit: false });
    expect(fin.cookies.find((c) => c.name === "cv_refresh")).toBeTruthy();

    // Old sessions are gone; the other user's are not.
    expect((await call(u, "GET", "/me")).statusCode).toBe(401);
    expect((await t.app.inject({ method: "POST", url: "/api/v1/auth/refresh", headers: { cookie: u.cookie } })).statusCode).toBe(401);
    expect((await call(other, "GET", "/me")).statusCode).toBe(200);
    expect((await call({ accessToken: fin.json().accessToken }, "GET", "/me")).statusCode).toBe(200);

    // New password works, old one doesn't; the user key is unchanged.
    const login = await pub("POST", "/auth/login", { email: u.email, authKey: next.authKey, code: await totp(u) });
    expect(login.statusCode).toBe(200);
    expect((await pub("POST", "/auth/login", { email: u.email, authKey: await authKeyOf(u), code: await totp(u) })).statusCode).toBe(401);
    const { wrapKey } = await deriveLoginKeys(next.password, next.material.kdfSalt, next.material.kdfParams);
    expect((await unlockAccount(wrapKey, login.json().material)).userKey).toEqual(u.keys.userKey);

    // The kit is used up, and so is the token.
    const row = await t.prisma.user.findUniqueOrThrow({ where: { id: u.id } });
    expect([row.recoveryWrap, row.recoveryAuthHash, row.recoveryCreatedAt]).toEqual([null, null, null]);
    expect((await pub("POST", "/auth/recovery/kit", { email: u.email, recoveryAuth, code: await totp(u) })).json()).toEqual({ error: "invalid_recovery" });
    expect((await pub("POST", "/auth/recovery/finish", { authKey: next.authKey, material: next.material }, { authorization: `Bearer ${body.recoveryToken}` })).statusCode).toBe(410);
    expect(await events("auth.recovery_kit_used")).toHaveLength(1);
  });

  it("refuses a different key pair and a token from before a kit regeneration", async () => {
    const u = await createActiveUser(t);
    const kit = await makeKit(u);
    const recoveryAuth = kit.recoveryAuth;
    const { recoveryToken } = (await pub("POST", "/auth/recovery/kit", { email: u.email, recoveryAuth, code: await totp(u) })).json();
    const next = await newPasswordFor(u.material, u.keys.userKey);
    const other = await generateKeyPair();
    const swapped = { ...next.material, publicKey: b64url.encode(other.publicKey) };
    expect((await pub("POST", "/auth/recovery/finish", { authKey: next.authKey, material: swapped }, { authorization: `Bearer ${recoveryToken}` })).json()).toEqual({ error: "key_mismatch" });
    await makeKit(u); // regenerated after the check
    expect((await pub("POST", "/auth/recovery/finish", { authKey: next.authKey, material: next.material }, { authorization: `Bearer ${recoveryToken}` })).statusCode).toBe(410);
    expect((await call(u, "GET", "/me")).statusCode).toBe(200); // nothing changed
  });

  it("after an admin 2FA reset, the kit leads through a new authenticator first", async () => {
    const a = await createActiveUser(t, { role: "admin" }), u = await createActiveUser(t);
    const kit = await makeKit(u);
    await call(a, "POST", `/admin/users/${u.id}/reset-2fa`);
    const res = (await pub("POST", "/auth/recovery/kit", { email: u.email, recoveryAuth: kit.recoveryAuth })).json();
    expect(res.needsTotpSetup).toBe(true);
    const auth = { authorization: `Bearer ${res.setupToken}` };
    const secret = (await pub("POST", "/auth/totp/setup", {}, auth)).json().secret as string;
    const code = await freshTotp(secret);
    expect((await pub("POST", "/auth/totp/verify", { code }, auth)).statusCode).toBe(200);
    // the setup code was consumed: the same code again is a replay
    expect((await pub("POST", "/auth/recovery/kit", { email: u.email, recoveryAuth: kit.recoveryAuth, code })).json()).toEqual({ error: "totp_invalid" });
    const ok = (await pub("POST", "/auth/recovery/kit", { email: u.email, recoveryAuth: kit.recoveryAuth, code: await freshTotp(secret) })).json();
    const next = await newPasswordFor(ok.material, await openRecoveryWrap(u.id, await parseRecoveryCode(kit.code), ok.recoveryWrap));
    expect((await pub("POST", "/auth/recovery/finish", { authKey: next.authKey, material: next.material }, { authorization: `Bearer ${ok.recoveryToken}` })).statusCode).toBe(200);
  });

  it("emails the user when Resend is configured", async () => {
    const u = await createActiveUser(t);
    const kit = await makeKit(u);
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("{}", { status: 200 }));
    Object.assign(t.config, { resendApiKey: "re_test", emailFrom: "vault@clane.ai" });
    try {
      const ok = (await pub("POST", "/auth/recovery/kit", { email: u.email, recoveryAuth: kit.recoveryAuth, code: await totp(u) })).json();
      const next = await newPasswordFor(ok.material, u.keys.userKey);
      await pub("POST", "/auth/recovery/finish", { authKey: next.authKey, material: next.material }, { authorization: `Bearer ${ok.recoveryToken}` });
      // The email is sent in the background (the reply doesn't wait for it).
      const sent = await vi.waitFor(() => { const c = fetchSpy.mock.calls.find(([url]) => String(url).includes("resend.com")); expect(c).toBeTruthy(); return c; });
      const payload = JSON.parse(String((sent![1] as RequestInit).body));
      expect(payload.to).toEqual([u.email]);
      expect(payload.subject).toMatch(/master password was reset/);
      expect(payload.text).not.toContain(kit.code);
    } finally {
      fetchSpy.mockRestore();
      Object.assign(t.config, { resendApiKey: undefined, emailFrom: undefined });
    }
  });
});


async function enablePolicy(a: U, on = true) {
  const res = await call(a, "PUT", "/admin/settings/admin-recovery", on ? { enabled: true, code: await totp(a), authKey: await authKeyOf(a) } : { enabled: false });
  expect(res.statusCode).toBe(200);
  return res.json();
}

/** A user whose client has unlocked once: they have a membership key in their org (admins need one to be escrowed to). */
async function keyed(opts: Parameters<typeof createActiveUser>[1] = {}) {
  const u = await createActiveUser(t, opts);
  await keyUp(t, u);
  return u;
}

/** What a member's client does on unlock while the policy is on: acknowledge once (the in-app notice), then escrow. */
const escrow = (m: U) => escrowKey(t, m);

async function requestFor(email: string) {
  expect((await pub("POST", "/auth/recovery/admin/request", { email })).statusCode).toBe(202);
  return t.prisma.recoveryRequest.findFirst({ where: { user: { email } }, orderBy: { createdAt: "desc" } });
}

const approve = async (a: U, requestId: string) => approveScoped(t, a, requestId, await totp(a));

describe("admin recovery policy", () => {
  it("is off by default, admin-only, and announced in /options and /me/security", async () => {
    const a = await keyed({ role: "admin" }), m = await keyed();
    expect((await pub("GET", "/auth/recovery/options")).json()).toEqual({ adminRecoveryEnabled: false });
    expect((await call(m, "PUT", "/admin/settings/admin-recovery", { enabled: true })).statusCode).toBe(403);
    expect((await call(m, "GET", "/admin/settings")).statusCode).toBe(403);
    expect((await call(a, "GET", "/admin/settings")).json().adminRecovery.enabled).toBe(false);
    const on = await enablePolicy(a);
    expect(on.adminRecovery).toMatchObject({ enabled: true, changedBy: { id: a.id } });
    expect((await pub("GET", "/auth/recovery/options")).json()).toEqual({ adminRecoveryEnabled: true });
    let sec = (await call(m, "GET", "/me/security")).json();
    expect(sec).toMatchObject({ adminRecoveryEnabled: true, adminRecoveryAckRequired: true });
    expect(sec.orgs).toEqual([{ orgId: m.orgId, orgName: "Test org", adminRecoveryEnabled: true, ackRequired: true, recoverable: false, escrowHolders: [] }]);
    // Nothing to escrow before the acknowledgement.
    expect((await call(m, "GET", "/membership-key")).json().escrow).toMatchObject({ enabled: true, ackRequired: true, needed: [] });
    expect((await call(m, "POST", "/me/admin-recovery-ack", { orgId: m.orgId })).statusCode).toBe(200);
    sec = (await call(m, "GET", "/me/security")).json();
    expect(sec.adminRecoveryAckRequired).toBe(false);
    // Escrow to the admin's membership key (not their account key).
    const aKey = b64url.encode(keysOf(a).get(a.orgId)!.publicKey);
    expect((await call(m, "GET", "/membership-key")).json().escrow.needed).toEqual([{ adminId: a.id, publicKey: aKey }]);
    // the admin who switched it on has acknowledged by doing so, and doesn't escrow to themselves
    expect((await call(a, "GET", "/membership-key")).json().escrow).toMatchObject({ ackRequired: false, needed: [] });
    expect(await escrow(m)).toBe(1);
    sec = (await call(m, "GET", "/me/security")).json();
    // Members see who holds their escrow.
    expect(sec.orgs[0]).toMatchObject({ recoverable: true, escrowHolders: [{ adminId: a.id, name: expect.any(String), email: a.email, since: expect.any(String) }] });
    expect(await events("admin.recovery_policy_enabled")).toHaveLength(1);
  });

  it("escrows: only to current admins' current keys, only while on; switching off deletes them all and ends open requests", async () => {
    const a = await keyed({ role: "admin" }), m = await keyed(), m2 = await keyed();
    const mk = keysOf(m).get(m.orgId)!;
    const m2Key = keysOf(m2).get(m2.orgId)!.publicKey;
    const fake = { memberPublicKey: b64url.encode(mk.publicKey), escrows: [{ adminId: m2.id, adminPublicKey: b64url.encode(m2Key), sealedKey: await sealMembershipEscrow(m2Key, mk, { userId: m.id, adminId: m2.id }) }] };
    expect((await call(m, "PUT", "/membership-key/escrows", fake)).json()).toEqual({ error: "policy_off" });
    await enablePolicy(a);
    expect((await call(m, "PUT", "/membership-key/escrows", fake)).json()).toEqual({ error: "ack_required" });
    await call(m, "POST", "/me/admin-recovery-ack", { orgId: m.orgId });
    expect((await call(m, "PUT", "/membership-key/escrows", fake)).json()).toEqual({ error: "not_admin" });
    // The admin's key must be their current membership key.
    const stale = { ...fake, escrows: [{ ...fake.escrows[0]!, adminId: a.id }] };
    expect((await call(m, "PUT", "/membership-key/escrows", stale)).json()).toEqual({ error: "stale_admin_key" });
    expect(await escrow(m)).toBe(1);
    expect(await escrow(m)).toBe(0); // nothing left to do
    expect(await escrow(m2)).toBe(1);
    expect((await events("recovery.escrow_created"))[0]!.meta).toEqual({ count: 1 });
    expect((await call(a, "GET", "/admin/settings")).json().escrows).toEqual({ total: 2, members: 2 });
    const r = await requestFor(m.email);
    await approve(a, r!.id);
    const off = await enablePolicy(a, false);
    expect(off.escrows).toEqual({ total: 0, members: 0 });
    expect(await t.prisma.membershipEscrow.count()).toBe(0);
    const ended = await t.prisma.recoveryRequest.findUniqueOrThrow({ where: { id: r!.id } });
    expect(ended).toMatchObject({ status: "expired", wrappedMembershipKey: null, proofHash: null });
    expect((await events("admin.recovery_policy_disabled"))[0]!.meta).toEqual({ escrowsDeleted: 2, requestsEnded: 1 });
  });

  it("no escrow while rows are still sealed to the account key (the membership must be recoverable first)", async () => {
    const a = await keyed({ role: "admin" }), o = await keyed(), m = await createActiveUser(t);
    await enablePolicy(a);
    // A folder key sealed to m's account key before m had a membership key.
    const fid = crypto.randomUUID();
    const ok = keysOf(o).get(o.orgId)!;
    const f = await createTeamFolder(fid, "Ops", ok.publicKey);
    const ownWrap = await sealOrgFolderKey(f.folderKey, { orgId: o.orgId, folderId: fid }, ok.publicKey);
    expect((await call(o, "POST", "/folders", { id: fid, kind: "team", encName: f.encName, wrappedFolderKey: ownWrap, sealedTo: b64url.encode(ok.publicKey) })).statusCode).toBe(201);
    expect((await call(o, "POST", `/folders/${fid}/members`, { userId: m.id, permission: "view", wrappedFolderKey: await sealFolderKeyFor(f.folderKey, fid, m.keys.publicKey) })).statusCode).toBe(201);
    const mk = await keyUp(t, m);
    await call(m, "POST", "/me/admin-recovery-ack", { orgId: m.orgId });
    let st = (await call(m, "GET", "/membership-key")).json();
    expect(st.pendingRows).toBe(1);
    expect(st.escrow.needed).toEqual([]);
    // Sealing to m's account key is refused now that m has a membership key.
    expect((await call(o, "POST", `/folders/${fid}/members`, { userId: a.id, permission: "view", wrappedFolderKey: await sealFolderKeyFor(f.folderKey, fid, a.keys.publicKey) })).json()).toEqual({ error: "stale_recipient_key" });
    // The client moves the row, then escrows.
    const p = (await call(m, "GET", "/membership-key/pending")).json();
    expect(p.folders).toEqual([{ folderId: fid, sealedTo: null, wrappedFolderKey: expect.stringMatching(/^s1\./) }]);
    const moved = await resealFolderKeyToMembership(p.folders[0].wrappedFolderKey, { orgId: m.orgId, folderId: fid }, m.keys, mk);
    expect((await call(m, "PUT", "/membership-key/rows", { to: b64url.encode(mk.publicKey), folders: [{ folderId: fid, from: null, wrappedFolderKey: moved }] })).json()).toMatchObject({ updated: 1, pendingRows: 0 });
    // Compare-and-set: the same move again changes nothing.
    expect((await call(m, "PUT", "/membership-key/rows", { to: b64url.encode(mk.publicKey), folders: [{ folderId: fid, from: null, wrappedFolderKey: moved }] })).json()).toMatchObject({ updated: 0 });
    st = (await call(m, "GET", "/membership-key")).json();
    expect(st.escrow.needed).toHaveLength(1);
    expect(await escrow(m)).toBe(1);
  });

  it("a new admin is escrowed to when members next unlock (once the new admin has a membership key)", async () => {
    const a = await keyed({ role: "admin" }), m = await keyed();
    await enablePolicy(a);
    await escrow(m);
    const b = await createActiveUser(t, { role: "admin" });
    expect((await call(m, "GET", "/membership-key")).json().escrow.needed).toEqual([]);
    await keyUp(t, b);
    expect((await call(m, "GET", "/membership-key")).json().escrow.needed.map((x: { adminId: string }) => x.adminId)).toEqual([b.id]);
    expect(await escrow(m)).toBe(1);
  });

  it("disabling an admin drops the escrows they hold", async () => {
    const a = await keyed({ role: "admin" }), b = await keyed({ role: "admin" }), m = await keyed();
    await enablePolicy(a);
    await escrow(m);
    expect(await t.prisma.membershipEscrow.count({ where: { adminId: b.id } })).toBe(1);
    await call(a, "POST", `/admin/users/${b.id}/disable`);
    expect(await t.prisma.membershipEscrow.count({ where: { adminId: b.id } })).toBe(0);
    expect(await t.prisma.membershipEscrow.count({ where: { adminId: a.id } })).toBe(1);
  });
});

describe("admin recovery requests", () => {
  it("creating one is enumeration-safe and only happens while the policy is on and the member is escrowed", async () => {
    const a = await keyed({ role: "admin" }), m = await keyed();
    const ghost = await pub("POST", "/auth/recovery/admin/request", { email: "ghost@clane.ai" });
    const real = await pub("POST", "/auth/recovery/admin/request", { email: m.email });
    expect([ghost.statusCode, real.statusCode]).toEqual([202, 202]);
    expect(ghost.json()).toEqual(real.json());
    expect(await t.prisma.recoveryRequest.count()).toBe(0); // policy off
    await enablePolicy(a);
    await requestFor(m.email);
    expect(await t.prisma.recoveryRequest.count()).toBe(0); // no escrow yet: nothing an admin could restore
    await escrow(m);
    await requestFor(m.email);
    await requestFor(m.email); // one open request per person and org
    expect(await t.prisma.recoveryRequest.count()).toBe(1);
    expect((await events("recovery.request_created"))[0]).toMatchObject({ targetUserId: m.id });
  });

  it("listing and approving are admin-only; approving needs fresh 2FA and the admin's own escrow", async () => {
    const a = await keyed({ role: "admin" }), m = await keyed();
    await enablePolicy(a);
    await escrow(m);
    const r = (await requestFor(m.email))!;
    // member: forbidden everywhere
    for (const [method, url] of [["GET", "/admin/recovery-requests"], ["POST", `/admin/recovery-requests/${r.id}/escrow`], ["POST", `/admin/recovery-requests/${r.id}/approve`], ["POST", `/admin/recovery-requests/${r.id}/deny`]] as const)
      expect((await call(m, method, url, method === "POST" ? { code: "123456" } : undefined)).statusCode, url).toBe(403);
    // c became admin after m escrowed: no escrow for c
    const c = await keyed({ role: "admin" });
    const list = (await call(c, "GET", "/admin/recovery-requests")).json().requests;
    expect(list).toEqual([expect.objectContaining({ id: r.id, status: "pending", canApprove: false, user: { id: m.id, name: expect.any(String), email: m.email } })]);
    expect((await call(c, "POST", `/admin/recovery-requests/${r.id}/escrow`, { code: await totp(c) })).json()).toEqual({ error: "no_escrow" });
    expect((await call(a, "GET", "/admin/recovery-requests")).json().requests[0].canApprove).toBe(true);
    const bad = await call(a, "POST", `/admin/recovery-requests/${r.id}/escrow`, { code: wrongTotp(a) });
    expect(bad.json()).toEqual({ error: "totp_invalid" });
    expect((await t.prisma.user.findUniqueOrThrow({ where: { id: a.id } })).failedLogins).toBe(1);
    const g = await approve(a, r.id);
    expect(g.linkBase).toBe(`http://localhost:5173/recover/${r.id}`);
    const row = await t.prisma.recoveryRequest.findUniqueOrThrow({ where: { id: r.id } });
    expect(row).toMatchObject({ status: "approved", approvedBy: a.id, memberPublicKey: b64url.encode(keysOf(m).get(m.orgId)!.publicKey) });
    expect(row.proofHash).not.toBe(g.proof);
    expect(JSON.stringify(row)).not.toContain(g.fragment);
    expect(row.expiresAt!.getTime() - row.approvedAt!.getTime()).toBe(24 * 3600e3);
    expect(await events("recovery.request_approved")).toHaveLength(1);
    // The member's key is marked for rotation: an admin has seen it.
    expect((await t.prisma.membershipKey.findFirstOrThrow({ where: { userId: m.id } })).escrowOpenedAt).toBeInstanceOf(Date);
    expect((await call(m, "GET", "/membership-key")).json().rotateNeeded).toBe(true);
    // can't approve twice
    expect((await call(a, "POST", `/admin/recovery-requests/${r.id}/escrow`, { code: await totp(a) })).json()).toEqual({ error: "not_pending" });
  });

  it("never hands an admin another admin's escrow, and an approval token only works for its admin and request", async () => {
    const a = await keyed({ role: "admin" }), b = await keyed({ role: "admin" }), m = await keyed(), m2 = await keyed();
    await enablePolicy(a);
    await escrow(m); await escrow(m2);
    const r = (await requestFor(m.email))!, r2 = (await requestFor(m2.email))!;
    const ea = (await call(a, "POST", `/admin/recovery-requests/${r.id}/escrow`, { code: await totp(a) })).json();
    const eb = (await call(b, "POST", `/admin/recovery-requests/${r.id}/escrow`, { code: await totp(b) })).json();
    const rowA = await t.prisma.membershipEscrow.findUniqueOrThrow({ where: { orgId_userId_adminId: { orgId: m.orgId, userId: m.id, adminId: a.id } } });
    const rowB = await t.prisma.membershipEscrow.findUniqueOrThrow({ where: { orgId_userId_adminId: { orgId: m.orgId, userId: m.id, adminId: b.id } } });
    expect(ea.sealedKey).toBe(rowA.sealedKey);
    expect(eb.sealedKey).toBe(rowB.sealedKey);
    await expect(openMembershipEscrow(keysOf(b).get(b.orgId)!, ea.sealedKey, { userId: m.id, adminId: b.id }, ea.memberPublicKey)).rejects.toThrow();
    const key = await openMembershipEscrow(keysOf(a).get(a.orgId)!, ea.sealedKey, { userId: m.id, adminId: a.id }, ea.memberPublicKey);
    const g = await createMembershipRecoveryGrant(r.id, { orgId: m.orgId, userId: m.id }, key);
    const body = (tok: string) => ({ approvalToken: tok, memberPublicKey: ea.memberPublicKey, wrappedMembershipKey: g.wrappedMembershipKey, proof: g.proof });
    // b's token on a's call, and a's token for another request, both fail
    expect((await call(a, "POST", `/admin/recovery-requests/${r.id}/approve`, body(eb.approvalToken))).json()).toEqual({ error: "approval_expired" });
    expect((await call(a, "POST", `/admin/recovery-requests/${r2.id}/approve`, body(ea.approvalToken))).json()).toEqual({ error: "approval_expired" });
    // The key named must be the one this admin's escrow held.
    expect((await call(a, "POST", `/admin/recovery-requests/${r.id}/approve`, { ...body(ea.approvalToken), memberPublicKey: b64url.encode((await generateKeyPair()).publicKey) })).json()).toEqual({ error: "no_escrow" });
    expect((await call(a, "POST", `/admin/recovery-requests/${r.id}/approve`, body(ea.approvalToken))).statusCode).toBe(200);
  });

  it("an admin can't approve their own request", async () => {
    const a = await keyed({ role: "admin" }), b = await keyed({ role: "admin" });
    await enablePolicy(a);
    await escrow(a); // a's key escrowed to b
    const r = (await requestFor(a.email))!;
    expect((await call(a, "GET", "/admin/recovery-requests")).json().requests[0].canApprove).toBe(false);
    expect((await call(a, "POST", `/admin/recovery-requests/${r.id}/escrow`, { code: await totp(a) })).json()).toEqual({ error: "self" });
    expect((await call(b, "GET", "/admin/recovery-requests")).json().requests[0].canApprove).toBe(true);
  });

  it("the link: fresh 2FA, single use, wrong proofs burn it; the member sets the password and gets new account keys", async () => {
    const a = await keyed({ role: "admin" }), m = await keyed();
    await enablePolicy(a);
    await escrow(m);
    const kit = await makeKit(m);
    const r = (await requestFor(m.email))!;
    const g = await approve(a, r.id);
    const proof = await adminRecoveryProof(g.fragment);
    const wrongProof = b64url.encode(crypto.getRandomValues(new Uint8Array(32)));
    expect((await pub("POST", `/auth/recovery/admin/${r.id}`, { proof: wrongProof })).json()).toEqual({ error: "invalid_link" });
    expect((await pub("POST", `/auth/recovery/admin/${r.id}`, { proof })).json()).toEqual({ error: "totp_required", email: m.email });
    expect((await pub("POST", `/auth/recovery/admin/${r.id}`, { proof, code: wrongTotp(m) })).json()).toMatchObject({ error: "totp_invalid" });
    const ok = await pub("POST", `/auth/recovery/admin/${r.id}`, { proof, code: await totp(m) });
    expect(ok.statusCode).toBe(200);
    const body = ok.json();
    expect(body).toMatchObject({ mode: "reset", orgId: m.orgId, orgName: "Test org", memberPublicKey: g.memberPublicKey });
    expect(body).not.toHaveProperty("wrappedUserKey");
    const reset = await scopedReset(r.id, g.fragment, body);
    expect(reset.membershipKey.privateKey).toEqual(keysOf(m).get(m.orgId)!.privateKey);
    // The account key pair must change, and the restored membership must be the escrowed one.
    const sameKeys = { ...reset.payload, material: { ...reset.payload.material, publicKey: m.material.publicKey } };
    expect((await pub("POST", "/auth/recovery/finish", sameKeys, { authorization: `Bearer ${body.recoveryToken}` })).json()).toEqual({ error: "key_mismatch" });
    const other = await anyScopedPayload(m.orgId, m.id);
    expect((await pub("POST", "/auth/recovery/finish", { ...reset.payload, membership: other.membership }, { authorization: `Bearer ${body.recoveryToken}` })).json()).toEqual({ error: "key_mismatch" });
    const fin = await pub("POST", "/auth/recovery/finish", reset.payload, { authorization: `Bearer ${body.recoveryToken}` });
    expect(fin.statusCode).toBe(200);
    expect((await call(m, "GET", "/me")).statusCode).toBe(401); // signed out everywhere
    const login = await pub("POST", "/auth/login", { email: m.email, authKey: reset.payload.authKey, code: await totp(m) });
    expect(login.statusCode).toBe(200);
    const { wrapKey } = await deriveLoginKeys(reset.password, reset.payload.material.kdfSalt, reset.payload.material.kdfParams);
    const now = await unlockAccount(wrapKey, login.json().material);
    expect(now.userKey).not.toEqual(m.keys.userKey);
    // The membership key opens under the new user key; it's flagged for rotation.
    const st = (await call({ accessToken: login.json().accessToken, orgId: m.orgId }, "GET", "/membership-key")).json();
    expect(st).toMatchObject({ userKeyGen: 2, rotateNeeded: true, repairNeeded: true });
    expect((await unlockMembershipKeys(now.userKey, { orgId: m.orgId, userId: m.id }, st.keys[0])).privateKey).toEqual(reset.membershipKey.privateKey);
    // The old account material and kit went to the archive.
    const arch = await t.prisma.accountKeyArchive.findFirstOrThrow({ where: { userId: m.id } });
    expect(arch).toMatchObject({ userKeyGen: 1, publicKey: m.material.publicKey, wrappedUserKey: m.material.wrappedUserKey, recoveryWrap: kit.recoveryWrap, privateItems: 0, otherOrgs: 0 });
    expect((await t.prisma.user.findUniqueOrThrow({ where: { id: m.id } })).recoveryWrap).toBeNull();
    // single use
    expect((await pub("POST", `/auth/recovery/admin/${r.id}`, { proof, code: await totp(m) })).json()).toEqual({ error: "invalid_link" });
    const again = await anyScopedPayload(m.orgId, m.id);
    expect((await pub("POST", "/auth/recovery/finish", again, { authorization: `Bearer ${body.recoveryToken}` })).statusCode).toBe(410);
    const row = await t.prisma.recoveryRequest.findUniqueOrThrow({ where: { id: r.id } });
    expect(row).toMatchObject({ status: "used", wrappedMembershipKey: null, proofHash: null });
    expect((await events("auth.admin_recovery_used"))[0]).toMatchObject({ actorId: m.id, orgId: m.orgId, meta: { requestId: r.id, approvedBy: a.id, scope: "membership" } });
  });

  it("five wrong proofs burn the link", async () => {
    const a = await keyed({ role: "admin" }), m = await keyed();
    await enablePolicy(a); await escrow(m);
    const r = (await requestFor(m.email))!;
    const g = await approve(a, r.id);
    for (let i = 0; i < 5; i++) await pub("POST", `/auth/recovery/admin/${r.id}`, { proof: b64url.encode(crypto.getRandomValues(new Uint8Array(32))) });
    expect((await pub("POST", `/auth/recovery/admin/${r.id}`, { proof: g.proof, code: await totp(m) })).json()).toEqual({ error: "invalid_link" });
    expect(await t.prisma.recoveryRequest.findUniqueOrThrow({ where: { id: r.id } })).toMatchObject({ status: "expired", wrappedMembershipKey: null });
  });

  it("expires after 24 hours (on use and by the sweep), and pending requests after 7 days", async () => {
    const a = await keyed({ role: "admin" }), m = await keyed(), m2 = await keyed();
    await enablePolicy(a); await escrow(m); await escrow(m2);
    const r = (await requestFor(m.email))!;
    const g = await approve(a, r.id);
    await t.prisma.recoveryRequest.update({ where: { id: r.id }, data: { expiresAt: new Date(Date.now() - 1000) } });
    expect((await pub("POST", `/auth/recovery/admin/${r.id}`, { proof: g.proof, code: await totp(m) })).json()).toEqual({ error: "invalid_link" });
    const r2 = (await requestFor(m2.email))!;
    await t.prisma.recoveryRequest.update({ where: { id: r2.id }, data: { createdAt: new Date(Date.now() - 8 * 864e5) } });
    expect(await sweepRecoveryRequests(t.prisma)).toBe(2);
    expect(await t.prisma.recoveryRequest.findUniqueOrThrow({ where: { id: r.id } })).toMatchObject({ status: "expired", wrappedMembershipKey: null, proofHash: null });
    expect(await t.prisma.recoveryRequest.findUniqueOrThrow({ where: { id: r2.id } })).toMatchObject({ status: "expired" });
    expect(await events("recovery.request_expired")).toHaveLength(2);
  });

  it("a recovery token from an expired request can't finish", async () => {
    const a = await keyed({ role: "admin" }), m = await keyed();
    await enablePolicy(a); await escrow(m);
    const r = (await requestFor(m.email))!;
    const g = await approve(a, r.id);
    const body = (await pub("POST", `/auth/recovery/admin/${r.id}`, { proof: g.proof, code: await totp(m) })).json();
    await t.prisma.recoveryRequest.update({ where: { id: r.id }, data: { expiresAt: new Date(Date.now() - 1000) } });
    const reset = await scopedReset(r.id, g.fragment, body);
    expect((await pub("POST", "/auth/recovery/finish", reset.payload, { authorization: `Bearer ${body.recoveryToken}` })).statusCode).toBe(410);
    expect((await call(m, "GET", "/me")).statusCode).toBe(200);
    expect(await t.prisma.accountKeyArchive.count()).toBe(0);
  });

  it("deny ends the request", async () => {
    const a = await keyed({ role: "admin" }), m = await keyed();
    await enablePolicy(a); await escrow(m);
    const r = (await requestFor(m.email))!;
    expect((await call(a, "POST", `/admin/recovery-requests/${r.id}/deny`)).statusCode).toBe(200);
    expect((await call(a, "GET", "/admin/recovery-requests")).json().requests).toEqual([]);
    expect(await events("recovery.request_denied")).toHaveLength(1);
  });

  it("a member can't read escrows through any member route", async () => {
    const a = await keyed({ role: "admin" }), m = await keyed();
    await enablePolicy(a); await escrow(m);
    const sealed = (await t.prisma.membershipEscrow.findFirstOrThrow()).sealedKey;
    for (const url of ["/me", "/me/security", "/sync", "/users", "/membership-key"]) expect((await call(m, "GET", url)).body).not.toContain(sealed);
  });
});

describe("0.5.1 hardening", () => {
  const delay = (h: number) => Object.assign(t.config, { adminRecoveryResetDelayHours: h });
  beforeEach(() => { delay(0); });

  async function setup2() {
    const a = await keyed({ role: "admin" }), b = await keyed({ role: "admin" }), m = await keyed();
    await enablePolicy(a); await escrow(m);
    return { a, b, m };
  }

  it("turning admin recovery on needs the master password and a fresh 2FA code; off doesn't", async () => {
    const a = await createActiveUser(t, { role: "admin" });
    expect((await call(a, "PUT", "/admin/settings/admin-recovery", { enabled: true })).json()).toEqual({ error: "invalid_credentials" });
    expect((await call(a, "PUT", "/admin/settings/admin-recovery", { enabled: true, authKey: await authKeyOf(a), code: wrongTotp(a) })).json()).toEqual({ error: "totp_invalid" });
    expect((await call(a, "PUT", "/admin/settings/admin-recovery", { enabled: true, authKey: "AAAA", code: await totp(a) })).json()).toEqual({ error: "invalid_credentials" });
    expect((await t.prisma.user.findUniqueOrThrow({ where: { id: a.id } })).failedLogins).toBe(3);
    expect((await pub("GET", "/auth/recovery/options")).json().adminRecoveryEnabled).toBe(false);
    await enablePolicy(a);
    await enablePolicy(a, false);
  });

  it("emails everyone when the policy turns on, never an agent", async () => {
    const a = await createActiveUser(t, { role: "admin" }), m = await createActiveUser(t);
    await createTestAgent(t, { orgId: a.orgId, createdById: a.id, verified: true });
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("{}", { status: 200 }));
    Object.assign(t.config, { resendApiKey: "re_test", emailFrom: "vault@clane.ai" });
    try {
      await enablePolicy(a);
      // The emails are sent in the background (the reply doesn't wait for them).
      const to = () => fetchSpy.mock.calls.filter(([u]) => String(u).includes("resend.com")).map(([, init]) => JSON.parse(String((init as RequestInit).body)).to[0]);
      await vi.waitFor(() => expect(to()).toEqual([m.email]));
      await new Promise((r) => setTimeout(r, 100)); // and nothing else follows
      expect(to()).toEqual([m.email]);
    } finally { fetchSpy.mockRestore(); Object.assign(t.config, { resendApiKey: undefined, emailFrom: undefined }); }
  });

  it("an acknowledgement from before a switch-off doesn't carry over to the next switch-on", async () => {
    const a = await keyed({ role: "admin" }), m = await keyed();
    await enablePolicy(a); await escrow(m);
    await enablePolicy(a, false); await enablePolicy(a);
    expect((await call(m, "GET", "/me/security")).json().adminRecoveryAckRequired).toBe(true);
  });

  it("TOTP codes are single-use across sign-in and recovery", async () => {
    const u = await createActiveUser(t);
    const authKey = await authKeyOf(u);
    const code = await totp(u);
    expect((await pub("POST", "/auth/login", { email: u.email, authKey, code })).statusCode).toBe(200);
    expect((await pub("POST", "/auth/login", { email: u.email, authKey, code })).json()).toEqual({ error: "totp_invalid" });
    const kit = await makeKit(u);
    expect((await pub("POST", "/auth/recovery/kit", { email: u.email, recoveryAuth: kit.recoveryAuth, code })).json()).toEqual({ error: "totp_invalid" });
    expect((await pub("POST", "/auth/recovery/kit", { email: u.email, recoveryAuth: kit.recoveryAuth, code: await totp(u) })).statusCode).toBe(200);
  });

  it("an admin's escrow-opening code can't be replayed", async () => {
    const { a, m } = await setup2();
    const r = (await requestFor(m.email))!;
    const code = await totp(a);
    expect((await call(a, "POST", `/admin/recovery-requests/${r.id}/escrow`, { code })).statusCode).toBe(200);
    expect((await call(a, "POST", `/admin/recovery-requests/${r.id}/escrow`, { code })).json()).toEqual({ error: "totp_invalid" });
  });

  it("wrong 2FA codes on the link count against it: five burn it", async () => {
    const { a, m } = await setup2();
    const r = (await requestFor(m.email))!;
    const g = await approve(a, r.id);
    for (let i = 0; i < 5; i++) expect((await pub("POST", `/auth/recovery/admin/${r.id}`, { proof: g.proof, code: wrongTotp(m) })).json()).toMatchObject({ error: "totp_invalid" });
    expect((await pub("POST", `/auth/recovery/admin/${r.id}`, { proof: g.proof, code: await totp(m) })).json()).toEqual({ error: "invalid_link" });
  });

  it("approve, then reset 2FA, by the same admin: the link is refused (no one-person takeover)", async () => {
    const { a, m } = await setup2();
    const r = (await requestFor(m.email))!;
    const g = await approve(a, r.id);
    await call(a, "POST", `/admin/users/${m.id}/reset-2fa`);
    const res = await pub("POST", `/auth/recovery/admin/${r.id}`, { proof: g.proof });
    expect(res.statusCode).toBe(403);
    expect(res.json()).toEqual({ error: "two_person_required" });
    expect(await events("recovery.two_person_refused")).toHaveLength(1);
  });

  it("reset 2FA, then approve, by the same admin: approval is refused", async () => {
    const { a, b, m } = await setup2();
    await call(a, "POST", `/admin/users/${m.id}/reset-2fa`);
    const r = (await requestFor(m.email))!;
    const list = (await call(a, "GET", "/admin/recovery-requests")).json().requests;
    expect(list[0]).toMatchObject({ canApprove: false, twoFactorReset: true });
    expect((await call(a, "POST", `/admin/recovery-requests/${r.id}/escrow`, { code: await totp(a) })).json()).toEqual({ error: "two_person_required" });
    expect((await call(b, "GET", "/admin/recovery-requests")).json().requests[0].canApprove).toBe(true);
  });

  it("reset by admin A, approve by admin B: works after the waiting period, refused (423) within it", async () => {
    const { a, b, m } = await setup2();
    await call(a, "POST", `/admin/users/${m.id}/reset-2fa`);
    const r = (await requestFor(m.email))!;
    const g = await approve(b, r.id); // allowed for a pending_2fa member now
    delay(24);
    const early = await pub("POST", `/auth/recovery/admin/${r.id}`, { proof: g.proof });
    expect(early.statusCode).toBe(423);
    expect(early.json().error).toBe("reset_delay");
    expect(early.json().retryAfterSeconds).toBeGreaterThan(23 * 3600);
    await t.prisma.user.update({ where: { id: m.id }, data: { totpResetAt: new Date(Date.now() - 24 * 3600e3 - 1000) } });
    await t.prisma.membership.updateMany({ where: { userId: b.id }, data: { adminSince: new Date(Date.now() - 30 * 864e5) } });
    const res = (await pub("POST", `/auth/recovery/admin/${r.id}`, { proof: g.proof })).json();
    expect(res.needsTotpSetup).toBe(true);
    const auth = { authorization: `Bearer ${res.setupToken}` };
    const secret = (await pub("POST", "/auth/totp/setup", {}, auth)).json().secret as string;
    expect((await pub("POST", "/auth/totp/verify", { code: await freshTotp(secret) }, auth)).statusCode).toBe(200);
    const ok = (await pub("POST", `/auth/recovery/admin/${r.id}`, { proof: g.proof, code: await freshTotp(secret) })).json();
    expect(ok.recoveryToken).toBeTruthy();
    const reset = await scopedReset(r.id, g.fragment, ok);
    expect((await pub("POST", "/auth/recovery/finish", reset.payload, { authorization: `Bearer ${ok.recoveryToken}` })).statusCode).toBe(200);
  });

  it("a link approved right after a 2FA reset stays valid after the delay, and expires 24 h after it ends", async () => {
    const { a, b, m } = await setup2();
    delay(24);
    await call(a, "POST", `/admin/users/${m.id}/reset-2fa`);
    const resetAt = (await t.prisma.user.findUniqueOrThrow({ where: { id: m.id } })).totpResetAt!;
    const r = (await requestFor(m.email))!;
    const g = await approve(b, r.id);
    const row = await t.prisma.recoveryRequest.findUniqueOrThrow({ where: { id: r.id } });
    expect(row.expiresAt!.getTime()).toBe(resetAt.getTime() + 48 * 3600e3);
    expect(new Date(g.expiresAt).getTime()).toBe(row.expiresAt!.getTime());
    const shift = 30 * 3600e3;
    await t.prisma.user.update({ where: { id: m.id }, data: { totpResetAt: new Date(resetAt.getTime() - shift) } });
    await t.prisma.membership.updateMany({ where: { userId: b.id }, data: { adminSince: new Date(resetAt.getTime() - shift - 864e5) } });
    await t.prisma.recoveryRequest.update({ where: { id: r.id }, data: { approvedAt: new Date(row.approvedAt!.getTime() - shift), expiresAt: new Date(row.expiresAt!.getTime() - shift) } });
    expect(await sweepRecoveryRequests(t.prisma)).toBe(0);
    expect((await pub("POST", `/auth/recovery/admin/${r.id}`, { proof: g.proof })).json().needsTotpSetup).toBe(true);
    await t.prisma.recoveryRequest.update({ where: { id: r.id }, data: { expiresAt: new Date(Date.now() - 1000) } });
    expect((await pub("POST", `/auth/recovery/admin/${r.id}`, { proof: g.proof })).json()).toEqual({ error: "invalid_link" });
  });

  it("without a 2FA reset the link still expires 24 h after approval", async () => {
    const { a, m } = await setup2();
    delay(24);
    const r = (await requestFor(m.email))!;
    await approve(a, r.id);
    const row = await t.prisma.recoveryRequest.findUniqueOrThrow({ where: { id: r.id } });
    expect(row.expiresAt!.getTime() - row.approvedAt!.getTime()).toBe(24 * 3600e3);
  });

  it("finish re-checks the two-person rule when the authenticator was set up through the link", async () => {
    const { a, b, m } = await setup2();
    await call(a, "POST", `/admin/users/${m.id}/reset-2fa`);
    const r = (await requestFor(m.email))!;
    const g = await approve(b, r.id);
    const res = (await pub("POST", `/auth/recovery/admin/${r.id}`, { proof: g.proof })).json();
    const auth = { authorization: `Bearer ${res.setupToken}` };
    const secret = (await pub("POST", "/auth/totp/setup", {}, auth)).json().secret as string;
    await pub("POST", "/auth/totp/verify", { code: await freshTotp(secret) }, auth);
    const ok = (await pub("POST", `/auth/recovery/admin/${r.id}`, { proof: g.proof, code: await freshTotp(secret) })).json();
    await t.prisma.user.update({ where: { id: m.id }, data: { totpResetBy: b.id } });
    const reset = await scopedReset(r.id, g.fragment, ok);
    expect((await pub("POST", "/auth/recovery/finish", reset.payload, { authorization: `Bearer ${ok.recoveryToken}` })).json()).toEqual({ error: "two_person_required" });
  });

  it("the member is emailed when an admin opens the escrow and when the request is approved", async () => {
    const { a, m } = await setup2();
    const r = (await requestFor(m.email))!;
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("{}", { status: 200 }));
    Object.assign(t.config, { resendApiKey: "re_test", emailFrom: "vault@clane.ai" });
    try {
      await approve(a, r.id);
      // (The request's own email may still be on its way: only the two admin-action notices count here.)
      const read = () => fetchSpy.mock.calls.filter(([u]) => String(u).includes("resend.com")).map(([, init]) => JSON.parse(String((init as RequestInit).body)))
        .filter((m: { subject: string }) => /an admin is resetting your master password/.test(m.subject));
      await vi.waitFor(() => expect(read()).toHaveLength(2));
      const mails = read();
      expect(mails.map((x) => x.to[0])).toEqual([m.email, m.email]);
      expect(mails[0].text).toMatch(/opened your escrowed/);
      expect(mails[1].text).toMatch(/approved a master-password reset/);
    } finally { fetchSpy.mockRestore(); Object.assign(t.config, { resendApiKey: undefined, emailFrom: undefined }); }
  });

  it("disabling an admin burns the links they approved", async () => {
    const { a, b, m } = await setup2();
    const r = (await requestFor(m.email))!;
    const g = await approve(b, r.id);
    await call(a, "POST", `/admin/users/${b.id}/disable`);
    expect(await t.prisma.recoveryRequest.findUniqueOrThrow({ where: { id: r.id } })).toMatchObject({ status: "expired", wrappedMembershipKey: null, proofHash: null });
    expect((await pub("POST", `/auth/recovery/admin/${r.id}`, { proof: g.proof, code: await totp(m) })).json()).toEqual({ error: "invalid_link" });
  });

  it("re-escrowing replaces an existing escrow (after the admin's key rotates)", async () => {
    const { a, m } = await setup2();
    const before = (await t.prisma.membershipEscrow.findUniqueOrThrow({ where: { orgId_userId_adminId: { orgId: m.orgId, userId: m.id, adminId: a.id } } })).sealedKey;
    const next = await createMembershipKeys(a.keys.userKey, { orgId: a.orgId, userId: a.id });
    expect((await call(a, "POST", "/membership-key/rotate", { from: b64url.encode(keysOf(a).get(a.orgId)!.publicKey), ...next.material })).statusCode).toBe(200);
    keysOf(a).set(a.orgId, next.keys);
    expect(await escrow(m)).toBe(1);
    const after = await t.prisma.membershipEscrow.findUniqueOrThrow({ where: { orgId_userId_adminId: { orgId: m.orgId, userId: m.id, adminId: a.id } } });
    expect(after.sealedKey).not.toBe(before);
    expect(after.adminPublicKey).toBe(next.material.publicKey);
  });
});

describe("0.5.3: approver age (no sock-puppet admin)", () => {
  const set = (o: object) => Object.assign(t.config, o);
  beforeEach(() => { set({ adminRecoveryResetDelayHours: 0, adminRecoveryApproverMinAgeDays: 7 }); });
  afterAll(() => { set({ adminRecoveryApproverMinAgeDays: 0 }); });
  const ageAdmin = (u: U, days: number) => t.prisma.membership.updateMany({ where: { userId: u.id }, data: { adminSince: new Date(Date.now() - days * 864e5) } });

  it("a new admin account becomes active with adminSince; existing admins are emailed and admin.added is logged", async () => {
    const a = await createActiveUser(t, { role: "admin" });
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("{}", { status: 200 }));
    Object.assign(t.config, { resendApiKey: "re_test", emailFrom: "vault@clane.ai" });
    try {
      const b = await createActiveUser(t, { role: "admin" });
      await createActiveUser(t); // a member: no email
      // The email is sent in the background (activation doesn't wait for it).
      const read = () => fetchSpy.mock.calls.filter(([u]) => String(u).includes("resend.com")).map(([, init]) => JSON.parse(String((init as RequestInit).body)));
      await vi.waitFor(() => expect(read().map((x) => x.to[0])).toEqual([a.email]));
      const mails = read();
      expect(mails[0].subject).toContain(b.email);
      expect((await t.prisma.membership.findFirstOrThrow({ where: { userId: b.id } })).adminSince).toBeInstanceOf(Date);
      expect(await events("admin.added")).toHaveLength(2);
    } finally { fetchSpy.mockRestore(); Object.assign(t.config, { resendApiKey: undefined, emailFrom: undefined }); }
  });

  it("the member is emailed when an admin resets their 2FA", async () => {
    const a = await createActiveUser(t, { role: "admin" }), m = await createActiveUser(t);
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("{}", { status: 200 }));
    Object.assign(t.config, { resendApiKey: "re_test", emailFrom: "vault@clane.ai" });
    try {
      await call(a, "POST", `/admin/users/${m.id}/reset-2fa`);
      // The email is sent in the background (the reply doesn't wait for it).
      const mails = () => fetchSpy.mock.calls.filter(([u]) => String(u).includes("resend.com")).map(([, init]) => JSON.parse(String((init as RequestInit).body)));
      await vi.waitFor(() => expect(mails()).toHaveLength(1));
      const mail = mails()[0];
      expect(mail.to).toEqual([m.email]);
      expect(mail.text).toMatch(/reset the two-step sign-in/);
      expect(mail.text).toMatch(/If this wasn't expected, contact another/);
    } finally { fetchSpy.mockRestore(); Object.assign(t.config, { resendApiKey: undefined, emailFrom: undefined }); }
  });

  it("sock-puppet admin made within 7 days of the reset: refused at escrow, approve and link use", async () => {
    const a = await keyed({ role: "admin" }), m = await keyed();
    await ageAdmin(a, 30);
    await enablePolicy(a);
    const puppet = await keyed({ role: "admin" }); // invited by a, controlled by a
    await escrow(m);
    await ageAdmin(puppet, 3);
    await call(a, "POST", `/admin/users/${m.id}/reset-2fa`);
    const r = (await requestFor(m.email))!;
    expect((await call(puppet, "GET", "/admin/recovery-requests")).json().requests[0].canApprove).toBe(false);
    expect((await call(puppet, "POST", `/admin/recovery-requests/${r.id}/escrow`, { code: await totp(puppet) })).json()).toEqual({ error: "approver_too_new" });
    set({ adminRecoveryApproverMinAgeDays: 0 });
    const g = await approve(puppet, r.id);
    set({ adminRecoveryApproverMinAgeDays: 7 });
    const res = await pub("POST", `/auth/recovery/admin/${r.id}`, { proof: g.proof });
    expect(res.statusCode).toBe(403);
    expect(res.json()).toEqual({ error: "approver_too_new" });
  });

  it("approve is refused too when the approval token was obtained earlier", async () => {
    const a = await keyed({ role: "admin" }), m = await keyed();
    await ageAdmin(a, 30);
    await enablePolicy(a);
    const puppet = await keyed({ role: "admin" });
    await escrow(m);
    await call(a, "POST", `/admin/users/${m.id}/reset-2fa`);
    const r = (await requestFor(m.email))!;
    set({ adminRecoveryApproverMinAgeDays: 0 });
    const e = (await call(puppet, "POST", `/admin/recovery-requests/${r.id}/escrow`, { code: await totp(puppet) })).json();
    set({ adminRecoveryApproverMinAgeDays: 7 });
    const key = await openMembershipEscrow(keysOf(puppet).get(puppet.orgId)!, e.sealedKey, { userId: m.id, adminId: puppet.id }, e.memberPublicKey);
    const g = await createMembershipRecoveryGrant(r.id, { orgId: m.orgId, userId: m.id }, key);
    expect((await call(puppet, "POST", `/admin/recovery-requests/${r.id}/approve`, { approvalToken: e.approvalToken, memberPublicKey: e.memberPublicKey, wrappedMembershipKey: g.wrappedMembershipKey, proof: g.proof })).json()).toEqual({ error: "approver_too_new" });
  });

  it("a long-standing second admin can approve, and the member recovers after the delay", async () => {
    const a = await keyed({ role: "admin" }), b = await keyed({ role: "admin" }), m = await keyed();
    await ageAdmin(a, 30); await ageAdmin(b, 30);
    await enablePolicy(a); await escrow(m);
    set({ adminRecoveryResetDelayHours: 24 });
    await call(a, "POST", `/admin/users/${m.id}/reset-2fa`);
    const r = (await requestFor(m.email))!;
    expect((await call(b, "GET", "/admin/recovery-requests")).json().requests[0].canApprove).toBe(true);
    const g = await approve(b, r.id);
    expect((await pub("POST", `/auth/recovery/admin/${r.id}`, { proof: g.proof })).json().error).toBe("reset_delay");
    const u = await t.prisma.user.findUniqueOrThrow({ where: { id: m.id } });
    await t.prisma.user.update({ where: { id: m.id }, data: { totpResetAt: new Date(u.totpResetAt!.getTime() - 25 * 3600e3) } });
    const res = (await pub("POST", `/auth/recovery/admin/${r.id}`, { proof: g.proof })).json();
    expect(res.needsTotpSetup).toBe(true);
    const auth = { authorization: `Bearer ${res.setupToken}` };
    const secret = (await pub("POST", "/auth/totp/setup", {}, auth)).json().secret as string;
    await pub("POST", "/auth/totp/verify", { code: await freshTotp(secret) }, auth);
    const ok = (await pub("POST", `/auth/recovery/admin/${r.id}`, { proof: g.proof, code: await freshTotp(secret) })).json();
    const reset = await scopedReset(r.id, g.fragment, ok);
    expect((await pub("POST", "/auth/recovery/finish", reset.payload, { authorization: `Bearer ${ok.recoveryToken}` })).statusCode).toBe(200);
  });

  it("finish refuses a too-new approver when the authenticator was set up through the link", async () => {
    const a = await keyed({ role: "admin" }), b = await keyed({ role: "admin" }), m = await keyed();
    await ageAdmin(a, 30); await ageAdmin(b, 30);
    await enablePolicy(a); await escrow(m);
    await call(a, "POST", `/admin/users/${m.id}/reset-2fa`);
    const r = (await requestFor(m.email))!;
    const g = await approve(b, r.id);
    const res = (await pub("POST", `/auth/recovery/admin/${r.id}`, { proof: g.proof })).json();
    const auth = { authorization: `Bearer ${res.setupToken}` };
    const secret = (await pub("POST", "/auth/totp/setup", {}, auth)).json().secret as string;
    await pub("POST", "/auth/totp/verify", { code: await freshTotp(secret) }, auth);
    const ok = (await pub("POST", `/auth/recovery/admin/${r.id}`, { proof: g.proof, code: await freshTotp(secret) })).json();
    await ageAdmin(b, 1);
    const reset = await scopedReset(r.id, g.fragment, ok);
    expect((await pub("POST", "/auth/recovery/finish", reset.payload, { authorization: `Bearer ${ok.recoveryToken}` })).json()).toEqual({ error: "approver_too_new" });
  });
});
