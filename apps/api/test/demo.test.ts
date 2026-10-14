import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { randomUUID } from "node:crypto";
import argon2 from "argon2";
import { createAccount, deriveLoginKeys, type KdfParams } from "@clane-vault/crypto";
import type { FastifyInstance } from "fastify";
import { createActiveUser, createInvite, FAST_KDF, makeTestApp, resetDb } from "./helpers.js";
import { loadConfig, type Config } from "../src/config.js";
import { checkDemoStartup, DEMO_ORG_NAME, DemoStartupRefused, sweepExpiredDemos } from "../src/lib/demo.js";
import { signSetup } from "../src/lib/tokens.js";

// Public demo mode (docs/demo.md). One database, apps with different configurations on it.
const DEMO: Config["demo"] = { ttlMinutes: 120, sandboxesPerIpPerHour: 50 };
const plain = await makeTestApp();
const demo = await makeTestApp({ demo: DEMO, resendApiKey: "re_test_key_never_used", emailFrom: "vault@example.com" });
afterAll(async () => { await plain.app.close(); await demo.app.close(); });
beforeEach(() => resetDb(demo.prisma));
afterEach(() => vi.restoreAllMocks());

let ipSeq = 0;
const nextIp = () => `10.88.${(++ipSeq >> 8) & 255}.${ipSeq & 255}`;
const auth = (token: string, orgId?: string) => ({ authorization: `Bearer ${token}`, ...(orgId ? { "x-org-id": orgId } : {}) });

/** What the web app does for "Try the demo": a sandbox, the normal sign-up through its invite, then the demo session. */
async function newSandbox(app: FastifyInstance, o: { colleagues?: string[]; ip?: string } = {}) {
  const ip = o.ip ?? nextIp();
  const created = await app.inject({ remoteAddress: ip, method: "POST", url: "/api/v1/auth/demo", payload: {} });
  expect(created.statusCode).toBe(201);
  const { inviteToken, email } = created.json() as { inviteToken: string; email: string };
  const password = `random demo password ${randomUUID()}`;
  const acct = await createAccount(password, FAST_KDF);
  const reg = await app.inject({ remoteAddress: ip, method: "POST", url: "/api/v1/auth/register", payload: { inviteToken, name: "Demo visitor", authKey: acct.authKey, material: acct.material } });
  expect(reg.statusCode).toBe(201);
  const colleagues = await Promise.all((o.colleagues ?? []).map(async (name) => ({ name, material: (await createAccount(`no one knows ${randomUUID()}`, FAST_KDF)).material })));
  const session = await app.inject({ remoteAddress: ip, method: "POST", url: "/api/v1/auth/demo/session", headers: auth(reg.json().setupToken), payload: { colleagues } });
  expect(session.statusCode).toBe(200);
  const body = session.json();
  const cookie = session.cookies.find((c) => c.name === "cv_refresh")!;
  return { ip, email, password, acct, accessToken: body.accessToken as string, cookie: `cv_refresh=${cookie.value}`, userId: body.user.id as string, orgId: body.orgs[0].id as string, body };
}

describe("the demo endpoints", () => {
  it("don't exist without demo mode (404)", async () => {
    expect((await plain.app.inject({ method: "POST", url: "/api/v1/auth/demo", payload: {} })).statusCode).toBe(404);
    expect((await plain.app.inject({ method: "POST", url: "/api/v1/auth/demo/session", payload: {} })).statusCode).toBe(404);
    expect((await plain.app.inject({ method: "GET", url: "/api/v1/brand" })).json().demo).toBeNull();
  });

  it("say so in the public brand answer", async () => {
    expect((await demo.app.inject({ method: "GET", url: "/api/v1/brand" })).json().demo).toEqual({ ttlMinutes: 120 });
  });

  it("make a sandbox: the visitor owns Northwind (demo), signed in without an authenticator, with made-up colleagues", async () => {
    const before = Date.now();
    const s = await newSandbox(demo.app, { colleagues: ["Bea Lindqvist", "Tom Reyes"] });
    expect(s.body.orgs).toEqual([expect.objectContaining({ name: DEMO_ORG_NAME, role: "owner" })]);
    expect(s.body.user.email).toBe(s.email);
    const expires = Date.parse(s.body.user.demoExpiresAt);
    expect(expires).toBeGreaterThanOrEqual(before + 119 * 60e3);
    expect(expires).toBeLessThanOrEqual(Date.now() + 120 * 60e3);
    const user = await demo.prisma.user.findUniqueOrThrow({ where: { id: s.userId } });
    expect(user).toMatchObject({ status: "active", totpSecretEnc: null, instanceAdmin: false });
    expect(user.demoExpiresAt?.getTime()).toBe(expires);
    // The session ends with the sandbox.
    const sessions = await demo.prisma.session.findMany({ where: { userId: s.userId } });
    expect(sessions.every((x) => x.expiresAt.getTime() <= expires)).toBe(true);
    expect((await demo.app.inject({ method: "GET", url: "/api/v1/me", headers: auth(s.accessToken) })).statusCode).toBe(200);
    // Colleagues: active members of the sandbox with the browser's public keys, expiring with it, and no way to sign in.
    expect(s.body.colleagues).toHaveLength(2);
    const people = await demo.prisma.membership.findMany({ where: { orgId: s.orgId }, select: { role: true, user: { select: { name: true, demoExpiresAt: true, status: true } } } });
    expect(people).toHaveLength(3);
    expect(people.every((p) => p.user.demoExpiresAt?.getTime() === expires && p.user.status === "active")).toBe(true);
    const bea = s.body.colleagues.find((c: { name: string }) => c.name === "Bea Lindqvist");
    const login = await demo.app.inject({ remoteAddress: nextIp(), method: "POST", url: "/api/v1/auth/login", payload: { email: bea.email, authKey: s.acct.authKey } });
    expect(login.statusCode).toBe(401);
    expect(login.json().error).toBe("invalid_credentials");
  });

  it("give one session per sign-up: the setup token can't be used again", async () => {
    const ip = nextIp();
    const { inviteToken } = (await demo.app.inject({ remoteAddress: ip, method: "POST", url: "/api/v1/auth/demo", payload: {} })).json();
    const acct = await createAccount("demo pw demo pw", FAST_KDF);
    const { setupToken } = (await demo.app.inject({ remoteAddress: ip, method: "POST", url: "/api/v1/auth/register", payload: { inviteToken, name: "Demo visitor", authKey: acct.authKey, material: acct.material } })).json();
    expect((await demo.app.inject({ remoteAddress: ip, method: "POST", url: "/api/v1/auth/demo/session", headers: auth(setupToken), payload: {} })).statusCode).toBe(200);
    expect((await demo.app.inject({ remoteAddress: ip, method: "POST", url: "/api/v1/auth/demo/session", headers: auth(setupToken), payload: {} })).statusCode).toBe(403);
  });

  it("limit sandboxes per client address, the trust-proxy aware one", async () => {
    const limited = await makeTestApp({ demo: { ttlMinutes: 120, sandboxesPerIpPerHour: 2 }, trustProxy: true });
    try {
      const make = (xff: string) => limited.app.inject({ remoteAddress: "127.0.0.1", method: "POST", url: "/api/v1/auth/demo", headers: { "x-forwarded-for": xff }, payload: {} });
      expect((await make("203.0.113.7")).statusCode).toBe(201);
      expect((await make("203.0.113.7")).statusCode).toBe(201);
      const third = await make("203.0.113.7");
      expect(third.statusCode).toBe(429);
      expect(third.json()).toEqual({ error: "rate_limited" });
      // Another visitor behind the same proxy isn't held back.
      expect((await make("198.51.100.20")).statusCode).toBe(201);
    } finally { await limited.app.close(); }
  });
});

describe("the authenticator skip", () => {
  it("lets a demo account sign in without a code, in demo mode", async () => {
    const s = await newSandbox(demo.app);
    const r = await demo.app.inject({ remoteAddress: nextIp(), method: "POST", url: "/api/v1/auth/login", payload: { email: s.email, authKey: s.acct.authKey } });
    expect(r.statusCode).toBe(200);
    expect(r.json().accessToken).toEqual(expect.any(String));
  });

  it("doesn't exist for a demo account when the instance isn't in demo mode", async () => {
    const s = await newSandbox(demo.app);
    const r = await plain.app.inject({ remoteAddress: nextIp(), method: "POST", url: "/api/v1/auth/login", payload: { email: s.email, authKey: s.acct.authKey } });
    expect(r.statusCode).toBe(401);
    expect(r.json().error).toBe("totp_required");
    // Nor before it is set up: a pending demo account must set up an authenticator there.
    await demo.prisma.user.update({ where: { id: s.userId }, data: { status: "pending_2fa" } });
    const pending = await plain.app.inject({ remoteAddress: nextIp(), method: "POST", url: "/api/v1/auth/login", payload: { email: s.email, authKey: s.acct.authKey } });
    expect(pending.json()).toMatchObject({ needsTotpSetup: true });
  });

  it("can't be used by a real account on a demo instance", async () => {
    // A real account (made on the same database without demo mode), signing in on the demo instance.
    const real = await createActiveUser(plain, { email: "real@clane.ai" });
    const login = await demo.app.inject({ remoteAddress: nextIp(), method: "POST", url: "/api/v1/auth/login", payload: { email: real.email, authKey: await authKeyOf(real.password, real.material) } });
    expect(login.statusCode).toBe(401);
    expect(login.json().error).toBe("totp_required");
    // And the demo session route refuses its setup token.
    await demo.prisma.user.update({ where: { id: real.id }, data: { status: "pending_2fa" } });
    const s = await demo.app.inject({ remoteAddress: nextIp(), method: "POST", url: "/api/v1/auth/demo/session", headers: auth(await signSetup(demo.config, real.id)), payload: {} });
    expect(s.statusCode).toBe(403);
    expect(s.json().error).toBe("not_demo");
    expect((await demo.prisma.user.findUniqueOrThrow({ where: { id: real.id } })).status).toBe("pending_2fa");
  });

  it("isn't reachable through an invite to a real organisation: a demo instance makes demo accounts only", async () => {
    const token = await createInvite(demo.prisma, "boss@clane.ai", "owner");
    const acct = await createAccount("boss master password", FAST_KDF);
    const r = await demo.app.inject({ remoteAddress: nextIp(), method: "POST", url: "/api/v1/auth/register", payload: { inviteToken: token, name: "Boss", authKey: acct.authKey, material: acct.material } });
    expect(r.statusCode).toBe(400);
    expect(r.json().error).toBe("invite_invalid");
    expect(await demo.prisma.user.count()).toBe(0);
  });
});

async function authKeyOf(password: string, material: { kdfSalt: string; kdfParams: KdfParams }) {
  return (await deriveLoginKeys(password, material.kdfSalt, material.kdfParams)).authKey;
}

describe("expiry", () => {
  it("ends the sessions at the sandbox's time, before the sweep runs", async () => {
    const s = await newSandbox(demo.app);
    await demo.prisma.user.update({ where: { id: s.userId }, data: { demoExpiresAt: new Date(Date.now() - 1000) } });
    expect((await demo.app.inject({ method: "GET", url: "/api/v1/me", headers: auth(s.accessToken) })).statusCode).toBe(401);
    expect((await demo.app.inject({ method: "POST", url: "/api/v1/auth/refresh", headers: { cookie: s.cookie } })).statusCode).toBe(401);
    expect((await demo.app.inject({ remoteAddress: nextIp(), method: "POST", url: "/api/v1/auth/login", payload: { email: s.email, authKey: s.acct.authKey } })).statusCode).toBe(401);
  });
});

describe("the cleanup", () => {
  /** Rows of every kind a sandbox can hold, written straight to the database. */
  async function fill(userId: string, orgId: string) {
    const folderId = randomUUID(), recordId = randomUUID(), privateId = randomUUID(), fileId = randomUUID(), linkId = randomUUID();
    await demo.prisma.folder.create({ data: { id: folderId, kind: "team", orgId, ownerId: userId, encName: "v1.name", members: { create: { userId, permission: "owner", directPermission: "owner", wrappedFolderKey: "s1.key" } } } });
    for (const [id, folder] of [[recordId, folderId], [privateId, null]] as const) {
      await demo.prisma.record.create({ data: { id, folderId: folder, ownerId: userId, type: "login", encBody: "v1.body",
        access: { create: { holderType: "user", holderId: userId, permission: "owner", wrappedRecordKey: "v1.key" } } } });
    }
    await demo.prisma.attachment.create({ data: { id: fileId, recordId, createdBy: userId, state: "ready", encMeta: "v1.meta", wrappedFileKey: "v1.key", nonceBase: "AAAAAAAAAAA", chunkSize: 16, chunkCount: 1, size: 16,
      chunks: { create: { index: 0, length: 16, sha256: "00", data: new Uint8Array(16) } } } });
    await demo.prisma.shareLink.create({ data: { id: linkId, recordId, createdBy: userId, orgId, encPayload: "v1.payload", expiresAt: new Date(Date.now() + 3600e3), attachments: { create: { attachmentId: fileId } } } });
    await demo.prisma.event.create({ data: { orgId, actorId: userId, action: "record.create", recordId } });
    await demo.prisma.event.create({ data: { actorId: userId, action: "auth.login" } });
    await demo.prisma.group.create({ data: { orgId, name: "Engineering", members: { create: { userId } } } });
    return { folderId, recordIds: [recordId, privateId], fileId, linkId };
  }

  /** Everything still in the database that belongs to these accounts or this organisation. */
  async function left(userIds: string[], orgId: string) {
    const p = demo.prisma;
    return {
      users: await p.user.count({ where: { id: { in: userIds } } }), orgs: await p.organization.count({ where: { id: orgId } }),
      memberships: await p.membership.count({ where: { OR: [{ orgId }, { userId: { in: userIds } }] } }), sessions: await p.session.count({ where: { userId: { in: userIds } } }),
      folders: await p.folder.count({ where: { OR: [{ orgId }, { ownerId: { in: userIds } }] } }), records: await p.record.count({ where: { ownerId: { in: userIds } } }),
      access: await p.recordAccess.count({ where: { holderId: { in: userIds } } }), attachments: await p.attachment.count({ where: { createdBy: { in: userIds } } }),
      chunks: await p.attachmentChunk.count({ where: { attachment: { createdBy: { in: userIds } } } }), links: await p.shareLink.count({ where: { createdBy: { in: userIds } } }),
      events: await p.event.count({ where: { OR: [{ orgId }, { actorId: { in: userIds } }] } }), invites: await p.invite.count({ where: { orgId } }),
      keys: await p.membershipKey.count({ where: { userId: { in: userIds } } }), groups: await p.group.count({ where: { orgId } }),
    };
  }

  it("deletes everything of an expired sandbox and nothing else", async () => {
    const real = await createActiveUser(plain, { email: "real@clane.ai" });
    const realRows = await fill(real.id, real.orgId);
    const gone = await newSandbox(demo.app, { colleagues: ["Bea Lindqvist"] });
    const kept = await newSandbox(demo.app, { colleagues: ["Tom Reyes"] });
    await fill(gone.userId, gone.orgId);
    await fill(kept.userId, kept.orgId);
    await demo.prisma.membershipKey.create({ data: { orgId: gone.orgId, userId: gone.userId, publicKey: `pk-${randomUUID()}`, wrappedPrivateKey: "v1.x", userKeyGen: 1 } });
    const goneIds = (await demo.prisma.membership.findMany({ where: { orgId: gone.orgId }, select: { userId: true } })).map((m) => m.userId);
    const keptIds = (await demo.prisma.membership.findMany({ where: { orgId: kept.orgId }, select: { userId: true } })).map((m) => m.userId);
    const keptBefore = await left(keptIds, kept.orgId);
    const realBefore = await left([real.id], real.orgId);
    expect(realBefore.records).toBe(2);
    expect(Object.values(await left(goneIds, gone.orgId)).every((n) => n > 0)).toBe(true);

    // The first sandbox's time is up (its organisation and accounts carry the same expiry).
    const past = new Date(Date.now() - 60e3);
    await demo.prisma.organization.update({ where: { id: gone.orgId }, data: { demoExpiresAt: past } });
    await demo.prisma.user.updateMany({ where: { id: { in: goneIds } }, data: { demoExpiresAt: past } });
    const r = await sweepExpiredDemos(demo.prisma);
    expect(r).toEqual({ sandboxes: 1, users: 2 });

    expect(Object.values(await left(goneIds, gone.orgId)).every((n) => n === 0)).toBe(true);
    expect(await left(keptIds, kept.orgId)).toEqual(keptBefore);
    expect(await left([real.id], real.orgId)).toEqual(realBefore);
    expect(await demo.prisma.attachment.count({ where: { id: realRows.fileId } })).toBe(1);
    // Nothing more on a second run.
    expect(await sweepExpiredDemos(demo.prisma)).toEqual({ sandboxes: 0, users: 0 });
  });

  it("never touches an account without demoExpiresAt, even in an expired sandbox", async () => {
    const s = await newSandbox(demo.app);
    const real = await createActiveUser(plain, { email: "real@clane.ai" });
    await demo.prisma.membership.create({ data: { orgId: s.orgId, userId: real.id, role: "member", status: "active" } });
    await demo.prisma.organization.update({ where: { id: s.orgId }, data: { demoExpiresAt: new Date(Date.now() - 1000) } });
    await sweepExpiredDemos(demo.prisma);
    expect(await demo.prisma.user.count({ where: { id: real.id } })).toBe(1);
    expect(await demo.prisma.organization.count({ where: { id: s.orgId } })).toBe(0);
  });

  it("removes an expired sandbox nobody signed up to", async () => {
    await demo.app.inject({ remoteAddress: nextIp(), method: "POST", url: "/api/v1/auth/demo", payload: {} });
    await demo.prisma.organization.updateMany({ where: { demoExpiresAt: { not: null } }, data: { demoExpiresAt: new Date(Date.now() - 1000) } });
    expect(await sweepExpiredDemos(demo.prisma)).toEqual({ sandboxes: 1, users: 0 });
    expect(await demo.prisma.invite.count()).toBe(0);
  });
});

describe("limits in demo mode", () => {
  it("sends no email: invites come back as links even with email set up", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const s = await newSandbox(demo.app);
    expect(await demo.app.mail.configured(s.orgId)).toBe(false);
    const r = await demo.app.inject({ method: "POST", url: "/api/v1/admin/invites", headers: auth(s.accessToken, s.orgId), payload: { email: "friend@example.com" } });
    expect(r.statusCode).toBe(201);
    expect(r.json()).toMatchObject({ emailed: false, inviteUrl: expect.stringContaining("/invite/") });
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("refuses to change email and single sign-on settings", async () => {
    const s = await newSandbox(demo.app);
    const h = auth(s.accessToken, s.orgId);
    expect((await demo.app.inject({ method: "GET", url: "/api/v1/admin/settings/sso", headers: h })).statusCode).toBe(200);
    const sso = await demo.app.inject({ method: "PUT", url: "/api/v1/admin/settings/sso", headers: h, payload: { issuer: "https://idp.example.com", clientId: "x", clientSecret: "y", requireSso: false, trustIdpMfa: false, autoJoin: false } });
    expect(sso.statusCode).toBe(403);
    expect(sso.json().error).toBe("demo_mode");
    expect((await demo.app.inject({ method: "POST", url: "/api/v1/admin/settings/sso/domains", headers: h, payload: { domain: "example.com" } })).json().error).toBe("demo_mode");
    const email = await demo.app.inject({ method: "PUT", url: "/api/v1/admin/settings/email", headers: h, payload: { provider: "resend", fromAddress: "a@example.com", apiKey: "re_123456789" } });
    expect(email.json().error).toBe("demo_mode");
    expect((await demo.app.inject({ method: "POST", url: "/api/v1/admin/settings/email/test", headers: h, payload: {} })).json().error).toBe("demo_mode");
    expect((await demo.app.inject({ method: "POST", url: "/api/v1/auth/sso/discover", payload: { email: "a@example.com" } })).json().error).toBe("demo_mode");
  });

  it("keeps sandboxes apart: no invitation to another visitor's account, no joining another sandbox", async () => {
    const a = await newSandbox(demo.app);
    const b = await newSandbox(demo.app);
    const r = await demo.app.inject({ method: "POST", url: "/api/v1/admin/invites", headers: auth(a.accessToken, a.orgId), payload: { email: b.email } });
    expect(r.statusCode).toBe(201);
    expect(r.json().inviteUrl).toBeUndefined();
    expect(await demo.prisma.membership.count({ where: { orgId: a.orgId, userId: b.userId } })).toBe(0);
    expect((await demo.app.inject({ method: "POST", url: `/api/v1/me/invitations/${a.orgId}/accept`, headers: auth(b.accessToken), payload: {} })).statusCode).toBe(404);
  });

  it("closes organisation creation, server pages and recovery; caps files small", async () => {
    const s = await newSandbox(demo.app);
    const org = await demo.app.inject({ method: "POST", url: "/api/v1/orgs", headers: auth(s.accessToken), payload: { name: "Another" } });
    expect(org.json().error).toBe("org_creation_disabled");
    expect((await demo.app.inject({ method: "GET", url: "/api/v1/me/orgs", headers: auth(s.accessToken) })).json().allowOrgCreation).toBe(false);
    expect((await demo.app.inject({ method: "GET", url: "/api/v1/admin/backups", headers: auth(s.accessToken) })).json().error).toBe("demo_mode");
    expect((await demo.app.inject({ method: "POST", url: "/api/v1/auth/recovery/kit", payload: { email: s.email, recoveryAuth: "a".repeat(43) } })).json().error).toBe("demo_mode");
    expect((await demo.app.inject({ method: "GET", url: "/api/v1/auth/recovery/options" })).statusCode).toBe(200);
    expect((await demo.app.inject({ method: "GET", url: "/api/v1/attachments/limits", headers: auth(s.accessToken) })).json()).toMatchObject({ maxFileMb: 5, maxRecordMb: 20 });
  });
});

describe("startup", () => {
  const env = { DATABASE_URL: "postgresql://x:y@localhost/z", JWT_SECRET: "j".repeat(40), SERVER_SECRET: "s".repeat(40), PUBLIC_URL: "https://demo.example.com" };

  it("reads DEMO_MODE and its settings, off by default", () => {
    expect(loadConfig(env).demo).toBeUndefined();
    expect(loadConfig({ ...env, DEMO_MODE: "false" }).demo).toBeUndefined();
    expect(loadConfig({ ...env, DEMO_MODE: "true" }).demo).toEqual({ ttlMinutes: 120, sandboxesPerIpPerHour: 5 });
    expect(loadConfig({ ...env, DEMO_MODE: "true", DEMO_TTL_MINUTES: "30", DEMO_SANDBOXES_PER_IP_PER_HOUR: "2" }).demo).toEqual({ ttlMinutes: 30, sandboxesPerIpPerHour: 2 });
  });

  it("refuses DEMO_MODE together with HOSTED_MODE", () => {
    expect(() => loadConfig({ ...env, DEMO_MODE: "true", HOSTED_MODE: "true" })).toThrow(/HOSTED_MODE/);
  });

  it("refuses to start on a database with a real account, the instance admin included", async () => {
    const off: Pick<Config, "demo" | "hostedMode"> = {}, on = { demo: DEMO };
    await expect(checkDemoStartup(demo.prisma, on)).resolves.toBeUndefined();
    await newSandbox(demo.app);
    await expect(checkDemoStartup(demo.prisma, on)).resolves.toBeUndefined();
    await demo.prisma.user.create({ data: { email: "admin@clane.ai", name: "Admin", status: "active", instanceAdmin: true, authHash: await argon2.hash("x"),
      kdfSalt: "AAAA", kdfParams: { ...FAST_KDF }, wrappedUserKey: "v1.x", publicKey: "AAAA", wrappedPrivateKey: "v1.x" } });
    await expect(checkDemoStartup(demo.prisma, on)).rejects.toBeInstanceOf(DemoStartupRefused);
    await expect(checkDemoStartup(demo.prisma, off)).resolves.toBeUndefined();
    await expect(checkDemoStartup(demo.prisma, { ...on, hostedMode: true })).rejects.toThrow(/HOSTED_MODE/);
  });
});
