import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { createLink, createTeamFolder, encryptNewRecord, wrapKey, type KdfParams } from "@clane-vault/crypto";
import { makeTestApp, resetDb, createActiveUser, orgHeader } from "./helpers.js";
import { ipAllowed, policySchema, readPolicies } from "../src/lib/policies.js";
import { generateKeyPairSync } from "node:crypto";
import { startFakeGateway } from "./fakeGateway.js";
import { createTestPersonalAgent } from "./agentHelpers.js";

const t = await makeTestApp();
const fake = await startFakeGateway();
const pem = generateKeyPairSync("ec", { namedCurve: "prime256v1" }).privateKey.export({ type: "pkcs8", format: "pem" }) as string;
const t2 = await makeTestApp({ billingMode: "hosted", agents: { gatewayInternalUrl: fake.url, gatewayPublicUrl: "https://gw.test/mcp", gatewayApiToken: fake.token, tokenPrivateKeyPem: pem, acceptNewGatewayIdentity: false, personalAgents: true } });
afterAll(async () => { await t.app.close(); await t2.app.close(); await fake.close(); });
beforeEach(async () => { await resetDb(t.prisma); await resetDb(t2.prisma); fake.dropped.length = 0; });

type U = Awaited<ReturnType<typeof createActiveUser>>;
const FAST: KdfParams = { alg: "argon2id", m: 1024, t: 2, p: 1 };
const call = (u: U, method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE", url: string, payload?: unknown, ip = "10.0.0.5", org = true) =>
  t.app.inject({ method, url: `/api/v1${url}`, payload: payload as object, remoteAddress: ip, headers: { authorization: `Bearer ${u.accessToken}`, ...(org ? orgHeader(u) : {}) } });
const put = (u: U, p: object, ip?: string) => call(u, "PUT", "/admin/settings/policies", p, ip);

async function teamRecord(u: U) {
  const fid = crypto.randomUUID();
  const f = await createTeamFolder(fid, "Links", u.keys.publicKey);
  await call(u, "POST", "/folders", { id: fid, kind: "team", encName: f.encName, wrappedFolderKey: f.wrappedFolderKey });
  const id = crypto.randomUUID();
  const enc = await encryptNewRecord(id, { type: "login", title: "T", password: "p" }, u.keys.userKey);
  expect((await call(u, "POST", "/records", { id, folderId: fid, type: "login", encBody: enc.encBody, wrappedRecordKey: await wrapKey(enc.recordKey, f.folderKey, `record-key:${id}`), ownerWrappedRecordKey: enc.wrappedRecordKey })).statusCode).toBe(201);
  return id;
}
async function privateRecord(u: U) {
  const id = crypto.randomUUID();
  const enc = await encryptNewRecord(id, { type: "login", title: "P", password: "p" }, u.keys.userKey);
  await call(u, "POST", "/records", { id, folderId: null, type: "login", encBody: enc.encBody, wrappedRecordKey: enc.wrappedRecordKey });
  return id;
}
async function link(u: U, recordId: string, opts: { hours?: number; password?: string } = {}) {
  const id = crypto.randomUUID();
  const l = await createLink(id, { title: "T", password: "p" }, opts.password ? { password: opts.password, kdf: FAST } : {});
  return call(u, "POST", "/links", { id, recordId, encPayload: l.encPayload, expiresInHours: opts.hours ?? 24, maxOpens: 1, ...(l.passwordSalt ? { passwordSalt: l.passwordSalt, accessHash: l.accessHash } : {}) });
}

describe("policy schema", () => {
  it("validates CIDRs (IPv4 and IPv6), fills defaults and refuses unknown keys", () => {
    const p = policySchema.parse({ ipAllowlist: ["10.0.0.0/8", "2001:DB8::/32", "192.168.1.7"] });
    expect(p.ipAllowlist).toEqual(["10.0.0.0/8", "2001:db8::/32", "192.168.1.7/32"]);
    expect(p.links).toEqual({ allowed: true, maxExpiryHours: 168, requirePassword: false, allowAttachments: true });
    expect(p.attachments).toEqual({ allowed: true, maxFileMb: null, previews: true });
    for (const bad of ["10.0.0.0/33", "2001:db8::/129", "10.0.0", "evil.example/8", "10.0.0.0/8/1", "::1/-1"]) expect(policySchema.safeParse({ ipAllowlist: [bad] }).success).toBe(false);
    expect(policySchema.safeParse({ nope: true }).success).toBe(false);
    expect(policySchema.safeParse({ minPasswordLength: 8 }).success).toBe(false);
    // A corrupt stored allowlist fails closed.
    expect(readPolicies({ ipAllowlist: ["garbage"], autoLockMinutes: 5 })).toMatchObject({ autoLockMinutes: 5, ipAllowlist: ["0.0.0.0/32"] });
  });

  it("matches addresses", () => {
    expect(ipAllowed("10.1.2.3", [])).toBe(true);
    expect(ipAllowed("10.1.2.3", ["10.0.0.0/8"])).toBe(true);
    expect(ipAllowed("::ffff:10.1.2.3", ["10.0.0.0/8"])).toBe(true);
    expect(ipAllowed("11.1.2.3", ["10.0.0.0/8"])).toBe(false);
    expect(ipAllowed("2001:db8:1::5", ["2001:db8::/32"])).toBe(true);
    expect(ipAllowed("2001:db9::5", ["2001:db8::/32"])).toBe(false);
    expect(ipAllowed("fe80::1%eth0", ["fe80::/10"])).toBe(true);
    expect(ipAllowed(undefined, ["10.0.0.0/8"])).toBe(false);
    expect(ipAllowed("not-an-ip", ["10.0.0.0/8"])).toBe(false);
  });
});

describe("org policies", () => {
  it("owners and admins read and change them, members can't; clients get them with the org list; changes are logged", async () => {
    const admin = await createActiveUser(t, { role: "admin" }), m = await createActiveUser(t);
    expect((await call(m, "GET", "/admin/settings/policies")).statusCode).toBe(403);
    expect((await put(m, { autoLockMinutes: 5 })).statusCode).toBe(403);
    const g = await call(admin, "GET", "/admin/settings/policies");
    expect(g.json()).toMatchObject({ policies: { autoLockMinutes: null, minPasswordLength: 12, ipAllowlist: [], ownerBreakGlass: true }, changedAt: null, yourIp: "10.0.0.5" });
    expect((await put(admin, { autoLockMinutes: 0 })).statusCode).toBe(400);
    expect((await put(admin, { ipAllowlist: ["nope"] })).statusCode).toBe(400);
    const r = await put(admin, { autoLockMinutes: 5, minPasswordLength: 16, minPasswordScore: 3, offlineAllowed: false, extensionAllowed: false, breachCheckAllowed: false, ipAllowlist: ["10.0.0.0/24"] });
    expect(r.statusCode).toBe(200);
    expect(r.json()).toMatchObject({ policies: { autoLockMinutes: 5, minPasswordLength: 16 }, changedBy: { id: admin.id } });
    // Every member reads them (but not the allowlist itself) with their organisations.
    const orgs = (await call(m, "GET", "/me/orgs", undefined, "10.0.0.9", false)).json().orgs;
    expect(orgs[0].policies).toEqual({ autoLockMinutes: 5, minPasswordLength: 16, minPasswordScore: 3, links: { allowed: true, maxExpiryHours: 168, requirePassword: false, allowAttachments: true },
      attachments: { allowed: true, maxFileMb: null, previews: true }, offlineAllowed: false, extensionAllowed: false, breachCheckAllowed: false, ipRestricted: true,
      personalAgents: { allowed: true, maxPerMember: null, write: true, reveal: "approval" }, personalAgentsEnabled: false });
    const e = await t.prisma.event.findFirstOrThrow({ where: { action: "org.policies_update" } });
    expect(e).toMatchObject({ actorId: admin.id, orgId: admin.orgId });
    expect((e.meta as { changed: string[] }).changed.sort()).toEqual(["autoLockMinutes", "breachCheckAllowed", "extensionAllowed", "ipAllowlist", "minPasswordLength", "minPasswordScore", "offlineAllowed"]);
  });

  it("one-time links: off, maximum expiry and required password are enforced on org records only", async () => {
    const admin = await createActiveUser(t, { role: "admin" });
    const team = await teamRecord(admin), mine = await privateRecord(admin);
    const live = (await link(admin, team)).json().id as string;
    const week = (await link(admin, team, { hours: 168, password: "pw" })).json().id as string;
    const day = (await link(admin, team, { hours: 24, password: "pw" })).json().id as string;
    const tighten = await put(admin, { links: { maxExpiryHours: 24, requirePassword: true } });
    expect(tighten.statusCode).toBe(200);
    // Live links that break the stricter rules end now: the one without a password and the week-long one.
    const revokedNow = async (id: string) => (await t.prisma.shareLink.findUniqueOrThrow({ where: { id } })).revokedAt !== null;
    expect([await revokedNow(live), await revokedNow(week), await revokedNow(day)]).toEqual([true, true, false]);
    expect((await t.prisma.event.findFirstOrThrow({ where: { action: "org.policies_update" }, orderBy: { id: "desc" } })).meta).toMatchObject({ linksRevoked: 2 });
    const long = await link(admin, team, { hours: 168, password: "pw" });
    expect(long.statusCode).toBe(400);
    expect(long.json()).toMatchObject({ error: "link_expiry_too_long", maxExpiryHours: 24 });
    expect((await link(admin, team, { hours: 24 })).json().error).toBe("link_password_required");
    expect((await link(admin, team, { hours: 24, password: "pw" })).statusCode).toBe(201);
    // The owner's private record isn't the org's: its links are theirs to make.
    expect((await link(admin, mine, { hours: 168 })).statusCode).toBe(201);
    // Links off: refused, and the org's live links stop working at once.
    expect((await put(admin, { links: { allowed: false } })).statusCode).toBe(200);
    expect((await link(admin, team, { hours: 1, password: "pw" })).json().error).toBe("links_disabled");
    expect(await revokedNow(day)).toBe(true);
    expect(await t.prisma.shareLink.count({ where: { orgId: null, revokedAt: null } })).toBe(1);
    expect((await t.app.inject({ method: "POST", url: `/api/v1/public/links/${day}/open`, payload: {} })).statusCode).toBe(410);
  });

  it("IP allowlist: enforced on org-scoped requests (IPv4 and IPv6); the private vault stays reachable", async () => {
    const owner = await createActiveUser(t, { role: "owner" }), admin = await createActiveUser(t, { role: "admin" }), m = await createActiveUser(t);
    expect((await put(admin, { ipAllowlist: ["10.0.0.0/24", "2001:db8::/32"] }, "10.0.0.5")).statusCode).toBe(200);
    expect((await call(m, "GET", "/sync", undefined, "10.0.0.77")).statusCode).toBe(200);
    expect((await call(m, "GET", "/sync", undefined, "::ffff:10.0.0.77")).statusCode).toBe(200);
    expect((await call(m, "GET", "/sync", undefined, "2001:db8:4::1")).statusCode).toBe(200);
    const blocked = await call(m, "GET", "/sync", undefined, "10.0.1.1");
    expect(blocked.statusCode).toBe(403);
    expect(blocked.json()).toMatchObject({ error: "ip_not_allowed", orgId: m.orgId });
    expect((await call(m, "GET", "/sync", undefined, "2001:db9::1")).statusCode).toBe(403);
    expect((await call(admin, "GET", "/admin/people", undefined, "192.0.2.1")).statusCode).toBe(403);
    // No org header: the private vault and the org list still work.
    expect((await call(m, "GET", "/sync", undefined, "10.0.1.1", false)).statusCode).toBe(200);
    expect((await call(m, "GET", "/me/orgs", undefined, "10.0.1.1", false)).statusCode).toBe(200);
    // The owner keeps break-glass access from anywhere, logged once per session.
    expect((await call(owner, "GET", "/sync", undefined, "192.0.2.1")).statusCode).toBe(200);
    expect((await call(owner, "GET", "/org", undefined, "192.0.2.1")).statusCode).toBe(200);
    expect(await t.prisma.event.count({ where: { action: "policy.ip_bypass_owner", actorId: owner.id } })).toBe(1);
  });

  it("IP allowlist: nobody can lock themselves out, and only the owner changes break-glass", async () => {
    const owner = await createActiveUser(t, { role: "owner" }), admin = await createActiveUser(t, { role: "admin" });
    // An admin can't save a list that leaves out their own address.
    expect((await put(admin, { ipAllowlist: ["10.9.0.0/16"] }, "10.0.0.5")).json().error).toBe("would_lock_out");
    // ...nor turn the owner's break-glass off (or on).
    expect((await put(admin, { ipAllowlist: ["10.0.0.0/24"], ownerBreakGlass: false }, "10.0.0.5")).statusCode).toBe(403);
    // The owner, with break-glass on, may set a list without their address.
    expect((await put(owner, { ipAllowlist: ["10.9.0.0/16"] }, "192.0.2.1")).statusCode).toBe(200);
    // Turning break-glass off from outside the list would lock them out: refused.
    expect((await put(owner, { ipAllowlist: ["10.9.0.0/16"], ownerBreakGlass: false }, "192.0.2.1")).json().error).toBe("would_lock_out");
    expect((await put(owner, { ipAllowlist: ["10.9.0.0/16"], ownerBreakGlass: false }, "10.9.3.4")).statusCode).toBe(200);
    // Now the owner is held to the list too.
    expect((await call(owner, "GET", "/sync", undefined, "192.0.2.1")).statusCode).toBe(403);
    expect((await call(owner, "GET", "/sync", undefined, "10.9.0.1")).statusCode).toBe(200);
    // An admin inside the list can still change other settings but never break-glass.
    expect((await put(admin, { ipAllowlist: ["10.9.0.0/16"], ownerBreakGlass: false, autoLockMinutes: 10 }, "10.9.0.2")).statusCode).toBe(200);
    expect((await put(admin, { ipAllowlist: ["10.9.0.0/16"], ownerBreakGlass: true }, "10.9.0.2")).statusCode).toBe(403);
    // With break-glass off, an admin can't narrow the list (that could shut the owner out); widening is fine.
    const narrow = await put(admin, { ipAllowlist: ["10.9.0.2/32"], ownerBreakGlass: false }, "10.9.0.2");
    expect(narrow.statusCode).toBe(403);
    expect(narrow.json().error).toBe("owner_only");
    expect((await put(admin, { ipAllowlist: ["10.9.0.0/16", "10.8.0.0/16"], ownerBreakGlass: false }, "10.9.0.2")).statusCode).toBe(200);
    expect((await put(admin, { ipAllowlist: ["10.9.0.0/16"], ownerBreakGlass: false }, "10.9.0.2")).json().error).toBe("owner_only");
    expect((await put(owner, { ipAllowlist: ["10.9.0.0/16"], ownerBreakGlass: false }, "10.9.0.1")).statusCode).toBe(200);
    // Clearing the list reopens the org.
    expect((await put(owner, { ownerBreakGlass: false }, "10.9.0.1")).statusCode).toBe(200);
    expect((await call(admin, "GET", "/sync", undefined, "198.51.100.1")).statusCode).toBe(200);
  });

  it("policies are per organisation", async () => {
    const B = await t.prisma.organization.create({ data: { name: "Beta", slug: `beta-${crypto.randomUUID().slice(0, 8)}` } });
    const adminA = await createActiveUser(t, { role: "admin" }), ownerB = await createActiveUser(t, { role: "owner", orgId: B.id });
    expect((await put(adminA, { ipAllowlist: ["10.0.0.0/24"], links: { allowed: false } }, "10.0.0.5")).statusCode).toBe(200);
    expect((await call(ownerB, "GET", "/admin/settings/policies", undefined, "198.51.100.1")).json().policies).toMatchObject({ ipAllowlist: [], links: { allowed: true } });
    expect((await call(ownerB, "GET", "/sync", undefined, "198.51.100.1")).statusCode).toBe(200);
  });
});

describe("personal-agents policy block", () => {
  const block = { allowed: false, maxPerMember: 2, write: false, reveal: "off" };
  const orgOf = (u: U) => t2.prisma.organization.findUniqueOrThrow({ where: { id: u.orgId } });
  const call2 = (u: U, method: "GET" | "PUT" | "POST", url: string, payload?: unknown) =>
    t2.app.inject({ method, url: `/api/v1${url}`, payload: payload as object, remoteAddress: "10.0.0.7", headers: { authorization: `Bearer ${u.accessToken}`, ...orgHeader(u) } });
  const business = (u: U) => t2.prisma.organization.update({ where: { id: u.orgId }, data: { plan: "business", billingStatus: "active", seatsPaid: 20 } });

  it("defaults for {} and for a missing block; the block is part of the schema", () => {
    const d = { allowed: true, maxPerMember: null, write: true, reveal: "approval" };
    expect(policySchema.parse({}).personalAgents).toEqual(d);
    expect(readPolicies({}).personalAgents).toEqual(d);
    expect(readPolicies({}, { features: { policyEdit: false } as never }).personalAgents).toEqual(d);
    for (const bad of [{ maxPerMember: 0 }, { maxPerMember: 21 }, { reveal: "always" }]) expect(policySchema.shape.personalAgents.safeParse(bad).success).toBe(false);
  });

  it("on hosted Team the block has its own route; the full route stays Business-only", async () => {
    const owner = await createActiveUser(t2, { role: "owner" }), member = await createActiveUser(t2, { role: "member" });
    expect((await call2(owner, "PUT", "/admin/settings/policies", {})).statusCode).toBe(402);
    expect((await call2(member, "PUT", "/admin/settings/policies/personal-agents", block)).statusCode).toBe(403);
    const r = await call2(owner, "PUT", "/admin/settings/policies/personal-agents", block);
    expect(r.statusCode).toBe(200);
    expect(r.json().policies.personalAgents).toEqual(block);
    expect((await call2(owner, "GET", "/admin/settings/policies")).json().policies.personalAgents).toEqual(block);
    expect((await call2(owner, "PUT", "/admin/settings/policies/personal-agents", { reveal: "nope" })).statusCode).toBe(400);
    expect(await t2.prisma.event.findFirst({ where: { action: "org.policies_update" } })).toMatchObject({ orgId: owner.orgId, meta: { changed: ["personalAgents"] } });
    // Members' clients get it with the org list, and whether this server has the feature at all.
    expect((await call2(member, "GET", "/me")).json().orgs[0].policies).toMatchObject({ personalAgents: block, personalAgentsEnabled: true });
    const plain = await createActiveUser(t);
    expect((await t.app.inject({ method: "GET", url: "/api/v1/me", headers: { authorization: `Bearer ${plain.accessToken}` } })).json().orgs[0].policies.personalAgentsEnabled).toBe(false);
  });

  it("survives a full PUT without the key and a risk-ignore write; a full PUT with the key replaces it", async () => {
    const owner = await createActiveUser(t2, { role: "owner" });
    await business(owner);
    await call2(owner, "PUT", "/admin/settings/policies/personal-agents", block);
    expect((await call2(owner, "PUT", "/admin/settings/policies", { autoLockMinutes: 5 })).statusCode).toBe(200);
    expect((await orgOf(owner)).policies).toMatchObject({ autoLockMinutes: 5, personalAgents: block });
    expect((await call2(owner, "POST", "/admin/risk/benchmarks/ip_allowlist/ignore")).statusCode).toBe(200);
    expect((await orgOf(owner)).policies).toMatchObject({ riskIgnored: ["ip_allowlist"], personalAgents: block });
    const r = await call2(owner, "PUT", "/admin/settings/policies", { personalAgents: { reveal: "standing" } });
    expect(r.json().policies.personalAgents).toEqual({ allowed: true, maxPerMember: null, write: true, reveal: "standing" });
    // The personal-agents route keeps the rest of the stored JSON.
    await call2(owner, "PUT", "/admin/settings/policies/personal-agents", block);
    expect((await orgOf(owner)).policies).toMatchObject({ riskIgnored: ["ip_allowlist"], personalAgents: block });
  });

  it("stopping personal agents suspends the members' live ones: one event per organisation, and the gateway drops them", async () => {
    for (const via of ["personal-agents", "full"] as const) {
      fake.dropped.length = 0;
      await resetDb(t2.prisma);
      const owner = await createActiveUser(t2, { role: "owner" }), member = await createActiveUser(t2, { role: "member" });
      await business(owner);
      const other = await t2.prisma.organization.create({ data: { name: "Other", slug: `other-${via}` } });
      await t2.prisma.membership.create({ data: { orgId: other.id, userId: member.id, role: "member", status: "active" } });
      const live = await createTestPersonalAgent(t2, { ownerUserId: member.id }), revoked = await createTestPersonalAgent(t2, { ownerUserId: member.id, revoked: true });
      const outsider = await createTestPersonalAgent(t2, { ownerUserId: (await createActiveUser(t2, { email: `o-${via}@x.test`, orgId: other.id })).id });
      const stop = via === "full" ? call2(owner, "PUT", "/admin/settings/policies", { personalAgents: { allowed: false } }) : call2(owner, "PUT", "/admin/settings/policies/personal-agents", { allowed: false });
      expect((await stop).statusCode).toBe(200);
      const ev = await t2.prisma.event.findMany({ where: { action: "personal_agent.suspended" } });
      expect(ev.map((e) => `${e.orgId}:${(e.meta as { agentId: string }).agentId}`).sort()).toEqual([`${owner.orgId}:${live.id}`, `${other.id}:${live.id}`].sort());
      await expect.poll(() => fake.dropped).toEqual([live.id]);
      expect(fake.dropped).not.toContain(revoked.id);
      expect(fake.dropped).not.toContain(outsider.id);
      // Saving the same block again suspends nothing more.
      await call2(owner, "PUT", "/admin/settings/policies/personal-agents", { allowed: false });
      expect(await t2.prisma.event.count({ where: { action: "personal_agent.suspended" } })).toBe(2);
    }
  });

  it("a full PUT without the key leaves a stored allowed: false untouched, and suspends nothing", async () => {
    const owner = await createActiveUser(t2, { role: "owner" });
    await business(owner);
    await t2.prisma.organization.update({ where: { id: owner.orgId }, data: { policies: { personalAgents: { allowed: false } } } });
    const a = await createTestPersonalAgent(t2, { ownerUserId: owner.id });
    expect((await call2(owner, "PUT", "/admin/settings/policies", { autoLockMinutes: 9 })).statusCode).toBe(200);
    expect((await orgOf(owner)).policies).toMatchObject({ autoLockMinutes: 9, personalAgents: { allowed: false } });
    expect(await t2.prisma.event.count({ where: { action: "personal_agent.suspended" } })).toBe(0);
    expect(fake.dropped).not.toContain(a.id);
  });
});
