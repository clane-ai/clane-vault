import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";
import { randomUUID } from "node:crypto";
import { makeTestApp, resetDb, createActiveUser, createInvite } from "./helpers.js";

const t = await makeTestApp({ billingMode: "hosted" });
afterAll(() => t.app.close());
beforeEach(() => resetDb(t.prisma));

let n = 0;
const call = (u: { accessToken: string; orgId?: string | null }, method: "GET" | "POST", url: string) =>
  t.app.inject({ method, url: `/api/v1${url}`, remoteAddress: `10.190.0.${++n % 250}`, headers: { authorization: `Bearer ${u.accessToken}`, ...(u.orgId ? { "x-org-id": u.orgId } : {}) } });
const options = async () => (await t.app.inject({ method: "GET", url: "/api/v1/auth/recovery/options", remoteAddress: `10.193.0.${++n % 250}` })).json().adminRecoveryEnabled;
const pub = (url: string, payload: object) => t.app.inject({ method: "POST", url: `/api/v1${url}`, payload, remoteAddress: `10.191.0.${++n % 250}` });

describe("Team reads stored Business settings as off", () => {
  it("downgrade turns every read off without touching storage; upgrading restores it", async () => {
    const owner = await createActiveUser(t, { role: "owner", email: "boss@acme.test" });
    const member = await createActiveUser(t, { email: "sara@acme.test" });
    const orgId = owner.orgId!;
    const policies = { ipAllowlist: ["203.0.113.0/24"], ownerBreakGlass: true, minPasswordLength: 20, autoLockMinutes: 3 };
    await t.prisma.organization.update({ where: { id: orgId }, data: { plan: "business", seatsPaid: 50, policies, adminRecoveryEnabled: true } });
    await t.prisma.orgSso.create({ data: { id: randomUUID(), orgId, issuer: "https://idp.test", clientId: "c", requireSso: true, autoJoin: true } });
    await t.prisma.ssoDomain.create({ data: { orgId, domain: "acme.test", token: "tok", verifiedAt: new Date(), checkedAt: new Date() } });
    await t.prisma.orgDomainJoin.create({ data: { orgId, enabled: true } });
    const day = 864e5;
    await t.prisma.event.createMany({ data: [
      { orgId, action: "test.recent", at: new Date(Date.now() - 40 * day) },
      { orgId, action: "test.ancient", at: new Date(Date.now() - 400 * day) },
    ] });
    t.config.resendApiKey = "re_test"; t.config.emailFrom = "vault@clane.ai";
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("{}", { status: 200 }));
    const actions = async () => (await call(owner, "GET", "/admin/events?limit=200")).json().events.map((e: { action: string }) => e.action);
    const inviteToken = await createInvite(t.prisma, "pending@acme.test", "member", orgId);
    const clientPol = async () => (await call(member, "GET", "/me")).json().orgs.find((o: { id: string }) => o.id === orgId).policies;
    const invitePol = async () => (await t.app.inject({ method: "GET", url: `/api/v1/auth/invite/${inviteToken}`, remoteAddress: "10.192.0.1" })).json().passwordPolicy;
    const stored = () => t.prisma.organization.findUniqueOrThrow({ where: { id: orgId }, select: { policies: true, adminRecoveryEnabled: true } });

    // Business: everything on.
    expect(await clientPol()).toMatchObject({ autoLockMinutes: 3 });
    expect((await invitePol()).minLength).toBe(20);
    expect((await pub("/auth/sso/discover", { email: "x@acme.test" })).json().orgs).toHaveLength(1);
    expect((await call(member, "GET", "/sync")).json()).toEqual({ error: "sso_required", orgId });
    expect((await call(owner, "GET", "/admin/settings/policies")).json().policies).toMatchObject(policies);
    expect((await call(owner, "GET", "/admin/settings")).json().adminRecovery.enabled).toBe(true);
    expect(await options()).toBe(true);
    const ev = await actions();
    expect(ev).toContain("test.recent");
    expect(ev).not.toContain("test.ancient");
    expect((await pub("/auth/domain-join", { email: "new@acme.test" })).statusCode).toBe(202);
    expect(await t.prisma.invite.count({ where: { email: "new@acme.test" } })).toBe(1);
    await t.prisma.invite.deleteMany({ where: { email: "new@acme.test" } });
    await t.prisma.event.deleteMany({ where: { action: "org.domain_join_request" } });

    // Team: all off, nothing stored changes.
    await t.prisma.organization.update({ where: { id: orgId }, data: { plan: "team", seatsPaid: null } });
    const before = await stored();
    expect((await pub("/auth/sso/discover", { email: "x@acme.test" })).json().orgs).toEqual([]);
    expect((await pub("/auth/sso/start", { org: "default" })).json()).toEqual({ error: "sso_not_configured" });
    expect((await call(member, "GET", "/sync")).statusCode).toBe(200);
    expect((await call(owner, "GET", "/admin/settings/policies")).json().policies).toMatchObject({ ipAllowlist: [], minPasswordLength: 12 });
    expect((await call(owner, "GET", "/admin/settings")).json().adminRecovery.enabled).toBe(false);
    expect(await options()).toBe(false);
    expect(await actions()).not.toContain("test.recent");
    expect(await actions()).not.toContain("test.ancient");
    expect((await pub("/auth/domain-join", { email: "new@acme.test" })).statusCode).toBe(202);
    expect(await t.prisma.invite.count({ where: { email: "new@acme.test" } })).toBe(0);
    expect(await clientPol()).toMatchObject({ autoLockMinutes: null, ipRestricted: false });
    expect((await invitePol()).minLength).toBe(12);
    expect(await stored()).toEqual(before);
    expect(await t.prisma.orgSso.count({ where: { orgId, requireSso: true, autoJoin: true } })).toBe(1);
    expect(await t.prisma.orgDomainJoin.count({ where: { orgId, enabled: true } })).toBe(1);

    // Back to Business: restored with nothing re-entered.
    await t.prisma.organization.update({ where: { id: orgId }, data: { plan: "business", seatsPaid: 50 } });
    expect((await pub("/auth/sso/discover", { email: "x@acme.test" })).json().orgs).toHaveLength(1);
    expect((await call(member, "GET", "/sync")).json()).toEqual({ error: "sso_required", orgId });
    expect((await call(owner, "GET", "/admin/settings/policies")).json().policies).toMatchObject(policies);
    expect((await call(owner, "GET", "/admin/settings")).json().adminRecovery.enabled).toBe(true);
    expect(await actions()).toContain("test.recent");
    expect(await clientPol()).toMatchObject({ autoLockMinutes: 3 });
    expect((await invitePol()).minLength).toBe(20);
    expect((await pub("/auth/domain-join", { email: "new@acme.test" })).statusCode).toBe(202);
    expect(await t.prisma.invite.count({ where: { email: "new@acme.test" } })).toBe(1);
  });
});
