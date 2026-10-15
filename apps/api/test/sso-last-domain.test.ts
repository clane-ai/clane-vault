import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { makeTestApp, resetDb, createActiveUser } from "./helpers.js";

// Removing the last verified SSO domain switches off "Require SSO" and email domain auto-join, which are the owner's
// settings: while either is on, only the owner may remove it (docs/sso.md).
const t = await makeTestApp();
afterAll(() => t.app.close());
beforeEach(() => resetDb(t.prisma));
const saved = { ...t.config };
afterEach(() => { vi.restoreAllMocks(); Object.assign(t.config, saved); delete t.config.resendApiKey; delete t.config.emailFrom; delete t.config.hostedMode; delete t.config.maxOwnedOrgs; });

type U = Awaited<ReturnType<typeof createActiveUser>>;
type M = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
let ipSeq = 0;
const ip = () => `10.172.${(++ipSeq >> 8) & 255}.${ipSeq & 255}`;
const call = (u: U, method: M, url: string, payload?: unknown, org?: string | null) => {
  const o = org === undefined ? u.orgId : org;
  return t.app.inject({ method, url: `/api/v1${url}`, payload: payload as object, remoteAddress: ip(), headers: { authorization: `Bearer ${u.accessToken}`, ...(o ? { "x-org-id": o } : {}) } });
};

/** An account that owns its own organisation (not the default one). */
async function ownerOfNewOrg(name = "Customer"): Promise<U> {
  const org = await t.prisma.organization.create({ data: { name, slug: `${name.toLowerCase()}-${crypto.randomUUID().slice(0, 8)}` } });
  return createActiveUser(t, { role: "owner", orgId: org.id });
}

describe("removing the last verified SSO domain", () => {
  async function setup(o: { requireSso?: boolean; domainJoin?: boolean; domains?: string[] } = {}) {
    const owner = await ownerOfNewOrg("Acme");
    const admin = await createActiveUser(t, { role: "admin", orgId: owner.orgId! });
    for (const domain of o.domains ?? ["acme.test"]) await t.prisma.ssoDomain.create({ data: { orgId: owner.orgId!, domain, token: "tok", verifiedAt: new Date(), checkedAt: new Date() } });
    await t.prisma.orgSso.create({ data: { id: crypto.randomUUID(), orgId: owner.orgId!, issuer: "https://idp.acme.test", clientId: "c", requireSso: !!o.requireSso, autoJoin: true } });
    if (o.domainJoin) await t.prisma.orgDomainJoin.create({ data: { orgId: owner.orgId!, enabled: true } });
    return { owner, admin, orgId: owner.orgId! };
  }
  const settings = async (orgId: string) => ({
    sso: await t.prisma.orgSso.findUniqueOrThrow({ where: { orgId }, select: { requireSso: true, autoJoin: true } }),
    join: (await t.prisma.orgDomainJoin.findUnique({ where: { orgId } }))?.enabled ?? false,
    domains: (await t.prisma.ssoDomain.findMany({ where: { orgId } })).map((d) => d.domain).sort(),
  });

  it("is the owner's only while Require SSO or domain auto-join is on: an admin gets 403 and nothing changes", async () => {
    for (const o of [{ requireSso: true }, { domainJoin: true }, { requireSso: true, domainJoin: true }]) {
      await resetDb(t.prisma);
      const { owner, admin, orgId } = await setup(o);
      const r = await call(admin, "DELETE", "/admin/settings/sso/domains/acme.test");
      expect(r.statusCode).toBe(403);
      expect(r.json()).toEqual({ error: "owner_only_last_domain", settings: [...(o.requireSso ? ["requireSso"] : []), ...(o.domainJoin ? ["domainJoin"] : [])] });
      expect(await settings(orgId)).toEqual({ sso: { requireSso: !!o.requireSso, autoJoin: true }, join: !!o.domainJoin, domains: ["acme.test"] });
      // The owner may: the settings switch off with the domain.
      expect((await call(owner, "DELETE", "/admin/settings/sso/domains/acme.test")).statusCode).toBe(200);
      expect(await settings(orgId)).toEqual({ sso: { requireSso: false, autoJoin: false }, join: false, domains: [] });
    }
  });

  it("stays open to admins when it switches nothing owner-only off, or another verified domain remains", async () => {
    // Only just-in-time joining (admins may change it) depends on the domain: an admin removes it.
    let s = await setup();
    expect((await call(s.admin, "DELETE", "/admin/settings/sso/domains/acme.test")).statusCode).toBe(200);
    expect(await settings(s.orgId)).toEqual({ sso: { requireSso: false, autoJoin: false }, join: false, domains: [] });
    // Require SSO and domain auto-join on, but another verified domain stays: nothing switches off.
    await resetDb(t.prisma);
    s = await setup({ requireSso: true, domainJoin: true, domains: ["acme.test", "acme-group.test"] });
    expect((await call(s.admin, "DELETE", "/admin/settings/sso/domains/acme.test")).statusCode).toBe(200);
    expect(await settings(s.orgId)).toEqual({ sso: { requireSso: true, autoJoin: true }, join: true, domains: ["acme-group.test"] });
    // An unverified domain is never the last verified one.
    await t.prisma.ssoDomain.create({ data: { orgId: s.orgId, domain: "pending.test", token: "t2" } });
    expect((await call(s.admin, "DELETE", "/admin/settings/sso/domains/pending.test")).statusCode).toBe(200);
    expect((await call(s.admin, "DELETE", "/admin/settings/sso/domains/acme-group.test")).statusCode).toBe(403);
  });
});
