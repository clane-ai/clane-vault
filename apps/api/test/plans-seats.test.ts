import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";
import { createAccount } from "@clane-vault/crypto";
import { makeTestApp, resetDb, createActiveUser, FAST_KDF } from "./helpers.js";
import { MockOidc } from "./mockOidc.js";
import { seatsUsed, SeatLimitError } from "../src/lib/seats.js";
import { requestDomainJoin } from "../src/lib/domainJoin.js";
import { linkAndJoin } from "../src/lib/ssoLink.js";

// Seat limits (hosted plans): every way into an organisation checks the allowance under the org row lock.
const t = await makeTestApp({ billingMode: "hosted" });
t.config.ssoAllowHttpIssuer = true;
const idp = await new MockOidc().start();
const CLIENT = idp.addClient({ id: "clane-vault", secret: "idp-client-secret-1234", redirectUris: [`${t.config.publicUrl}/api/v1/auth/sso/callback`] });
afterAll(async () => { await t.app.close(); await idp.stop(); });
beforeEach(async () => { await resetDb(t.prisma); idp.users.clear(); });

type U = Awaited<ReturnType<typeof createActiveUser>>;
type M = "GET" | "POST" | "PUT" | "DELETE";
let ipSeq = 0;
const ip = () => `10.190.${(++ipSeq >> 8) & 255}.${ipSeq & 255}`;
const call = (u: { accessToken: string; orgId?: string | null }, method: M, url: string, payload?: unknown) =>
  t.app.inject({ method, url: `/api/v1${url}`, payload: payload as object, remoteAddress: ip(), headers: { authorization: `Bearer ${u.accessToken}`, ...(u.orgId ? { "x-org-id": u.orgId } : {}) } });
const invite = (u: U, email: string) => call(u, "POST", "/admin/invites", { email });
const fill = async (owner: U, n: number) => { for (let i = 0; i < n; i++) expect((await invite(owner, `fill${i}@x.test`)).statusCode).toBe(201); };

describe("seat limits", () => {
  it("Team allows 10: the 11th seat is 402, deleting a pending invite frees one, an expired one is free", async () => {
    const owner = await createActiveUser(t, { role: "owner" });
    await fill(owner, 9);
    const full = await invite(owner, "late@x.test");
    expect([full.statusCode, full.json()]).toEqual([402, { error: "seat_limit", used: 10, allowed: 10 }]);
    expect(await t.prisma.invite.count({ where: { email: "late@x.test" } })).toBe(0);
    const inv = await t.prisma.invite.findFirstOrThrow({ where: { email: "fill0@x.test" } });
    expect((await call(owner, "DELETE", `/admin/invites/${inv.id}`)).statusCode).toBeLessThan(300);
    expect((await invite(owner, "late@x.test")).statusCode).toBe(201);
    expect((await invite(owner, "later@x.test")).statusCode).toBe(402);
    await t.prisma.invite.updateMany({ where: { email: "fill1@x.test" }, data: { expiresAt: new Date(Date.now() - 1000) } });
    expect((await invite(owner, "later@x.test")).statusCode).toBe(201);
  });

  it("seatsPaid replaces the free allowance", async () => {
    const owner = await createActiveUser(t, { role: "owner" });
    await fill(owner, 9);
    expect((await invite(owner, "x11@x.test")).statusCode).toBe(402);
    await t.prisma.organization.update({ where: { id: owner.orgId! }, data: { seatsPaid: 11 } });
    expect((await invite(owner, "x11@x.test")).statusCode).toBe(201);
    expect((await invite(owner, "x12@x.test")).json()).toEqual({ error: "seat_limit", used: 11, allowed: 11 });
  });

  it("an existing account counts one seat when invited, and accepting keeps it", async () => {
    const owner = await createActiveUser(t, { role: "owner" });
    const other = await t.prisma.organization.create({ data: { name: "Other", slug: "other-org" } });
    const guest = await createActiveUser(t, { orgId: other.id, role: "owner" });
    expect(await seatsUsed(t.prisma, owner.orgId!)).toBe(1);
    expect((await invite(owner, guest.email)).statusCode).toBe(201);
    expect(await seatsUsed(t.prisma, owner.orgId!)).toBe(2);
    expect((await call(guest, "POST", `/me/invitations/${owner.orgId}/accept`)).statusCode).toBe(200);
    expect(await seatsUsed(t.prisma, owner.orgId!)).toBe(2);
  });

  it("re-enabling a disabled member needs a free seat", async () => {
    const owner = await createActiveUser(t, { role: "owner" });
    const members: U[] = [];
    for (let i = 0; i < 9; i++) members.push(await createActiveUser(t));
    expect((await invite(owner, "new@x.test")).statusCode).toBe(402);
    expect((await call(owner, "POST", `/admin/users/${members[0]!.id}/disable`)).statusCode).toBe(200);
    expect((await invite(owner, "new@x.test")).statusCode).toBe(201);
    const r = await call(owner, "POST", `/admin/users/${members[0]!.id}/enable`);
    expect([r.statusCode, r.json()]).toEqual([402, { error: "seat_limit", used: 10, allowed: 10 }]);
  });

  it("six invites racing for the last seat: exactly one wins", async () => {
    const owner = await createActiveUser(t, { role: "owner" });
    await fill(owner, 8);
    const res = await Promise.all([1, 2, 3, 4, 5, 6].map((i) => invite(owner, `r${i}@x.test`)));
    expect(res.map((r) => r.statusCode).sort()).toEqual([201, 402, 402, 402, 402, 402]);
    expect(await seatsUsed(t.prisma, owner.orgId!)).toBe(10);
  });

  it("a bulk invite crossing the limit refuses the rows that do not fit", async () => {
    const owner = await createActiveUser(t, { role: "owner" });
    await fill(owner, 7); // 8 used
    const r = await call(owner, "POST", "/admin/invites/bulk", { rows: ["a", "b", "c", "d", "e"].map((x) => ({ email: `${x}@bulk.test` })) });
    expect(r.statusCode).toBe(200);
    expect(r.json().results.map((x: { status: string }) => x.status)).toEqual(["invited", "invited", "seat_limit", "seat_limit", "seat_limit"]);
    expect(await seatsUsed(t.prisma, owner.orgId!)).toBe(10);
    expect(await t.prisma.invite.count({ where: { email: { endsWith: "@bulk.test" } } })).toBe(2);
  });

  it("Resend all keeps going when an expired invite no longer fits", async () => {
    const owner = await createActiveUser(t, { role: "owner" });
    await fill(owner, 9); // 10 used
    await t.prisma.invite.updateMany({ where: { email: "fill0@x.test" }, data: { expiresAt: new Date(Date.now() - 1000), lastSentAt: new Date(Date.now() - 864e5) } });
    await t.prisma.invite.updateMany({ where: { email: { not: "fill0@x.test" } }, data: { lastSentAt: new Date(Date.now() - 864e5) } });
    expect((await invite(owner, "late@x.test")).statusCode).toBe(201); // takes the expired one's seat
    const r = await call(owner, "POST", "/admin/invites/resend-all", { includeExpired: true });
    expect(r.statusCode).toBe(200);
    const st = (r.json().results as { email: string; status: string }[]);
    expect(st.find((x) => x.email === "fill0@x.test")!.status).toBe("seat_limit");
    expect(st.filter((x) => x.status === "resent").length).toBe(8);
  });

  it("GET /org/plan reports seats", async () => {
    const owner = await createActiveUser(t, { role: "owner" });
    await fill(owner, 2);
    expect((await call(owner, "GET", "/org/plan")).json().seats).toEqual({ used: 3, allowed: 10 });
  });

  it("billing off: no limit", async () => {
    const off = await makeTestApp({ billingMode: "off" });
    try {
      const owner = await createActiveUser(off, { role: "owner" });
      for (let i = 0; i < 15; i++) {
        const r = await off.app.inject({ method: "POST", url: "/api/v1/admin/invites", payload: { email: `o${i}@x.test` }, remoteAddress: ip(), headers: { authorization: `Bearer ${owner.accessToken}`, "x-org-id": owner.orgId! } });
        expect(r.statusCode).toBe(201);
      }
    } finally { await off.app.close(); }
  });
});

describe("seat limits on self-service joins", () => {
  it("a domain-join request at a full org is refused", async () => {
    const owner = await createActiveUser(t, { role: "owner" });
    await t.prisma.organization.update({ where: { id: owner.orgId! }, data: { plan: "business", seatsPaid: 1 } });
    await t.prisma.ssoDomain.create({ data: { orgId: owner.orgId!, domain: "acme.test", token: "tok", verifiedAt: new Date(), checkedAt: new Date() } });
    await t.prisma.orgDomainJoin.create({ data: { orgId: owner.orgId!, enabled: true } });
    t.config.resendApiKey = "re_test"; t.config.emailFrom = "vault@clane.ai";
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("{}", { status: 200 }));
    try {
      expect(await requestDomainJoin(t.app, "new@acme.test", t.app.log)).toBe("seat_limit");
      expect(await t.prisma.invite.count({ where: { email: "new@acme.test" } })).toBe(0);
      expect(await t.prisma.event.findFirst({ where: { orgId: owner.orgId!, action: "org.domain_join_refused" }, select: { meta: true } }))
        .toEqual({ meta: { domain: "acme.test", reason: "seat_limit" } });
      await t.prisma.organization.update({ where: { id: owner.orgId! }, data: { seatsPaid: 2 } });
      expect(await requestDomainJoin(t.app, "new@acme.test", t.app.log)).toBe("sent");
    } finally { vi.restoreAllMocks(); delete t.config.resendApiKey; delete t.config.emailFrom; }
  });

  it("SSO just-in-time register at a full org: sent back to sign-in with a reason, or 402 if the seat goes in between", async () => {
    const owner = await createActiveUser(t, { role: "owner", email: "boss@acme.test" });
    await t.prisma.organization.update({ where: { id: owner.orgId! }, data: { plan: "business", seatsPaid: 5 } });
    const h = (m: M, u: string, p?: unknown) => call(owner, m, u, p);
    expect((await h("PUT", "/admin/settings/sso", { issuer: idp.issuer, clientId: CLIENT.id, clientSecret: CLIENT.secret })).statusCode).toBe(200);
    const added = await h("POST", "/admin/settings/sso/domains", { domain: "acme.test" });
    const rec = added.json().domains.find((d: { domain: string }) => d.domain === "acme.test").txtRecord;
    t.app.ssoDeps.resolveTxt = async () => [["v=spf1 -all"], [rec.value]];
    expect((await h("POST", "/admin/settings/sso/domains/acme.test/verify")).statusCode).toBe(200);
    expect((await h("PUT", "/admin/settings/sso", { issuer: idp.issuer, clientId: CLIENT.id, autoJoin: true })).statusCode).toBe(200);
    await t.prisma.organization.update({ where: { id: owner.orgId! }, data: { seatsPaid: 1 } });
    idp.addUser({ sub: "n1", email: "new@acme.test", email_verified: true, name: "New" });
    const pub = (u: string, p: unknown, cookie?: string) => t.app.inject({ method: "POST", url: `/api/v1${u}`, payload: p as object, remoteAddress: ip(), ...(cookie ? { cookies: { cv_sso: cookie } } : {}) });
    const signIn = async () => {
      const start = await pub("/auth/sso/start", { org: "default", email: "new@acme.test" });
      const cookie = start.cookies.find((x) => x.name === "cv_sso")!.value;
      const back = new URL((await fetch(new URL(start.json().url), { redirect: "manual" })).headers.get("location")!);
      const cb = await t.app.inject({ method: "GET", url: `${back.pathname}${back.search}`, remoteAddress: ip(), cookies: { cv_sso: cookie } });
      return { cookie, location: String(cb.headers.location) };
    };
    // Full at the identity provider's callback: a redirect with a reason, logged for the org's admins.
    expect((await signIn()).location).toBe(`${t.config.publicUrl}/sign-in?sso_error=sso_org_full`);
    expect(await t.prisma.event.count({ where: { orgId: owner.orgId!, action: "sso.callback_failed", meta: { path: ["reason"], equals: "sso_org_full" } } })).toBe(1);
    // A seat free at the callback but gone by the time the account is made: 402, and nothing is created.
    await t.prisma.organization.update({ where: { id: owner.orgId! }, data: { seatsPaid: 2 } });
    const { cookie, location } = await signIn();
    const proof = new URLSearchParams(location.split("#")[1] ?? "").get("proof");
    expect(proof).toBeTruthy();
    await t.prisma.organization.update({ where: { id: owner.orgId! }, data: { seatsPaid: 1 } });
    const acct = await createAccount("a new master password", FAST_KDF);
    const reg = await pub("/auth/sso/register", { proof, name: "New", authKey: acct.authKey, material: acct.material }, cookie);
    expect([reg.statusCode, reg.json()]).toEqual([402, { error: "seat_limit", used: 1, allowed: 1 }]);
    expect(await t.prisma.user.count({ where: { email: "new@acme.test" } })).toBe(0);
  });
});

describe("seat limits: late paths", () => {
  async function fullOrgWithGuest() {
    const owner = await createActiveUser(t, { role: "owner" });
    const other = await t.prisma.organization.create({ data: { name: "Other", slug: "other-org" } });
    const guest = await createActiveUser(t, { orgId: other.id, role: "owner" });
    expect((await invite(owner, guest.email)).statusCode).toBe(201);
    await fill(owner, 8); // owner + guest + 8 = 10
    expect((await invite(owner, "late@x.test")).statusCode).toBe(402);
    return { owner, guest };
  }

  it("a fresh invitation is accepted at a full org (its seat was counted)", async () => {
    const { owner, guest } = await fullOrgWithGuest();
    expect((await call(guest, "POST", `/me/invitations/${owner.orgId}/accept`)).statusCode).toBe(200);
    expect(await seatsUsed(t.prisma, owner.orgId!)).toBe(10);
  });

  it("a stale invitation is not accepted at a full org", async () => {
    const { owner, guest } = await fullOrgWithGuest();
    await t.prisma.invite.deleteMany({ where: { email: guest.email } });
    await t.prisma.membership.updateMany({ where: { orgId: owner.orgId!, userId: guest.id }, data: { createdAt: new Date(Date.now() - 8 * 864e5) } });
    // Past the 7 days the accept route already answers 404; its seat check would be 402 if it ever got that far.
    expect((await call(guest, "POST", `/me/invitations/${owner.orgId}/accept`)).statusCode).toBe(404);
    expect(await t.prisma.membership.findFirstOrThrow({ where: { orgId: owner.orgId!, userId: guest.id } })).toMatchObject({ status: "invited" });
  });

  it("SSO just-in-time join at a full org leaves no identity link or membership", async () => {
    const owner = await createActiveUser(t, { role: "owner" });
    const other = await t.prisma.organization.create({ data: { name: "Other", slug: "other-org" } });
    const user = await createActiveUser(t, { orgId: other.id, role: "owner", email: "jit@acme.test" });
    await t.prisma.organization.update({ where: { id: owner.orgId! }, data: { plan: "business", seatsPaid: 1 } });
    const p = { orgId: owner.orgId!, issuer: idp.issuer, subject: "s1", email: user.email, jit: true };
    await expect(linkAndJoin(t.app, p, { id: user.id }, t.app.log)).rejects.toBeInstanceOf(SeatLimitError);
    expect(await t.prisma.ssoIdentity.count({ where: { orgId: owner.orgId!, userId: user.id } })).toBe(0);
    expect(await t.prisma.membership.count({ where: { orgId: owner.orgId!, userId: user.id } })).toBe(0);
    await t.prisma.organization.update({ where: { id: owner.orgId! }, data: { seatsPaid: 2 } });
    await linkAndJoin(t.app, p, { id: user.id }, t.app.log);
    expect(await t.prisma.ssoIdentity.count({ where: { orgId: owner.orgId!, userId: user.id } })).toBe(1);
    expect(await t.prisma.membership.count({ where: { orgId: owner.orgId!, userId: user.id, status: "active" } })).toBe(1);
  });
});
