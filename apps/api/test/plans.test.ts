import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { makeTestApp, resetDb, createActiveUser } from "./helpers.js";

const off = await makeTestApp({});
const on = await makeTestApp({ billingMode: "hosted" });
afterAll(async () => { await off.app.close(); await on.app.close(); });
beforeEach(() => resetDb(on.prisma));

type T = typeof on;
type U = Awaited<ReturnType<typeof createActiveUser>>;
let ipSeq = 0;
const call = (t: T, u: U, method: "GET" | "POST", url: string, payload?: unknown, org: string | null = u.orgId ?? null) =>
  t.app.inject({ method, url: `/api/v1${url}`, payload: payload as object, remoteAddress: `10.173.0.${++ipSeq % 250}`, headers: { authorization: `Bearer ${u.accessToken}`, ...(org ? { "x-org-id": org } : {}) } });

describe("GET /org/plan", () => {
  it("does not exist with billing off", async () => {
    const admin = await createActiveUser(off, { role: "admin" });
    expect((await call(off, admin, "GET", "/org/plan")).statusCode).toBe(404);
  });

  it("is for owners and admins only", async () => {
    const admin = await createActiveUser(on, { role: "admin" });
    const r = await call(on, admin, "GET", "/org/plan");
    expect(r.statusCode).toBe(200);
    expect(r.json()).toMatchObject({ plan: "team", billingStatus: "free", entitlements: { seatsAllowed: 10 } });
    const member = await createActiveUser(on, { role: "member", orgId: admin.orgId! });
    expect((await call(on, member, "GET", "/org/plan")).statusCode).toBe(403);
  });

  it("starts a 14-day trial on a new org when hosted, and none with billing off", async () => {
    const u = await createActiveUser(on, { role: "member" });
    const created = (await call(on, u, "POST", "/orgs", { name: "Trial Co" })).json();
    const org = await on.prisma.organization.findUniqueOrThrow({ where: { id: created.id } });
    expect(Math.abs(+org.trialEndsAt! - (Date.now() + 14 * 864e5))).toBeLessThan(60_000);
    expect((await call(on, u, "GET", "/org/plan", undefined, created.id)).json().entitlements).toMatchObject({ trial: true, plan: "team" });

    const v = await createActiveUser(off, { role: "member" });
    const c2 = (await call(off, v, "POST", "/orgs", { name: "No Trial" })).json();
    expect((await off.prisma.organization.findUniqueOrThrow({ where: { id: c2.id } })).trialEndsAt).toBeNull();
  });
});
