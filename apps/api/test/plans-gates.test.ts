import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { makeTestApp, resetDb, createActiveUser } from "./helpers.js";

const hosted = await makeTestApp({ billingMode: "hosted" });
afterAll(() => hosted.app.close());
beforeEach(() => resetDb(hosted.prisma));

type Row = { feature: string; method: "GET" | "PUT" | "POST"; url: string; payload?: unknown; raw?: Buffer; unlocked: number };
const rows: Row[] = [
  { feature: "sso", method: "PUT", url: "/admin/settings/sso", payload: {}, unlocked: 400 },
  { feature: "sso", method: "POST", url: "/admin/settings/sso/test", payload: {}, unlocked: 409 },
  { feature: "domains", method: "POST", url: "/admin/settings/sso/domains", payload: { domain: "acme.test" }, unlocked: 201 },
  { feature: "domains", method: "POST", url: "/admin/settings/sso/domains/nope.test/verify", unlocked: 404 },
  { feature: "domains", method: "PUT", url: "/admin/settings/domain-join", payload: { enabled: true }, unlocked: 409 },
  { feature: "adminRecovery", method: "PUT", url: "/admin/settings/admin-recovery", payload: { enabled: true }, unlocked: 401 },
  { feature: "risk", method: "GET", url: "/admin/risk", unlocked: 200 },
  { feature: "risk", method: "GET", url: "/admin/risk/members", unlocked: 200 },
  { feature: "risk", method: "GET", url: "/admin/risk/members.csv", unlocked: 200 },
  { feature: "risk", method: "GET", url: "/admin/risk/alerts.csv", unlocked: 200 },
  { feature: "orgLogo", method: "PUT", url: "/org/logo", raw: Buffer.from("not an image"), unlocked: 415 },
  { feature: "eventExport", method: "GET", url: "/admin/events/export.csv", unlocked: 200 },
];

describe("Business-only write routes", () => {
  it("402 plan_required on Team, the normal status on Business", async () => {
    const owner = await createActiveUser(hosted, { role: "owner" });
    const call = (r: Row) => hosted.app.inject({
      method: r.method, url: `/api/v1${r.url}`, remoteAddress: "10.180.0.1",
      headers: { authorization: `Bearer ${owner.accessToken}`, "x-org-id": owner.orgId!, ...(r.raw ? { "content-type": "image/png" } : {}) },
      payload: (r.raw ?? r.payload) as object,
    });
    for (const r of rows) {
      const res = await call(r);
      expect([r.url, res.statusCode, res.json()]).toEqual([r.url, 402, { error: "plan_required", feature: r.feature, requiredPlan: "business" }]);
    }
    await hosted.prisma.organization.update({ where: { id: owner.orgId! }, data: { plan: "business", seatsPaid: 50 } });
    for (const r of rows) expect([r.url, (await call(r)).statusCode]).toEqual([r.url, r.unlocked]);
  });

  it("turning admin recovery or domain auto-join off stays open on Team", async () => {
    const owner = await createActiveUser(hosted, { role: "owner" });
    const h = { authorization: `Bearer ${owner.accessToken}`, "x-org-id": owner.orgId! };
    for (const [url, payload] of [["/admin/settings/admin-recovery", { enabled: false }], ["/admin/settings/domain-join", { enabled: false }]] as const) {
      const res = await hosted.app.inject({ method: "PUT", url: `/api/v1${url}`, headers: h, payload, remoteAddress: "10.180.0.2" });
      expect([url, res.statusCode]).toEqual([url, 200]);
    }
  });

  it("billing off: the gate is inert on a team org", async () => {
    const off = await makeTestApp({ billingMode: "off" });
    try {
      const owner = await createActiveUser(off, { role: "owner" });
      const h = { authorization: `Bearer ${owner.accessToken}`, "x-org-id": owner.orgId! };
      const pol = (await off.app.inject({ method: "GET", url: "/api/v1/admin/settings/policies", headers: h })).json().policies;
      expect((await off.app.inject({ method: "PUT", url: "/api/v1/admin/settings/policies", headers: h, payload: pol })).statusCode).toBe(200);
    } finally { await off.app.close(); }
  });
});
