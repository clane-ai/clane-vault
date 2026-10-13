import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { makeTestApp, resetDb, createActiveUser, orgHeader } from "./helpers.js";
import { csvCell } from "../src/routes/events.js";

const t = await makeTestApp();
afterAll(() => t.app.close());
beforeEach(() => resetDb(t.prisma));

type U = Awaited<ReturnType<typeof createActiveUser>>;
const call = (u: U, method: "GET" | "POST" | "DELETE", url: string, payload?: unknown, org = true) =>
  t.app.inject({ method, url: `/api/v1${url}`, payload: payload as object, headers: { authorization: `Bearer ${u.accessToken}`, ...(org ? orgHeader(u) : {}) } });
const newOrg = (name: string) => t.prisma.organization.create({ data: { name, slug: `${name.toLowerCase()}-${crypto.randomUUID().slice(0, 8)}` } });
const good = { score: 72, total: 40, weak: 3, reused: 4, old: 5, breached: null };

describe("password health reports", () => {
  it("members post counts per org; admins see them per member; nothing else is accepted", async () => {
    const admin = await createActiveUser(t, { role: "admin" }), m = await createActiveUser(t), quiet = await createActiveUser(t);
    expect((await call(m, "POST", "/me/health-report", good)).statusCode).toBe(204);
    expect((await call(m, "POST", "/me/health-report", { ...good, breached: 2, score: 60 })).statusCode).toBe(204);
    expect((await call(m, "POST", "/me/health-report", { ...good, weak: 41 })).statusCode).toBe(400);
    expect((await call(m, "POST", "/me/health-report", { ...good, score: 101 })).statusCode).toBe(400);
    // Only counts: extra fields (say, a password list) are dropped, never stored.
    expect((await call(m, "POST", "/me/health-report", { ...good, passwords: ["hunter2"] })).statusCode).toBe(204);
    expect(JSON.stringify(await t.prisma.healthReport.findMany())).not.toContain("hunter2");
    expect((await call(m, "POST", "/me/health-report", good, false)).statusCode).toBe(403);

    expect((await call(m, "GET", "/admin/health")).statusCode).toBe(403);
    const rows = (await call(admin, "GET", "/admin/health")).json().members as any[];
    expect(rows.find((r) => r.id === m.id).report).toMatchObject({ score: 72, total: 40, weak: 3, reused: 4, old: 5, breached: null, reportedAt: expect.any(String) });
    expect(rows.find((r) => r.id === quiet.id).report).toBeNull();
    expect(await t.prisma.healthReport.count()).toBe(1);
  });

  it("is per organisation", async () => {
    const B = await newOrg("Beta");
    const m = await createActiveUser(t), ownerB = await createActiveUser(t, { role: "owner", orgId: B.id });
    await call(m, "POST", "/me/health-report", good);
    const rows = (await call(ownerB, "GET", "/admin/health")).json().members as any[];
    expect(rows.map((r) => r.id)).toEqual([ownerB.id]);
    // Leaving the org drops the report.
    expect((await call(m, "POST", "/org/leave")).statusCode).toBe(204);
    expect(await t.prisma.healthReport.count()).toBe(0);
  });
});

describe("event log", () => {
  it("admins page and filter the org's events; members can't", async () => {
    const admin = await createActiveUser(t, { role: "admin" }), m = await createActiveUser(t);
    await call(admin, "POST", "/admin/groups", { name: "One" });
    await call(admin, "POST", "/admin/groups", { name: "Two" });
    await call(m, "POST", "/org/leave");
    expect((await call(m, "GET", "/admin/events")).statusCode).toBe(403);
    const all = (await call(admin, "GET", "/admin/events")).json();
    expect(all.events[0]).toMatchObject({ action: "org.leave", actor: { id: m.id, name: expect.any(String), email: m.email } });
    const groups = (await call(admin, "GET", "/admin/events?action=group.create")).json().events;
    expect(groups).toHaveLength(2);
    expect(groups.every((e: any) => e.actor.id === admin.id)).toBe(true);
    expect((await call(admin, "GET", "/admin/events?action=group.")).json().events).toHaveLength(2);
    expect((await call(admin, "GET", `/admin/events?actor=${m.id}`)).json().events.every((e: any) => e.actor.id === m.id)).toBe(true);
    expect((await call(admin, "GET", `/admin/events?actor=${m.id}&action=org.leave`)).json().events).toHaveLength(1);
    const page1 = (await call(admin, "GET", "/admin/events?limit=1")).json();
    expect(page1.events).toHaveLength(1);
    const page2 = (await call(admin, "GET", `/admin/events?limit=1&before=${page1.nextBefore}`)).json();
    expect(page2.events[0].id).not.toBe(page1.events[0].id);
    const future = new Date(Date.now() + 864e5).toISOString();
    expect((await call(admin, "GET", `/admin/events?from=${encodeURIComponent(future)}`)).json().events).toEqual([]);
    expect((await call(admin, "GET", "/admin/events?action=DROP%20TABLE")).statusCode).toBe(400);
    expect((await call(admin, "GET", "/admin/events/actions")).json().actions).toEqual(expect.arrayContaining(["group.create", "org.leave"]));
  });

  it("exports CSV for admins only, scoped to the org", async () => {
    const B = await newOrg("Beta");
    const admin = await createActiveUser(t, { role: "admin" }), m = await createActiveUser(t);
    const ownerB = await createActiveUser(t, { role: "owner", orgId: B.id });
    await call(admin, "POST", "/admin/groups", { name: "=HYPERLINK(\"x\")" });
    await call(ownerB, "POST", "/admin/groups", { name: "Secret B group" });
    expect((await call(m, "GET", "/admin/events/export.csv")).statusCode).toBe(403);
    expect((await call(m, "GET", "/admin/events/export.csv", undefined, false)).statusCode).toBe(403);
    const res = await call(admin, "GET", "/admin/events/export.csv?action=group.create");
    expect(res.statusCode).toBe(200);
    expect(res.headers["content-type"]).toContain("text/csv");
    expect(res.headers["content-disposition"]).toMatch(/^attachment; filename="events-\d{4}-\d{2}-\d{2}\.csv"$/);
    const lines = res.body.trim().split("\r\n");
    expect(lines[0]).toBe("id,at,action,actor_id,actor_name,actor_email,target_id,target_name,target_email,record_id,folder_id,ip,user_agent,meta");
    expect(lines).toHaveLength(2);
    expect(lines[1]).toContain(`"${admin.email}"`);
    expect(res.body).not.toContain("Secret B group");
    // The export itself is logged.
    expect(await t.prisma.event.count({ where: { action: "admin.events_export", actorId: admin.id, orgId: admin.orgId } })).toBe(1);
    const resB = await call(ownerB, "GET", "/admin/events/export.csv");
    expect(resB.body).toContain("Secret B group");
    expect(resB.body).not.toContain(admin.email);
  });

  it("neutralises spreadsheet formulas in cells", () => {
    expect(csvCell("=1+1")).toBe(`"'=1+1"`);
    expect(csvCell("+cmd")).toBe(`"'+cmd"`);
    expect(csvCell("@x")).toBe(`"'@x"`);
    expect(csvCell('say "hi"')).toBe(`"say ""hi"""`);
    expect(csvCell(null)).toBe(`""`);
    expect(csvCell({ a: 1 })).toBe(`"{""a"":1}"`);
  });
});
