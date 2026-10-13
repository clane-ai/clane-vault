import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";
import { randomUUID } from "node:crypto";
import { makeTestApp, resetDb, createActiveUser, orgHeader, createInvite } from "./helpers.js";
import { computeBenchmarks, computeScore, trendPercent, type BenchmarkInput } from "../src/lib/risk.js";
import { DEFAULT_POLICIES, readPolicies } from "../src/lib/policies.js";

const t = await makeTestApp();
afterAll(() => t.app.close());
beforeEach(() => resetDb(t.prisma));

type U = Awaited<ReturnType<typeof createActiveUser>>;
const call = (u: U, method: "GET" | "POST" | "DELETE" | "PUT", url: string, payload?: unknown, headers?: Record<string, string>) =>
  t.app.inject({ method, url: `/api/v1${url}`, payload: payload as object, headers: { authorization: `Bearer ${u.accessToken}`, ...(headers ?? orgHeader(u)) } });
const newOrg = (name: string) => t.prisma.organization.create({ data: { name, slug: `${name.toLowerCase()}-${randomUUID().slice(0, 8)}` } });
const bench = (body: any, key: string) => (body.benchmarks as any[]).find((b) => b.key === key);
const alert = (body: any, action: string) => (body.alerts as any[]).find((a) => a.action === action);

/** A team folder in `orgId` owned by `owner`, with `n` records, opened by `members` too. */
async function teamFolder(orgId: string, owner: string, n: number, members: string[] = []) {
  const id = randomUUID();
  await t.prisma.folder.create({ data: { id, kind: "team", orgId, ownerId: owner, encName: "enc" } });
  for (const u of [owner, ...members]) await t.prisma.folderMember.create({ data: { folderId: id, userId: u, permission: u === owner ? "owner" : "view", directPermission: u === owner ? "owner" : "view", wrappedFolderKey: "k" } });
  for (let i = 0; i < n; i++) await t.prisma.record.create({ data: { id: randomUUID(), folderId: id, ownerId: owner, type: "login", encBody: "enc" } });
  return id;
}
const event = (data: { orgId?: string | null; actorId?: string; targetUserId?: string; action: string; daysAgo: number }) =>
  t.prisma.event.create({ data: { orgId: data.orgId ?? null, actorId: data.actorId, targetUserId: data.targetUserId, action: data.action, at: new Date(Date.now() - data.daysAgo * 864e5) } });

describe("risk dashboard: access", () => {
  it("is for the org's owners and admins only", async () => {
    const owner = await createActiveUser(t, { role: "owner" }), admin = await createActiveUser(t, { role: "admin" }), m = await createActiveUser(t);
    expect((await call(owner, "GET", "/admin/risk")).statusCode).toBe(200);
    expect((await call(admin, "GET", "/admin/risk")).statusCode).toBe(200);
    for (const url of ["/admin/risk", "/admin/risk/members", "/admin/risk/members.csv", "/admin/risk/alerts.csv", "/admin/risk/alerts/admin.reset_2fa/members"])
      expect((await call(m, "GET", url)).statusCode).toBe(403);
    expect((await call(m, "POST", "/admin/risk/benchmarks/ip_allowlist/ignore")).statusCode).toBe(403);
    // No org header: no org dashboard.
    expect((await call(owner, "GET", "/admin/risk", undefined, {})).statusCode).toBe(403);
    expect((await t.app.inject({ method: "GET", url: "/api/v1/admin/risk" })).statusCode).toBe(401);
  });

  it("keeps organisations apart", async () => {
    const B = await newOrg("Beta");
    const ownerA = await createActiveUser(t, { role: "owner" }), memberA = await createActiveUser(t);
    const ownerB = await createActiveUser(t, { role: "owner", orgId: B.id }), memberB = await createActiveUser(t, { orgId: B.id });
    await teamFolder(B.id, ownerB.id, 4, [memberB.id]);
    await event({ orgId: B.id, actorId: ownerB.id, targetUserId: memberB.id, action: "admin.reset_2fa", daysAgo: 1 });
    await event({ actorId: memberB.id, action: "auth.login_failed", daysAgo: 1 });
    await t.prisma.membership.updateMany({ where: { userId: memberB.id }, data: { createdAt: new Date(Date.now() - 10 * 864e5) } });
    await t.prisma.healthReport.create({ data: { orgId: B.id, userId: memberB.id, score: 10, total: 5, weak: 5, reused: 0, old: 0, breached: 3 } });
    // Org A's admin asking with org B's id: refused.
    expect((await call(ownerA, "GET", "/admin/risk", undefined, { "x-org-id": B.id })).statusCode).toBe(403);
    const a = (await call(ownerA, "GET", "/admin/risk")).json();
    expect(a.utilisation).toMatchObject({ members: 2, withRecords: 0 });
    expect(alert(a, "admin.reset_2fa").current).toBe(0);
    expect(alert(a, "auth.login_failed").current).toBe(0);
    expect(a.health.reported).toBe(0);
    const people = (await call(ownerA, "GET", "/admin/risk/members")).json();
    expect(people.members.map((x: any) => x.id).sort()).toEqual([ownerA.id, memberA.id].sort());
    const csv = (await call(ownerA, "GET", "/admin/risk/members.csv")).body;
    expect(csv).not.toContain(memberB.email);
    expect((await call(ownerA, "GET", "/admin/risk/alerts/admin.reset_2fa/members")).json().people).toEqual([]);
    // Org B sees its own.
    const b = (await call(ownerB, "GET", "/admin/risk")).json();
    expect(b.utilisation).toMatchObject({ members: 2, withRecords: 2 });
    expect(alert(b, "admin.reset_2fa").current).toBe(1);
    expect(alert(b, "auth.login_failed").current).toBe(1);
  });

  it("answers with metadata and counts only", async () => {
    const owner = await createActiveUser(t, { role: "owner" });
    await teamFolder(owner.orgId, owner.id, 2);
    const body = JSON.stringify((await call(owner, "GET", "/admin/risk")).json()) + JSON.stringify((await call(owner, "GET", "/admin/risk/members")).json());
    for (const secret of ["wrappedFolderKey", "encBody", "encName", "authHash", "totpSecret", "recoveryWrap", "publicKey", "tokenHash"]) expect(body).not.toContain(secret);
  });
});

describe("risk dashboard: utilisation", () => {
  it("counts records, recent sign-ins, invitations, recovery kits, IdP MFA sessions and health reports", async () => {
    const owner = await createActiveUser(t, { role: "owner" }), m1 = await createActiveUser(t), m2 = await createActiveUser(t);
    await teamFolder(owner.orgId, owner.id, 3, [m1.id]);
    await createInvite(t.prisma, "pending@clane.ai", "member", owner.orgId);
    // m2 hasn't been seen for 40 days; m1 holds a kit; owner's current session skipped TOTP via the org's IdP.
    await t.prisma.session.updateMany({ where: { userId: m2.id }, data: { lastSeen: new Date(Date.now() - 40 * 864e5) } });
    await t.prisma.user.update({ where: { id: m1.id }, data: { recoveryWrap: "w", recoveryAuthHash: "h", recoveryCreatedAt: new Date() } });
    await t.prisma.session.updateMany({ where: { userId: owner.id }, data: { totpSkippedForOrg: owner.orgId } });
    await t.prisma.healthReport.create({ data: { orgId: owner.orgId, userId: m1.id, score: 90, total: 10, weak: 1, reused: 0, old: 0, breached: null } });
    await t.prisma.healthReport.create({ data: { orgId: owner.orgId, userId: m2.id, score: 40, total: 10, weak: 4, reused: 2, old: 1, breached: 1, reportedAt: new Date(Date.now() - 45 * 864e5) } });
    const r = (await call(owner, "GET", "/admin/risk")).json();
    expect(r.utilisation).toEqual({ members: 3, withRecords: 2, active30d: 2, invitations: { accepted: 3, pending: 1 },
      twoFactor: { required: true, members: 3, idpMfaSessions: 1 }, recoveryKit: 1, healthReported30d: 1,
      storage: { used: 0, quota: 2048 * 1024 * 1024, files: 0, alertRatio: 0.9, enabled: true } });
    expect(r.health).toMatchObject({ reported: 2, reported30d: 1, averageScore: 65, atRisk: 1, passwords: 20, weak: 5, reused: 2, old: 1, breached: 1, breachCheckMembers: 1 });
    const d = (await call(owner, "GET", "/admin/risk/members")).json();
    expect(d.members.find((x: any) => x.id === owner.id)).toMatchObject({ records: { owned: 3, canOpen: 3 }, idpMfa: true, active30d: true });
    expect(d.members.find((x: any) => x.id === m1.id)).toMatchObject({ records: { owned: 0, canOpen: 3 }, recoveryKit: true, health: { score: 90, recent: true } });
    expect(d.members.find((x: any) => x.id === m2.id)).toMatchObject({ records: { owned: 0, canOpen: 0 }, active30d: false, health: { recent: false } });
    expect(d.invites).toEqual([expect.objectContaining({ email: "pending@clane.ai", role: "member" })]);
    // Drill-down CSV, filtered to members without records; and the pending invitations.
    const csv = await call(owner, "GET", "/admin/risk/members.csv?tile=records&has=no");
    expect(csv.headers["content-type"]).toContain("text/csv");
    expect(csv.body.trim().split("\r\n")).toHaveLength(2);
    expect(csv.body).toContain(m2.email);
    expect((await call(owner, "GET", "/admin/risk/members.csv?tile=invites")).body).toContain("pending@clane.ai");
    expect((await call(owner, "GET", "/admin/risk/members.csv?tile=nope")).statusCode).toBe(400);
    expect(await t.prisma.event.count({ where: { action: "admin.risk_export" } })).toBe(2);
  });

  it("escapes CSV cells (quotes and spreadsheet formulas)", async () => {
    const owner = await createActiveUser(t, { role: "owner" }), m = await createActiveUser(t);
    await t.prisma.user.update({ where: { id: m.id }, data: { name: '=HYPERLINK("http://x","y")' } });
    const csv = (await call(owner, "GET", "/admin/risk/members.csv")).body;
    expect(csv).toContain(`"'=HYPERLINK(""http://x"",""y"")"`);
    expect(csv).not.toMatch(/(^|,)=HYPERLINK/m);
  });
});

describe("risk dashboard: benchmarks", () => {
  it("computes each benchmark from the org's configuration", async () => {
    const owner = await createActiveUser(t, { role: "owner" });
    let r = (await call(owner, "GET", "/admin/risk")).json();
    expect(bench(r, "backup_admin").status).toBe("critical");
    expect(bench(r, "admin_recovery").status).toBe("critical");
    expect(bench(r, "auto_lock").status).toBe("critical");
    expect(bench(r, "master_password").status).toBe("critical");
    expect(bench(r, "share_links").status).toBe("critical");
    expect(bench(r, "ip_allowlist").status).toBe("critical");
    expect(bench(r, "org_email").status).toBe("critical");
    // One member on clane.ai: no shared company domain yet.
    expect(bench(r, "sso").status).toBe("not_applicable");
    expect(bench(r, "backups")).toMatchObject({ status: "unknown", detail: expect.stringContaining("ask your server admin") });
    expect(bench(r, "password_health").status).toBe("not_applicable");
    expect(bench(r, "inactive_admins").status).toBe("completed");

    await createActiveUser(t, { role: "admin" });
    const pol = { ...DEFAULT_POLICIES, autoLockMinutes: 10, minPasswordScore: 3, links: { allowed: true, maxExpiryHours: 24, requirePassword: false } };
    expect((await call(owner, "PUT", "/admin/settings/policies", pol)).statusCode).toBe(200);
    await t.prisma.organization.update({ where: { id: owner.orgId }, data: { adminRecoveryEnabled: true } });
    r = (await call(owner, "GET", "/admin/risk")).json();
    for (const k of ["backup_admin", "admin_recovery", "auto_lock", "master_password", "share_links"]) expect(bench(r, k).status).toBe("completed");
    // Two members now share clane.ai, a company domain: single sign-on applies.
    expect(bench(r, "sso").status).toBe("critical");
    expect(r.score.value).toBeGreaterThan(0);

    // Instance admins see the backups benchmark (backups are off in tests).
    await t.prisma.user.update({ where: { id: owner.id }, data: { instanceAdmin: true } });
    r = (await call(owner, "GET", "/admin/risk")).json();
    expect(bench(r, "backups")).toMatchObject({ status: "critical", detail: expect.stringContaining("switched off") });

    // An admin not seen for 100 days.
    const old = await createActiveUser(t, { role: "admin" });
    await t.prisma.session.updateMany({ where: { userId: old.id }, data: { lastSeen: new Date(Date.now() - 100 * 864e5) } });
    await t.prisma.membership.updateMany({ where: { userId: old.id }, data: { joinedAt: new Date(Date.now() - 200 * 864e5) } });
    // A member with a breached password.
    await t.prisma.healthReport.create({ data: { orgId: owner.orgId, userId: old.id, score: 95, total: 4, weak: 0, reused: 0, old: 0, breached: 1 } });
    r = (await call(owner, "GET", "/admin/risk")).json();
    expect(bench(r, "inactive_admins").status).toBe("critical");
    expect(bench(r, "password_health").status).toBe("critical");
  });

  it("ignores a benchmark (logged, kept across policy saves, reversible)", async () => {
    const owner = await createActiveUser(t, { role: "owner" }), m = await createActiveUser(t);
    const res = await call(owner, "POST", "/admin/risk/benchmarks/ip_allowlist/ignore");
    expect(res.statusCode).toBe(200);
    expect(bench(res.json(), "ip_allowlist")).toMatchObject({ status: "ignored", passing: false });
    expect(await t.prisma.event.count({ where: { action: "risk.benchmark_ignored", orgId: owner.orgId, actorId: owner.id } })).toBe(1);
    // Twice is once.
    await call(owner, "POST", "/admin/risk/benchmarks/ip_allowlist/ignore");
    expect(await t.prisma.event.count({ where: { action: "risk.benchmark_ignored" } })).toBe(1);
    // Saving the policies keeps it, and the policies themselves still read fine (members' clients too).
    expect((await call(owner, "PUT", "/admin/settings/policies", { ...DEFAULT_POLICIES, autoLockMinutes: 5 })).statusCode).toBe(200);
    const stored = (await t.prisma.organization.findUniqueOrThrow({ where: { id: owner.orgId } })).policies;
    expect(stored).toMatchObject({ riskIgnored: ["ip_allowlist"], autoLockMinutes: 5 });
    expect(readPolicies(stored)).toMatchObject({ autoLockMinutes: 5, ipAllowlist: [] });
    expect((await call(owner, "GET", "/admin/settings/policies")).json().policies).not.toHaveProperty("riskIgnored");
    expect((await call(m, "GET", "/me/orgs", undefined, {})).statusCode).toBe(200);
    expect(bench((await call(owner, "GET", "/admin/risk")).json(), "ip_allowlist").status).toBe("ignored");
    // Ignored benchmarks don't count in the score.
    const before = (await call(owner, "GET", "/admin/risk")).json().score;
    const back = await call(owner, "DELETE", "/admin/risk/benchmarks/ip_allowlist/ignore");
    expect(bench(back.json(), "ip_allowlist").status).toBe("critical");
    expect(back.json().score.counted.possible).toBe(before.counted.possible + 1);
    expect(await t.prisma.event.count({ where: { action: "risk.benchmark_restored" } })).toBe(1);
    expect((await call(owner, "POST", "/admin/risk/benchmarks/nope/ignore")).statusCode).toBe(404);
  });

  it("ignores per organisation", async () => {
    const B = await newOrg("Beta");
    const ownerA = await createActiveUser(t, { role: "owner" }), ownerB = await createActiveUser(t, { role: "owner", orgId: B.id });
    await call(ownerA, "POST", "/admin/risk/benchmarks/sso/ignore");
    expect(bench((await call(ownerB, "GET", "/admin/risk")).json(), "sso").status).not.toBe("ignored");
    expect(await t.prisma.event.count({ where: { action: "risk.benchmark_ignored", orgId: B.id } })).toBe(0);
  });
});

describe("risk dashboard: alerts", () => {
  it("counts risky events in the last 30 days against the 30 before, with a trend", async () => {
    const owner = await createActiveUser(t, { role: "owner" }), m = await createActiveUser(t);
    const outsider = await createActiveUser(t, { orgId: (await newOrg("Gamma")).id });
    for (const d of [1, 2, 3]) await event({ orgId: owner.orgId, actorId: owner.id, targetUserId: m.id, action: "admin.reset_2fa", daysAgo: d });
    await event({ orgId: owner.orgId, actorId: owner.id, targetUserId: m.id, action: "admin.reset_2fa", daysAgo: 40 });
    await event({ orgId: owner.orgId, actorId: owner.id, action: "admin.reset_2fa", daysAgo: 70 }); // outside both windows
    await event({ orgId: owner.orgId, actorId: owner.id, action: "link.create", daysAgo: 45 });
    // Account-level: the member's failed sign-ins count (no org on the event), an outsider's don't.
    await event({ actorId: m.id, action: "auth.login_failed", daysAgo: 1 });
    await event({ actorId: m.id, action: "auth.login_failed", daysAgo: 2 });
    await event({ actorId: outsider.id, action: "auth.login_failed", daysAgo: 1 });
    const r = (await call(owner, "GET", "/admin/risk")).json();
    expect(alert(r, "admin.reset_2fa")).toMatchObject({ current: 3, previous: 1, trend: 200, scope: "org" });
    expect(alert(r, "link.create")).toMatchObject({ current: 0, previous: 1, trend: -100 });
    // The member registered moments ago, so their failed sign-ins count only from then: these were "before" they joined.
    expect(alert(r, "auth.login_failed")).toMatchObject({ current: 0, scope: "account" });
    await t.prisma.membership.updateMany({ where: { userId: m.id }, data: { createdAt: new Date(Date.now() - 100 * 864e5) } });
    const r2 = (await call(owner, "GET", "/admin/risk")).json();
    expect(alert(r2, "auth.login_failed")).toMatchObject({ current: 2, previous: 0, trend: null });

    const people = (await call(owner, "GET", "/admin/risk/alerts/admin.reset_2fa/members")).json().people;
    expect(people.find((p: any) => p.user.id === owner.id)).toMatchObject({ asActor: 3, asTarget: 0 });
    expect(people.find((p: any) => p.user.id === m.id)).toMatchObject({ asActor: 0, asTarget: 3, user: { email: m.email } });
    const acc = (await call(owner, "GET", "/admin/risk/alerts/auth.login_failed/members")).json().people;
    expect(acc).toEqual([expect.objectContaining({ user: expect.objectContaining({ id: m.id }), asActor: 2 })]);
    expect((await call(owner, "GET", "/admin/risk/alerts/record.create/members")).statusCode).toBe(404);

    const csv = (await call(owner, "GET", "/admin/risk/alerts.csv")).body;
    expect(csv.split("\r\n")[0]).toBe("action,alert,scope,last_30_days,previous_30_days,trend_percent");
    expect(csv).toContain(`"admin.reset_2fa","2FA resets","org","3","1","200"`);
  });

  it("trend and score arithmetic", () => {
    expect(trendPercent(0, 0)).toBe(0);
    expect(trendPercent(3, 0)).toBeNull();
    expect(trendPercent(1, 4)).toBe(-75);
    const input: BenchmarkInput = { admins: 2, adminRecoveryEnabled: true, policies: { ...DEFAULT_POLICIES, autoLockMinutes: 15, minPasswordScore: 4, ipAllowlist: ["10.0.0.0/8"], links: { ...DEFAULT_POLICIES.links, allowed: false } },
      sso: { hasDomain: false, configured: false, verifiedDomains: 0 }, email: { org: true, any: true }, backups: { enabled: true, lastSuccessAt: new Date() },
      health: { reported: 1, atRisk: 0 }, inactiveAdmins: 0, ignored: [], now: new Date() };
    const all = computeBenchmarks(input);
    expect(all.filter((b) => b.status === "critical")).toEqual([]);
    expect(all.find((b) => b.key === "sso")!.status).toBe("not_applicable");
    expect(computeScore(all, [80]).value).toBe(Math.round(0.7 * 100 + 0.3 * 80));
    expect(computeScore(all, []).value).toBe(100);
    // Old backups fail; one high-weight failure out of the rest.
    const stale = computeBenchmarks({ ...input, backups: { enabled: true, lastSuccessAt: new Date(input.now.getTime() - 49 * 3600e3) } });
    expect(stale.find((b) => b.key === "backups")!.status).toBe("critical");
    const s = computeScore(stale, []);
    expect(s.counted).toEqual({ earned: s.counted.possible - 3, possible: s.counted.possible });
  });

  it("words the password health detail for one and for several reporting members", () => {
    const input: BenchmarkInput = { admins: 2, adminRecoveryEnabled: true, policies: DEFAULT_POLICIES, sso: { hasDomain: false, configured: false, verifiedDomains: 0 },
      email: { org: true, any: true }, backups: null, health: { reported: 1, atRisk: 0 }, inactiveAdmins: 0, ignored: [], now: new Date() };
    const detail = (health: BenchmarkInput["health"]) => computeBenchmarks({ ...input, health }).find((b) => b.key === "password_health")!.detail;
    expect(detail({ reported: 1, atRisk: 0 })).toBe("The 1 reporting member is above 60 with no breached passwords.");
    expect(detail({ reported: 3, atRisk: 0 })).toBe("All 3 reporting members are above 60 with no breached passwords.");
    expect(detail({ reported: 3, atRisk: 1 })).toBe("1 member with a breached password or a health score under 60.");
    expect(detail({ reported: 3, atRisk: 2 })).toBe("2 members with a breached password or a health score under 60.");
  });
});

describe("risk dashboard: resend all pending invites (People's POST /admin/invites/resend-all)", () => {
  it("is admin-only, resends and logs, refreshes the dashboard's pending list, and won't resend again at once", async () => {
    const owner = await createActiveUser(t, { role: "owner" }), m = await createActiveUser(t);
    await createInvite(t.prisma, "one@clane.ai", "member", owner.orgId);
    await createInvite(t.prisma, "two@clane.ai", "member", owner.orgId);
    await t.prisma.invite.updateMany({ where: { acceptedAt: null }, data: { createdAt: new Date(Date.now() - 3600e3) } });
    t.config.resendApiKey = "re_test"; t.config.emailFrom = "Vault <vault@clane.ai>";
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("{}", { status: 200 }));
    try {
      expect((await call(m, "POST", "/admin/invites/resend-all", {})).statusCode).toBe(403);
      const before = (await call(owner, "GET", "/admin/risk/members")).json().invites;
      const res = await call(owner, "POST", "/admin/invites/resend-all", {});
      expect(res.statusCode).toBe(200);
      expect(res.json()).toMatchObject({ resent: 2, skipped: 0 });
      expect(fetchSpy).toHaveBeenCalledTimes(2);
      expect(await t.prisma.event.count({ where: { orgId: owner.orgId, action: "admin.invite_resend" } })).toBe(2);
      expect(await t.prisma.event.count({ where: { orgId: owner.orgId, action: "admin.invite_resend_all", actorId: owner.id } })).toBe(1);
      // Still pending on the dashboard, with a fresh week.
      const after = (await call(owner, "GET", "/admin/risk/members")).json().invites;
      expect(after.map((i: any) => i.email).sort()).toEqual(["one@clane.ai", "two@clane.ai"]);
      expect(Date.parse(after[0].expiresAt)).toBeGreaterThanOrEqual(Date.parse(before[0].expiresAt));
      expect((await call(owner, "POST", "/admin/invites/resend-all", {})).json()).toMatchObject({ resent: 0, skipped: 2 });
    } finally { delete t.config.resendApiKey; delete t.config.emailFrom; fetchSpy.mockRestore(); }
  });
});
