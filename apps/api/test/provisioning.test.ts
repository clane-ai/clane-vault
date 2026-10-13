import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { createAccount, createTeamFolder, sealFolderKeyFor } from "@clane-vault/crypto";
import { makeTestApp, resetDb, createActiveUser, FAST_KDF, freshTotp } from "./helpers.js";

// User provisioning (docs/provisioning.md): bulk invitations, pending group memberships, resend and revoke, exports,
// email domain auto-join and the onboarding checklist.
const t = await makeTestApp();
afterAll(() => t.app.close());
beforeEach(() => resetDb(t.prisma));
const saved = { ...t.config };
afterEach(() => { vi.restoreAllMocks(); Object.assign(t.config, saved); delete t.config.resendApiKey; delete t.config.emailFrom; delete t.config.hostedMode; delete t.config.invitesPerOrgPerDay; });

const txt: Record<string, string[]> = {};
beforeAll(() => { t.app.ssoDeps.resolveTxt = async (d) => { if (!txt[d]) throw Object.assign(new Error("no data"), { code: "ENODATA" }); return txt[d]!.map((r) => [r]); }; });

type U = Awaited<ReturnType<typeof createActiveUser>>;
type M = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
let ipSeq = 0;
const ip = () => `10.160.${(++ipSeq >> 8) & 255}.${ipSeq & 255}`;
const call = (u: U, method: M, url: string, payload?: unknown, org?: string | null) => {
  const o = org === undefined ? u.orgId : org;
  return t.app.inject({ method, url: `/api/v1${url}`, payload: payload as object, remoteAddress: ip(), headers: { authorization: `Bearer ${u.accessToken}`, ...(o ? { "x-org-id": o } : {}) } });
};
const pub = (method: M, url: string, payload?: unknown) => t.app.inject({ method, url: `/api/v1${url}`, payload: payload as object, remoteAddress: ip() });
const newOrg = (name: string) => t.prisma.organization.create({ data: { name, slug: `${name.toLowerCase().replace(/\W/g, "")}-${crypto.randomUUID().slice(0, 8)}` } });

/** Resend stub: every email is captured. */
function mailbox() {
  t.config.resendApiKey = "re_test"; t.config.emailFrom = "vault@clane.ai";
  const spy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("{}", { status: 200 }));
  return () => spy.mock.calls.filter(([u]) => String(u).includes("resend.com")).map(([, init]) => JSON.parse(String((init as RequestInit).body)) as { to: string[]; subject: string; text: string });
}
const linkIn = (text: string) => /\/(invite|join)\/([A-Za-z0-9_-]{20,})/.exec(text);

/** Signs up through an invite token (name, master password, authenticator), as the web app does. */
async function signUp(token: string, email: string, emailCode?: string): Promise<U> {
  const acct = await createAccount(`password for ${email}`, FAST_KDF);
  const a = ip();
  const reg = await t.app.inject({ remoteAddress: a, method: "POST", url: "/api/v1/auth/register", payload: { inviteToken: token, name: email.split("@")[0], authKey: acct.authKey, material: acct.material, ...(emailCode ? { emailCode } : {}) } });
  expect(reg.statusCode, reg.body).toBe(201);
  const auth = { authorization: `Bearer ${reg.json().setupToken}` };
  const secret = (await t.app.inject({ remoteAddress: a, method: "POST", url: "/api/v1/auth/totp/setup", headers: auth, payload: {} })).json().secret as string;
  const v = (await t.app.inject({ remoteAddress: a, method: "POST", url: "/api/v1/auth/totp/verify", headers: auth, payload: { code: await freshTotp(secret) } })).json();
  const orgId = v.orgs[0]?.id ?? null;
  return { id: v.user.id, email, password: "", orgId, accessToken: v.accessToken, cookie: "", totpSecret: secret, keys: acct.keys, material: acct.material } as U;
}
const tokenOf = (url: string) => url.split("/").pop()!;
async function group(admin: U, name: string) {
  const r = await call(admin, "POST", "/admin/groups", { name });
  expect(r.statusCode).toBe(201);
  return r.json().id as string;
}

describe("bulk invitations", () => {
  it("previews without creating anything, then invites valid rows with per-row results, one event each and a summary", async () => {
    const a = await createActiveUser(t, { role: "admin" });
    const member = await createActiveUser(t);
    const eng = await group(a, "Engineering");
    await call(a, "POST", "/admin/invites", { email: "pending@acme.test" });
    await t.prisma.inviteCooldown.create({ data: { orgId: a.orgId, email: "cool@acme.test", until: new Date(Date.now() + 3600e3) } });
    const rows = [
      { email: " Ann@Acme.test ", name: "Ann Example" },
      { email: "bob@acme.test", role: "admin", groups: "engineering" },
      { email: "not-an-email" },
      { email: "ann@acme.test" },
      { email: "cara@acme.test", role: "owner" },
      { email: "dan@acme.test", groups: "Engineering; Ghosts" },
      { email: member.email },
      { email: "pending@acme.test" },
      { email: "cool@acme.test" },
    ];
    const preview = await call(a, "POST", "/admin/invites/bulk", { rows, role: "member", dryRun: true });
    expect(preview.statusCode, preview.body).toBe(200);
    const p = preview.json();
    expect(p.results.map((r: { status: string }) => r.status)).toEqual(["valid", "valid", "invalid_email", "duplicate", "invalid_role", "unknown_group", "member", "already_invited", "cooldown"]);
    expect(p.results[0]).toMatchObject({ email: "ann@acme.test", name: "Ann Example", role: "member", groups: [] });
    expect(p.results[1]).toMatchObject({ email: "bob@acme.test", role: "admin", groups: ["Engineering"] });
    expect(p.results[5]).toMatchObject({ detail: "Ghosts" });
    expect(await t.prisma.invite.count({ where: { email: { in: ["ann@acme.test", "bob@acme.test"] } } })).toBe(0);

    const sent = await call(a, "POST", "/admin/invites/bulk", { rows, role: "member", groupIds: [] });
    const s = sent.json();
    expect(s.results.filter((r: { status: string }) => r.status === "invited").map((r: { email: string }) => r.email)).toEqual(["ann@acme.test", "bob@acme.test"]);
    // Self-hosted: each new invitation's link comes back once.
    expect(s.results[0].inviteUrl).toMatch(/^http:\/\/localhost:5173\/invite\//);
    expect(s.counts).toMatchObject({ invited: 2, invalid_email: 1, duplicate: 1, invalid_role: 1, unknown_group: 1, member: 1, already_invited: 1, cooldown: 1 });
    const bob = await t.prisma.invite.findFirstOrThrow({ where: { email: "bob@acme.test" } });
    expect(bob.role).toBe("admin");
    expect((await t.prisma.invite.findFirstOrThrow({ where: { email: "ann@acme.test" } })).nameHint).toBe("Ann Example");
    expect(await t.prisma.pendingGroupMember.findMany({ where: { email: "bob@acme.test" }, select: { groupId: true, addedBy: true } })).toEqual([{ groupId: eng, addedBy: a.id }]);
    const ev = await t.prisma.event.findMany({ where: { orgId: a.orgId, action: { in: ["admin.invite", "admin.invite_bulk"] } }, orderBy: { id: "asc" } });
    expect(ev.map((e) => e.action)).toEqual(["admin.invite", "admin.invite", "admin.invite", "admin.invite_bulk"]); // the first: the single invite above
    expect(ev[3]!.meta).toMatchObject({ requested: 9, invited: 2 });
    // The name hint reaches the sign-up page.
    expect((await pub("GET", `/auth/invite/${tokenOf(s.results[0].inviteUrl)}`)).json().name).toBe("Ann Example");
  });

  it("respects the daily cap (new invitations and resends count) and validates the request", async () => {
    const a = await createActiveUser(t, { role: "admin" });
    t.config.invitesPerOrgPerDay = 3;
    await call(a, "POST", "/admin/invites", { email: "one@acme.test" });
    const r = (await call(a, "POST", "/admin/invites/bulk", { rows: ["a", "b", "c", "d"].map((x) => ({ email: `${x}@acme.test` })) })).json();
    expect(r.results.map((x: { status: string }) => x.status)).toEqual(["invited", "invited", "over_cap", "over_cap"]);
    expect(r.cap).toEqual({ perDay: 3, sentToday: 3, remaining: 0 });
    expect((await call(a, "POST", "/admin/invites", { email: "e@acme.test" })).statusCode).toBe(429);
    // Bad requests: too many rows, no rows, another org's group.
    expect((await call(a, "POST", "/admin/invites/bulk", { rows: [] })).statusCode).toBe(400);
    expect((await call(a, "POST", "/admin/invites/bulk", { rows: Array.from({ length: 501 }, (_, i) => ({ email: `u${i}@acme.test` })) })).statusCode).toBe(400);
    const other = await newOrg("Other");
    const foreign = await t.prisma.group.create({ data: { orgId: other.id, name: "Theirs" } });
    expect((await call(a, "POST", "/admin/invites/bulk", { rows: [{ email: "x@acme.test" }], groupIds: [foreign.id], dryRun: true })).json()).toEqual({ error: "group_not_found" });
    // A row naming another org's group by name or id is unknown here.
    expect((await call(a, "POST", "/admin/invites/bulk", { rows: [{ email: "x@acme.test", groups: [foreign.id] }], dryRun: true })).json().results[0].status).toBe("unknown_group");
  });

  it("HOSTED_MODE: needs email, never returns links, emails every invitee", async () => {
    const a = await createActiveUser(t, { role: "admin" });
    const existing = await createActiveUser(t, { orgId: (await newOrg("Elsewhere")).id });
    t.config.hostedMode = true;
    expect((await call(a, "POST", "/admin/invites/bulk", { rows: [{ email: "x@acme.test" }] })).json()).toEqual({ error: "email_required" });
    const sent = mailbox();
    const r = (await call(a, "POST", "/admin/invites/bulk", { rows: [{ email: "x@acme.test" }, { email: existing.email }] })).json();
    expect(r.results.map((x: { status: string; inviteUrl?: string }) => [x.status, x.inviteUrl])).toEqual([["invited", undefined], ["invited", undefined]]);
    expect(sent().map((m) => m.to[0])).toEqual(["x@acme.test", existing.email]);
  });

  it("is for the org's owners and admins only, and stays inside the org", async () => {
    const m = await createActiveUser(t);
    const id = crypto.randomUUID();
    for (const [method, url] of [["POST", "/admin/invites/bulk"], ["GET", "/admin/invites"], ["POST", `/admin/invites/${id}/resend`], ["POST", "/admin/invites/resend-all"],
      ["GET", "/admin/people/export.csv"], ["GET", "/admin/invites/export.csv"], ["GET", "/admin/settings/domain-join"], ["PUT", "/admin/settings/domain-join"],
      ["GET", "/admin/onboarding"], ["PUT", "/admin/onboarding"]] as const) {
      expect((await call(m, method, url, method === "GET" ? undefined : { rows: [{ email: "x@y.test" }], enabled: true, dismissed: true })).statusCode, url).toBe(403);
      expect((await t.app.inject({ method, url: `/api/v1${url}` })).statusCode, url).toBe(401);
    }
    // An admin of another org can't list, resend or revoke this org's invitations.
    const a = await createActiveUser(t, { role: "admin" });
    await call(a, "POST", "/admin/invites", { email: "mine@acme.test" });
    const inv = await t.prisma.invite.findFirstOrThrow({ where: { email: "mine@acme.test" } });
    const other = await newOrg("Other");
    const b = await createActiveUser(t, { role: "owner", orgId: other.id });
    expect((await call(b, "GET", "/admin/invites")).json().invites).toEqual([]);
    expect((await call(b, "POST", `/admin/invites/${inv.id}/resend`)).statusCode).toBe(404);
    expect((await call(b, "DELETE", `/admin/invites/${inv.id}`)).statusCode).toBe(404);
    expect(await (await call(b, "GET", "/admin/invites/export.csv")).body).not.toContain("mine@acme.test");
  });
});

describe("pending group memberships", () => {
  it("apply when the invitee signs up; folder keys still need a key holder's approval", async () => {
    const owner = await createActiveUser(t, { role: "owner" });
    const g = await group(owner, "Engineering");
    const fid = crypto.randomUUID();
    const f = await createTeamFolder(fid, "Infra", owner.keys.publicKey);
    expect((await call(owner, "POST", "/folders", { id: fid, kind: "team", encName: f.encName, wrappedFolderKey: f.wrappedFolderKey })).statusCode).toBe(201);
    expect((await call(owner, "POST", `/folders/${fid}/groups`, { groupId: g, permission: "view", wraps: [] })).statusCode).toBe(201);
    const r = (await call(owner, "POST", "/admin/invites/bulk", { rows: [{ email: "new@acme.test" }], groupIds: [g] })).json();
    const u = await signUp(tokenOf(r.results[0].inviteUrl), "new@acme.test");
    expect(await t.prisma.groupMember.count({ where: { groupId: g, userId: u.id } })).toBe(1);
    expect(await t.prisma.pendingGroupMember.count()).toBe(0);
    // No folder key yet: they wait in the owner's approval list, exactly as after an admin adds them to the group.
    expect(await t.prisma.folderMember.count({ where: { folderId: fid, userId: u.id } })).toBe(0);
    const pending = (await call(owner, "GET", "/group-access/pending")).json().pending;
    expect(pending).toEqual([expect.objectContaining({ folderId: fid, userId: u.id, email: "new@acme.test", permission: "view", via: [expect.objectContaining({ groupId: g, addedBy: { id: owner.id, name: expect.any(String) } })] })]);
    // The owner approves explicitly (seals the key), as before.
    const wrap = await sealFolderKeyFor(f.folderKey, fid, u.keys.publicKey);
    expect((await call(owner, "POST", `/folders/${fid}/group-access`, { wraps: [{ userId: u.id, wrappedFolderKey: wrap }] })).json()).toEqual({ added: [u.id], skipped: 0 });
    const ev = await t.prisma.event.findFirstOrThrow({ where: { action: "group.member_add", targetUserId: u.id } });
    expect(ev).toMatchObject({ actorId: owner.id, meta: { groupId: g, via: "invite" } });
  });

  it("apply when an existing account accepts in the app; a revoke or a decline drops them", async () => {
    const a = await createActiveUser(t, { role: "admin" });
    const g = await group(a, "Ops");
    const other = await newOrg("Other");
    const x = await createActiveUser(t, { orgId: other.id });
    const y = await createActiveUser(t, { orgId: other.id });
    const z = await createActiveUser(t, { orgId: other.id });
    await call(a, "POST", "/admin/invites/bulk", { rows: [{ email: x.email }, { email: y.email }, { email: z.email }], groupIds: [g] });
    expect(await t.prisma.pendingGroupMember.count({ where: { groupId: g } })).toBe(3);
    expect((await call(x, "POST", `/me/invitations/${a.orgId}/accept`, {}, null)).statusCode).toBe(200);
    expect(await t.prisma.groupMember.count({ where: { groupId: g, userId: x.id } })).toBe(1);
    expect((await call(y, "POST", `/me/invitations/${a.orgId}/decline`, {}, null)).statusCode).toBe(204);
    const list = (await call(a, "GET", "/admin/invites")).json().invites as { id: string; email: string; groups: { name: string }[] }[];
    expect(list.map((i) => [i.email, i.groups.map((gg) => gg.name)])).toEqual([[z.email, ["Ops"]]]);
    expect((await call(a, "DELETE", `/admin/invites/${list[0]!.id}`)).statusCode).toBe(204);
    expect(await t.prisma.pendingGroupMember.count()).toBe(0);
    expect(await t.prisma.groupMember.count({ where: { groupId: g } })).toBe(1);
  });
});

describe("pending invitations: list, resend, resend all, exports", () => {
  it("resend gives a new link (the old one stops working), a fresh week, and is limited", async () => {
    const a = await createActiveUser(t, { role: "admin" });
    const first = (await call(a, "POST", "/admin/invites", { email: "late@acme.test" })).json();
    const inv = await t.prisma.invite.findFirstOrThrow({ where: { email: "late@acme.test" } });
    expect((await call(a, "POST", `/admin/invites/${inv.id}/resend`)).json()).toEqual({ error: "too_soon" });
    await t.prisma.invite.update({ where: { id: inv.id }, data: { lastSentAt: new Date(Date.now() - 8 * 864e5), createdAt: new Date(Date.now() - 8 * 864e5), expiresAt: new Date(Date.now() - 864e5) } });
    const pending = (await call(a, "GET", "/admin/invites")).json();
    expect(pending.invites).toEqual([]);
    const expired = (await call(a, "GET", "/admin/invites?status=expired&q=LATE")).json().invites;
    expect(expired).toEqual([expect.objectContaining({ id: inv.id, email: "late@acme.test", expired: true, source: "admin", invitedBy: { id: a.id, name: expect.any(String) } })]);
    const r = await call(a, "POST", `/admin/invites/${inv.id}/resend`);
    expect(r.statusCode, r.body).toBe(200);
    expect(r.json()).toMatchObject({ id: inv.id, email: "late@acme.test", emailed: false, inviteUrl: expect.stringMatching(/\/invite\//) });
    expect((await pub("GET", `/auth/invite/${tokenOf(first.inviteUrl)}`)).statusCode).toBe(404);
    expect((await pub("GET", `/auth/invite/${tokenOf(r.json().inviteUrl)}`)).statusCode).toBe(200);
    const after = await t.prisma.invite.findUniqueOrThrow({ where: { id: inv.id } });
    expect(after.expiresAt.getTime()).toBeGreaterThan(Date.now() + 6 * 864e5);
    expect(after.resendCount).toBe(1);
    expect(await t.prisma.event.count({ where: { action: "admin.invite_resend", orgId: a.orgId } })).toBe(1);
    expect((await call(a, "POST", `/admin/invites/${crypto.randomUUID()}/resend`)).statusCode).toBe(404);
  });

  it("resend all sends every pending invitation up to the cap", async () => {
    const a = await createActiveUser(t, { role: "admin" });
    t.config.invitesPerOrgPerDay = 5;
    await call(a, "POST", "/admin/invites/bulk", { rows: [{ email: "p1@acme.test" }, { email: "p2@acme.test" }, { email: "p3@acme.test" }] });
    await t.prisma.invite.updateMany({ data: { lastSentAt: new Date(Date.now() - 3600e3) } });
    const r = (await call(a, "POST", "/admin/invites/resend-all", {})).json();
    expect(r.resent).toBe(2);
    expect(r.results.map((x: { status: string }) => x.status).sort()).toEqual(["invite_limit", "resent", "resent"]);
    expect(await t.prisma.event.count({ where: { action: "admin.invite_resend_all" } })).toBe(1);
  });

  it("exports members and invitations as CSV, with spreadsheet formulas neutralised", async () => {
    const a = await createActiveUser(t, { role: "admin" });
    const g = await group(a, "Finance");
    await call(a, "POST", `/admin/groups/${g}/members`, { userIds: [a.id] });
    await call(a, "POST", "/admin/invites/bulk", { rows: [{ email: "csv@acme.test" }], groupIds: [g] });
    await t.prisma.user.update({ where: { id: a.id }, data: { name: "=HYPERLINK(1)" } });
    const members = await call(a, "GET", "/admin/people/export.csv");
    expect(members.headers["content-type"]).toContain("text/csv");
    expect(members.body.split("\n")[0]).toBe("name,email,role,status,two_factor,joined_at,groups");
    expect(members.body).toContain(`"'=HYPERLINK(1)","${a.email}","admin","active","yes"`);
    expect(members.body).toContain('"Finance"');
    const invites = await call(a, "GET", "/admin/invites/export.csv");
    expect(invites.body.split("\n")[0]).toBe("email,role,status,source,groups,invited_at,expires_at,last_sent_at,resend_count,invited_by");
    expect(invites.body).toContain('"csv@acme.test","member","pending","admin","Finance"');
    expect(await t.prisma.event.count({ where: { action: "admin.export" } })).toBe(2);
  });
});

describe("email domain auto-join", () => {
  async function verifiedDomain(owner: U, domain: string) {
    expect((await call(owner, "POST", "/admin/settings/sso/domains", { domain })).statusCode).toBe(201);
    const row = await t.prisma.ssoDomain.findFirstOrThrow({ where: { orgId: owner.orgId!, domain } });
    txt[domain] = [`clane-vault-verify=${row.token}`];
    const v = await call(owner, "POST", `/admin/settings/sso/domains/${domain}/verify`);
    expect(v.statusCode, v.body).toBe(200);
  }
  const ask = (email: string) => pub("POST", "/auth/domain-join", { email });

  it("is off by default; only the owner turns it on, and only with a domain this org verified and email set up", async () => {
    const owner = await createActiveUser(t, { role: "owner" });
    const admin = await createActiveUser(t, { role: "admin" });
    expect((await call(admin, "GET", "/admin/settings/domain-join")).json()).toMatchObject({ enabled: false, role: "member", domains: [], canEdit: false });
    expect((await call(admin, "PUT", "/admin/settings/domain-join", { enabled: true })).json()).toEqual({ error: "owner_only" });
    expect((await call(owner, "PUT", "/admin/settings/domain-join", { enabled: true })).json()).toEqual({ error: "domain_not_verified" });
    await call(owner, "POST", "/admin/settings/sso/domains", { domain: "unverified.test" });
    expect((await call(owner, "PUT", "/admin/settings/domain-join", { enabled: true })).json()).toEqual({ error: "domain_not_verified" });
    await verifiedDomain(owner, "acme.test");
    expect((await call(owner, "PUT", "/admin/settings/domain-join", { enabled: true })).json()).toEqual({ error: "email_required" });
    const sent = mailbox();
    const g = await group(owner, "Everyone");
    const on = await call(owner, "PUT", "/admin/settings/domain-join", { enabled: true, groupIds: [g] });
    expect(on.statusCode, on.body).toBe(200);
    expect(on.json()).toMatchObject({ enabled: true, groups: [{ id: g, name: "Everyone" }], domains: [{ domain: "acme.test", verified: true }, { domain: "unverified.test", verified: false }], joinUrl: "http://localhost:5173/join" });
    expect(await t.prisma.event.count({ where: { action: "org.domain_join_enabled", actorId: owner.id } })).toBe(1);
    // Owners and admins are told.
    expect(sent().filter((m) => m.subject.includes("auto-join")).map((m) => m.to[0]).sort()).toEqual([owner.email, admin.email].sort());
    // Public mail domains can't even be added.
    expect((await call(owner, "POST", "/admin/settings/sso/domains", { domain: "gmail.com" })).json()).toEqual({ error: "public_domain" });
  });

  it("an address in the verified domain gets an emailed sign-up link, joins as a member into the groups, and sets up 2FA", async () => {
    const owner = await createActiveUser(t, { role: "owner" });
    const sent = mailbox();
    await verifiedDomain(owner, "acme.test");
    const g = await group(owner, "Everyone");
    await call(owner, "PUT", "/admin/settings/domain-join", { enabled: true, groupIds: [g] });
    const before = sent().length;
    const r = await ask("New.Hire@ACME.test");
    expect(r.statusCode).toBe(202);
    expect(r.json()).toEqual({ ok: true });
    const mails = sent().slice(before);
    expect(mails.map((m) => m.to[0])).toEqual(["new.hire@acme.test"]);
    const link = linkIn(mails[0]!.text)!;
    expect(link[1]).toBe("invite");
    const inv = await t.prisma.invite.findFirstOrThrow({ where: { email: "new.hire@acme.test" } });
    expect(inv).toMatchObject({ source: "domain", role: "member", invitedById: null });
    // Asking again right away sends nothing more.
    await ask("new.hire@acme.test");
    expect(sent().length).toBe(before + 1);
    const u = await signUp(link[2]!, "new.hire@acme.test");
    const m = await t.prisma.membership.findUniqueOrThrow({ where: { orgId_userId: { orgId: owner.orgId!, userId: u.id } } });
    expect(m).toMatchObject({ role: "member", status: "active" });
    expect((await t.prisma.user.findUniqueOrThrow({ where: { id: u.id } })).status).toBe("active"); // authenticator set up
    expect(await t.prisma.groupMember.count({ where: { groupId: g, userId: u.id } })).toBe(1);
    expect(await t.prisma.event.count({ where: { action: "org.domain_join", targetUserId: u.id } })).toBe(1);
    expect(await t.prisma.event.count({ where: { action: "org.domain_join_request", orgId: owner.orgId } })).toBe(1);
  });

  it("an existing account claims the emailed link signed in, then accepts in the app; nobody else can claim it", async () => {
    const owner = await createActiveUser(t, { role: "owner" });
    const sent = mailbox();
    await verifiedDomain(owner, "acme.test");
    await call(owner, "PUT", "/admin/settings/domain-join", { enabled: true });
    const other = await newOrg("Other");
    const existing = await createActiveUser(t, { email: "old@acme.test", orgId: other.id });
    const stranger = await createActiveUser(t, { email: "eve@evil.test", orgId: other.id });
    const before = sent().length;
    await ask("old@acme.test");
    const link = linkIn(sent()[before]!.text)!;
    expect(link[1]).toBe("join");
    // Not a sign-up link for an existing account, and not claimable by another account.
    expect((await call(stranger, "POST", "/me/join", { token: link[2] }, null)).statusCode).toBe(404);
    const c = await call(existing, "POST", "/me/join", { token: link[2] }, null);
    expect(c.statusCode, c.body).toBe(200);
    expect(c.json()).toEqual({ orgId: owner.orgId, orgName: "Test org", status: "invited" });
    expect((await call(existing, "POST", "/me/join", { token: link[2] }, null)).statusCode).toBe(404); // single use
    expect((await call(existing, "GET", "/me/orgs", undefined, null)).json().invitations).toEqual([expect.objectContaining({ orgId: owner.orgId, role: "member" })]);
    expect((await call(existing, "POST", `/me/invitations/${owner.orgId}/accept`, {}, null)).statusCode).toBe(200);
    expect((await t.prisma.membership.findUniqueOrThrow({ where: { orgId_userId: { orgId: owner.orgId!, userId: existing.id } } })).status).toBe("active");
  });

  it("can't be used to join someone else's org: unverified, public, other orgs' and contested domains get nothing", async () => {
    const owner = await createActiveUser(t, { role: "owner" });
    const sent = mailbox();
    await verifiedDomain(owner, "acme.test");
    await call(owner, "PUT", "/admin/settings/domain-join", { enabled: true });
    // Org B adds acme.test but can't verify it (one org per domain), so it can't turn auto-join on.
    const orgB = await newOrg("Beta");
    const ownerB = await createActiveUser(t, { role: "owner", orgId: orgB.id });
    await call(ownerB, "POST", "/admin/settings/sso/domains", { domain: "acme.test" });
    expect((await call(ownerB, "POST", "/admin/settings/sso/domains/acme.test/verify")).json()).toEqual({ error: "domain_taken" });
    expect((await call(ownerB, "PUT", "/admin/settings/domain-join", { enabled: true })).json()).toEqual({ error: "domain_not_verified" });
    const before = sent().length;
    // Unverified domain of an org with auto-join on; a public provider; a domain nobody verified.
    await call(owner, "POST", "/admin/settings/sso/domains", { domain: "pending.test" });
    for (const e of ["a@pending.test", "a@gmail.com", "a@nobody.test"]) expect((await ask(e)).json()).toEqual({ ok: true });
    expect(sent().length).toBe(before);
    expect(await t.prisma.invite.count({ where: { source: "domain" } })).toBe(0);
    // A joiner from acme.test lands in the org that verified it, never in Beta.
    await ask("x@acme.test");
    expect(await t.prisma.invite.findMany({ where: { source: "domain" }, select: { orgId: true } })).toEqual([{ orgId: owner.orgId }]);
    // If two orgs ever held the same verified domain, nobody gets in through it.
    await t.prisma.ssoDomain.updateMany({ where: { orgId: orgB.id, domain: "acme.test" }, data: { verifiedAt: new Date() } });
    await ask("y@acme.test");
    expect(await t.prisma.invite.count({ where: { email: "y@acme.test" } })).toBe(0);
  });

  it("stops when switched off, when the TXT record is gone, or when the domain is removed", async () => {
    const owner = await createActiveUser(t, { role: "owner" });
    mailbox();
    await verifiedDomain(owner, "acme.test");
    await call(owner, "PUT", "/admin/settings/domain-join", { enabled: true });
    await call(owner, "PUT", "/admin/settings/domain-join", { enabled: false });
    expect(await t.prisma.event.count({ where: { action: "org.domain_join_disabled" } })).toBe(1);
    await ask("off@acme.test");
    expect(await t.prisma.invite.count({ where: { email: "off@acme.test" } })).toBe(0);
    // The TXT record disappeared (re-checked after 24 h): the domain is un-verified and auto-join goes off.
    await call(owner, "PUT", "/admin/settings/domain-join", { enabled: true });
    await t.prisma.ssoDomain.updateMany({ where: { orgId: owner.orgId! }, data: { checkedAt: new Date(Date.now() - 25 * 3600e3) } });
    delete txt["acme.test"];
    await ask("gone@acme.test");
    expect(await t.prisma.invite.count({ where: { email: "gone@acme.test" } })).toBe(0);
    expect((await t.prisma.orgDomainJoin.findUniqueOrThrow({ where: { orgId: owner.orgId! } })).enabled).toBe(false);
    // Removing the last verified domain switches it off too.
    await verifiedDomain(owner, "acme.test");
    await call(owner, "PUT", "/admin/settings/domain-join", { enabled: true });
    expect((await call(owner, "DELETE", "/admin/settings/sso/domains/acme.test")).statusCode).toBe(200);
    expect((await t.prisma.orgDomainJoin.findUniqueOrThrow({ where: { orgId: owner.orgId! } })).enabled).toBe(false);
  });

  it("existing members, admins' own invitations and declined addresses are left alone", async () => {
    const owner = await createActiveUser(t, { role: "owner", email: "boss@acme.test" });
    const sent = mailbox();
    await verifiedDomain(owner, "acme.test");
    await call(owner, "PUT", "/admin/settings/domain-join", { enabled: true });
    await call(owner, "POST", "/admin/invites", { email: "invited@acme.test", role: "admin" });
    await t.prisma.inviteCooldown.create({ data: { orgId: owner.orgId!, email: "no@acme.test", until: new Date(Date.now() + 3600e3) } });
    const before = sent().length;
    for (const e of ["boss@acme.test", "invited@acme.test", "no@acme.test"]) await ask(e);
    expect(sent().length).toBe(before);
    expect((await t.prisma.invite.findFirstOrThrow({ where: { email: "invited@acme.test" } })).role).toBe("admin");
  });

  it("works in HOSTED_MODE: the link is emailed and sign-up still needs the emailed code", async () => {
    const owner = await createActiveUser(t, { role: "owner" });
    const sent = mailbox();
    t.config.hostedMode = true;
    await verifiedDomain(owner, "acme.test");
    await call(owner, "PUT", "/admin/settings/domain-join", { enabled: true });
    const before = sent().length;
    await ask("h@acme.test");
    const link = linkIn(sent()[before]!.text)!;
    const token = link[2]!;
    const acct = await createAccount("password for h", FAST_KDF);
    expect((await pub("POST", "/auth/register", { inviteToken: token, name: "H", authKey: acct.authKey, material: acct.material })).json()).toEqual({ error: "email_code_required" });
    expect((await pub("POST", "/auth/register/code", { inviteToken: token })).statusCode).toBe(202);
    const code = /\b(\d{6})\b/.exec(sent().at(-1)!.text)![1]!;
    const u = await signUp(token, "h@acme.test", code);
    expect(u.orgId).toBe(owner.orgId);
  });
});

describe("onboarding checklist", () => {
  it("is computed from what is set up, and can be dismissed", async () => {
    const org = await newOrg("Fresh");
    const owner = await createActiveUser(t, { role: "owner", orgId: org.id });
    const get = async () => (await call(owner, "GET", "/admin/onboarding")).json();
    expect(await get()).toEqual({ show: true, dismissed: false, done: 0, total: 5,
      steps: [{ id: "invite", done: false }, { id: "group", done: false }, { id: "policies", done: false }, { id: "recovery", done: false }, { id: "sso", done: false }] });
    await call(owner, "POST", "/admin/invites", { email: "x@acme.test" });
    await group(owner, "Team");
    await t.prisma.organization.update({ where: { id: org.id }, data: { policiesChangedAt: new Date() } });
    expect((await get()).steps.filter((s: { done: boolean }) => s.done).map((s: { id: string }) => s.id)).toEqual(["invite", "group", "policies"]);
    expect((await call(owner, "PUT", "/admin/onboarding", { dismissed: true })).json()).toEqual({ dismissed: true });
    expect(await get()).toMatchObject({ show: false, dismissed: true });
    // The default org of an older install doesn't get it.
    const old = await createActiveUser(t, { role: "admin" });
    expect((await call(old, "GET", "/admin/onboarding")).json().show).toBe(false);
  });
});
