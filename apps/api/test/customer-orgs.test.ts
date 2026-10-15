import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createAccount } from "@clane-vault/crypto";
import { makeTestApp, resetDb, createActiveUser, FAST_KDF, freshTotp } from "./helpers.js";
import { keyUp } from "./keys.js";
import { INVITE_TTL_MS } from "../src/lib/invites.js";

// Organisations an instance admin creates for customers, with an owner invitation (docs/provisioning.md).
const t = await makeTestApp();
afterAll(() => t.app.close());
beforeEach(() => resetDb(t.prisma));
const saved = { ...t.config };
afterEach(() => { vi.restoreAllMocks(); Object.assign(t.config, saved); delete t.config.resendApiKey; delete t.config.emailFrom; delete t.config.hostedMode; delete t.config.maxOwnedOrgs; });

type U = Awaited<ReturnType<typeof createActiveUser>>;
type M = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
let ipSeq = 0;
const ip = () => `10.173.${(++ipSeq >> 8) & 255}.${ipSeq & 255}`;
const call = (u: U, method: M, url: string, payload?: unknown, org?: string | null) => {
  const o = org === undefined ? u.orgId : org;
  return t.app.inject({ method, url: `/api/v1${url}`, payload: payload as object, remoteAddress: ip(), headers: { authorization: `Bearer ${u.accessToken}`, ...(o ? { "x-org-id": o } : {}) } });
};
const pub = (method: M, url: string, payload?: unknown) => t.app.inject({ method, url: `/api/v1${url}`, payload: payload as object, remoteAddress: ip() });

/** Resend stub: every email is captured. */
function mailbox() {
  t.config.resendApiKey = "re_test"; t.config.emailFrom = "vault@clane.ai";
  const spy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("{}", { status: 200 }));
  return () => spy.mock.calls.filter(([u]) => String(u).includes("resend.com")).map(([, init]) => JSON.parse(String((init as RequestInit).body)) as { to: string[]; subject: string; text: string });
}

async function instanceAdmin(): Promise<U> {
  const a = await createActiveUser(t, { role: "owner" });
  await t.prisma.user.update({ where: { id: a.id }, data: { instanceAdmin: true } });
  return a;
}

/** An account that owns its own organisation (not the default one). */
async function ownerOfNewOrg(name = "Customer"): Promise<U> {
  const org = await t.prisma.organization.create({ data: { name, slug: `${name.toLowerCase()}-${crypto.randomUUID().slice(0, 8)}` } });
  return createActiveUser(t, { role: "owner", orgId: org.id });
}

/** Signs up through an invite token (name, master password, authenticator), as the web app does. */
async function signUp(token: string, email: string, emailCode?: string): Promise<U> {
  const acct = await createAccount(`password for ${email}`, FAST_KDF);
  const a = ip();
  const reg = await t.app.inject({ remoteAddress: a, method: "POST", url: "/api/v1/auth/register", payload: { inviteToken: token, name: email.split("@")[0], authKey: acct.authKey, material: acct.material, ...(emailCode ? { emailCode } : {}) } });
  expect(reg.statusCode, reg.body).toBe(201);
  const auth = { authorization: `Bearer ${reg.json().setupToken}` };
  const secret = (await t.app.inject({ remoteAddress: a, method: "POST", url: "/api/v1/auth/totp/setup", headers: auth, payload: {} })).json().secret as string;
  const v = (await t.app.inject({ remoteAddress: a, method: "POST", url: "/api/v1/auth/totp/verify", headers: auth, payload: { code: await freshTotp(secret) } })).json();
  return { id: v.user.id, email, password: `password for ${email}`, orgId: v.orgs[0]?.id ?? null, accessToken: v.accessToken, cookie: "", totpSecret: secret, keys: acct.keys, material: acct.material } as U;
}
const tokenOf = (url: string) => url.split("/").pop()!;

describe("organisations for customers", () => {
  const create = (ia: U, name: string, ownerEmail: string) => call(ia, "POST", "/admin/instance/orgs", { name, ownerEmail }, null);
  const list = async (ia: U) => (await call(ia, "GET", "/admin/instance/orgs", undefined, null)).json().orgs as { id: string; name: string; ownerEmail: string; status: string; expiresAt: string | null }[];

  it("a new person: the org has no members, the link signs them up as its only owner and their browser makes their key", async () => {
    const ia = await instanceAdmin();
    const r = await create(ia, "Globex", "Ceo@Globex.test");
    expect(r.statusCode, r.body).toBe(201);
    const { org, emailed, inviteUrl } = r.json();
    expect(org).toMatchObject({ name: "Globex", ownerEmail: "ceo@globex.test", status: "pending" });
    expect(emailed).toBe(false);
    expect(inviteUrl).toMatch(/\/invite\//);
    expect(await t.prisma.membership.count({ where: { orgId: org.id } })).toBe(0);
    expect(await t.prisma.invite.findFirstOrThrow({ where: { orgId: org.id } })).toMatchObject({ email: "ceo@globex.test", role: "owner", source: "customer", instanceAdmin: false });
    // Not limited by ALLOW_ORG_CREATION or MAX_OWNED_ORGS for the operator.
    t.config.allowOrgCreation = false; t.config.maxOwnedOrgs = 0;
    expect((await create(ia, "Initech", "boss@initech.test")).statusCode).toBe(201);
    t.config.allowOrgCreation = true; delete t.config.maxOwnedOrgs;

    const ceo = await signUp(tokenOf(inviteUrl), "ceo@globex.test");
    expect(ceo.orgId).toBe(org.id);
    const ms = await t.prisma.membership.findMany({ where: { orgId: org.id }, select: { userId: true, role: true, status: true } });
    expect(ms).toEqual([{ userId: ceo.id, role: "owner", status: "active" }]);
    expect(await t.prisma.membership.count({ where: { orgId: org.id, userId: ia.id } })).toBe(0);
    // Keys: the first member's client creates the org's first membership key, as on any first unlock.
    await keyUp(t, ceo, org.id);
    expect(await t.prisma.membershipKey.count({ where: { orgId: org.id, userId: ceo.id, state: "current" } })).toBe(1);
    expect((await call(ceo, "GET", "/membership-key", undefined, org.id)).json()).toMatchObject({ pendingRows: 0, escrow: { enabled: false, needed: [] } });
    // The operator sees the status, never the org itself.
    expect((await list(ia)).find((o) => o.id === org.id)).toMatchObject({ status: "accepted", expiresAt: null });
    expect((await call(ia, "GET", "/admin/people", undefined, org.id)).statusCode).toBe(403);
    // Logged in the org (who set it up) and at instance level.
    expect((await t.prisma.event.findMany({ where: { orgId: org.id, action: { in: ["org.create", "admin.invite"] } }, orderBy: { id: "asc" } })).map((e) => [e.action, e.actorId])).toEqual([["org.create", ia.id], ["admin.invite", ia.id]]);
    expect(await t.prisma.event.count({ where: { orgId: null, action: "instance.customer_org_create", actorId: ia.id } })).toBe(2);
    // Accepted: it can't be cancelled or resent any more.
    expect((await call(ia, "DELETE", `/admin/instance/orgs/${org.id}`, undefined, null)).json()).toEqual({ error: "accepted" });
    expect((await call(ia, "POST", `/admin/instance/orgs/${org.id}/resend`, undefined, null)).json()).toEqual({ error: "accepted" });
    expect(await t.prisma.organization.count({ where: { id: org.id } })).toBe(1);
  });

  it("an existing account (HOSTED_MODE): an emailed invitation to accept in the app, which makes them the sole owner", async () => {
    const ia = await instanceAdmin();
    const boss = await ownerOfNewOrg("Theirs");
    const sent = mailbox();
    t.config.hostedMode = true;
    const r = await create(ia, "Umbrella", boss.email);
    expect(r.statusCode, r.body).toBe(201);
    const { org, inviteUrl } = r.json();
    expect(inviteUrl).toBeUndefined();
    expect(r.json().emailed).toBe(true);
    const mail = sent().at(-1)!;
    expect(mail.to).toEqual([boss.email]);
    expect(mail.subject).toBe("You're invited to own Umbrella on Clane Vault");
    expect(mail.text).toContain("accept the invitation from the organisation menu");
    expect(mail.text).not.toMatch(/\/(invite|join)\//);
    expect(await t.prisma.invite.count({ where: { orgId: org.id } })).toBe(0);
    const inv = (await call(boss, "GET", "/me/orgs", undefined, null)).json().invitations;
    expect(inv).toEqual([expect.objectContaining({ orgId: org.id, orgName: "Umbrella", role: "owner" })]);
    const acc = await call(boss, "POST", `/me/invitations/${org.id}/accept`, undefined, null);
    expect(acc.statusCode, acc.body).toBe(200);
    expect(acc.json().orgs.find((o: { id: string }) => o.id === org.id)).toMatchObject({ role: "owner" });
    expect(await t.prisma.membership.findMany({ where: { orgId: org.id }, select: { userId: true, role: true, status: true } })).toEqual([{ userId: boss.id, role: "owner", status: "active" }]);
    await keyUp(t, boss, org.id);
    expect((await list(ia)).find((o) => o.id === org.id)?.status).toBe("accepted");
  });

  it("HOSTED_MODE: a new person's link is only emailed, and sign-up still needs the emailed code", async () => {
    const ia = await instanceAdmin();
    t.config.hostedMode = true;
    expect((await create(ia, "Nomail", "x@nomail.test")).json()).toEqual({ error: "email_required" });
    expect(await t.prisma.organization.count({ where: { name: "Nomail" } })).toBe(0);
    const sent = mailbox();
    const r = await create(ia, "Hooli", "gavin@hooli.test");
    expect(r.json()).toMatchObject({ emailed: true });
    expect(r.json().inviteUrl).toBeUndefined();
    const mail = sent().at(-1)!;
    expect(mail.subject).toBe("You're invited to own Hooli on Clane Vault");
    const token = /\/invite\/([A-Za-z0-9_-]{20,})/.exec(mail.text)![1]!;
    expect((await pub("POST", "/auth/register/code", { inviteToken: token })).statusCode).toBe(202);
    const code = /\b(\d{6})\b/.exec(sent().at(-1)!.text)![1]!;
    const gavin = await signUp(token, "gavin@hooli.test", code);
    expect(await t.prisma.membership.findFirstOrThrow({ where: { orgId: r.json().org.id, userId: gavin.id } })).toMatchObject({ role: "owner", status: "active" });
  });

  it("MAX_OWNED_ORGS applies to the invitee when they accept", async () => {
    const ia = await instanceAdmin();
    const boss = await ownerOfNewOrg("Theirs");
    t.config.maxOwnedOrgs = 1;
    const { org } = (await create(ia, "Second", boss.email)).json();
    expect((await call(boss, "POST", `/me/invitations/${org.id}/accept`, undefined, null)).json()).toEqual({ error: "org_limit" });
    expect(await t.prisma.membership.findFirstOrThrow({ where: { orgId: org.id, userId: boss.id } })).toMatchObject({ status: "invited", role: "owner" });
    t.config.maxOwnedOrgs = 2;
    expect((await call(boss, "POST", `/me/invitations/${org.id}/accept`, undefined, null)).statusCode).toBe(200);
  });

  it("a link meets an account made since: it stays an owner invitation (claimed, or converted at sign-up elsewhere)", async () => {
    const ia = await instanceAdmin();
    const { org, inviteUrl } = (await create(ia, "Later", "later@later.test")).json();
    // They sign up through another organisation's invite first: the owner link becomes an owner invitation in the app.
    const other = await createActiveUser(t, { email: "later@later.test" });
    expect(await t.prisma.membership.findFirstOrThrow({ where: { orgId: org.id, userId: other.id } })).toMatchObject({ role: "owner", status: "invited" });
    expect((await call(other, "POST", "/me/join", { token: tokenOf(inviteUrl) }, null)).statusCode).toBe(404); // already used up
    expect((await call(other, "POST", `/me/invitations/${org.id}/accept`, undefined, null)).statusCode).toBe(200);
    expect(await t.prisma.membership.findFirstOrThrow({ where: { orgId: org.id, userId: other.id } })).toMatchObject({ role: "owner", status: "active" });
    // A bootstrap-style owner link (not a customer one) still becomes admin when claimed by an existing account.
    const plain = await t.prisma.organization.create({ data: { name: "Plain", slug: `plain-${crypto.randomUUID().slice(0, 8)}` } });
    const { createInvite } = await import("./helpers.js");
    const tok = await createInvite(t.prisma, other.email, "owner", plain.id);
    expect((await call(other, "POST", "/me/join", { token: tok }, null)).json()).toMatchObject({ status: "invited" });
    expect((await t.prisma.membership.findFirstOrThrow({ where: { orgId: plain.id, userId: other.id } })).role).toBe("admin");
  });

  it("resend: a new link and 7 days again, not more than every 5 minutes; then expired shows as expired", async () => {
    const ia = await instanceAdmin();
    const sent = mailbox();
    const { org, inviteUrl } = (await create(ia, "Resendco", "who@resend.test")).json();
    expect((await call(ia, "POST", `/admin/instance/orgs/${org.id}/resend`, undefined, null)).json()).toEqual({ error: "too_soon" });
    await t.prisma.invite.updateMany({ where: { orgId: org.id }, data: { lastSentAt: new Date(Date.now() - 3600e3), expiresAt: new Date(Date.now() - 1000) } });
    expect((await list(ia))[0]).toMatchObject({ id: org.id, status: "expired" });
    const before = sent().length;
    const r = await call(ia, "POST", `/admin/instance/orgs/${org.id}/resend`, undefined, null);
    expect(r.statusCode, r.body).toBe(200);
    expect(r.json()).toMatchObject({ org: { status: "pending" }, emailed: true });
    expect(r.json().inviteUrl).not.toBe(inviteUrl);
    expect(sent().slice(before).map((m) => m.to[0])).toEqual(["who@resend.test"]);
    expect(await t.prisma.invite.findMany({ where: { orgId: org.id }, select: { role: true, source: true, resendCount: true } })).toEqual([{ role: "owner", source: "customer", resendCount: 1 }]);
    // The old link no longer works; the new one does.
    expect((await pub("GET", `/auth/invite/${tokenOf(inviteUrl)}`)).statusCode).toBe(404);
    expect((await pub("GET", `/auth/invite/${tokenOf(r.json().inviteUrl)}`)).json()).toMatchObject({ orgName: "Resendco", email: "who@resend.test" });
    expect(await t.prisma.event.count({ where: { orgId: org.id, action: "admin.invite_resend" } })).toBe(1);
    // An invitation to an existing account (self-hosted: and a link): its 7 days count from its date.
    const acct = await createActiveUser(t);
    const { org: o2 } = (await create(ia, "Existing", acct.email)).json();
    await t.prisma.membership.updateMany({ where: { orgId: o2.id }, data: { createdAt: new Date(Date.now() - INVITE_TTL_MS - 1000) } });
    expect((await list(ia)).find((o) => o.id === o2.id)?.status).toBe("pending");
    await t.prisma.invite.updateMany({ where: { orgId: o2.id }, data: { lastSentAt: new Date(Date.now() - 3600e3), expiresAt: new Date(Date.now() - 1000) } });
    expect((await list(ia)).find((o) => o.id === o2.id)?.status).toBe("expired");
    expect((await call(ia, "POST", `/admin/instance/orgs/${o2.id}/resend`, undefined, null)).json().org.status).toBe("pending");
  });

  it("cancel deletes the never-accepted org, its invitation and its events; the link stops working", async () => {
    const ia = await instanceAdmin();
    const acct = await createActiveUser(t);
    const a = (await create(ia, "Gone", "gone@gone.test")).json();
    const b = (await create(ia, "Gone too", acct.email)).json();
    for (const x of [a, b]) {
      expect((await call(ia, "DELETE", `/admin/instance/orgs/${x.org.id}`, undefined, null)).statusCode).toBe(204);
      expect(await t.prisma.organization.count({ where: { id: x.org.id } })).toBe(0);
      expect(await t.prisma.event.count({ where: { orgId: x.org.id } })).toBe(0);
    }
    expect(await t.prisma.invite.count({ where: { email: "gone@gone.test" } })).toBe(0);
    expect((await pub("GET", `/auth/invite/${tokenOf(a.inviteUrl)}`)).statusCode).toBe(404);
    expect((await call(acct, "GET", "/me/orgs", undefined, null)).json().invitations).toEqual([]);
    expect(await list(ia)).toEqual([]);
    expect((await t.prisma.event.findMany({ where: { action: "instance.customer_org_cancel" } })).map((e) => (e.meta as { name: string }).name).sort()).toEqual(["Gone", "Gone too"]);
    expect((await call(ia, "DELETE", `/admin/instance/orgs/${a.org.id}`, undefined, null)).statusCode).toBe(404);
    // Only organisations created this way: never another organisation.
    expect((await call(ia, "DELETE", `/admin/instance/orgs/${acct.orgId}`, undefined, null)).statusCode).toBe(404);
  });

  it("is for instance admins only, never for their own address, and shows nothing but what the operator typed", async () => {
    const ia = await instanceAdmin();
    const owner = await createActiveUser(t, { role: "admin" });
    const { org } = (await create(ia, "Private", "p@private.test")).json();
    for (const [method, url] of [["GET", "/admin/instance/orgs"], ["POST", "/admin/instance/orgs"], ["POST", `/admin/instance/orgs/${org.id}/resend`], ["DELETE", `/admin/instance/orgs/${org.id}`]] as const)
      expect((await call(owner, method, url, method === "POST" ? { name: "X", ownerEmail: "x@x.test" } : undefined, null)).statusCode, url).toBe(403);
    expect((await create(ia, "Mine", ia.email)).json()).toEqual({ error: "self" });
    expect((await create(ia, "Visit https://evil.test", "a@b.test")).statusCode).toBe(400);
    // Orgs the operator didn't create this way never show.
    await ownerOfNewOrg("Selfserve");
    const rows = await list(ia);
    expect(rows.map((o) => Object.keys(o).sort())).toEqual([["createdAt", "expiresAt", "id", "name", "ownerEmail", "status"]]);
    expect(rows.map((o) => o.name)).toEqual(["Private"]);
  });
});
