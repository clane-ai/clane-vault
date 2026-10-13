import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { b64url, createAccount, createTeamFolder, encryptNewRecord, sealFolderKeyFor, shareRecordKey, wrapKey } from "@clane-vault/crypto";
import { escrowKey, keyUp } from "./keys.js";
import { makeTestApp, resetDb, createActiveUser, createInvite, FAST_KDF, freshTotp } from "./helpers.js";
import { cleanName, nameProblem } from "../src/lib/names.js";

// Security review of 0.6.0 (multi-org): hosted mode, single-org admin recovery, invite enumeration and spam,
// activity scoping, owner protection and the smaller fixes.
const t = await makeTestApp();
afterAll(() => t.app.close());
beforeEach(() => resetDb(t.prisma));
const saved = { ...t.config };
afterEach(() => { vi.restoreAllMocks(); Object.assign(t.config, saved); delete t.config.resendApiKey; delete t.config.emailFrom; delete t.config.hostedMode; });

type U = Awaited<ReturnType<typeof createActiveUser>>;
type M = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
let ipSeq = 0;
const call = (u: U, method: M, url: string, payload?: unknown, org?: string | null) => {
  const o = org === undefined ? u.orgId : org;
  return t.app.inject({ method, url: `/api/v1${url}`, payload: payload as object, remoteAddress: `10.150.${(++ipSeq >> 8) & 255}.${ipSeq & 255}`,
    headers: { authorization: `Bearer ${u.accessToken}`, ...(o ? { "x-org-id": o } : {}) } });
};
const pub = (method: M, url: string, payload?: unknown) => t.app.inject({ method, url: `/api/v1${url}`, payload: payload as object, remoteAddress: `10.151.${(++ipSeq >> 8) & 255}.${ipSeq & 255}` });
const newOrg = (name: string) => t.prisma.organization.create({ data: { name, slug: `${name.toLowerCase().replace(/\W/g, "")}-${crypto.randomUUID().slice(0, 8)}` } });
const join = (u: U, orgId: string, role: "owner" | "admin" | "member" = "member") =>
  t.prisma.membership.create({ data: { orgId, userId: u.id, role, status: "active", joinedAt: new Date(), ...(role !== "member" ? { adminSince: new Date() } : {}) } });
/** Resend stub: every email is captured. */
function mailbox() {
  t.config.resendApiKey = "re_test"; t.config.emailFrom = "vault@clane.ai";
  const spy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("{}", { status: 200 }));
  return () => spy.mock.calls.filter(([u]) => String(u).includes("resend.com")).map(([, init]) => JSON.parse(String((init as RequestInit).body)) as { to: string[]; subject: string; text: string });
}
async function policyOn(orgId: string) {
  await t.prisma.organization.update({ where: { id: orgId }, data: { adminRecoveryEnabled: true, adminRecoveryChangedAt: new Date(Date.now() - 1000) } });
}
/** The member's client: move rows, acknowledge, then escrow to every admin it's asked to. */
const escrow = (m: U) => escrowKey(t, m);
async function privateRecord(u: U) {
  const id = crypto.randomUUID();
  const enc = await encryptNewRecord(id, { type: "login", title: "Mine", password: "pw" }, u.keys.userKey);
  expect((await call(u, "POST", "/records", { id, folderId: null, type: "login", encBody: enc.encBody, wrappedRecordKey: enc.wrappedRecordKey }, null)).statusCode).toBe(201);
  return { id, recordKey: enc.recordKey };
}
async function teamFolder(owner: U, org?: string) {
  const id = crypto.randomUUID();
  const f = await createTeamFolder(id, "Team", owner.keys.publicKey);
  expect((await call(owner, "POST", "/folders", { id, kind: "team", encName: f.encName, wrappedFolderKey: f.wrappedFolderKey }, org)).statusCode).toBe(201);
  return { id, folderKey: f.folderKey };
}
async function addMember(owner: U, f: { id: string; folderKey: Uint8Array }, who: U, permission: string, org?: string) {
  expect((await call(owner, "POST", `/folders/${f.id}/members`, { userId: who.id, permission, wrappedFolderKey: await sealFolderKeyFor(f.folderKey, f.id, who.keys.publicKey) }, org)).statusCode).toBe(201);
}

describe("C1 hosted mode: invites only by email, and sign-up needs an emailed code", () => {
  it("refuses to invite without email, never returns a link, and emails new and existing addresses alike", async () => {
    const a = await createActiveUser(t, { role: "admin" });
    const other = await newOrg("Other");
    const existing = await createActiveUser(t, { orgId: other.id });
    t.config.hostedMode = true;
    expect((await call(a, "POST", "/admin/invites", { email: "new@x.io" })).json()).toEqual({ error: "email_required" });
    const mails = mailbox();
    const r1 = (await call(a, "POST", "/admin/invites", { email: "new@x.io" })).json();
    const r2 = (await call(a, "POST", "/admin/invites", { email: existing.email })).json();
    expect(r1).toEqual({ invited: true, email: "new@x.io", role: "member", emailed: true });
    expect(r2).toEqual({ invited: true, email: existing.email, role: "member", emailed: true });
    const sent = mails();
    expect(sent.map((m) => m.to[0])).toEqual(["new@x.io", existing.email]);
    expect(sent[0]!.text).toMatch(/\/invite\/[A-Za-z0-9_-]{20,}/);
    expect(sent[1]!.text).not.toMatch(/\/invite\//);
  });

  it("registering needs the 6-digit code sent to the invited address; 5 wrong codes burn it", async () => {
    t.config.hostedMode = true;
    const mails = mailbox();
    const token = await createInvite(t.prisma, "sara@x.io");
    expect((await pub("GET", `/auth/invite/${token}`)).json()).toMatchObject({ emailVerification: true });
    const acct = await createAccount("pw for sara", FAST_KDF);
    const reg = (emailCode?: string) => pub("POST", "/auth/register", { inviteToken: token, name: "Sara", authKey: acct.authKey, material: acct.material, ...(emailCode ? { emailCode } : {}) });
    expect((await reg()).json()).toEqual({ error: "email_code_required" });
    expect((await pub("POST", "/auth/register/code", { inviteToken: token })).statusCode).toBe(202);
    const code = /\b(\d{6})\b/.exec(mails().at(-1)!.text)![1]!;
    const wrong = code === "000000" ? "111111" : "000000";
    for (let i = 0; i < 5; i++) expect((await reg(wrong)).json()).toEqual({ error: "email_code_invalid" });
    expect((await reg(code)).json()).toEqual({ error: "email_code_invalid" }); // burned
    expect(await t.prisma.user.count({ where: { email: "sara@x.io" } })).toBe(0);
    await pub("POST", "/auth/register/code", { inviteToken: token });
    const fresh = /\b(\d{6})\b/.exec(mails().at(-1)!.text)![1]!;
    expect((await reg(fresh)).statusCode).toBe(201);
    // An expired code doesn't work either.
    const token2 = await createInvite(t.prisma, "omar@x.io");
    await pub("POST", "/auth/register/code", { inviteToken: token2 });
    const c2 = /\b(\d{6})\b/.exec(mails().at(-1)!.text)![1]!;
    await t.prisma.invite.updateMany({ where: { email: "omar@x.io" }, data: { emailCodeExpiresAt: new Date(Date.now() - 1000) } });
    const acct2 = await createAccount("pw for omar", FAST_KDF);
    expect((await pub("POST", "/auth/register", { inviteToken: token2, name: "Omar", authKey: acct2.authKey, material: acct2.material, emailCode: c2 })).json()).toEqual({ error: "email_code_invalid" });
  });

  it("self-hosted mode keeps the copy-link flow and needs no code", async () => {
    const a = await createActiveUser(t, { role: "admin" });
    const r = (await call(a, "POST", "/admin/invites", { email: "new@x.io" })).json();
    expect(r.inviteUrl).toMatch(/\/invite\//);
    expect((await pub("POST", "/auth/register/code", { inviteToken: r.inviteUrl.split("/invite/")[1] })).json()).toEqual({ error: "not_needed" });
  });

  it("instance admin is an account flag: the bootstrap invite sets it; an email in config or a default-org role does not", async () => {
    const token = await createInvite(t.prisma, "boss@x.io", "owner");
    await t.prisma.invite.updateMany({ where: { email: "boss@x.io" }, data: { instanceAdmin: true } });
    const acct = await createAccount("pw for boss", FAST_KDF);
    expect((await pub("POST", "/auth/register", { inviteToken: token, name: "Boss", authKey: acct.authKey, material: acct.material })).statusCode).toBe(201);
    expect((await t.prisma.user.findUniqueOrThrow({ where: { email: "boss@x.io" } })).instanceAdmin).toBe(true);
    const owner = await createActiveUser(t, { role: "admin" });
    await t.prisma.membership.updateMany({ where: { userId: owner.id }, data: { role: "owner" } });
    expect((await call(owner, "GET", "/me/orgs", undefined, null)).json().instanceAdmin).toBe(false);
    expect((await call(owner, "GET", "/admin/backups", undefined, null)).statusCode).toBe(403);
  });

  it("organisation creation is off unless ALLOW_ORG_CREATION=true, and one account owns at most MAX_OWNED_ORGS", async () => {
    const u = await createActiveUser(t);
    delete t.config.allowOrgCreation;
    expect((await call(u, "POST", "/orgs", { name: "Mine" }, null)).json()).toEqual({ error: "org_creation_disabled" });
    expect((await call(u, "GET", "/me/orgs", undefined, null)).json().allowOrgCreation).toBe(false);
    t.config.allowOrgCreation = true; t.config.maxOwnedOrgs = 1;
    expect((await call(u, "POST", "/orgs", { name: "Mine" }, null)).statusCode).toBe(201);
    expect((await call(u, "POST", "/orgs", { name: "Second" }, null)).json()).toEqual({ error: "org_limit" });
  });

  it("instance admins can always create organisations, past MAX_OWNED_ORGS", async () => {
    const op = await createActiveUser(t);
    await t.prisma.user.update({ where: { id: op.id }, data: { instanceAdmin: true } });
    delete t.config.allowOrgCreation; t.config.maxOwnedOrgs = 1;
    try {
      expect((await call(op, "GET", "/me/orgs", undefined, null)).json().allowOrgCreation).toBe(true);
      expect((await call(op, "POST", "/orgs", { name: "Customer A" }, null)).statusCode).toBe(201);
      expect((await call(op, "POST", "/orgs", { name: "Customer B" }, null)).statusCode).toBe(201);
    } finally { t.config.allowOrgCreation = true; delete t.config.maxOwnedOrgs; }
  });
});

describe("C2 admin recovery is scoped to one org (per-org key pairs)", () => {
  it("joining a second org keeps admin recovery in the first: the escrow is of the first org's membership key only", async () => {
    const admin = await createActiveUser(t, { role: "admin" }), m = await createActiveUser(t);
    await keyUp(t, admin);
    await policyOn(m.orgId);
    expect(await escrow(m)).toBe(1);
    expect((await pub("POST", "/auth/recovery/admin/request", { email: m.email })).statusCode).toBe(202);
    expect(await t.prisma.recoveryRequest.count({ where: { userId: m.id, status: "pending" } })).toBe(1);
    const other = await newOrg("Other");
    const otherOwner = await createActiveUser(t, { role: "owner", orgId: other.id });
    await call(otherOwner, "POST", "/admin/invites", { email: m.email });
    expect((await call(m, "POST", `/me/invitations/${other.id}/accept`, undefined, null)).statusCode).toBe(200);
    expect(await t.prisma.membershipEscrow.count({ where: { userId: m.id } })).toBe(1);
    expect(await t.prisma.recoveryRequest.count({ where: { userId: m.id, status: "pending" } })).toBe(1);
    // The escrowed key is not the account key and not the new org's key.
    const e = await t.prisma.membershipEscrow.findFirstOrThrow({ where: { userId: m.id } });
    expect(e.memberPublicKey).not.toBe(m.material.publicKey);
    const mInOther = await keyUp(t, m, other.id);
    expect(b64url.encode(mInOther.publicKey)).not.toBe(e.memberPublicKey);
  });

  it("recovery emails name the org whose admin acted", async () => {
    const { recoveryAdminActionEmail, recoveryRequestedEmail } = await import("../src/lib/email.js");
    expect(recoveryAdminActionEmail("Clane Vault", "escrow_opened", "Ann", "Acme").text).toContain("an admin of Acme");
    expect(recoveryAdminActionEmail("Clane Vault", "escrow_opened", "Ann", "Acme").text).toContain("never your private items or other organisations");
    expect(recoveryRequestedEmail("Clane Vault", "Acme").text).toContain("admins of Acme");
  });
});

describe("I2 invite spam and names", () => {
  it("caps invites per org per day", async () => {
    t.config.invitesPerOrgPerDay = 2;
    const a = await createActiveUser(t, { role: "admin" });
    expect((await call(a, "POST", "/admin/invites", { email: "a@x.io" })).statusCode).toBe(201);
    expect((await call(a, "POST", "/admin/invites", { email: "b@x.io" })).statusCode).toBe(201);
    expect((await call(a, "POST", "/admin/invites", { email: "c@x.io" })).json()).toEqual({ error: "invite_limit" });
  });

  it("cleans names and refuses links or addresses in them", async () => {
    expect(cleanName("  Acme\n\tLtd ​ ")).toBe("Acme Ltd");
    for (const bad of ["Reset at https://evil.example", "www.evil", "Mail ann@evil.io", "evil.com support", "x".repeat(61), ""]) expect(nameProblem(cleanName(bad)), bad).not.toBeNull();
    expect(nameProblem(cleanName("Acme Ltd."))).toBeNull();
    const u = await createActiveUser(t);
    expect((await call(u, "POST", "/orgs", { name: "Free gift at evil.com" }, null)).statusCode).toBe(400);
    const ok = await call(u, "POST", "/orgs", { name: "Acme\r\nSupport   Team" }, null);
    expect(ok.json().name).toBe("Acme Support Team");
    const token = await createInvite(t.prisma, "n@x.io");
    const acct = await createAccount("pw n", FAST_KDF);
    expect((await pub("POST", "/auth/register", { inviteToken: token, name: "Click https://evil.example", authKey: acct.authKey, material: acct.material })).statusCode).toBe(400);
  });
});

describe("I3 activity and links are scoped to the active org", () => {
  it("a record shared in A and in B: each org sees only its own share events and links", async () => {
    const A = await newOrg("Alpha"), B = await newOrg("Beta");
    const owner = await createActiveUser(t, { orgId: A.id });
    await join(owner, B.id);
    const x = await createActiveUser(t, { orgId: A.id }), y = await createActiveUser(t, { orgId: B.id });
    const p = await privateRecord(owner);
    for (const [who, org] of [[x, A.id], [y, B.id]] as const)
      expect((await call(owner, "POST", `/records/${p.id}/shares`, { userId: who.id, permission: "edit", sealedRecordKey: await shareRecordKey(p.recordKey, p.id, who.keys.publicKey) }, org)).statusCode).toBe(201);
    const lx = (await call(x, "POST", "/links", { id: crypto.randomUUID(), recordId: p.id, encPayload: "v1.AAAA", expiresInHours: 24, maxOpens: null })).json();
    const ly = (await call(y, "POST", "/links", { id: crypto.randomUUID(), recordId: p.id, encPayload: "v1.AAAA", expiresInHours: 24, maxOpens: null })).json();
    const acts = async (u: U, org: string) => (await call(u, "GET", `/records/${p.id}/activity`, undefined, org)).json().events as { action: string; target: string | null }[];
    const xName = x.email.split("@")[0], yName = y.email.split("@")[0];
    const inA = await acts(owner, A.id);
    expect(inA.some((e) => e.action === "record.share" && e.target === xName)).toBe(true);
    expect(inA.some((e) => e.target === yName)).toBe(false);
    expect(inA.some((e) => e.action === "record.create")).toBe(true);
    const seenByX = await acts(x, A.id);
    expect(seenByX.some((e) => e.target === yName)).toBe(false);
    expect(seenByX.some((e) => e.action === "record.create")).toBe(true); // the owner's own (org-less) events
    expect(seenByX.filter((e) => e.action === "link.create")).toHaveLength(1);
    const links = async (u: U, org: string) => ((await call(u, "GET", `/records/${p.id}/links`, undefined, org)).json().links as { id: string }[]).map((l) => l.id);
    expect(await links(owner, A.id)).toEqual([lx.id]);
    expect(await links(owner, B.id)).toEqual([ly.id]);
    expect(await links(x, A.id)).toEqual([lx.id]);
  });

  it("moving a private record into a team folder ends its shares made in other orgs", async () => {
    const A = await newOrg("Alpha"), B = await newOrg("Beta");
    const owner = await createActiveUser(t, { orgId: A.id });
    await join(owner, B.id);
    const x = await createActiveUser(t, { orgId: A.id }), y = await createActiveUser(t, { orgId: B.id });
    const p = await privateRecord(owner);
    for (const [who, org] of [[x, A.id], [y, B.id]] as const)
      await call(owner, "POST", `/records/${p.id}/shares`, { userId: who.id, permission: "view", sealedRecordKey: await shareRecordKey(p.recordKey, p.id, who.keys.publicKey) }, org);
    const f = await teamFolder(owner, A.id);
    const r = await call(owner, "PUT", `/records/${p.id}/folder`, { folderId: f.id, folderWrappedRecordKey: await wrapKey(p.recordKey, f.folderKey, `record-key:${p.id}`), ownerWrappedRecordKey: "v1.AAAA" }, A.id);
    expect(r.statusCode).toBe(200);
    const rows = await t.prisma.recordAccess.findMany({ where: { recordId: p.id, holderType: "user", permission: { not: "owner" } } });
    expect(rows.map((x2) => x2.holderId)).toEqual([x.id]);
  });
});

describe("I4 owners and invitations", () => {
  it("no org admin can reset an owner's 2FA (any org); enabling an invitation is refused", async () => {
    const admin = await createActiveUser(t, { role: "admin" });
    const owner = await createActiveUser(t, { role: "owner" });
    const side = await newOrg("Side");
    const ownerOfSide = await createActiveUser(t);
    await join(ownerOfSide, side.id, "owner");
    expect((await call(admin, "POST", `/admin/users/${owner.id}/reset-2fa`)).json()).toEqual({ error: "owner" });
    expect((await call(admin, "POST", `/admin/users/${ownerOfSide.id}/reset-2fa`)).json()).toEqual({ error: "other_orgs" });
    await t.prisma.user.update({ where: { id: admin.id }, data: { instanceAdmin: true } });
    expect((await call(admin, "POST", `/admin/users/${ownerOfSide.id}/reset-2fa`)).statusCode).toBe(200);
    // An invited (not yet accepted) membership can't be "enabled" into an active one, even for a disabled account.
    const other = await newOrg("Other");
    const invitee = await createActiveUser(t, { orgId: other.id });
    await call(admin, "POST", "/admin/invites", { email: invitee.email });
    await t.prisma.user.update({ where: { id: invitee.id }, data: { status: "disabled" } });
    expect((await call(admin, "POST", `/admin/users/${invitee.id}/enable`)).json()).toEqual({ error: "not_disabled" });
    expect((await t.prisma.membership.findFirstOrThrow({ where: { userId: invitee.id, orgId: admin.orgId } })).status).toBe("invited");
  });
});

describe("minor fixes", () => {
  it("renaming a private folder logs no org: it never shows in the org's event log or export", async () => {
    const u = await createActiveUser(t), a = await createActiveUser(t, { role: "admin" });
    const id = crypto.randomUUID();
    const { encryptFolderName } = await import("@clane-vault/crypto");
    expect((await call(u, "POST", "/folders", { id, encName: await encryptFolderName(id, "Mine", u.keys.userKey) })).statusCode).toBe(201);
    expect((await call(u, "PATCH", `/folders/${id}`, { encName: await encryptFolderName(id, "Still mine", u.keys.userKey) })).statusCode).toBe(200);
    const ev = await t.prisma.event.findMany({ where: { folderId: id } });
    expect(ev.map((e) => [e.action, e.orgId])).toEqual([["folder.create", null], ["folder.rename", null]]);
    expect(JSON.stringify((await call(a, "GET", "/admin/events")).json())).not.toContain(id);
    const team = await teamFolder(u);
    const { encryptFolderName: enc } = await import("@clane-vault/crypto");
    await call(u, "PATCH", `/folders/${team.id}`, { encName: await enc(team.id, "Team 2", team.folderKey) });
    expect((await t.prisma.event.findFirstOrThrow({ where: { folderId: team.id, action: "folder.rename" } })).orgId).toBe(u.orgId);
  });

  it("disable drops the member's escrows in that org; re-enable restarts their admin age", async () => {
    const a = await createActiveUser(t, { role: "admin" }), b = await createActiveUser(t, { role: "admin" }), m = await createActiveUser(t);
    for (const x of [a, b]) await keyUp(t, x);
    await policyOn(m.orgId);
    await escrow(m);
    await escrow(b);
    await t.prisma.membership.updateMany({ where: { userId: b.id }, data: { adminSince: new Date("2020-01-01") } });
    expect(await t.prisma.membershipEscrow.count({ where: { userId: b.id } })).toBe(1);
    await call(a, "POST", `/admin/users/${b.id}/disable`);
    expect(await t.prisma.membershipEscrow.count({ where: { OR: [{ userId: b.id }, { adminId: b.id }] } })).toBe(0);
    await call(a, "POST", `/admin/users/${b.id}/enable`);
    expect((await t.prisma.membership.findFirstOrThrow({ where: { userId: b.id } })).adminSince!.getTime()).toBeGreaterThan(Date.now() - 60_000);
  });

  it("demoting an admin also ends the reset links they approved", async () => {
    const a = await createActiveUser(t, { role: "admin" }), b = await createActiveUser(t, { role: "admin" }), m = await createActiveUser(t);
    const r = await t.prisma.recoveryRequest.create({ data: { orgId: m.orgId, userId: m.id, status: "approved", approvedBy: b.id, approvedAt: new Date(), expiresAt: new Date(Date.now() + 3600e3), wrappedMembershipKey: "v1.x", proofHash: "ab" } });
    expect((await call(a, "PATCH", `/admin/members/${b.id}`, { role: "member" })).statusCode).toBe(200);
    expect(await t.prisma.recoveryRequest.findUniqueOrThrow({ where: { id: r.id } })).toMatchObject({ status: "expired", wrappedMembershipKey: null, proofHash: null });
  });

  it("a leaving folder owner never hands the folder to a use-only member: then it goes to the trash", async () => {
    const o = await createActiveUser(t), u = await createActiveUser(t), v = await createActiveUser(t);
    const onlyUse = await teamFolder(o);
    await addMember(o, onlyUse, u, "use");
    const withView = await teamFolder(o);
    await addMember(o, withView, u, "use");
    await addMember(o, withView, v, "view");
    expect((await call(o, "POST", "/org/leave")).statusCode).toBe(204);
    expect((await t.prisma.folder.findUniqueOrThrow({ where: { id: onlyUse.id } })).deletedAt).not.toBeNull();
    expect((await t.prisma.folder.findUniqueOrThrow({ where: { id: withView.id } })).ownerId).toBe(v.id);
  });
});

describe("re-review: races, code caps, org deletion, instance admin, invite dates", () => {
  it("sign-up codes: concurrent wrong guesses count atomically; a total cap burns the invite; re-issues are capped", async () => {
    const a = await createActiveUser(t, { role: "admin" });
    void a;
    t.config.hostedMode = true;
    const mails = mailbox();
    const token = await createInvite(t.prisma, "c@x.io");
    const acct = await createAccount("pw for c", FAST_KDF);
    const reg = (emailCode: string) => pub("POST", "/auth/register", { inviteToken: token, name: "C", authKey: acct.authKey, material: acct.material, emailCode });
    expect((await pub("POST", "/auth/register/code", { inviteToken: token })).statusCode).toBe(202);
    const code = /\b(\d{6})\b/.exec(mails().at(-1)!.text)![1]!;
    const wrong = code === "000000" ? "111111" : "000000";
    await Promise.all(Array.from({ length: 10 }, () => reg(wrong)));
    const inv = await t.prisma.invite.findFirstOrThrow({ where: { email: "c@x.io" } });
    expect(inv.emailCodeAttempts).toBe(5);
    expect(inv.emailCodeHash).toBeNull();
    expect((await reg(code)).json()).toEqual({ error: "email_code_invalid" });
    // Two more codes, five wrong guesses each: 15 in total burns the invite.
    for (let i = 0; i < 2; i++) {
      expect((await pub("POST", "/auth/register/code", { inviteToken: token })).statusCode).toBe(202);
      for (let j = 0; j < 5; j++) await reg(wrong);
    }
    expect((await pub("GET", `/auth/invite/${token}`)).statusCode).toBe(404);
    expect((await pub("POST", "/auth/register/code", { inviteToken: token })).json()).toEqual({ error: "invite_invalid" });
    // Re-issue cap: the sixth code for one invite is refused.
    const token2 = await createInvite(t.prisma, "d@x.io");
    for (let i = 0; i < 5; i++) expect((await pub("POST", "/auth/register/code", { inviteToken: token2 })).statusCode).toBe(202);
    expect((await pub("POST", "/auth/register/code", { inviteToken: token2 })).json()).toEqual({ error: "code_limit" });
  });

  it("registering is rate limited per address (10 a minute at the default limit)", async () => {
    const codes: number[] = [];
    for (let i = 0; i < 11; i++) {
      const r = await t.app.inject({ method: "POST", url: "/api/v1/auth/register", remoteAddress: "10.170.0.1", payload: { inviteToken: "x".repeat(20), name: "N", authKey: "AAAA", material: {} } });
      codes.push(r.statusCode);
    }
    expect(codes.slice(0, 10).every((c) => c === 400)).toBe(true);
    expect(codes[10]).toBe(429);
  });

  it("deleting an org deletes its events (none become org-less)", async () => {
    const u = await createActiveUser(t);
    const org = (await call(u, "POST", "/orgs", { name: "Doomed" }, null)).json();
    const f = await teamFolder(u, org.id);
    void f;
    expect(await t.prisma.event.count({ where: { orgId: org.id } })).toBeGreaterThan(0);
    const before = await t.prisma.event.count({ where: { orgId: null } });
    expect((await call(u, "DELETE", "/org", { confirmName: "Doomed", trashTeamFolders: true }, org.id)).statusCode).toBe(204);
    expect(await t.prisma.event.count({ where: { orgId: org.id } })).toBe(0);
    // Only the deletion itself is logged (org-less, by the owner).
    expect((await t.prisma.event.findMany({ where: { orgId: null } })).slice(before).map((x) => x.action)).toEqual(["org.delete"]);
  });

  it("instance admin goes when the account stops being owner or admin of the main org", async () => {
    const o = await createActiveUser(t, { role: "owner" }), b = await createActiveUser(t);
    await t.prisma.user.update({ where: { id: o.id }, data: { instanceAdmin: true } });
    // Transfer: o stays an admin, so stays instance admin.
    expect((await call(o, "POST", "/org/transfer", { userId: b.id })).statusCode).toBe(200);
    expect((await t.prisma.user.findUniqueOrThrow({ where: { id: o.id } })).instanceAdmin).toBe(true);
    // Demoted to member: revoked, with an event.
    expect((await call(b, "PATCH", `/admin/members/${o.id}`, { role: "member" })).statusCode).toBe(200);
    expect((await t.prisma.user.findUniqueOrThrow({ where: { id: o.id } })).instanceAdmin).toBe(false);
    expect(await t.prisma.event.count({ where: { action: "instance.admin_revoked", targetUserId: o.id } })).toBe(1);
    // Removed: revoked too.
    const c = await createActiveUser(t, { role: "admin" });
    await t.prisma.user.update({ where: { id: c.id }, data: { instanceAdmin: true } });
    expect((await call(b, "DELETE", `/admin/members/${c.id}`)).statusCode).toBe(204);
    expect((await t.prisma.user.findUniqueOrThrow({ where: { id: c.id } })).instanceAdmin).toBe(false);
  });

  it("an invite turned into an invitation at registration keeps the invite's date", async () => {
    const A = await newOrg("Alpha"), B = await newOrg("Beta");
    const tokenA = await createInvite(t.prisma, "late@x.io", "member", A.id);
    await createInvite(t.prisma, "late@x.io", "member", B.id);
    const sent = new Date(Date.now() - 3 * 864e5);
    await t.prisma.invite.updateMany({ where: { email: "late@x.io", orgId: B.id }, data: { createdAt: sent } });
    const acct = await createAccount("pw late", FAST_KDF);
    expect((await pub("POST", "/auth/register", { inviteToken: tokenA, name: "Late", authKey: acct.authKey, material: acct.material })).statusCode).toBe(201);
    const m = await t.prisma.membership.findFirstOrThrow({ where: { orgId: B.id, user: { email: "late@x.io" } } });
    expect(m.status).toBe("invited");
    expect(m.createdAt.getTime()).toBe(sent.getTime());
  });
});
