import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { execSync } from "node:child_process";
import { cpSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PrismaClient } from "@prisma/client";
import { buildApp } from "../src/app.js";
import type { Config } from "../src/config.js";
import { ensureDefaultOrg } from "../src/lib/orgs.js";
import { newRefreshToken, signAccess } from "../src/lib/tokens.js";

/**
 * The multi-org migration on a database seeded with single-tenant (0.5.3) data: every row lands in the default
 * organisation and nothing is lost (docs/design/2026-10-07-multi-org-design.md §3).
 */
/** The multi-org migrations: everything from here on runs after the legacy data is seeded. */
const FIRST_ORG_MIGRATION = "20261007000000_organizations";
const isOrgMigration = (m: string) => m >= FIRST_ORG_MIGRATION;
const base = new URL(process.env.TEST_DATABASE_URL!);
const dbName = `legacy_${Date.now()}`;
const url = new URL(base.toString()); url.pathname = `/${dbName}`;
const dir = mkdtempSync(join(tmpdir(), "cv-orgmig-"));
let prisma: PrismaClient;

const deploy = () => execSync(`npx prisma migrate deploy --schema "${join(dir, "schema.prisma")}"`, { env: { ...process.env, DATABASE_URL: url.toString() }, stdio: "pipe" });

const ids = {
  admin1: "00000000-0000-4000-8000-000000000001", admin2: "00000000-0000-4000-8000-000000000002", member: "00000000-0000-4000-8000-000000000003",
  disabled: "00000000-0000-4000-8000-000000000004", team: "00000000-0000-4000-8000-0000000000f1", priv: "00000000-0000-4000-8000-0000000000f2",
  rTeam: "00000000-0000-4000-8000-0000000000a1", rPriv: "00000000-0000-4000-8000-0000000000a2",
  linkTeam: "00000000-0000-4000-8000-0000000000b1", linkPriv: "00000000-0000-4000-8000-0000000000b2", linkShare: "00000000-0000-4000-8000-0000000000b3",
};

beforeAll(async () => {
  const admin = new PrismaClient({ datasourceUrl: base.toString() });
  await admin.$executeRawUnsafe(`CREATE DATABASE "${dbName}"`);
  await admin.$disconnect();
  // The schema and every migration before multi-org.
  cpSync("prisma/schema.prisma", join(dir, "schema.prisma"));
  for (const m of readdirSync("prisma/migrations")) if (!isOrgMigration(m)) cpSync(join("prisma/migrations", m), join(dir, "migrations", m), { recursive: true });
  deploy();
  prisma = new PrismaClient({ datasourceUrl: url.toString() });
  const q = (sql: string) => prisma.$executeRawUnsafe(sql);
  const user = (id: string, email: string, role: string, status: string, created: string, extra = "") =>
    q(`INSERT INTO "User" (id,email,name,role,status,"kdfSalt","kdfParams","authHash","wrappedUserKey","publicKey","wrappedPrivateKey","createdAt"${extra ? `,${extra.split("=")[0]}` : ""})
       VALUES ('${id}','${email}','${email.split("@")[0]}','${role}','${status}','salt','{"alg":"argon2id","m":1024,"t":2,"p":1}','hash','v1.wuk','pk','v1.wpk','${created}'${extra ? `,${extra.split("=")[1]}` : ""})`);
  await user(ids.admin1, "first.admin@legacy.io", "admin", "active", "2026-01-01", `"adminSince"='2026-01-01'`);
  await user(ids.admin2, "second.admin@legacy.io", "admin", "active", "2026-02-01", `"adminSince"='2026-02-01'`);
  await user(ids.member, "member@legacy.io", "member", "active", "2026-03-01", `"adminRecoveryAckAt"='2026-05-02'`);
  await user(ids.disabled, "gone@legacy.io", "member", "disabled", "2026-03-02");
  await q(`INSERT INTO "OrgSettings" (id,"adminRecoveryEnabled","adminRecoveryChangedBy","adminRecoveryChangedAt") VALUES (1,true,'${ids.admin1}','2026-05-01')`);
  await q(`INSERT INTO "Invite" (id,email,role,"tokenHash","expiresAt") VALUES (gen_random_uuid(),'invitee@legacy.io','admin','th1',now()+interval '1 day')`);
  await q(`INSERT INTO "Folder" (id,kind,"ownerId","encName","updatedAt") VALUES ('${ids.team}','team','${ids.admin1}','v1.team',now()),('${ids.priv}','private','${ids.member}','v1.priv',now())`);
  await q(`INSERT INTO "FolderMember" (id,"folderId","userId",permission,"wrappedFolderKey") VALUES (gen_random_uuid(),'${ids.team}','${ids.admin1}','owner','s1.k1'),(gen_random_uuid(),'${ids.team}','${ids.member}','edit','s1.k2')`);
  await q(`INSERT INTO "PendingFolderMember" (id,"folderId",email,permission,"createdBy") VALUES (gen_random_uuid(),'${ids.team}','later@legacy.io','view','${ids.admin1}')`);
  await q(`INSERT INTO "Record" (id,"folderId","ownerId",type,"encBody","updatedAt") VALUES ('${ids.rTeam}','${ids.team}','${ids.admin1}','login','v1.body1',now()),('${ids.rPriv}','${ids.priv}','${ids.member}','login','v1.body2',now())`);
  await q(`INSERT INTO "RecordAccess" (id,"recordId","holderType","holderId",permission,"wrappedRecordKey") VALUES
    (gen_random_uuid(),'${ids.rTeam}','user','${ids.admin1}','owner','v1.o1'),(gen_random_uuid(),'${ids.rTeam}','folder','${ids.team}','edit','v1.f1'),
    (gen_random_uuid(),'${ids.rPriv}','user','${ids.member}','owner','v1.o2'),(gen_random_uuid(),'${ids.rPriv}','user','${ids.admin2}','view','s1.share')`);
  await q(`INSERT INTO "ShareLink" (id,"recordId","createdBy","encPayload","expiresAt") VALUES
    ('${ids.linkTeam}','${ids.rTeam}','${ids.member}','v1.x',now()+interval '1 day'),('${ids.linkPriv}','${ids.rPriv}','${ids.member}','v1.y',now()+interval '1 day'),
    ('${ids.linkShare}','${ids.rPriv}','${ids.admin2}','v1.z',now()+interval '1 day')`);
  await q(`INSERT INTO "Event" (action,"actorId","recordId") VALUES ('record.create','${ids.admin1}','${ids.rTeam}'),('auth.login','${ids.member}',NULL)`);
  await q(`INSERT INTO "AdminRecoveryEscrow" (id,"userId","adminId","sealedUserKey") VALUES (gen_random_uuid(),'${ids.member}','${ids.admin1}','s1.e1'),(gen_random_uuid(),'${ids.member}','${ids.admin2}','s1.e2')`);
  await q(`INSERT INTO "RecoveryRequest" (id,"userId",status) VALUES (gen_random_uuid(),'${ids.member}','pending')`);
  // Now the multi-org migrations.
  for (const m of readdirSync("prisma/migrations")) if (isOrgMigration(m)) cpSync(join("prisma/migrations", m), join(dir, "migrations", m), { recursive: true });
  deploy();
}, 180_000);

afterAll(async () => {
  await prisma?.$disconnect();
  const admin = new PrismaClient({ datasourceUrl: base.toString() });
  await admin.$executeRawUnsafe(`DROP DATABASE IF EXISTS "${dbName}" WITH (FORCE)`);
  await admin.$disconnect();
  rmSync(dir, { recursive: true, force: true });
});

describe("multi-org migration of single-tenant data", () => {
  it("creates one default organisation with the old policy, named on start", async () => {
    const orgs = await prisma.organization.findMany();
    expect(orgs).toHaveLength(1);
    expect(orgs[0]).toMatchObject({ name: "", slug: "default", adminRecoveryEnabled: true, adminRecoveryChangedBy: ids.admin1, adminRecoveryChangedAt: new Date("2026-05-01") });
    const config = { productName: "Acme Vault" } as Config;
    await ensureDefaultOrg(prisma, config);
    expect((await prisma.organization.findFirstOrThrow()).name).toBe("Acme Vault org");
    await ensureDefaultOrg(prisma, { ...config, defaultOrgName: "Other" }); // named once, never renamed
    expect((await prisma.organization.findFirstOrThrow()).name).toBe("Acme Vault org");
  });

  it("attaches every user with their role, admin age, acknowledgement and status; the longest-standing admin owns it", async () => {
    const org = await prisma.organization.findFirstOrThrow();
    const ms = await prisma.membership.findMany({ orderBy: { userId: "asc" } });
    expect(ms.map((m) => ({ orgId: m.orgId, userId: m.userId, role: m.role, status: m.status }))).toEqual([
      { orgId: org.id, userId: ids.admin1, role: "owner", status: "active" },
      { orgId: org.id, userId: ids.admin2, role: "admin", status: "active" },
      { orgId: org.id, userId: ids.member, role: "member", status: "active" },
      { orgId: org.id, userId: ids.disabled, role: "member", status: "disabled" },
    ]);
    expect(ms[0]!.adminSince).toEqual(new Date("2026-01-01"));
    expect(ms[1]!.adminSince).toEqual(new Date("2026-02-01"));
    expect(ms[2]!.adminRecoveryAckAt).toEqual(new Date("2026-05-02"));
    expect(ms[2]!.joinedAt).toEqual(new Date("2026-03-01"));
    // The owner of the default org is the instance admin (an account flag); the other admin is not.
    expect((await prisma.user.findMany({ where: { instanceAdmin: true } })).map((u) => u.id)).toEqual([ids.admin1]);
    // Still globally disabled: can't sign in, as before.
    expect((await prisma.user.findUniqueOrThrow({ where: { id: ids.disabled } })).status).toBe("disabled");
  });

  it("moves invites, team folders, shares, links, events, escrows and requests into it; private things stay private", async () => {
    const org = await prisma.organization.findFirstOrThrow();
    expect(await prisma.invite.findFirstOrThrow()).toMatchObject({ orgId: org.id, role: "admin", email: "invitee@legacy.io" });
    expect((await prisma.folder.findUniqueOrThrow({ where: { id: ids.team } })).orgId).toBe(org.id);
    expect((await prisma.folder.findUniqueOrThrow({ where: { id: ids.priv } })).orgId).toBeNull();
    expect(await prisma.folderMember.count()).toBe(2);
    expect(await prisma.pendingFolderMember.count()).toBe(1);
    const access = await prisma.recordAccess.findMany();
    expect(access).toHaveLength(4);
    for (const a of access) expect(a.orgId, `${a.holderType} ${a.permission}`).toBe(a.holderType === "user" && a.permission !== "owner" ? org.id : null);
    const links = Object.fromEntries((await prisma.shareLink.findMany()).map((l) => [l.id, l.orgId]));
    expect(links).toEqual({ [ids.linkTeam]: org.id, [ids.linkPriv]: null, [ids.linkShare]: org.id });
    expect((await prisma.event.findMany()).map((e) => e.orgId)).toEqual([org.id, org.id]);
    // Whole-account escrows end with per-org key pairs (20261014000000_membership_keys): members escrow their
    // membership keys again on their next unlock, and open requests end with their wrapped keys burned.
    expect(await prisma.membershipEscrow.count()).toBe(0);
    expect(await prisma.recoveryRequest.findFirstOrThrow()).toMatchObject({ orgId: org.id, status: "expired", wrappedMembershipKey: null, proofHash: null });
    expect(await prisma.record.count()).toBe(2);
  });

  it("the API serves the migrated data in the default org", async () => {
    const org = await prisma.organization.findFirstOrThrow();
    const config: Config = { databaseUrl: url.toString(), jwtSecret: "test-jwt-secret-test-jwt-secret-test-jwt-secret", serverSecret: "test-server-secret-test-server-secret-test-server",
      publicUrl: "http://localhost:5173", cookieSecure: false, port: 0, kdfMinMemoryKiB: 1024, productName: "Clane Vault", trustProxy: false };
    const app = await buildApp({ config, prisma });
    try {
      const token = async (userId: string) => {
        const s = await prisma.session.create({ data: { userId, refreshHash: newRefreshToken("x").hash, expiresAt: new Date(Date.now() + 3600e3) } });
        return signAccess(config, { userId, sessionId: s.id });
      };
      const get = async (userId: string, path: string) => app.inject({ method: "GET", url: `/api/v1${path}`, headers: { authorization: `Bearer ${await token(userId)}`, "x-org-id": org.id } });
      const s = (await get(ids.member, "/sync")).json();
      expect(s.folders.map((f: { id: string }) => f.id).sort()).toEqual([ids.team, ids.priv].sort());
      expect(s.records.map((r: { id: string }) => r.id).sort()).toEqual([ids.rTeam, ids.rPriv].sort());
      expect(s.records.find((r: { id: string }) => r.id === ids.rPriv).sharedWith).toEqual([expect.objectContaining({ userId: ids.admin2, permission: "view" })]);
      const shared = (await get(ids.admin2, "/sync")).json();
      expect(shared.records.map((r: { id: string }) => r.id)).toContain(ids.rPriv);
      const people = (await get(ids.admin1, "/admin/people")).json();
      expect(people.users).toHaveLength(4);
      expect((await get(ids.admin1, "/admin/settings")).json()).toMatchObject({ adminRecovery: { enabled: true }, escrows: { total: 0, members: 0 } });
      expect((await get(ids.admin1, "/admin/recovery-requests")).json().requests).toHaveLength(0);
      expect((await get(ids.admin1, "/me/orgs")).json()).toMatchObject({ instanceAdmin: true, orgs: [{ id: org.id, role: "owner", isDefault: true }] });
      expect((await get(ids.admin2, "/me/orgs")).json().instanceAdmin).toBe(false);
    } finally { await app.close(); }
  });
});

describe("multi-org migration without an active admin", () => {
  const name2 = `legacy_noadmin_${Date.now()}`;
  const url2 = new URL(base.toString()); url2.pathname = `/${name2}`;
  const dir2 = mkdtempSync(join(tmpdir(), "cv-orgmig2-"));
  const deploy2 = () => execSync(`npx prisma migrate deploy --schema "${join(dir2, "schema.prisma")}"`, { env: { ...process.env, DATABASE_URL: url2.toString() }, stdio: "pipe" });
  let p2: PrismaClient;
  beforeAll(async () => {
    const admin = new PrismaClient({ datasourceUrl: base.toString() });
    await admin.$executeRawUnsafe(`CREATE DATABASE "${name2}"`);
    await admin.$disconnect();
    cpSync("prisma/schema.prisma", join(dir2, "schema.prisma"));
    for (const m of readdirSync("prisma/migrations")) if (!isOrgMigration(m)) cpSync(join("prisma/migrations", m), join(dir2, "migrations", m), { recursive: true });
    deploy2();
    p2 = new PrismaClient({ datasourceUrl: url2.toString() });
    const user = (id: string, email: string, role: string, status: string, created: string) =>
      p2.$executeRawUnsafe(`INSERT INTO "User" (id,email,name,role,status,"kdfSalt","kdfParams","authHash","wrappedUserKey","publicKey","wrappedPrivateKey","createdAt")
        VALUES ('${id}','${email}','n','${role}','${status}','s','{"alg":"argon2id","m":1024,"t":2,"p":1}','h','v1.w','pk','v1.p','${created}')`);
    await user(ids.admin1, "old.admin@legacy.io", "admin", "disabled", "2026-01-01"); // the only admin, disabled
    await user(ids.member, "first.member@legacy.io", "member", "active", "2026-02-01");
    await user(ids.admin2, "second.member@legacy.io", "member", "active", "2026-03-01");
    for (const m of readdirSync("prisma/migrations")) if (isOrgMigration(m)) cpSync(join("prisma/migrations", m), join(dir2, "migrations", m), { recursive: true });
    deploy2();
  }, 180_000);
  afterAll(async () => {
    await p2?.$disconnect();
    const admin = new PrismaClient({ datasourceUrl: base.toString() });
    await admin.$executeRawUnsafe(`DROP DATABASE IF EXISTS "${name2}" WITH (FORCE)`);
    await admin.$disconnect();
    rmSync(dir2, { recursive: true, force: true });
  });

  it("makes the longest-standing active member the owner (and instance admin)", async () => {
    const owners = await p2.membership.findMany({ where: { role: "owner" } });
    expect(owners.map((m) => m.userId)).toEqual([ids.member]);
    expect(owners[0]!.adminSince).not.toBeNull();
    expect((await p2.user.findMany({ where: { instanceAdmin: true } })).map((u) => u.id)).toEqual([ids.member]);
  });
});
