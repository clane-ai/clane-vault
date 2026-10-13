import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { execSync } from "node:child_process";
import { cpSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PrismaClient } from "@prisma/client";
import argon2 from "argon2";
import {
  b64url, createAccount, createTeamFolder, decryptRecordBody, encryptNewRecord, openFolderKey, openRecordKey, openSharedRecordKeyInOrg, openTeamFolderKey,
  sealFolderKeyFor, sealOrgFolderKey, shareRecordKey, unlockMembershipKeys, wrapKey, type MembershipKeys, type UnlockedKeys,
} from "@clane-vault/crypto";
import type { FastifyInstance } from "fastify";
import { buildApp } from "../src/app.js";
import type { Config } from "../src/config.js";
import { hashSecretValue } from "../src/lib/recovery.js";
import { newRefreshToken, signAccess } from "../src/lib/tokens.js";
import { FAST_KDF } from "./helpers.js";
import { escrowKey, keyUp, keysOf, migrateRows, req, type KeyUser } from "./keys.js";

/**
 * Upgrading a 1.0.0 instance (multi-org, groups and policies; before per-org key pairs) to membership keys
 * (20261014000000_membership_keys and later): existing members, team folders, records and direct shares keep opening with
 * real keys, whole-account escrows go and open requests end with their wrapped user keys burned, and the client job then
 * moves everything to membership keys and escrows again (docs/design/2026-10-08-per-org-keypairs.md).
 */
const FIRST_KEYS_MIGRATION = "20261014000000_membership_keys";
const isNew = (m: string) => m >= FIRST_KEYS_MIGRATION;
const base = new URL(process.env.TEST_DATABASE_URL!);
const dbName = `v100_${Date.now()}`;
const url = new URL(base.toString()); url.pathname = `/${dbName}`;
const dir = mkdtempSync(join(tmpdir(), "cv-keysmig-"));
const deploy = () => execSync(`npx prisma migrate deploy --schema "${join(dir, "schema.prisma")}"`, { env: { ...process.env, DATABASE_URL: url.toString() }, stdio: "pipe" });

const ids = {
  owner: "00000000-0000-4000-8000-000000000011", admin: "00000000-0000-4000-8000-000000000012", member: "00000000-0000-4000-8000-000000000013",
  late: "00000000-0000-4000-8000-000000000014", team: "00000000-0000-4000-8000-0000000000e1", rTeam: "00000000-0000-4000-8000-0000000000c1",
  rShared: "00000000-0000-4000-8000-0000000000c2", req: "00000000-0000-4000-8000-0000000000d1",
};
type Acct = { keys: UnlockedKeys; authKey: string; material: Awaited<ReturnType<typeof createAccount>>["material"] };
const accts = {} as Record<"owner" | "admin" | "member" | "late", Acct>;
let orgId = "";
let folderKey: Uint8Array;
let prisma: PrismaClient;
let app: FastifyInstance;
const config: Config = { databaseUrl: url.toString(), jwtSecret: "test-jwt-secret-test-jwt-secret-test-jwt-secret", serverSecret: "test-server-secret-test-server-secret-test-server",
  publicUrl: "http://localhost:5173", cookieSecure: false, port: 0, kdfMinMemoryKiB: 1024, productName: "Clane Vault", trustProxy: false };

beforeAll(async () => {
  const admin = new PrismaClient({ datasourceUrl: base.toString() });
  await admin.$executeRawUnsafe(`CREATE DATABASE "${dbName}"`);
  await admin.$disconnect();
  cpSync("prisma/schema.prisma", join(dir, "schema.prisma"));
  for (const m of readdirSync("prisma/migrations")) if (!isNew(m)) cpSync(join("prisma/migrations", m), join(dir, "migrations", m), { recursive: true });
  deploy();
  prisma = new PrismaClient({ datasourceUrl: url.toString() });
  const q = (sql: string, ...v: unknown[]) => prisma.$executeRawUnsafe(sql, ...v);

  // 1.0.0 data with real keys: an owner, an admin and a member in the default org (admin recovery on, member escrowed
  // with a whole-account escrow and an approved request), a team folder, a team record, a direct share.
  orgId = (await prisma.$queryRawUnsafe<{ id: string }[]>(`SELECT id FROM "Organization" WHERE slug = 'default'`))[0]!.id;
  await q(`UPDATE "Organization" SET name = 'Acme', "adminRecoveryEnabled" = true, "adminRecoveryChangedAt" = '2026-05-01' WHERE id = $1::uuid`, orgId);
  for (const [k, id, role] of [["owner", ids.owner, "owner"], ["admin", ids.admin, "admin"], ["member", ids.member, "member"], ["late", ids.late, "member"]] as const) {
    const a = await createAccount(`password of ${k}`, FAST_KDF);
    accts[k] = { keys: a.keys, authKey: a.authKey, material: a.material };
    await q(`INSERT INTO "User" (id,email,name,status,"kdfSalt","kdfParams","authHash","wrappedUserKey","publicKey","wrappedPrivateKey","createdAt")
      VALUES ($1::uuid,$2,$3,'active',$4,$5::jsonb,$6,$7,$8,$9,'2026-01-01')`, id, `${k}@acme.io`, k, a.material.kdfSalt, JSON.stringify(a.material.kdfParams),
      await argon2.hash(a.authKey, { type: argon2.argon2id }), a.material.wrappedUserKey, a.material.publicKey, a.material.wrappedPrivateKey);
    await q(`INSERT INTO "Membership" (id,"orgId","userId",role,status,"adminSince","adminRecoveryAckAt","joinedAt") VALUES (gen_random_uuid(),$1::uuid,$2::uuid,$3::"OrgRole",'active',$4,$5,'2026-01-01')`,
      orgId, id, role, role === "member" ? null : new Date("2026-01-01"), new Date("2026-05-02"));
  }
  const f = await createTeamFolder(ids.team, "Ops", accts.owner.keys.publicKey);
  folderKey = f.folderKey;
  await q(`INSERT INTO "Folder" (id,kind,"ownerId","orgId","encName","updatedAt") VALUES ($1::uuid,'team',$2::uuid,$3::uuid,$4,now())`, ids.team, ids.owner, orgId, f.encName);
  await q(`INSERT INTO "FolderMember" (id,"folderId","userId",permission,"directPermission","wrappedFolderKey") VALUES (gen_random_uuid(),$1::uuid,$2::uuid,'owner','owner',$3),(gen_random_uuid(),$1::uuid,$4::uuid,'edit','edit',$5)`,
    ids.team, ids.owner, f.wrappedFolderKey, ids.member, await sealFolderKeyFor(folderKey, ids.team, accts.member.keys.publicKey));
  const team = await encryptNewRecord(ids.rTeam, { type: "login", title: "Router", password: "r0uter" }, accts.owner.keys.userKey);
  const shared = await encryptNewRecord(ids.rShared, { type: "note", title: "Shared note" }, accts.owner.keys.userKey);
  await q(`INSERT INTO "Record" (id,"folderId","ownerId",type,"encBody","updatedAt") VALUES ($1::uuid,$2::uuid,$3::uuid,'login',$4,now()),($5::uuid,NULL,$3::uuid,'note',$6,now())`,
    ids.rTeam, ids.team, ids.owner, team.encBody, ids.rShared, shared.encBody);
  await q(`INSERT INTO "RecordAccess" (id,"recordId","holderType","holderId",permission,"wrappedRecordKey","orgId") VALUES
    (gen_random_uuid(),$1::uuid,'user',$2::uuid,'owner',$3,NULL),(gen_random_uuid(),$1::uuid,'folder',$4::uuid,'edit',$5,NULL),
    (gen_random_uuid(),$6::uuid,'user',$2::uuid,'owner',$7,NULL),(gen_random_uuid(),$6::uuid,'user',$8::uuid,'view',$9,$10::uuid)`,
    ids.rTeam, ids.owner, team.wrappedRecordKey, ids.team, await wrapKey(team.recordKey, folderKey, `record-key:${ids.rTeam}`),
    ids.rShared, shared.wrappedRecordKey, ids.member, await shareRecordKey(shared.recordKey, ids.rShared, accts.member.keys.publicKey), orgId);
  await q(`INSERT INTO "AdminRecoveryEscrow" (id,"orgId","userId","adminId","sealedUserKey") VALUES (gen_random_uuid(),$1::uuid,$2::uuid,$3::uuid,'s1.legacy.escrow.x')`, orgId, ids.member, ids.admin);
  await q(`INSERT INTO "RecoveryRequest" (id,"orgId","userId",status,"approvedBy","approvedAt","expiresAt","wrappedUserKey","proofHash") VALUES ($1::uuid,$2::uuid,$3::uuid,'approved',$4::uuid,now(),now()+interval '1 day','v1.legacy-wrapped-user-key',$5)`,
    ids.req, orgId, ids.member, ids.admin, hashSecretValue("proof"));

  // Upgrade.
  for (const m of readdirSync("prisma/migrations")) if (isNew(m)) cpSync(join("prisma/migrations", m), join(dir, "migrations", m), { recursive: true });
  deploy();
  app = await buildApp({ config, prisma });
}, 240_000);

afterAll(async () => {
  await app?.close();
  await prisma?.$disconnect();
  const admin = new PrismaClient({ datasourceUrl: base.toString() });
  await admin.$executeRawUnsafe(`DROP DATABASE IF EXISTS "${dbName}" WITH (FORCE)`);
  await admin.$disconnect();
  rmSync(dir, { recursive: true, force: true });
});

async function client(k: keyof typeof accts, id: string): Promise<KeyUser> {
  const s = await prisma.session.create({ data: { userId: id, refreshHash: newRefreshToken("x").hash, expiresAt: new Date(Date.now() + 3600e3) } });
  return { id, email: `${k}@acme.io`, totpSecret: "", orgId, keys: accts[k].keys, accessToken: await signAccess(config, { userId: id, sessionId: s.id }) };
}
const t = { get app() { return app; } };
type SyncBody = { membershipKeys?: { publicKey: string; wrappedPrivateKey: string }[]; folders: { id: string; kind: string; wrappedFolderKey?: string; sealedTo?: string | null; encName: string }[];
  records: { id: string; holderType: "user" | "folder"; wrappedRecordKey: string; keyFolderId: string | null; folderId: string | null; sealedTo?: string | null; encBody: string }[] };

/** What the web client does with a sync (decryptSync): membership keys bound to the org it asked for, legacy rows on the account key. */
async function openAll(u: KeyUser, s: SyncBody) {
  const ring = new Map<string, MembershipKeys>();
  for (const k of s.membershipKeys ?? []) ring.set(k.publicKey, await unlockMembershipKeys(u.keys.userKey, { orgId, userId: u.id }, k));
  const folderKeys = new Map<string, Uint8Array>();
  for (const f of s.folders.filter((x) => x.kind === "team")) folderKeys.set(f.id, await openTeamFolderKey({ orgId, folderId: f.id, wrappedFolderKey: f.wrappedFolderKey!, sealedTo: f.sealedTo ?? null }, u.keys, ring));
  const titles: Record<string, string> = {};
  for (const r of s.records) {
    const rk = r.holderType === "user" && r.wrappedRecordKey.startsWith("s1.") && r.sealedTo
      ? await openSharedRecordKeyInOrg({ orgId, recordId: r.id, wrappedRecordKey: r.wrappedRecordKey, sealedTo: r.sealedTo }, u.keys, ring)
      : await openRecordKey({ recordId: r.id, holderType: r.holderType, wrappedRecordKey: r.wrappedRecordKey, folderId: r.keyFolderId ?? r.folderId }, u.keys, folderKeys);
    titles[r.id] = (await decryptRecordBody(r.id, r.encBody, rk)).title;
  }
  return { folderKeys, titles };
}

describe("upgrading 1.0.0 data to per-org key pairs", () => {
  it("drops whole-account escrows and ends open requests with their wrapped keys burned", async () => {
    expect(await prisma.membershipEscrow.count()).toBe(0);
    expect(await prisma.$queryRawUnsafe<{ n: number }[]>(`SELECT count(*)::int AS n FROM information_schema.tables WHERE table_name = 'AdminRecoveryEscrow'`)).toEqual([{ n: 0 }]);
    expect(await prisma.recoveryRequest.findUniqueOrThrow({ where: { id: ids.req } })).toMatchObject({ status: "expired", proofHash: null, wrappedMembershipKey: null });
    const rows = await prisma.folderMember.findMany();
    expect(rows.every((r) => r.sealedTo === null)).toBe(true);
    expect((await prisma.user.findMany()).every((u) => u.userKeyGen === 1)).toBe(true);
  });

  it("existing members open everything as before, then the client job moves it to membership keys and escrows again", async () => {
    const owner = await client("owner", ids.owner), member = await client("member", ids.member), adminU = await client("admin", ids.admin);
    // Right after the upgrade: legacy rows open with the account keys.
    let s = (await req(t, member, "GET", "/sync", undefined, orgId)).json() as SyncBody;
    expect(s.membershipKeys).toEqual([]);
    let opened = await openAll(member, s);
    expect(opened.folderKeys.get(ids.team)).toEqual(folderKey);
    expect(opened.titles).toEqual({ [ids.rTeam]: "Router", [ids.rShared]: "Shared note" });
    const so = await openAll(owner, (await req(t, owner, "GET", "/sync", undefined, orgId)).json() as SyncBody);
    expect(so.titles[ids.rTeam]).toBe("Router");

    // The owner (not upgraded yet) can still add someone on their account key.
    const late = await client("late", ids.late);
    expect((await req(t, owner, "POST", `/folders/${ids.team}/members`, { userId: ids.late, permission: "view", wrappedFolderKey: await sealFolderKeyFor(folderKey, ids.team, accts.late.keys.publicKey) }, orgId)).statusCode).toBe(201);
    expect((await openAll(late, (await req(t, late, "GET", "/sync", undefined, orgId)).json() as SyncBody)).titles[ids.rTeam]).toBe("Router");

    // The member's client on unlock: create the key, move rows. Everything still opens, now through the membership key.
    await keyUp(t, adminU);
    const mk = await keyUp(t, member);
    expect(await migrateRows(t, member)).toBe(2);
    s = (await req(t, member, "GET", "/sync", undefined, orgId)).json() as SyncBody;
    expect(s.folders.find((f) => f.id === ids.team)!.sealedTo).toBe(b64url.encode(mk.publicKey));
    expect(s.records.find((r) => r.id === ids.rShared)!.sealedTo).toBe(b64url.encode(mk.publicKey));
    opened = await openAll(member, s);
    expect(opened.titles).toEqual({ [ids.rTeam]: "Router", [ids.rShared]: "Shared note" });
    // From now on, sealing to the member's account key is refused; to the membership key it works.
    expect((await req(t, owner, "POST", `/records/${ids.rTeam}/shares`, { userId: ids.member, permission: "view", sealedRecordKey: await shareRecordKey(new Uint8Array(32), ids.rTeam, accts.member.keys.publicKey) }, orgId)).json()).toEqual({ error: "stale_recipient_key" });
    const f2 = crypto.randomUUID();
    const nf = await createTeamFolder(f2, "Second", accts.owner.keys.publicKey);
    expect((await req(t, owner, "POST", "/folders", { id: f2, kind: "team", encName: nf.encName, wrappedFolderKey: nf.wrappedFolderKey }, orgId)).statusCode).toBe(201);
    expect((await req(t, owner, "POST", `/folders/${f2}/members`, { userId: ids.member, permission: "view", sealedTo: b64url.encode(mk.publicKey), wrappedFolderKey: await sealOrgFolderKey(nf.folderKey, { orgId, folderId: f2 }, mk.publicKey) }, orgId)).statusCode).toBe(201);
    expect((await openAll(member, (await req(t, member, "GET", "/sync", undefined, orgId)).json() as SyncBody)).folderKeys.get(f2)).toEqual(nf.folderKey);

    // Admin recovery comes back: the member (acknowledged before the upgrade) escrows to the owner and admin.
    await keyUp(t, owner);
    expect(await escrowKey(t, member)).toBe(2);
    expect(await prisma.membershipEscrow.count({ where: { userId: ids.member, memberPublicKey: b64url.encode(keysOf(member).get(orgId)!.publicKey) } })).toBe(2);
    expect((await app.inject({ method: "POST", url: "/api/v1/auth/recovery/admin/request", payload: { email: "member@acme.io" }, remoteAddress: "10.99.0.1" })).statusCode).toBe(202);
    expect(await prisma.recoveryRequest.count({ where: { userId: ids.member, orgId, status: "pending" } })).toBe(1);
    // The owner's legacy copy still opens for them (their client moves it on their next unlock).
    expect(await openFolderKey((await prisma.folderMember.findFirstOrThrow({ where: { folderId: ids.team, userId: ids.owner } })).wrappedFolderKey, ids.team, accts.owner.keys)).toEqual(folderKey);
  });
});
