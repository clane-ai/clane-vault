import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { execSync } from "node:child_process";
import { cpSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PrismaClient } from "@prisma/client";
import { aeadEncrypt, decryptRecord, randomBytes, utf8 } from "@clane-vault/crypto";

/**
 * Upgrading to record types (20261020000000_record_item_type): existing "note" rows become "item", logins stay, the
 * encrypted bodies are untouched (v1 bodies still open), and the column only takes "login" or "item" from then on.
 */
const MIGRATION = "20261020000000_record_item_type";
const base = new URL(process.env.TEST_DATABASE_URL!);
const dbName = `rtype_${Date.now()}`;
const url = new URL(base.toString()); url.pathname = `/${dbName}`;
const dir = mkdtempSync(join(tmpdir(), "cv-rtype-"));
const deploy = () => execSync(`npx prisma migrate deploy --schema "${join(dir, "schema.prisma")}"`, { env: { ...process.env, DATABASE_URL: url.toString() }, stdio: "pipe" });
const copy = (pick: (m: string) => boolean) => { for (const m of readdirSync("prisma/migrations")) if (pick(m)) cpSync(join("prisma/migrations", m), join(dir, "migrations", m), { recursive: true }); };

const userKey = randomBytes(32);
const ids = { user: "00000000-0000-4000-8000-000000000101", login: "00000000-0000-4000-8000-0000000001a1", note: "00000000-0000-4000-8000-0000000001a2" };
const bodies: Record<string, { enc: string; wrapped: string; plain: object }> = {};
let prisma: PrismaClient;

/** A v1 body as an old client wrote it (no version), encrypted without today's validation. */
async function v1(id: string, plain: object) {
  const rk = randomBytes(32);
  bodies[id] = { enc: await aeadEncrypt(rk, utf8.encode(JSON.stringify(plain)), `record-body:${id}`), wrapped: await aeadEncrypt(userKey, rk, `record-key:${id}`), plain };
}

beforeAll(async () => {
  const admin = new PrismaClient({ datasourceUrl: base.toString() });
  await admin.$executeRawUnsafe(`CREATE DATABASE "${dbName}"`);
  await admin.$disconnect();
  cpSync("prisma/schema.prisma", join(dir, "schema.prisma"));
  copy((m) => m < MIGRATION && m !== "migration_lock.toml");
  cpSync("prisma/migrations/migration_lock.toml", join(dir, "migrations", "migration_lock.toml"));
  deploy();
  prisma = new PrismaClient({ datasourceUrl: url.toString() });
  const q = (sql: string, ...v: unknown[]) => prisma.$executeRawUnsafe(sql, ...v);
  await q(`INSERT INTO "User" (id,email,name,status,"kdfSalt","kdfParams","authHash","wrappedUserKey","publicKey","wrappedPrivateKey") VALUES ($1::uuid,'a@x.io','A','active','s','{}'::jsonb,'h','w','p','wp')`, ids.user);
  await v1(ids.login, { type: "login", title: "Router", username: "admin", password: "r0uter" });
  await v1(ids.note, { type: "note", title: "Alarm code", notes: "1234" });
  await q(`INSERT INTO "Record" (id,"ownerId",type,"encBody","updatedAt") VALUES ($1::uuid,$3::uuid,'login',$4,now()),($2::uuid,$3::uuid,'note',$5,now())`,
    ids.login, ids.note, ids.user, bodies[ids.login]!.enc, bodies[ids.note]!.enc);
  copy((m) => m >= MIGRATION && m !== "migration_lock.toml");
  deploy();
}, 240_000);

afterAll(async () => {
  await prisma?.$disconnect();
  const admin = new PrismaClient({ datasourceUrl: base.toString() });
  await admin.$executeRawUnsafe(`DROP DATABASE IF EXISTS "${dbName}" WITH (FORCE)`);
  await admin.$disconnect();
  rmSync(dir, { recursive: true, force: true });
});

describe("record item type migration", () => {
  it("turns notes into items, keeps logins, leaves the encrypted bodies as they were", async () => {
    const rows = await prisma.record.findMany({ orderBy: { id: "asc" } });
    expect(rows.map((r) => [r.id, r.type])).toEqual([[ids.login, "login"], [ids.note, "item"]]);
    for (const r of rows) {
      expect(r.encBody).toBe(bodies[r.id]!.enc);
      expect((await decryptRecord(r.id, r.encBody, bodies[r.id]!.wrapped, userKey)).body).toEqual(bodies[r.id]!.plain);
    }
  });

  it("only takes login or item afterwards", async () => {
    await expect(prisma.record.update({ where: { id: ids.note }, data: { type: "note" } })).rejects.toThrow(/Record_type_check|check constraint/i);
    await expect(prisma.record.update({ where: { id: ids.note }, data: { type: "card" } })).rejects.toThrow(/Record_type_check|check constraint/i);
    await prisma.record.update({ where: { id: ids.note }, data: { type: "login" } });
  });
});
