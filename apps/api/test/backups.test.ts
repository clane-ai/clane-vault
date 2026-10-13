import { spawn } from "node:child_process";
import { execSync } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { PrismaClient } from "@prisma/client";
import type { FastifyInstance } from "fastify";
import { generateIdentity, identityToRecipient } from "age-encryption";
import { buildApp } from "../src/app.js";
import type { BackupConfig, Config } from "../src/config.js";
import { LocalDestination } from "../src/lib/backup/destinations.js";
import type { PgRunner } from "../src/lib/backup/pg.js";
import { RestoreRefused, restoreBackup } from "../src/lib/backup/restore.js";
import { BackupService } from "../src/lib/backup/service.js";
import { createActiveUser, makeTestApp, resetDb } from "./helpers.js";
import { testPgRunner } from "./pgRunner.js";

const identity = await generateIdentity();
const recipient = await identityToRecipient(identity);
const silent = { info: () => undefined, warn: () => undefined, error: () => undefined, debug: () => undefined, fatal: () => undefined, trace: () => undefined, child: () => silent, level: "silent", silent: () => undefined } as never;

const base = await makeTestApp();
afterAll(() => base.app.close());

/** A pg_dump stand-in that waits until `release` is created, then fails like a refused connection would. */
function holdingRunner(flag: string): PgRunner {
  return (tool, args, conn) => tool !== "pg_dump" ? testPgRunner(tool, args, conn) : spawn(process.execPath, ["-e",
    `const fs=require("fs");const t=setInterval(()=>{if(fs.existsSync(${JSON.stringify(flag)})){clearInterval(t);console.error("pg_dump: error: connection to server at postgresql://x:hunter2@db failed: password=hunter2");process.exit(1)}},20)`], { stdio: ["pipe", "pipe", "pipe"] });
}

async function backupApp(backup: Partial<BackupConfig> & { localDir: string }, runner: PgRunner = testPgRunner): Promise<{ app: FastifyInstance; prisma: PrismaClient }> {
  const prisma = new PrismaClient({ datasourceUrl: base.config.databaseUrl });
  const config: Config = { ...base.config, backup: { enabled: true, schedule: "30 2 * * *", retentionDays: 14, ageRecipient: recipient, ...backup } };
  const app = await buildApp({ config, prisma, backup: { runner } });
  app.addHook("onClose", () => prisma.$disconnect());
  return { app, prisma };
}

const as = (app: FastifyInstance, token: string, method: "GET" | "POST", url: string) => app.inject({ method, url: `/api/v1${url}`, headers: { authorization: `Bearer ${token}` } });
const counts = async (prisma: PrismaClient, schema: string) => {
  const out: Record<string, number> = {};
  for (const t of ["User", "Session", "Event", "Invite", "BackupRun", "_prisma_migrations"]) {
    out[t] = Number((await prisma.$queryRawUnsafe<{ n: bigint }[]>(`SELECT count(*) AS n FROM "${schema}"."${t}"`))[0]!.n);
  }
  return out;
};

beforeEach(async () => {
  await resetDb(base.prisma);
  await base.prisma.backupRun.deleteMany();
});

describe("admin backups API", () => {
  it("is instance-admin-only (an account flag, never an email or a role) and reports backups off by default", async () => {
    const m = await createActiveUser(base);
    // An org admin, the default org's owner and another org's owner are not instance admins without the flag.
    const orgAdmin = await createActiveUser(base, { role: "admin" });
    const owner = await createActiveUser(base, { role: "owner" });
    const other = await base.prisma.organization.create({ data: { name: "Other", slug: `other-${Date.now()}` } });
    const otherOwner = await createActiveUser(base, { role: "owner", orgId: other.id });
    for (const u of [m, orgAdmin, owner, otherOwner])
      for (const [method, url] of [["GET", "/admin/backups"], ["POST", "/admin/backups/run"]] as const) {
        expect((await as(base.app, u.accessToken, method, url)).statusCode, url).toBe(403);
        expect((await base.app.inject({ method, url: `/api/v1${url}` })).statusCode, url).toBe(401);
      }
    const a = owner;
    await base.prisma.user.update({ where: { id: a.id }, data: { instanceAdmin: true } });
    const s = (await as(base.app, a.accessToken, "GET", "/admin/backups")).json();
    expect(s).toMatchObject({ enabled: false, nextRun: null, lastSuccess: null, lastRun: null, runs: [] });
    expect((await as(base.app, a.accessToken, "POST", "/admin/backups/run")).json()).toEqual({ error: "backups_disabled" });
  });

  it("backs up the app schema to a local dir (encrypted), and restores it into a new schema with the same rows", async () => {
    const dir = mkdtempSync(join(tmpdir(), "cv-bk-"));
    const { app, prisma } = await backupApp({ localDir: dir });
    try {
      const a = await createActiveUser({ app, prisma }, { role: "owner" });
      await prisma.user.update({ where: { id: a.id }, data: { instanceAdmin: true } });
      await createActiveUser({ app, prisma });
      const before = (await as(app, a.accessToken, "GET", "/admin/backups")).json();
      expect(before).toMatchObject({ enabled: true, schedule: "30 2 * * *", timezone: "UTC", retentionDays: 14, destinations: [{ type: "local", dir }], lastSuccess: null });
      expect(new Date(before.nextRun).getUTCHours()).toBe(2);
      expect(JSON.stringify(before)).not.toContain("test-server-secret");

      const res = await as(app, a.accessToken, "POST", "/admin/backups/run");
      expect(res.statusCode).toBe(202);
      await app.backups.idle();
      const s = (await as(app, a.accessToken, "GET", "/admin/backups")).json();
      expect(s.lastRun).toMatchObject({ id: res.json().id, status: "success", trigger: "manual", error: null });
      expect(s.lastSuccess.id).toBe(res.json().id);
      expect(s.lastSuccess.objectKey).toMatch(/^clane-vault-public-\d{8}-\d{6}\.dump\.age$/);
      expect(s.lastSuccess.bytes).toBeGreaterThan(1000);
      expect(s.running).toBe(false);

      const files = readdirSync(dir);
      expect(files).toEqual([s.lastSuccess.objectKey]);
      const file = join(dir, files[0]!);
      const raw = readFileSync(file);
      expect(raw.subarray(0, 21).toString()).toBe("age-encryption.org/v1");
      expect(raw.includes(Buffer.from(a.email))).toBe(false);
      expect(raw.length).toBe(s.lastSuccess.bytes);
      const actions = (await prisma.event.findMany({ where: { action: { startsWith: "backup." } }, orderBy: { id: "asc" } })).map((e) => [e.action, e.actorId]);
      expect(actions).toEqual([["backup.run", a.id], ["backup.success", null]]);

      // Restore into a fresh schema and compare.
      const target = `restored_${Date.now()}`;
      const r = await restoreBackup({ databaseUrl: base.config.databaseUrl, from: file, identities: [identity], targetSchema: target, runner: testPgRunner });
      expect(r).toMatchObject({ sourceSchema: "public", targetSchema: target });
      const want = await counts(prisma, "public");
      // The run row was "running" when the dump was taken; everything else matches.
      expect(await counts(prisma, target)).toEqual({ ...want, Event: want.Event! - 1 });
      expect(want.User).toBe(2);
      const emails = await prisma.$queryRawUnsafe<{ email: string }[]>(`SELECT email FROM "${target}"."User" ORDER BY email`);
      expect(emails.map((e) => e.email)).toContain(a.email);

      // Refuses a schema that has tables, unless forced.
      await expect(restoreBackup({ databaseUrl: base.config.databaseUrl, from: file, identities: [identity], targetSchema: target, runner: testPgRunner })).rejects.toBeInstanceOf(RestoreRefused);
      await prisma.$executeRawUnsafe(`DELETE FROM "${target}"."Session"`);
      await restoreBackup({ databaseUrl: base.config.databaseUrl, from: file, identities: [identity], targetSchema: target, runner: testPgRunner, force: true });
      expect((await counts(prisma, target)).Session).toBe(want.Session);
      // A wrong identity can't read it.
      await expect(restoreBackup({ databaseUrl: base.config.databaseUrl, from: file, identities: [await generateIdentity()], targetSchema: `${target}_x`, runner: testPgRunner })).rejects.toThrow();
      await prisma.$executeRawUnsafe(`DROP SCHEMA "${target}" CASCADE`);
      await prisma.$executeRawUnsafe(`DROP SCHEMA IF EXISTS "${target}_x" CASCADE`);
    } finally { await app.close(); }
  });

  it("answers 409 while a backup is running and records a failure without secrets", async () => {
    const dir = mkdtempSync(join(tmpdir(), "cv-bk-"));
    const flag = join(dir, "release");
    const { app, prisma } = await backupApp({ localDir: join(dir, "out") }, holdingRunner(flag));
    try {
      const a = await createActiveUser({ app, prisma }, { role: "owner" });
      await prisma.user.update({ where: { id: a.id }, data: { instanceAdmin: true } });
      expect((await as(app, a.accessToken, "POST", "/admin/backups/run")).statusCode).toBe(202);
      const again = await as(app, a.accessToken, "POST", "/admin/backups/run");
      expect(again.statusCode).toBe(409);
      expect(again.json()).toEqual({ error: "backup_running" });
      const during = (await as(app, a.accessToken, "GET", "/admin/backups")).json();
      expect(during.running).toBe(true);
      expect(during.lastRun.status).toBe("running");

      // Another instance (same database) is held off by the advisory lock.
      const other = new BackupService({ prisma, databaseUrl: base.config.databaseUrl, log: silent, config: app.config.backup!, destinations: [new LocalDestination(join(dir, "other"))], runner: testPgRunner });
      expect(await other.start("manual")).toEqual({ ok: false, reason: "running" });

      writeFileSync(flag, "");
      await app.backups.idle();
      const after = (await as(app, a.accessToken, "GET", "/admin/backups")).json();
      expect(after.running).toBe(false);
      expect(after.lastSuccess).toBeNull();
      expect(after.lastRun.status).toBe("failed");
      expect(after.lastRun.error).toMatch(/^pg_dump exited with code 1: /);
      expect(after.lastRun.error).not.toContain("hunter2");
      expect(existsSync(join(dir, "out"))).toBe(false);
      expect((await prisma.event.findMany({ where: { action: "backup.failure" } })).length).toBe(1);
      await other.stop();
    } finally { await app.close(); }
  });

  it("runs a scheduled slot once across instances, and marks interrupted runs failed", async () => {
    const dir = mkdtempSync(join(tmpdir(), "cv-bk-"));
    const cfg: BackupConfig = { enabled: true, schedule: "30 2 * * *", retentionDays: 14, ageRecipient: recipient, localDir: dir };
    const mk = () => new BackupService({ prisma: base.prisma, databaseUrl: base.config.databaseUrl, log: silent, config: cfg, runner: testPgRunner });
    await base.prisma.backupRun.create({ data: { trigger: "schedule", destinations: [], startedAt: new Date(Date.now() - 3600e3) } });
    const slot = new Date(Math.floor(Date.now() / 60_000) * 60_000);
    const [x, y] = [mk(), mk()];
    const first = await x.start("schedule", { slot });
    expect(first.ok).toBe(true);
    await x.idle();
    expect(await y.start("schedule", { slot })).toEqual({ ok: false, reason: "skipped" });
    await y.idle();
    const runs = await base.prisma.backupRun.findMany({ orderBy: { startedAt: "asc" } });
    expect(runs.map((r) => [r.status, r.error?.startsWith("Interrupted") ?? false])).toEqual([["failed", true], ["success", false]]);
    await x.stop(); await y.stop();
  });

  it("works as a non-superuser that only owns its schema, with Prisma params in DATABASE_URL", async () => {
    const su = base.prisma;
    const role = `cv_app_${Date.now()}`;
    await su.$executeRawUnsafe(`CREATE ROLE ${role} LOGIN PASSWORD 'app pw/@1'`);
    await su.$executeRawUnsafe(`CREATE SCHEMA ${role}_s AUTHORIZATION ${role}`);
    await su.$executeRawUnsafe(`GRANT CREATE ON DATABASE "${new URL(base.config.databaseUrl).pathname.slice(1)}" TO ${role}`);
    const u = new URL(base.config.databaseUrl);
    u.username = role; u.password = encodeURIComponent("app pw/@1");
    u.search = `?schema=${role}_s&connection_limit=3&pool_timeout=20`;
    const url = u.toString();
    execSync("npx prisma migrate deploy", { env: { ...process.env, DATABASE_URL: url }, stdio: "ignore" });
    const prisma = new PrismaClient({ datasourceUrl: url });
    try {
      await prisma.user.create({ data: { email: "np@clane.ai", name: "Np", kdfSalt: "s", kdfParams: {}, authHash: "h", wrappedUserKey: "w", publicKey: "p", wrappedPrivateKey: "k" } });
      const dir = mkdtempSync(join(tmpdir(), "cv-bk-"));
      const svc = new BackupService({ prisma, databaseUrl: url, log: silent, config: { enabled: true, schedule: "30 2 * * *", retentionDays: 14, ageRecipient: recipient, localDir: dir }, runner: testPgRunner });
      expect((await svc.start("manual")).ok).toBe(true);
      await svc.idle();
      const run = await prisma.backupRun.findFirstOrThrow();
      expect(run.error).toBeNull();
      expect(run.objectKey).toMatch(new RegExp(`^clane-vault-${role}_s-`));
      const target = `${role}_r`;
      const r = await restoreBackup({ databaseUrl: url, from: join(dir, run.objectKey!), identities: [identity], targetSchema: target, runner: testPgRunner });
      expect(r.sourceSchema).toBe(`${role}_s`);
      expect(await su.$queryRawUnsafe<{ email: string }[]>(`SELECT email FROM "${target}"."User"`)).toEqual([{ email: "np@clane.ai" }]);
      await svc.stop();
    } finally {
      await prisma.$disconnect();
      await su.$executeRawUnsafe(`DROP SCHEMA IF EXISTS ${role}_s CASCADE`);
      await su.$executeRawUnsafe(`DROP SCHEMA IF EXISTS ${role}_r CASCADE`);
    }
  });
});
