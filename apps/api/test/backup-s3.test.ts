import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { CreateBucketCommand, PutObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { MinioContainer, type StartedMinioContainer } from "@testcontainers/minio";
import { generateIdentity, identityToRecipient } from "age-encryption";
import { S3Destination, type S3Settings } from "../src/lib/backup/destinations.js";
import { restoreBackup } from "../src/lib/backup/restore.js";
import { BackupService } from "../src/lib/backup/service.js";
import { makeTestApp, resetDb, createActiveUser } from "./helpers.js";
import { testPgRunner } from "./pgRunner.js";

const silent = { info: () => undefined, warn: () => undefined, error: () => undefined, debug: () => undefined, fatal: () => undefined, trace: () => undefined, child: () => silent, level: "silent", silent: () => undefined } as never;

// minio/minio is no longer published on Docker Hub; Chainguard's build is a drop-in (override with TEST_MINIO_IMAGE).
let minio: StartedMinioContainer;
let s3: S3Settings;
const t = await makeTestApp();

beforeAll(async () => {
  minio = await new MinioContainer(process.env.TEST_MINIO_IMAGE ?? "chainguard/minio:latest").start();
  s3 = { endpoint: minio.getConnectionUrl(), region: "us-east-1", bucket: "vault-backups", prefix: "clane-vault/", accessKeyId: minio.getUsername(), secretAccessKey: minio.getPassword(), forcePathStyle: true };
  const c = new S3Client({ endpoint: s3.endpoint!, region: s3.region, forcePathStyle: true, credentials: { accessKeyId: s3.accessKeyId!, secretAccessKey: s3.secretAccessKey! } });
  await c.send(new CreateBucketCommand({ Bucket: s3.bucket }));
  // Already there: an expired backup of this schema, an expired one of another schema, and an unrelated object.
  for (const Key of ["clane-vault/clane-vault-public-20200101-000000.dump.age", "clane-vault/clane-vault-other-20200101-000000.dump.age", "clane-vault/notes.txt", "elsewhere/clane-vault-public-20200101-000000.dump.age"]) {
    await c.send(new PutObjectCommand({ Bucket: s3.bucket, Key, Body: "x" }));
  }
  c.destroy();
}, 180_000);
afterAll(async () => { await t.app.close(); await minio?.stop(); });

describe("S3 destination (MinIO)", () => {
  it("uploads, lists, reads back and deletes under the prefix", async () => {
    const d = new S3Destination(s3);
    const f = join(mkdtempSync(join(tmpdir(), "cv-s3-")), "a");
    writeFileSync(f, Buffer.alloc(64 * 1024, 7));
    await d.put("probe.bin", f);
    expect(await d.list()).toContain("probe.bin");
    const chunks: Buffer[] = [];
    for await (const c of await d.get("probe.bin")) chunks.push(Buffer.from(c as Uint8Array));
    expect(Buffer.concat(chunks).length).toBe(64 * 1024);
    expect(d.describe()).toEqual({ type: "s3", bucket: "vault-backups", prefix: "clane-vault/", endpoint: new URL(s3.endpoint!).host });
    await d.remove(["probe.bin"]);
    expect(await d.list()).not.toContain("probe.bin");
    d.destroy();
  });

  it("backs up to S3, prunes only this schema's expired backups, and restores from the object key", async () => {
    await resetDb(t.prisma);
    await t.prisma.backupRun.deleteMany();
    await createActiveUser(t, { role: "admin" });
    const identity = await generateIdentity();
    const svc = new BackupService({ prisma: t.prisma, databaseUrl: t.config.databaseUrl, log: silent, runner: testPgRunner,
      config: { enabled: true, schedule: "30 2 * * *", retentionDays: 14, ageRecipient: await identityToRecipient(identity), s3 } });
    expect((await svc.start("schedule")).ok).toBe(true);
    await svc.idle();
    const run = await t.prisma.backupRun.findFirstOrThrow();
    expect(run).toMatchObject({ status: "success", trigger: "schedule", error: null });
    expect(run.destinations).toEqual([{ type: "s3", bucket: "vault-backups", prefix: "clane-vault/", endpoint: new URL(s3.endpoint!).host }]);
    expect(JSON.stringify({ ...run, bytes: Number(run.bytes), attachmentBytes: Number(run.attachmentBytes) })).not.toContain(s3.secretAccessKey!);
    const names = (await svc.destinations[0]!.list()).sort();
    expect(names).toEqual(["clane-vault-other-20200101-000000.dump.age", run.objectKey, "notes.txt"].sort());

    const target = `s3_restored_${Date.now()}`;
    const r = await restoreBackup({ databaseUrl: t.config.databaseUrl, from: `clane-vault/${run.objectKey}`, identities: [identity], targetSchema: target, destinations: svc.destinations, runner: testPgRunner });
    expect(r.sourceSchema).toBe("public");
    expect(Number((await t.prisma.$queryRawUnsafe<{ n: bigint }[]>(`SELECT count(*) AS n FROM "${target}"."User"`))[0]!.n)).toBe(1);
    await t.prisma.$executeRawUnsafe(`DROP SCHEMA "${target}" CASCADE`);
    await svc.stop();
  });
});
