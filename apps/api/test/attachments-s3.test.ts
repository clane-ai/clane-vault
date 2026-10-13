import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { CreateBucketCommand, ListObjectsV2Command, PutObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { MinioContainer, type StartedMinioContainer } from "@testcontainers/minio";
import { generateIdentity, identityToRecipient } from "age-encryption";
import { encryptNewRecord } from "@clane-vault/crypto";
import { DEFAULT_ATTACHMENTS } from "../src/config.js";
import type { S3Settings } from "../src/lib/backup/destinations.js";
import { BackupService, dumpArgs } from "../src/lib/backup/service.js";
import { restoreBackup } from "../src/lib/backup/restore.js";
import { S3ChunkStore } from "../src/lib/attachments/s3Store.js";
import { DbChunkStore } from "../src/lib/attachments/store.js";
import { moveAttachments } from "../src/lib/attachments/move.js";
import { makeTestApp, resetDb, createActiveUser } from "./helpers.js";
import { testPgRunner } from "./pgRunner.js";
import { attReq, bytes, download, getChunk, prepare, putChunk, create, upload } from "./attachmentClient.js";

const silent = { info: () => undefined, warn: () => undefined, error: () => undefined, debug: () => undefined, fatal: () => undefined, trace: () => undefined, child: () => silent, level: "silent", silent: () => undefined } as never;
const MiB = 1024 * 1024;

// The same MinIO image the backup tests use (override with TEST_MINIO_IMAGE).
let minio: StartedMinioContainer;
let s3: S3Settings;
let client: S3Client;
let t: Awaited<ReturnType<typeof makeTestApp>>;

beforeAll(async () => {
  minio = await new MinioContainer(process.env.TEST_MINIO_IMAGE ?? "chainguard/minio:latest").start();
  s3 = { endpoint: minio.getConnectionUrl(), region: "us-east-1", bucket: "vault-files", prefix: "attachments/", accessKeyId: minio.getUsername(), secretAccessKey: minio.getPassword(), forcePathStyle: true };
  client = new S3Client({ endpoint: s3.endpoint!, region: s3.region, forcePathStyle: true, credentials: { accessKeyId: s3.accessKeyId!, secretAccessKey: s3.secretAccessKey! } });
  await client.send(new CreateBucketCommand({ Bucket: s3.bucket }));
  t = await makeTestApp({ attachments: { ...DEFAULT_ATTACHMENTS, storage: "s3", s3 } });
}, 180_000);
afterAll(async () => { await t?.app.close(); client?.destroy(); await minio?.stop(); });
beforeEach(async () => {
  await resetDb(t.prisma);
  await t.prisma.attachmentTombstone.deleteMany();
  // An empty bucket per test (TRUNCATE leaves objects of the previous test's files behind, which would be orphans).
  const store = new S3ChunkStore(s3);
  for (const id of await store.listAttachmentIds()) await store.deleteAll(id);
  store.destroy();
});

const keys = async (prefix = s3.prefix) => ((await client.send(new ListObjectsV2Command({ Bucket: s3.bucket, Prefix: prefix }))).Contents ?? []).map((o) => o.Key!).sort();
type U = Awaited<ReturnType<typeof createActiveUser>>;
async function privateRecord(u: U) {
  const id = randomUUID();
  const enc = await encryptNewRecord(id, { type: "note", title: "Contract" }, u.keys.userKey);
  expect((await attReq(t, u, "POST", "/records", { id, folderId: null, type: "item", encBody: enc.encBody, wrappedRecordKey: enc.wrappedRecordKey }, { org: null })).statusCode).toBe(201);
  return { id, recordKey: enc.recordKey };
}

describe("S3ChunkStore (MinIO)", () => {
  it("puts, gets, lists and deletes chunks under <prefix><attachmentId>/<index>", async () => {
    const store = new S3ChunkStore(s3);
    const id = randomUUID();
    await store.put(id, 0, bytes(100));
    await store.put(id, 2, bytes(50, 3));
    expect(Buffer.from((await store.get(id, 0))!).equals(Buffer.from(bytes(100)))).toBe(true);
    expect(await store.get(id, 1)).toBeNull();
    expect([...(await store.has(id))].sort()).toEqual([0, 2]);
    expect(await store.listAttachmentIds()).toContain(id);
    expect(store.describe()).toEqual({ bucket: "vault-files", prefix: "attachments/", endpoint: new URL(s3.endpoint!).host });
    await store.deleteAll(id);
    expect((await store.has(id)).size).toBe(0);
    await store.deleteAll(id); // nothing there: fine
    store.destroy();
  });
});

describe("attachments in S3", () => {
  it("uploads to the bucket (Postgres keeps only the index rows), downloads identical bytes, PUT stays idempotent", async () => {
    const a = await createActiveUser(t);
    const rec = await privateRecord(a);
    const data = bytes(2 * MiB + 99);
    const p = await prepare(rec.id, rec.recordKey, data);
    expect((await create(t, a, rec.id, p, { org: null })).statusCode).toBe(201);
    for (let i = 0; i < 3; i++) expect((await putChunk(t, a, rec.id, p.id, i, p.chunks[i]!, { org: null })).statusCode).toBe(200);
    expect((await putChunk(t, a, rec.id, p.id, 1, p.chunks[1]!, { org: null })).statusCode).toBe(200);
    const other = p.chunks[1]!.slice(); other[0]! ^= 1;
    expect((await putChunk(t, a, rec.id, p.id, 1, other, { org: null })).json()).toEqual({ error: "chunk_mismatch" });
    expect((await attReq(t, a, "POST", `/records/${rec.id}/attachments/${p.id}/complete`, {}, { org: null })).statusCode).toBe(200);
    expect(await keys(`${s3.prefix}${p.id}/`)).toEqual([0, 1, 2].map((i) => `${s3.prefix}${p.id}/${i}`));
    const rows = await t.prisma.$queryRaw<{ n: number }[]>`SELECT octet_length(data)::int AS n FROM "AttachmentChunk" WHERE "attachmentId" = ${p.id}::uuid`;
    expect(rows.map((r) => r.n)).toEqual([0, 0, 0]);
    expect((await t.prisma.attachment.findUniqueOrThrow({ where: { id: p.id } })).storage).toBe("s3");
    expect((await download(t, a, rec.id, rec.recordKey, p.id, { org: null })).equals(Buffer.from(data))).toBe(true);
    // The object the bucket holds is the ciphertext the client sent: nothing readable.
    expect((await getChunk(t, a, rec.id, p.id, 0, { org: null })).rawPayload.equals(Buffer.from(p.chunks[0]!))).toBe(true);
  });

  it("removing a file deletes its objects; purging a record writes tombstones that the sweep clears; orphans are found", async () => {
    const a = await createActiveUser(t);
    const rec = await privateRecord(a);
    const p1 = await upload(t, a, rec.id, rec.recordKey, bytes(MiB + 1), { org: null });
    const p2 = await upload(t, a, rec.id, rec.recordKey, bytes(10), { org: null });
    expect((await attReq(t, a, "DELETE", `/records/${rec.id}/attachments/${p1.id}`, undefined, { org: null })).statusCode).toBe(204);
    expect(await keys(`${s3.prefix}${p1.id}/`)).toEqual([]);
    expect((await attReq(t, a, "DELETE", `/records/${rec.id}`, undefined, { org: null })).statusCode).toBe(204);
    expect((await attReq(t, a, "DELETE", `/records/${rec.id}/purge`, undefined, { org: null })).statusCode).toBe(204);
    expect(await t.prisma.attachmentTombstone.findMany()).toMatchObject([{ attachmentId: p2.id, storage: "s3", chunkCount: 1 }]);
    expect(await keys(`${s3.prefix}${p2.id}/`)).toHaveLength(1);
    // An object nobody's row points at (left by an org or account deletion).
    const orphan = randomUUID();
    await client.send(new PutObjectCommand({ Bucket: s3.bucket, Key: `${s3.prefix}${orphan}/0`, Body: "x" }));
    const r = await t.app.attachmentSweeper.run();
    expect(r).toMatchObject({ tombstones: 1, failures: 0, orphansFound: 1 });
    expect(await keys(`${s3.prefix}${p2.id}/`)).toEqual([]);
    expect(await keys(`${s3.prefix}${orphan}/`)).toEqual([]);
    expect(await t.prisma.attachmentTombstone.count()).toBe(0);
  });

  it("the sweep removes an abandoned upload's objects", async () => {
    const a = await createActiveUser(t);
    const rec = await privateRecord(a);
    const p = await prepare(rec.id, rec.recordKey, bytes(MiB + 5));
    expect((await create(t, a, rec.id, p, { org: null })).statusCode).toBe(201);
    expect((await putChunk(t, a, rec.id, p.id, 0, p.chunks[0]!, { org: null })).statusCode).toBe(200);
    await t.prisma.attachment.update({ where: { id: p.id }, data: { createdAt: new Date(Date.now() - 25 * 3600e3) } });
    expect((await t.app.attachmentSweeper.run()).abandoned).toBe(1);
    expect(await keys(`${s3.prefix}${p.id}/`)).toEqual([]);
  });

  it("attachments-move: database to S3 and back, each file flipped only after all its chunks were copied", async () => {
    const dbApp = await makeTestApp(); // ATTACHMENT_STORAGE=db
    try {
      const a = await createActiveUser(dbApp);
      const id = randomUUID();
      const enc = await encryptNewRecord(id, { type: "note", title: "Contract" }, a.keys.userKey);
      expect((await attReq(dbApp, a, "POST", "/records", { id, folderId: null, type: "item", encBody: enc.encBody, wrappedRecordKey: enc.wrappedRecordKey }, { org: null })).statusCode).toBe(201);
      const data = bytes(MiB + 300);
      const p = await upload(dbApp, a, id, enc.recordKey, data, { org: null });
      const stores = { db: new DbChunkStore(t.prisma), s3: new S3ChunkStore(s3), current: "s3" as const };
      const r = await moveAttachments(t.prisma, stores, "s3");
      expect(r).toMatchObject({ moved: 1, chunks: 2, failed: [] });
      expect(await keys(`${s3.prefix}${p.id}/`)).toHaveLength(2);
      expect((await t.prisma.$queryRaw<{ n: number }[]>`SELECT COALESCE(SUM(octet_length(data)), 0)::int AS n FROM "AttachmentChunk" WHERE "attachmentId" = ${p.id}::uuid`)[0]!.n).toBe(0);
      // Served from S3 now, by an app configured for S3.
      expect((await download(t, a, id, enc.recordKey, p.id, { org: null })).equals(Buffer.from(data))).toBe(true);
      const back = await moveAttachments(t.prisma, stores, "db");
      expect(back).toMatchObject({ moved: 1, chunks: 2 });
      expect(await keys(`${s3.prefix}${p.id}/`)).toEqual([]);
      expect((await download(dbApp, a, id, enc.recordKey, p.id, { org: null })).equals(Buffer.from(data))).toBe(true);
      stores.s3.destroy();
    } finally { await dbApp.app.close(); }
  });
});

describe("backups with attachments", () => {
  it("pg_dump runs at compression level 1 and leaves AttachmentChunk data out only when asked", () => {
    const args = dumpArgs("postgresql://x", "public", false);
    expect(args).toContain("--compress=1");
    expect(args.some((a) => a.startsWith("--exclude-table-data"))).toBe(false);
    expect(dumpArgs("postgresql://x", "public", true)).toContain('--exclude-table-data="public"."AttachmentChunk"');
  });

  async function backupAndRestore(storage: "db" | "s3") {
    const identity = await generateIdentity();
    const dir = mkdtempSync(join(tmpdir(), "cv-att-backup-"));
    const svc = new BackupService({ prisma: t.prisma, databaseUrl: t.config.databaseUrl, log: silent, runner: testPgRunner, attachmentStorage: storage,
      config: { enabled: true, schedule: "30 2 * * *", retentionDays: 14, ageRecipient: await identityToRecipient(identity), localDir: dir } });
    expect((await svc.start("manual")).ok).toBe(true);
    await svc.idle();
    const run = await t.prisma.backupRun.findFirstOrThrow({ orderBy: { startedAt: "desc" } });
    expect(run.status).toBe("success");
    const target = `att_restored_${storage}_${Date.now()}`;
    await restoreBackup({ databaseUrl: t.config.databaseUrl, from: run.objectKey!, identities: [identity], targetSchema: target, destinations: svc.destinations, runner: testPgRunner });
    const q = async (sql: string) => Number((await t.prisma.$queryRawUnsafe<{ n: bigint }[]>(sql))[0]!.n);
    const out = { attachments: await q(`SELECT count(*) AS n FROM "${target}"."Attachment"`), chunks: await q(`SELECT count(*) AS n FROM "${target}"."AttachmentChunk"`),
      bytes: await q(`SELECT COALESCE(SUM(octet_length(data)), 0) AS n FROM "${target}"."AttachmentChunk"`), run };
    await t.prisma.$executeRawUnsafe(`DROP SCHEMA "${target}" CASCADE`);
    await svc.stop();
    return out;
  }

  it("with database storage the dump includes every chunk; with S3 (and no file left in the database) it leaves chunk data out; attachmentBytes is recorded", async () => {
    // A second app on the same database, configured for database storage (made first: building it resets the database).
    const dbApp = await makeTestApp();
    await t.prisma.backupRun.deleteMany();
    const a = await createActiveUser(t);
    const rec = await privateRecord(a);
    await upload(t, a, rec.id, rec.recordKey, bytes(MiB + 7), { org: null });
    // Pretend this file lives in the database (as on an instance using db storage).
    const svcProbe = new BackupService({ prisma: t.prisma, databaseUrl: t.config.databaseUrl, log: silent, attachmentStorage: "s3", config: { enabled: false, schedule: "30 2 * * *", retentionDays: 14 } });
    expect(await svcProbe.excludesChunkData()).toBe(true);
    const viaS3 = await backupAndRestore("s3");
    expect(viaS3).toMatchObject({ attachments: 1, chunks: 0 });
    expect(Number(viaS3.run.attachmentBytes)).toBe(MiB + 7 + 32);

    const dbRec = await privateRecord(a);
    try {
      await upload(dbApp, a, dbRec.id, dbRec.recordKey, bytes(5000), { org: null });
    } finally { await dbApp.app.close(); }
    // A half-moved instance (one file still in the database) keeps every chunk in the dump.
    expect(await svcProbe.excludesChunkData()).toBe(false);
    const viaDb = await backupAndRestore("db");
    expect(viaDb.attachments).toBe(2);
    expect(viaDb.bytes).toBe(5016);
  });
});
