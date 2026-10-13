import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { FastifyBaseLogger } from "fastify";
import type { BackupRun, PrismaClient } from "@prisma/client";
import { Cron } from "croner";
import type { BackupConfig } from "../../config.js";
import { logEvent } from "../events.js";
import { encryptStream } from "./age.js";
import { LocalDestination, S3Destination, streamToFile, type Destination } from "./destinations.js";
import { pgConnection, quoteIdent, type PgConn } from "./dsn.js";
import { backupName, selectExpired } from "./naming.js";
import { redact, spawnPg, waitPg, type PgRunner } from "./pg.js";

export type Trigger = "schedule" | "manual";
export type StartResult = { ok: true; runId: string } | { ok: false; reason: "disabled" | "running" | "skipped" | "error" };

export interface BackupServiceOptions {
  prisma: PrismaClient; databaseUrl: string; config: BackupConfig; log: FastifyBaseLogger;
  /** Tests: run pg tools somewhere else, or use other destinations. */
  runner?: PgRunner; destinations?: Destination[];
  /** Where attachment chunks live (ATTACHMENT_STORAGE): with "s3" the dump leaves out AttachmentChunk data. */
  attachmentStorage?: "db" | "s3";
}

const RUN_TIMEOUT_MS = 6 * 3600e3;
/** Advisory lock namespace (first key) for backups; the second key is the schema name's hash. */
const LOCK_NS = 7341;

export function makeDestinations(c: BackupConfig): Destination[] {
  return [...(c.s3 ? [new S3Destination(c.s3)] : []), ...(c.localDir ? [new LocalDestination(c.localDir)] : [])];
}

/** Short and safe to store and show: one line, no URLs or credentials. */
export const shortError = (e: unknown) => redact((e instanceof Error ? e.message : String(e)).split("\n")[0] ?? "error") || "error";

export function serializeRun(r: BackupRun) {
  return { id: r.id, startedAt: r.startedAt.toISOString(), finishedAt: r.finishedAt?.toISOString() ?? null, status: r.status, trigger: r.trigger,
    bytes: r.bytes === null ? null : Number(r.bytes), attachmentBytes: r.attachmentBytes === null ? null : Number(r.attachmentBytes),
    destinations: r.destinations, objectKey: r.objectKey, error: r.error };
}

/**
 * pg_dump arguments (docs/attachments.md, "Backups"): custom format at compression level 1 (attachment ciphertext
 * doesn't compress; level 1 is about the same size as the default 6 at a fraction of the CPU), and with
 * `excludeChunkData` the AttachmentChunk rows' data stays out (the bucket is backed up by the operator).
 */
export function dumpArgs(url: string, schema: string, excludeChunkData: boolean): string[] {
  return [`--dbname=${url}`, `--schema=${quoteIdent(schema)}`, "--no-owner", "--no-privileges", "--format=custom", "--compress=1",
    ...(excludeChunkData ? [`--exclude-table-data=${quoteIdent(schema)}.${quoteIdent("AttachmentChunk")}`] : [])];
}

export class BackupService {
  readonly conn: PgConn;
  readonly destinations: Destination[];
  private readonly runner: PgRunner;
  private current: Promise<void> | null = null;
  private cron: Cron | null = null;

  constructor(private readonly o: BackupServiceOptions) {
    this.conn = pgConnection(o.databaseUrl);
    this.runner = o.runner ?? spawnPg;
    this.destinations = o.destinations ?? makeDestinations(o.config);
  }

  get schema() { return this.conn.schema; }
  get enabled() { return this.o.config.enabled; }
  get running() { return this.current !== null; }
  /** Resolves when the in-flight run (if any) has finished. */
  idle(): Promise<void> { return this.current ?? Promise.resolve(); }

  startScheduler(): void {
    if (!this.enabled || this.cron) return;
    this.cron = new Cron(this.o.config.schedule, { timezone: "UTC", mode: "5-part", protect: true, catch: true }, async () => {
      // Every instance fires at the same minute; the advisory lock plus this slot make sure only one of them backs it up.
      const slot = new Date(Math.floor(Date.now() / 60_000) * 60_000);
      const r = await this.start("schedule", { slot });
      if (r.ok) await this.idle();
      else if (r.reason === "running" || r.reason === "skipped") this.o.log.info({ event: "backup.skipped", reason: r.reason }, "backup.skipped");
    });
    this.o.log.info({ event: "backup.scheduled", schedule: this.o.config.schedule, nextRun: this.cron.nextRun()?.toISOString(), destinations: this.destinations.map((d) => d.describe()) }, "backup.scheduled");
  }

  nextRun(): Date | null {
    if (!this.enabled) return null;
    if (this.cron) return this.cron.nextRun();
    const c = new Cron(this.o.config.schedule, { timezone: "UTC", mode: "5-part", paused: true });
    const n = c.nextRun();
    c.stop();
    return n;
  }

  async stop(): Promise<void> {
    this.cron?.stop();
    this.cron = null;
    await this.idle().catch(() => undefined);
    for (const d of this.destinations) (d as { destroy?: () => void }).destroy?.();
  }

  /**
   * Starts a backup and resolves once it is recorded as running (or refused). The run continues in the background
   * inside a transaction that holds a Postgres advisory lock, so only one instance backs up at a time.
   */
  start(trigger: Trigger, opts: { actorId?: string; slot?: Date } = {}): Promise<StartResult> {
    if (!this.enabled) return Promise.resolve({ ok: false, reason: "disabled" });
    if (this.current) return Promise.resolve({ ok: false, reason: "running" });
    let settle!: (r: StartResult) => void;
    const started = new Promise<StartResult>((r) => { settle = r; });
    const { prisma, log } = this.o;
    const work = prisma.$transaction(async (tx) => {
      const rows = await tx.$queryRaw<{ locked: boolean }[]>`SELECT pg_try_advisory_xact_lock(${LOCK_NS}::int, hashtext(${this.schema})) AS locked`;
      if (!rows[0]?.locked) return settle({ ok: false, reason: "running" });
      // Holding the lock: anything still marked running was cut off (crash, redeploy).
      await prisma.backupRun.updateMany({ where: { status: "running" }, data: { status: "failed", finishedAt: new Date(), error: "Interrupted: the server stopped during the backup" } });
      if (opts.slot && (await prisma.backupRun.count({ where: { trigger: "schedule", startedAt: { gte: opts.slot } } })) > 0) return settle({ ok: false, reason: "skipped" });
      const attachmentBytes = await prisma.$queryRaw<{ n: bigint }[]>`SELECT COALESCE(SUM(size), 0)::bigint AS n FROM "Attachment" WHERE state IN ('uploading', 'ready')`.then((r) => r[0]?.n ?? 0n).catch(() => null);
      const run = await prisma.backupRun.create({ data: { trigger, destinations: this.destinations.map((d) => d.describe()), attachmentBytes } });
      settle({ ok: true, runId: run.id });
      if (trigger === "manual") await logEvent(prisma, { ...(opts.actorId ? { actorId: opts.actorId } : {}), action: "backup.run" }).catch(() => undefined);
      await this.execute(run);
    }, { maxWait: 15_000, timeout: RUN_TIMEOUT_MS }).catch((e: unknown) => {
      // Lock or transaction trouble; the backup itself records its own failures.
      log.error({ event: "backup.failure", error: shortError(e) }, "backup.failure");
      settle({ ok: false, reason: "error" });
    });
    this.current = work.finally(() => { this.current = null; });
    return started;
  }

  private async execute(run: BackupRun): Promise<void> {
    const { prisma, log, config } = this.o;
    const t0 = Date.now();
    const name = backupName(this.schema, run.startedAt);
    const dests = this.destinations.map((d) => d.describe());
    log.info({ event: "backup.start", runId: run.id, trigger: run.trigger, schema: this.schema, destinations: dests }, "backup.start");
    const dir = await mkdtemp(join(tmpdir(), "clane-backup-"));
    try {
      if (!config.ageRecipient) throw new Error("BACKUP_AGE_RECIPIENT is not set; refusing to write an unencrypted backup");
      const file = join(dir, name);
      const bytes = await this.dumpEncrypted(config.ageRecipient, file);
      for (const d of this.destinations) await d.put(name, file);
      await prisma.backupRun.update({ where: { id: run.id }, data: { status: "success", finishedAt: new Date(), bytes: BigInt(bytes), objectKey: name } });
      log.info({ event: "backup.success", runId: run.id, durationMs: Date.now() - t0, bytes, destinations: dests, objectKey: name }, "backup.success");
      await logEvent(prisma, { action: "backup.success" }).catch(() => undefined);
      await this.prune(name);
    } catch (e) {
      const error = shortError(e);
      await prisma.backupRun.update({ where: { id: run.id }, data: { status: "failed", finishedAt: new Date(), error } }).catch(() => undefined);
      log.error({ event: "backup.failure", runId: run.id, durationMs: Date.now() - t0, error }, "backup.failure");
      await logEvent(prisma, { action: "backup.failure" }).catch(() => undefined);
    } finally {
      await rm(dir, { recursive: true, force: true }).catch(() => undefined);
    }
  }

  /**
   * Whether this dump may leave out chunk data: attachments are stored in S3 and no file still has its chunks in the
   * database (a half-moved instance keeps everything in the dump until attachments-move has finished).
   */
  async excludesChunkData(): Promise<boolean> {
    if (this.o.attachmentStorage !== "s3") return false;
    const inDb = await this.o.prisma.attachment.count({ where: { storage: "db" } }).catch(() => 1);
    return inDb === 0;
  }

  /** pg_dump (custom format, this schema only) piped through age into `file`. Returns the encrypted size. */
  private async dumpEncrypted(recipient: string, file: string): Promise<number> {
    const p = this.runner("pg_dump", dumpArgs(this.conn.url, this.schema, await this.excludesChunkData()), this.conn);
    p.stdin?.end();
    const exited = waitPg("pg_dump", p);
    try {
      const [bytes] = await Promise.all([encryptStream(p.stdout!, recipient).then((enc) => streamToFile(enc, file)), exited]);
      return bytes;
    } catch (e) {
      p.kill();
      await exited.catch(() => undefined);
      throw e;
    }
  }

  /** Retention: removes this schema's backups older than BACKUP_RETENTION_DAYS from every destination. Never fails the run. */
  private async prune(keep: string): Promise<void> {
    for (const d of this.destinations) {
      try {
        const expired = selectExpired(await d.list(), { schema: this.schema, days: this.o.config.retentionDays, now: new Date(), keep });
        if (expired.length) {
          await d.remove(expired);
          this.o.log.info({ event: "backup.prune", destination: d.describe().type, removed: expired.length }, "backup.prune");
        }
      } catch (e) {
        this.o.log.warn({ event: "backup.prune_failed", destination: d.describe().type, error: shortError(e) }, "backup.prune_failed");
      }
    }
  }

  async status() {
    const [runs, lastSuccess] = await Promise.all([
      this.o.prisma.backupRun.findMany({ orderBy: { startedAt: "desc" }, take: 30 }),
      this.o.prisma.backupRun.findFirst({ where: { status: "success" }, orderBy: { startedAt: "desc" } }),
    ]);
    const next = this.nextRun();
    return {
      attachments: { storage: this.o.attachmentStorage ?? "db", chunkDataExcluded: await this.excludesChunkData() },
      enabled: this.enabled, schedule: this.o.config.schedule, timezone: "UTC", nextRun: next ? next.toISOString() : null,
      retentionDays: this.o.config.retentionDays, schema: this.schema, destinations: this.destinations.map((d) => d.describe()),
      running: this.running || runs.some((r) => r.status === "running"),
      lastSuccess: lastSuccess ? serializeRun(lastSuccess) : null, lastRun: runs[0] ? serializeRun(runs[0]) : null, runs: runs.map(serializeRun),
    };
  }
}
