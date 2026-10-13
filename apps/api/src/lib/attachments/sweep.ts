import type { PrismaClient } from "@prisma/client";
import type { Db } from "../access.js";
import { logEvent } from "../events.js";
import { chargeOf } from "./quota.js";
import { storeFor, type ChunkStores } from "./store.js";

/** Uploads not completed within this long are swept (their reservation is released). */
export const UPLOAD_TTL_MS = 24 * 3600e3;
/** The S3 orphan pass (objects without an Attachment row) runs at most this often. */
const ORPHAN_PASS_MS = 24 * 3600e3;
const BATCH = 200;

export interface SweepReport {
  at: string; abandoned: number; deleted: number; tombstones: number; failures: number;
  /** The last S3 orphan pass: when, and how many attachment ids had objects but no row (they were removed). */
  orphanPassAt: string | null; orphansFound: number;
}

/**
 * Records purged in this transaction take their Attachment rows with them (FK cascade): db chunks cascade too, S3
 * objects don't, so their ids are written down for the sweep. Call before deleting the records.
 */
export async function tombstoneAttachments(tx: Db, recordIds: string[]): Promise<number> {
  if (!recordIds.length) return 0;
  return tx.$executeRaw`INSERT INTO "AttachmentTombstone" ("attachmentId", "storage", "chunkCount")
    SELECT id, storage, "chunkCount" FROM "Attachment" WHERE "recordId" = ANY(${recordIds}::uuid[]) AND storage = 's3' ON CONFLICT DO NOTHING`;
}

/**
 * The attachment part of the periodic sweep (docs/design/2026-10-12-attachments.md §3.6): abandoned uploads,
 * removed files whose chunks are still there, tombstones of purged S3 files and, once a day, S3 orphans. Every step
 * tolerates failure (it is retried on the next run).
 */
export class AttachmentSweeper {
  last: SweepReport | null = null;
  private orphanPassAt: Date | null = null;
  private orphansFound = 0;
  private running: Promise<SweepReport> | null = null;

  constructor(private readonly prisma: PrismaClient, private readonly stores: ChunkStores, private readonly log?: { warn: (o: object, m: string) => void }) {}

  run(now = new Date()): Promise<SweepReport> {
    this.running ??= this.sweep(now).finally(() => { this.running = null; });
    return this.running;
  }

  private async sweep(now: Date): Promise<SweepReport> {
    const r = { abandoned: 0, deleted: 0, tombstones: 0, failures: 0 };
    const fail = (e: unknown, what: string) => { r.failures++; this.log?.warn({ event: "attachments.sweep_failed", what, error: e instanceof Error ? e.message.split("\n")[0] : String(e) }, "attachments.sweep_failed"); };

    const abandoned = await this.prisma.attachment.findMany({ where: { state: "uploading", createdAt: { lt: new Date(now.getTime() - UPLOAD_TTL_MS) } }, take: BATCH,
      select: { id: true, recordId: true, createdBy: true, size: true, storage: true, chunkCount: true } });
    const cutoff = new Date(now.getTime() - UPLOAD_TTL_MS);
    for (const a of abandoned) {
      try {
        // The row goes first, under its lock (a chunk PUT or a complete holds it meanwhile): a file completed at the last
        // moment is never touched, and nothing can be written for this id afterwards. Db chunks cascade; S3 objects are
        // written down as a tombstone in the same transaction and removed by the tombstone pass below.
        const gone = await this.prisma.$transaction(async (tx) => {
          await tx.$queryRaw`SELECT id FROM "Attachment" WHERE id = ${a.id}::uuid FOR UPDATE`;
          const n = await tx.attachment.deleteMany({ where: { id: a.id, state: "uploading", createdAt: { lt: cutoff } } });
          if (n.count && a.storage === "s3") {
            await tx.attachmentTombstone.createMany({ data: [{ attachmentId: a.id, storage: "s3", chunkCount: a.chunkCount }], skipDuplicates: true });
          }
          return n.count > 0;
        });
        if (!gone) continue;
        const charge = await chargeOf(this.prisma, a.recordId);
        await logEvent(this.prisma, { action: "attachment.upload_abandoned", actorId: a.createdBy, recordId: a.recordId, meta: { size: a.size },
          ...(charge?.kind === "org" ? { orgId: charge.orgId } : {}) });
        r.abandoned++;
      } catch (e) { fail(e, "abandoned"); }
    }

    const removed = await this.prisma.attachment.findMany({ where: { state: "deleted" }, take: BATCH, select: { id: true, storage: true } });
    for (const a of removed) {
      try {
        await storeFor(this.stores, a.storage).deleteAll(a.id);
        await this.prisma.attachment.deleteMany({ where: { id: a.id, state: "deleted" } });
        r.deleted++;
      } catch (e) { fail(e, "deleted"); }
    }

    const tombs = await this.prisma.attachmentTombstone.findMany({ take: BATCH, orderBy: { createdAt: "asc" } });
    for (const t of tombs) {
      try {
        await storeFor(this.stores, t.storage).deleteAll(t.attachmentId);
        await this.prisma.attachmentTombstone.delete({ where: { attachmentId: t.attachmentId } });
        r.tombstones++;
      } catch (e) { fail(e, "tombstone"); }
    }

    if (this.stores.s3 && (!this.orphanPassAt || now.getTime() - this.orphanPassAt.getTime() >= ORPHAN_PASS_MS)) {
      try { this.orphansFound = await this.orphanPass(); this.orphanPassAt = now; } catch (e) { fail(e, "orphans"); }
    }
    this.last = { at: now.toISOString(), ...r, orphanPassAt: this.orphanPassAt?.toISOString() ?? null, orphansFound: this.orphansFound };
    return this.last;
  }

  /**
   * Objects in the bucket whose attachment no longer exists (cascades from an org or account deletion leave these):
   * removed. A row always exists before its first object is written (create comes before any chunk).
   */
  async orphanPass(): Promise<number> {
    const s3 = this.stores.s3;
    if (!s3) return 0;
    const ids = await s3.listAttachmentIds();
    let found = 0;
    for (let i = 0; i < ids.length; i += 500) {
      const part = ids.slice(i, i + 500);
      const known = new Set((await this.prisma.attachment.findMany({ where: { id: { in: part } }, select: { id: true } })).map((a) => a.id));
      const tomb = new Set((await this.prisma.attachmentTombstone.findMany({ where: { attachmentId: { in: part } }, select: { attachmentId: true } })).map((t) => t.attachmentId));
      for (const id of part) {
        if (known.has(id) || tomb.has(id)) continue;
        found++;
        await s3.deleteAll(id);
      }
    }
    return found;
  }
}
