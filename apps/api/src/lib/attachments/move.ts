import type { AttachmentStorage, PrismaClient } from "@prisma/client";
import { storeFor, type ChunkStores } from "./store.js";

export interface MoveReport { moved: number; chunks: number; failed: { id: string; error: string }[] }

/**
 * Moves the chunks of ready files to another backend (docs/attachments.md, "Switching storage"): copy every chunk,
 * flip the row's `storage`, then clear the old copy. Each row says where its chunks are, so a run cut short leaves a
 * working instance (rows not flipped yet still read from their old place) and can simply be started again.
 */
export async function moveAttachments(prisma: PrismaClient, stores: ChunkStores, to: AttachmentStorage, o: { log?: (line: string) => void; limit?: number } = {}): Promise<MoveReport> {
  const target = storeFor(stores, to);
  const report: MoveReport = { moved: 0, chunks: 0, failed: [] };
  const rows = await prisma.attachment.findMany({ where: { state: "ready", storage: { not: to } }, select: { id: true, storage: true, chunkCount: true }, orderBy: { createdAt: "asc" }, ...(o.limit ? { take: o.limit } : {}) });
  for (const a of rows) {
    const source = storeFor(stores, a.storage);
    try {
      for (let i = 0; i < a.chunkCount; i++) {
        const data = await source.get(a.id, i);
        if (!data) throw new Error(`chunk ${i} is missing`);
        if (to === "db") {
          // The index row exists (s3 rows keep it with empty data): fill in the bytes.
          await prisma.$executeRaw`UPDATE "AttachmentChunk" SET "data" = ${Buffer.from(data)} WHERE "attachmentId" = ${a.id}::uuid AND "index" = ${i}`;
        } else {
          await target.put(a.id, i, data, prisma);
        }
        report.chunks++;
      }
      await prisma.attachment.update({ where: { id: a.id }, data: { storage: to } });
      // Only now is the old copy dropped (the row already reads from the new place).
      if (a.storage === "db") await prisma.$executeRaw`UPDATE "AttachmentChunk" SET "data" = ${Buffer.alloc(0)} WHERE "attachmentId" = ${a.id}::uuid`;
      else await source.deleteAll(a.id);
      report.moved++;
      o.log?.(`moved ${a.id} (${a.chunkCount} chunks) ${a.storage} -> ${to}`);
    } catch (e) {
      report.failed.push({ id: a.id, error: e instanceof Error ? e.message.split("\n")[0]! : String(e) });
      o.log?.(`FAILED ${a.id}: ${e instanceof Error ? e.message.split("\n")[0] : String(e)}`);
    }
  }
  return report;
}
