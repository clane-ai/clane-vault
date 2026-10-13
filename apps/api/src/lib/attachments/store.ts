import { createHash } from "node:crypto";
import type { AttachmentStorage } from "@prisma/client";
import type { Db } from "../access.js";

/**
 * Where attachment chunk bytes live (docs/design/2026-10-12-attachments.md §3.1). Both backends share the
 * `Attachment` rows and the `AttachmentChunk` index rows (index, length, sha256: what makes a chunk PUT idempotent);
 * only the bytes move. `db` keeps them in AttachmentChunk.data, `s3` in objects `<prefix><attachmentId>/<index>`.
 */
export interface ChunkStore {
  readonly kind: AttachmentStorage;
  /** Stores one chunk. Called once per (attachment, index), inside the transaction that records the index row. */
  put(attachmentId: string, index: number, data: Uint8Array, db: Db): Promise<void>;
  get(attachmentId: string, index: number): Promise<Uint8Array | null>;
  /** Indices whose bytes are present (resume, GC checks). */
  has(attachmentId: string): Promise<Set<number>>;
  /** Deletes every chunk of the attachment; tolerates nothing being there. */
  deleteAll(attachmentId: string): Promise<void>;
}

export const sha256Hex = (data: Uint8Array) => createHash("sha256").update(data).digest("hex");

/**
 * Chunks in Postgres, one row each. The column is STORAGE EXTERNAL (no TOAST compression of ciphertext). Raw queries
 * with Buffer parameters, so a chunk is never turned into JSON on its way to or from the database.
 */
export class DbChunkStore implements ChunkStore {
  readonly kind = "db" as const;
  constructor(private readonly prisma: Db) {}

  async put(attachmentId: string, index: number, data: Uint8Array, db: Db) {
    const buf = Buffer.from(data.buffer, data.byteOffset, data.byteLength);
    await db.$executeRaw`INSERT INTO "AttachmentChunk" ("attachmentId", "index", "length", "sha256", "data")
      VALUES (${attachmentId}::uuid, ${index}, ${buf.length}, ${sha256Hex(buf)}, ${buf}) ON CONFLICT ("attachmentId", "index") DO NOTHING`;
  }

  async get(attachmentId: string, index: number) {
    const rows = await this.prisma.$queryRaw<{ data: Uint8Array }[]>`SELECT "data" FROM "AttachmentChunk" WHERE "attachmentId" = ${attachmentId}::uuid AND "index" = ${index}`;
    const d = rows[0]?.data;
    return d ? new Uint8Array(d.buffer, d.byteOffset, d.byteLength) : null;
  }

  async has(attachmentId: string) {
    const rows = await this.prisma.$queryRaw<{ index: number }[]>`SELECT "index" FROM "AttachmentChunk" WHERE "attachmentId" = ${attachmentId}::uuid AND octet_length("data") = "length"`;
    return new Set(rows.map((r) => r.index));
  }

  async deleteAll(attachmentId: string) {
    await this.prisma.$executeRaw`DELETE FROM "AttachmentChunk" WHERE "attachmentId" = ${attachmentId}::uuid`;
  }
}

/** The stores this instance can read (every row says which one holds its chunks) and the one new uploads go to. */
export interface ChunkStores { db: DbChunkStore; s3?: ChunkStore & { listAttachmentIds(): Promise<string[]>; destroy(): void; describe(): { bucket: string; prefix: string; endpoint?: string } }; current: AttachmentStorage }
export function storeFor(stores: ChunkStores, kind: AttachmentStorage): ChunkStore {
  if (kind === "db") return stores.db;
  if (!stores.s3) throw new Error("This attachment is stored in S3, but ATTACHMENT_S3_* isn't configured");
  return stores.s3;
}
