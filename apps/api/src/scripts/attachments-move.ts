// Operator CLI: move attachment chunks between the database and S3 (docs/attachments.md, "Switching storage").
//   node dist/src/scripts/attachments-move.js --to s3 [--limit 1000]
//   node dist/src/scripts/attachments-move.js --to db
// Set ATTACHMENT_STORAGE to the target first (new uploads go there) and ATTACHMENT_S3_* for the bucket. Safe to stop and
// run again: each file says where its chunks are and flips only after every chunk was copied.
import { loadConfig } from "../config.js";
import { createPrisma } from "../db.js";
import { DbChunkStore, type ChunkStores } from "../lib/attachments/store.js";
import { S3ChunkStore } from "../lib/attachments/s3Store.js";
import { moveAttachments } from "../lib/attachments/move.js";
import { attachmentConfig } from "../lib/attachments/quota.js";

const arg = (name: string) => { const i = process.argv.indexOf(name); return i >= 0 ? process.argv[i + 1] : undefined; };
const to = arg("--to");
const limit = arg("--limit") ? Number(arg("--limit")) : undefined;
if ((to !== "s3" && to !== "db") || (limit !== undefined && !(limit > 0))) {
  console.error("Usage: attachments-move --to s3|db [--limit N]");
  process.exit(1);
}
const config = loadConfig();
const att = attachmentConfig(config);
if (to === "s3" && !att.s3) { console.error("Set ATTACHMENT_S3_BUCKET (and its endpoint and credentials) first."); process.exit(1); }
const prisma = createPrisma(config.databaseUrl);
const s3 = att.s3 ? new S3ChunkStore(att.s3) : undefined;
const stores: ChunkStores = { db: new DbChunkStore(prisma), current: to, ...(s3 ? { s3 } : {}) };
const r = await moveAttachments(prisma, stores, to, { log: (l) => console.log(l), limit });
await prisma.event.create({ data: { action: "instance.attachments_moved", meta: { to, moved: r.moved, chunks: r.chunks, failed: r.failed.length, via: "cli" } } });
console.log(`Moved ${r.moved} file(s), ${r.chunks} chunk(s) to ${to}; ${r.failed.length} failed.`);
if (to === "s3" && att.storage !== "s3") console.log("Remember to set ATTACHMENT_STORAGE=s3 so new uploads go to the bucket.");
s3?.destroy();
await prisma.$disconnect();
process.exit(r.failed.length ? 2 : 0);
