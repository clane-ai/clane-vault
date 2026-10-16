import type { FastifyInstance, FastifyPluginAsync, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import { accessFor, canEdit, isUniqueViolation } from "../lib/access.js";
import { logEvent } from "../lib/events.js";
import { BURN } from "../lib/links.js";
import { getEntitlements, PLAN_SELECT } from "../lib/plans.js";
import { readPolicies } from "../lib/policies.js";
import { privateLockGuard } from "../lib/privateLock.js";
import { seatOverage } from "../lib/seats.js";
import { attachmentConfig, chargeOf, checkQuota, dailyUploaded, lockQuota, MIB, recordUsage, type QuotaRefusal } from "../lib/attachments/quota.js";
import { sha256Hex, storeFor } from "../lib/attachments/store.js";
import { UPLOAD_TTL_MS } from "../lib/attachments/sweep.js";
import { attachmentView, readyAttachments } from "../lib/attachments/view.js";

/** Plaintext bytes per chunk and the AES-GCM tag (packages/crypto/src/attachments.ts). */
export const CHUNK_SIZE = 1_048_576;
export const TAG = 16;
/** A download of chunk 0 is logged once per person, file and this window (retries don't flood the log). */
const DOWNLOAD_LOG_WINDOW_MS = 10 * 60_000;
/** A record that this many people or more can open makes its downloads a "widely shared" alert (risk dashboard). */
export const WIDE_AUDIENCE = 10;

const rec = z.object({ id: z.string().uuid() });
const file = rec.extend({ fid: z.string().uuid() });
const chunk = file.extend({ index: z.string().regex(/^\d{1,6}$/).transform(Number) });
const envelope = z.string().startsWith("v1.").max(4096);

/** Ciphertext length of chunk `index` of a file of `size` ciphertext bytes in `chunkCount` chunks. */
export function chunkLength(size: number, chunkCount: number, index: number): number {
  return index === chunkCount - 1 ? size - (chunkCount - 1) * (CHUNK_SIZE + TAG) : CHUNK_SIZE + TAG;
}
/** The plaintext size `size` ciphertext bytes in `chunkCount` chunks stand for, or null when they can't be a real file. */
export function plaintextSize(size: number, chunkCount: number): number | null {
  const plain = size - TAG * chunkCount;
  if (plain < 0) return null;
  return Math.max(1, Math.ceil(plain / CHUNK_SIZE)) === chunkCount ? plain : null;
}

/** People who can open a record: its owner row, direct shares and the members of its team folder. */
export async function audienceOf(app: FastifyInstance, recordId: string): Promise<number> {
  const rows = await app.prisma.$queryRaw<{ n: bigint }[]>`
    SELECT COUNT(DISTINCT u)::bigint AS n FROM (
      SELECT ra."holderId" AS u FROM "RecordAccess" ra WHERE ra."recordId" = ${recordId}::uuid AND ra."holderType" = 'user' AND ra.state = 'active'
      UNION SELECT fm."userId" FROM "RecordAccess" ra JOIN "FolderMember" fm ON fm."folderId" = ra."holderId"
        WHERE ra."recordId" = ${recordId}::uuid AND ra."holderType" = 'folder' AND ra.state = 'active'
    ) x`;
  return Number(rows[0]?.n ?? 0);
}

/** Sends one stored chunk the way every attachment download goes out: opaque bytes, never rendered, never cached. */
export function sendChunk(reply: FastifyReply, fid: string, index: number, data: Uint8Array) {
  return reply.header("content-type", "application/octet-stream").header("content-disposition", `attachment; filename="${fid}.${index}.bin"`)
    .header("cache-control", "no-store").header("x-content-type-options", "nosniff").header("content-security-policy", "default-src 'none'; sandbox")
    .send(Buffer.from(data.buffer, data.byteOffset, data.byteLength));
}

/**
 * File attachments on records (docs/design/2026-10-12-attachments.md §4). Every route authorises through
 * accessFor with the active org, exactly like routes/records.ts: a record in another org's team folder is 404.
 */
export const attachmentRoutes: FastifyPluginAsync = async (app) => {
  const cfg = attachmentConfig(app.config);
  app.addHook("onRequest", async (_req, reply) => { if (!cfg.enabled) await reply.code(404).send({ error: "attachments_disabled" }); });
  app.addHook("preHandler", app.requireAuth);
  app.addHook("preHandler", app.orgOptional);
  app.addHook("preHandler", privateLockGuard(app));
  const ctx = (req: FastifyRequest) => req.org?.id ?? null;

  // Per-person buckets (an office behind one address would hit the per-address limit within two files), outside the
  // global per-address limit: chunk uploads and downloads 600 a minute each, creates 60.
  const perUser = (name: string, max: number) => {
    const limiter = app.createRateLimit({ max, timeWindow: "1 minute", keyGenerator: (req) => `${name}:${req.auth?.userId ?? req.ip}` });
    return async (req: FastifyRequest, reply: FastifyReply) => {
      if (reply.sent) return;
      const r = await limiter(req);
      if (!r.isAllowed && r.isExceeded) await reply.code(429).header("retry-after", String(r.ttlInSeconds)).send({ error: "rate_limited" });
    };
  };
  const createLimit = perUser("att-create", cfg.createRatePerMinute ?? 60);
  const uploadLimit = perUser("att-up", cfg.chunkRatePerMinute ?? 600);
  const downloadLimit = perUser("att-down", cfg.chunkRatePerMinute ?? 600);
  const own = { config: { rateLimit: false } } as const;

  async function access(req: FastifyRequest, reply: FastifyReply, id: string) {
    const a = await accessFor(app.prisma, req.auth.userId, id, ctx(req));
    if (!a) { await reply.code(404).send({ error: "not_found" }); return null; }
    return a;
  }
  const trashed = async (id: string) => !!(await app.prisma.record.findUnique({ where: { id }, select: { deletedAt: true } }))?.deletedAt;
  const fileOf = (id: string, fid: string) => app.prisma.attachment.findFirst({ where: { id: fid, recordId: id } });

  /** What a client needs before it sends anything: the limits for files on this server (the org's policy may lower maxFileMb). */
  app.get("/attachments/limits", async () => ({
    enabled: cfg.enabled, chunkSize: CHUNK_SIZE, maxFileMb: cfg.maxFileMb, maxPerRecord: cfg.maxPerRecord, maxRecordMb: cfg.maxRecordMb,
  }));

  app.get("/records/:id/attachments", async (req, reply) => {
    const { id } = rec.parse(req.params);
    const a = await access(req, reply, id);
    if (!a) return reply;
    const { rows, names } = await readyAttachments(app.prisma, [id]);
    return { attachments: (rows.get(id) ?? []).map((x) => attachmentView(x, names, a.permission)) };
  });

  // ---- upload: reserve, chunks, complete ----

  app.post("/records/:id/attachments", { ...own, preHandler: createLimit }, async (req, reply) => {
    const { id } = rec.parse(req.params);
    // The client's crypto ceiling (100 MiB); the configured limit is checked below with a clear 413.
    const maxChunks = Math.ceil((100 * MIB) / CHUNK_SIZE);
    const b = z.object({
      id: z.string().uuid(), encMeta: envelope, wrappedFileKey: envelope, nonceBase: z.string().regex(/^[A-Za-z0-9_-]{11}$/),
      size: z.number().int().min(TAG), chunkSize: z.literal(CHUNK_SIZE), chunkCount: z.number().int().min(1).max(Math.max(1, maxChunks)),
    }).parse(req.body);
    const a = await access(req, reply, id);
    if (!a) return reply;
    if (!canEdit(a.permission)) return reply.code(403).send({ error: "forbidden" });
    const plain = plaintextSize(b.size, b.chunkCount);
    if (plain === null) return reply.code(400).send({ error: "invalid_request", issues: ["size"] });
    // The org the access comes through decides (like one-time links); a private record of the caller's own: none.
    const po = a.orgId ? await app.prisma.organization.findUnique({ where: { id: a.orgId }, select: { ...PLAN_SELECT, policies: true } }) : null;
    const policy = a.orgId ? readPolicies(po?.policies, po ? getEntitlements(app.config, po) : undefined).attachments : null;
    if (policy && !policy.allowed) return reply.code(403).send({ error: "attachments_disabled" });
    const maxMb = Math.min(cfg.maxFileMb, policy?.maxFileMb ?? Infinity);
    if (plain > maxMb * MIB) return reply.code(413).send({ error: "file_too_large", max: maxMb });
    if (await trashed(id)) return reply.code(409).send({ error: "in_trash" });
    const me = req.auth.userId;
    type Refused = { code: number; body: Record<string, unknown>; quota?: QuotaRefusal };
    let refused: Refused | null = null;
    const expiresAt = new Date(Date.now() + UPLOAD_TTL_MS);
    let charged: Awaited<ReturnType<typeof chargeOf>> = null;
    try {
      await app.prisma.$transaction(async (tx) => {
        const charge = await chargeOf(tx, id);
        if (!charge) { refused = { code: 404, body: { error: "not_found" } }; return; }
        charged = charge;
        await lockQuota(tx, charge);
        const over = charge.kind === "org" ? await seatOverage(tx, app.config, charge.orgId) : null;
        if (over) { refused = { code: 402, body: { error: "seat_limit", ...over } }; return; }
        if (await tx.attachment.findUnique({ where: { id: b.id }, select: { id: true } })) { refused = { code: 409, body: { error: "exists" } }; return; }
        const usage = await recordUsage(tx, id);
        if (usage.files >= cfg.maxPerRecord) { refused = { code: 409, body: { error: "too_many_files", max: cfg.maxPerRecord } }; return; }
        if (usage.bytes + b.size > cfg.maxRecordMb * MIB) { refused = { code: 409, body: { error: "record_too_large", maxMb: cfg.maxRecordMb } }; return; }
        if ((await dailyUploaded(tx, me)) + b.size > cfg.dailyUploadMb * MIB) { refused = { code: 429, body: { error: "daily_upload_limit", maxMb: cfg.dailyUploadMb } }; return; }
        const q = await checkQuota(tx, cfg, charge, b.size);
        if (q) { refused = { code: 409, body: { error: "quota_exceeded", ...q }, quota: q }; return; }
        await tx.attachment.create({ data: { id: b.id, recordId: id, createdBy: me, state: "uploading", storage: app.attachmentStores.current,
          encMeta: b.encMeta, wrappedFileKey: b.wrappedFileKey, nonceBase: b.nonceBase, chunkSize: b.chunkSize, chunkCount: b.chunkCount, size: b.size } });
      }, { timeout: 30_000, maxWait: 15_000 });
    } catch (e) {
      if (isUniqueViolation(e)) return reply.code(409).send({ error: "exists" });
      throw e;
    }
    const no = refused as Refused | null;
    if (no) {
      if (no.quota) {
        const c = charged as Awaited<ReturnType<typeof chargeOf>>;
        await logEvent(app.prisma, { orgId: (c?.kind === "org" ? c.orgId : a.orgId) ?? undefined, actorId: me, action: "attachment.quota_exceeded", recordId: id, ip: req.ip,
          meta: { scope: no.quota.scope, used: no.quota.used, quota: no.quota.quota } });
      }
      return reply.code(no.code).send(no.body);
    }
    return reply.code(201).send({ id: b.id, expiresAt: expiresAt.toISOString() });
  });

  /** The caller's own upload in progress on a record they can still edit, or the 4xx already sent. */
  async function myUpload(req: FastifyRequest, reply: FastifyReply, id: string, fid: string) {
    const a = await access(req, reply, id);
    if (!a) return null;
    if (!canEdit(a.permission)) { await reply.code(403).send({ error: "forbidden" }); return null; }
    const f = await fileOf(id, fid);
    if (!f || f.state === "deleted") { await reply.code(404).send({ error: "not_found" }); return null; }
    if (f.createdBy !== req.auth.userId) { await reply.code(403).send({ error: "forbidden" }); return null; }
    if (f.state !== "uploading") { await reply.code(409).send({ error: "not_uploading" }); return null; }
    // Past its expiry an upload belongs to the sweep: nothing more is written to it, and it can't become ready.
    if (Date.now() >= f.createdAt.getTime() + UPLOAD_TTL_MS) { await reply.code(410).send({ error: "upload_expired" }); return null; }
    if (await trashed(id)) { await reply.code(409).send({ error: "in_trash" }); return null; }
    return { access: a, file: f };
  }

  // Chunks are raw bytes: this route alone takes application/octet-stream up to one chunk (the global 2 MB JSON limit is unchanged).
  await app.register(async (raw) => {
    raw.removeAllContentTypeParsers();
    raw.addContentTypeParser("application/octet-stream", { parseAs: "buffer", bodyLimit: CHUNK_SIZE + TAG }, (_req, body, done) => done(null, body));
    raw.put("/records/:id/attachments/:fid/chunks/:index", { ...own, bodyLimit: CHUNK_SIZE + TAG, preHandler: uploadLimit }, async (req, reply) => {
      const p = chunk.safeParse(req.params);
      if (!p.success) return reply.code(400).send({ error: "invalid_request" });
      const { id, fid, index } = p.data;
      const up = await myUpload(req, reply, id, fid);
      if (!up) return reply;
      const f = up.file;
      if (index >= f.chunkCount) return reply.code(400).send({ error: "bad_index" });
      const body = Buffer.isBuffer(req.body) ? req.body : null;
      if (!body) return reply.code(415).send({ error: "unsupported_media_type" });
      if (body.length !== chunkLength(f.size, f.chunkCount, index)) return reply.code(400).send({ error: "bad_length", expected: chunkLength(f.size, f.chunkCount, index) });
      const sha = sha256Hex(body);
      const store = storeFor(app.attachmentStores, f.storage);
      const r = await app.prisma.$transaction(async (tx) => {
        // One writer per chunk; the upload row can't be completed or cancelled meanwhile.
        const row = await tx.$queryRaw<{ state: string }[]>`SELECT state::text FROM "Attachment" WHERE id = ${fid}::uuid FOR SHARE`;
        if (row[0]?.state !== "uploading") return "gone" as const;
        await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtextextended(${`${fid}:${index}`}, 0))`;
        const prev = await tx.attachmentChunk.findUnique({ where: { attachmentId_index: { attachmentId: fid, index } }, select: { sha256: true } });
        if (prev) return prev.sha256 === sha ? "same" as const : "mismatch" as const;
        await store.put(fid, index, body, tx);
        // S3: the bytes are in the bucket; the row records that this index arrived, its length and hash.
        if (store.kind !== "db") await tx.$executeRaw`INSERT INTO "AttachmentChunk" ("attachmentId", "index", "length", "sha256", "data") VALUES (${fid}::uuid, ${index}, ${body.length}, ${sha}, ${Buffer.alloc(0)})`;
        return "stored" as const;
      }, { timeout: 60_000, maxWait: 15_000 });
      if (r === "gone") return reply.code(409).send({ error: "not_uploading" });
      // The same index with other bytes: the client must start again with a new file id and key (never re-encrypt).
      if (r === "mismatch") return reply.code(409).send({ error: "chunk_mismatch" });
      return { received: await app.prisma.attachmentChunk.count({ where: { attachmentId: fid } }) };
    });
  });

  app.get("/records/:id/attachments/:fid/upload", async (req, reply) => {
    const { id, fid } = file.parse(req.params);
    const a = await access(req, reply, id);
    if (!a) return reply;
    if (!canEdit(a.permission)) return reply.code(403).send({ error: "forbidden" });
    const f = await fileOf(id, fid);
    if (!f || f.state === "deleted" || f.createdBy !== req.auth.userId) return reply.code(404).send({ error: "not_found" });
    const received = (await app.prisma.attachmentChunk.findMany({ where: { attachmentId: fid }, select: { index: true }, orderBy: { index: "asc" } })).map((c) => c.index);
    return { state: f.state, received, expiresAt: new Date(f.createdAt.getTime() + UPLOAD_TTL_MS).toISOString() };
  });

  app.post("/records/:id/attachments/:fid/complete", async (req, reply) => {
    const { id, fid } = file.parse(req.params);
    const up = await myUpload(req, reply, id, fid);
    if (!up) return reply;
    const now = new Date();
    const r = await app.prisma.$transaction(async (tx) => {
      const row = await tx.$queryRaw<{ state: string; size: number; chunkCount: number }[]>`SELECT state::text, size, "chunkCount" FROM "Attachment" WHERE id = ${fid}::uuid FOR UPDATE`;
      const f = row[0];
      if (f?.state !== "uploading") return { error: "not_uploading" as const };
      const have = await tx.attachmentChunk.findMany({ where: { attachmentId: fid }, select: { index: true, length: true } });
      const got = new Set(have.map((c) => c.index));
      const missing = Array.from({ length: f.chunkCount }, (_, i) => i).filter((i) => !got.has(i));
      if (missing.length || have.reduce((s, c) => s + c.length, 0) !== f.size) return { error: "incomplete" as const, missing };
      await tx.attachment.update({ where: { id: fid }, data: { state: "ready", readyAt: now } });
      // Attachments aren't in the body: the revision stays, "modified" moves.
      await tx.record.update({ where: { id }, data: { updatedAt: now } });
      await logEvent(tx, { orgId: up.access.orgId ?? undefined, actorId: req.auth.userId, action: "attachment.add", recordId: id, meta: { size: f.size, chunkCount: f.chunkCount } });
      return { ok: true as const };
    });
    if ("error" in r) return reply.code(409).send(r.error === "incomplete" ? { error: "incomplete", missing: r.missing } : { error: r.error });
    return { id: fid, readyAt: now.toISOString() };
  });

  // ---- download ----

  app.get("/records/:id/attachments/:fid/chunks/:index", { ...own, preHandler: downloadLimit }, async (req, reply) => {
    const p = chunk.safeParse(req.params);
    if (!p.success) return reply.code(400).send({ error: "invalid_request" });
    const { id, fid, index } = p.data;
    const a = await access(req, reply, id);
    if (!a) return reply;
    // "Use only" can copy a password without seeing it; a file can't be used without seeing it.
    if (a.permission === "use") return reply.code(403).send({ error: "use_only" });
    if (await trashed(id)) return reply.code(409).send({ error: "in_trash" });
    const f = await fileOf(id, fid);
    if (!f || f.state !== "ready" || index >= f.chunkCount) return reply.code(404).send({ error: "not_found" });
    const data = await storeFor(app.attachmentStores, f.storage).get(fid, index);
    if (!data) { req.log.error({ event: "attachments.chunk_missing", attachmentId: fid, index }, "attachments.chunk_missing"); return reply.code(404).send({ error: "not_found" }); }
    if (index === 0) {
      const me = req.auth.userId;
      const seen = await app.prisma.event.findFirst({ where: { action: "attachment.download", actorId: me, recordId: id, at: { gte: new Date(Date.now() - DOWNLOAD_LOG_WINDOW_MS) },
        meta: { path: ["attachmentId"], equals: fid } }, select: { id: true } });
      if (!seen) {
        const wide = (await audienceOf(app, id)) >= WIDE_AUDIENCE;
        await logEvent(app.prisma, { orgId: a.orgId ?? undefined, actorId: me, action: "attachment.download", recordId: id, ip: req.ip, meta: { attachmentId: fid, ...(wide ? { wide: true } : {}) } });
      }
    }
    return sendChunk(reply, fid, index, data);
  });

  // ---- remove, cancel ----

  app.delete("/records/:id/attachments/:fid", async (req, reply) => {
    const { id, fid } = file.parse(req.params);
    const a = await access(req, reply, id);
    if (!a) return reply;
    const f = await fileOf(id, fid);
    if (!f || f.state === "deleted") return reply.code(404).send({ error: "not_found" });
    const store = storeFor(app.attachmentStores, f.storage);
    const me = req.auth.userId;
    if (f.state === "uploading") {
      // Cancel: the person uploading it (while they can still edit) or the record's owner.
      if (!((f.createdBy === me && canEdit(a.permission)) || a.isOwner)) return reply.code(403).send({ error: "forbidden" });
      const n = await app.prisma.$transaction(async (tx) => {
        await tx.$queryRaw`SELECT id FROM "Attachment" WHERE id = ${fid}::uuid FOR UPDATE`;
        return tx.attachment.deleteMany({ where: { id: fid, state: "uploading" } });
      });
      if (!n.count) return reply.code(409).send({ error: "not_uploading" });
      await store.deleteAll(fid).catch((e: unknown) => req.log.warn({ event: "attachments.cancel_cleanup_failed", error: String(e) }, "attachments.cancel_cleanup_failed"));
      return reply.code(204).send();
    }
    if (!canEdit(a.permission)) return reply.code(403).send({ error: "forbidden" });
    if (await trashed(id)) return reply.code(409).send({ error: "in_trash" });
    const now = new Date();
    const revoked = await app.prisma.$transaction(async (tx) => {
      const n = await tx.attachment.updateMany({ where: { id: fid, state: "ready" }, data: { state: "deleted", deletedAt: now } });
      if (!n.count) return null;
      // A live link that carries this file would be lying: it is revoked.
      const links = await tx.shareLink.findMany({ where: { revokedAt: null, attachments: { some: { attachmentId: fid } } }, select: { id: true, orgId: true } });
      if (links.length) await tx.shareLink.updateMany({ where: { id: { in: links.map((l) => l.id) }, revokedAt: null }, data: { revokedAt: now, ...BURN } });
      for (const l of links) await logEvent(tx, { orgId: l.orgId ?? undefined, actorId: me, action: "link.revoke", recordId: id, meta: { reason: "attachment_removed", linkId: l.id } });
      await logEvent(tx, { orgId: a.orgId ?? undefined, actorId: me, action: "attachment.remove", recordId: id, ip: req.ip, meta: { size: f.size } });
      await tx.record.update({ where: { id }, data: { updatedAt: now } });
      return links.length;
    });
    if (revoked === null) return reply.code(404).send({ error: "not_found" });
    // The chunks go now; the sweep retries whatever fails here.
    try {
      await store.deleteAll(fid);
      await app.prisma.attachment.deleteMany({ where: { id: fid, state: "deleted" } });
    } catch (e) { req.log.warn({ event: "attachments.remove_cleanup_failed", error: String(e) }, "attachments.remove_cleanup_failed"); }
    return reply.code(204).send();
  });
};
