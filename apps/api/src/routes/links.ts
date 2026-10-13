import type { FastifyPluginAsync, FastifyReply, FastifyRequest } from "fastify";
import { isPrivateLocked, privateLockGuard } from "../lib/privateLock.js";
import { z } from "zod";
import { accessFor, canEdit } from "../lib/access.js";
import { logEvent } from "../lib/events.js";
import { accessMatches, BURN, deadReason, hashAccess, isUniqueViolation, type LinkState } from "../lib/links.js";
import { readPolicies } from "../lib/policies.js";
import { signLinkDownload, verifyLinkDownload } from "../lib/tokens.js";
import { attachmentConfig, MIB } from "../lib/attachments/quota.js";
import { storeFor } from "../lib/attachments/store.js";
import { plaintextSize, sendChunk } from "./attachments.js";

/** A link carries at most this many files and this much (docs/design/2026-10-12-attachments.md §5.1). */
export const MAX_LINK_FILES = 25;
export const MAX_LINK_FILE_BYTES = 100 * MIB;

const idParam = z.object({ id: z.string().uuid() });
const b64 = z.string().regex(/^[A-Za-z0-9_-]+$/);
// `v1.<b64url>` (no password) or `w1.<b64url>.<b64url>` (data key wrapped under password + link key). A link that
// carries files has their keys and metadata inside, so it may be larger (64 KiB of plaintext at most).
const payload = z.string().max(90_000).regex(/^(v1\.[A-Za-z0-9_-]+|w1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/);

const createBody = z.object({
  id: z.string().uuid(),
  recordId: z.string().uuid(),
  encPayload: payload,
  expiresInHours: z.union([z.literal(1), z.literal(24), z.literal(168)]),
  maxOpens: z.union([z.literal(1), z.literal(3), z.null()]),
  passwordSalt: b64.min(16).max(64).optional(),
  accessHash: b64.min(32).max(64).optional(),
  labelEnc: z.string().startsWith("v1.").max(2048).optional(),
  attachmentIds: z.array(z.string().uuid()).max(MAX_LINK_FILES).optional(),
}).refine((b) => !!b.passwordSalt === !!b.accessHash && b.encPayload.startsWith("w1.") === !!b.accessHash, { message: "password fields must match the payload kind" })
  .refine((b) => b.encPayload.length <= 65536 || (b.attachmentIds?.length ?? 0) > 0, { message: "payload too large", path: ["encPayload"] })
  .refine((b) => new Set(b.attachmentIds ?? []).size === (b.attachmentIds?.length ?? 0), { message: "duplicate files", path: ["attachmentIds"] });

type Row = LinkState & { id: string; recordId: string; createdBy: string; createdAt: Date; labelEnc: string | null; passwordSalt: string | null; accessHash: string | null; record: { deletedAt: Date | null }; _count: { attachments: number } };
const withRecord = { record: { select: { deletedAt: true } }, _count: { select: { attachments: true } } } as const;

export const linkRoutes: FastifyPluginAsync = async (app) => {
  // ---- authenticated: create, list, revoke ----
  await app.register(async (authed) => {
    authed.addHook("preHandler", app.requireAuth);
    authed.addHook("preHandler", app.orgOptional);
    authed.addHook("preHandler", privateLockGuard(app));
    const ctx = (req: FastifyRequest) => req.org?.id ?? null;

    // Labels are encrypted under the creator's key, so other people's labels are never sent.
    const view = (l: Row, me: string) => ({
      id: l.id, recordId: l.recordId, expiresAt: l.expiresAt.toISOString(), maxOpens: l.maxOpens, opens: l.opens,
      revokedAt: l.revokedAt?.toISOString() ?? null, createdAt: l.createdAt.toISOString(), labelEnc: l.createdBy === me ? l.labelEnc : null,
      createdByMe: l.createdBy === me, hasPassword: l.accessHash != null, state: deadReason({ ...l, recordDeletedAt: l.record.deletedAt }) ?? "active",
      files: l._count.attachments,
    });

    authed.post("/links", async (req, reply) => {
      const b = createBody.parse(req.body);
      const access = await accessFor(app.prisma, req.auth.userId, b.recordId, ctx(req));
      if (!access) return reply.code(404).send({ error: "not_found" });
      if (!canEdit(access.permission)) return reply.code(403).send({ error: "forbidden" });
      const rec = await app.prisma.record.findUnique({ where: { id: b.recordId }, select: { deletedAt: true } });
      if (!rec || rec.deletedAt) return reply.code(409).send({ error: "in_trash" });
      const fileIds = b.attachmentIds ?? [];
      if (fileIds.length) {
        if (!attachmentConfig(app.config).enabled) return reply.code(404).send({ error: "attachments_disabled" });
        const files = await app.prisma.attachment.findMany({ where: { id: { in: fileIds }, recordId: b.recordId, state: "ready" }, select: { size: true, chunkCount: true } });
        if (files.length !== fileIds.length) return reply.code(400).send({ error: "bad_attachment" });
        const total = files.reduce((s, f) => s + (plaintextSize(f.size, f.chunkCount) ?? f.size), 0);
        if (total > MAX_LINK_FILE_BYTES) return reply.code(413).send({ error: "link_files_too_large", maxMb: MAX_LINK_FILE_BYTES / MIB });
      }
      const expiresAt = new Date(Date.now() + b.expiresInHours * 3600_000);
      let refused: { code: number; body: Record<string, unknown> } | null = null;
      try {
        await app.prisma.$transaction(async (tx) => {
          // The org's link policy (docs/policies.md) governs links that belong to it; a private record's links are the
          // owner's. Read under a share lock, so a policy switching links off can't miss a link created meanwhile.
          if (access.orgId) {
            await tx.$queryRaw`SELECT id FROM "Organization" WHERE id = ${access.orgId}::uuid FOR SHARE`;
            const p = readPolicies((await tx.organization.findUnique({ where: { id: access.orgId }, select: { policies: true } }))?.policies).links;
            if (!p.allowed) { refused = { code: 403, body: { error: "links_disabled" } }; return; }
            if (b.expiresInHours > p.maxExpiryHours) { refused = { code: 400, body: { error: "link_expiry_too_long", maxExpiryHours: p.maxExpiryHours } }; return; }
            if (p.requirePassword && !b.accessHash) { refused = { code: 400, body: { error: "link_password_required" } }; return; }
            if (fileIds.length && !p.allowAttachments) { refused = { code: 403, body: { error: "link_attachments_disabled" } }; return; }
          }
          await tx.shareLink.create({ data: {
            // The link belongs to the org the access comes through (none for the creator's own private record).
            id: b.id, recordId: b.recordId, createdBy: req.auth.userId, orgId: access.orgId, encPayload: b.encPayload, expiresAt, maxOpens: b.maxOpens,
            passwordSalt: b.passwordSalt ?? null, accessHash: b.accessHash ? hashAccess(b.accessHash) : null, labelEnc: b.labelEnc ?? null,
            ...(fileIds.length ? { attachments: { create: fileIds.map((attachmentId) => ({ attachmentId })) } } : {}),
          } });
        });
      } catch (e) {
        if (isUniqueViolation(e)) return reply.code(409).send({ error: "exists" });
        throw e;
      }
      const no = refused as { code: number; body: Record<string, unknown> } | null;
      if (no) return reply.code(no.code).send(no.body);
      await logEvent(app.prisma, { orgId: access.orgId ?? undefined, actorId: req.auth.userId, action: "link.create", recordId: b.recordId,
        ...(fileIds.length ? { meta: { attachments: fileIds.length } } : {}) });
      return reply.code(201).send({ id: b.id, expiresAt: expiresAt.toISOString() });
    });

    authed.get("/links", async (req, reply) => {
      // My links of the active org, plus those on my own private records. `?space=org` (the org's space in the web app,
      // docs/design/2026-10-07-multi-org-design.md §11): the org's links only; no header: personal ones only.
      const orgOnly = (req.query as { space?: unknown } | undefined)?.space === "org";
      if (orgOnly && !req.org) return reply.code(403).send({ error: "org_required" });
      const links = await app.prisma.shareLink.findMany({ where: { createdBy: req.auth.userId, OR: [...(orgOnly ? [] : [{ orgId: null }]), ...(req.org ? [{ orgId: req.org.id }] : [])] }, orderBy: { createdAt: "desc" }, include: withRecord }).then((ls) => (isPrivateLocked(req) ? ls.filter((l) => l.orgId !== null) : ls));
      return { links: links.map((l) => view(l, req.auth.userId)) };
    });

    // Links on one record: the owner sees all of them, whoever created them; others see their own.
    authed.get("/records/:id/links", async (req, reply) => {
      const { id } = idParam.parse(req.params);
      const access = await accessFor(app.prisma, req.auth.userId, id, ctx(req));
      if (!access) return reply.code(404).send({ error: "not_found" });
      // The owner: links of the active org and personal ones; anyone else: their own, of the active org.
      const where = access.permission === "owner" ? { recordId: id, OR: [{ orgId: null }, { orgId: ctx(req) }] } : { recordId: id, createdBy: req.auth.userId, orgId: ctx(req) };
      const links = await app.prisma.shareLink.findMany({ where, orderBy: { createdAt: "desc" }, include: withRecord });
      return { links: links.map((l) => view(l, req.auth.userId)) };
    });

    // The creator or the record owner may revoke.
    authed.delete("/links/:id", async (req, reply) => {
      const { id } = idParam.parse(req.params);
      const l = await app.prisma.shareLink.findUnique({ where: { id }, select: { recordId: true, createdBy: true, orgId: true } });
      if (!l) return reply.code(404).send({ error: "not_found" });
      // The creator (for a link of the active org or a personal one), or the record's owner in the active org.
      const mineHere = l.createdBy === req.auth.userId && (l.orgId === null || l.orgId === ctx(req));
      if (!mineHere && (await accessFor(app.prisma, req.auth.userId, l.recordId, ctx(req)))?.permission !== "owner") return reply.code(404).send({ error: "not_found" });
      const n = await app.prisma.shareLink.updateMany({ where: { id, revokedAt: null }, data: { revokedAt: new Date(), ...BURN } });
      if (n.count > 0) await logEvent(app.prisma, { orgId: l.orgId ?? undefined, actorId: req.auth.userId, action: "link.revoke", recordId: l.recordId });
      return reply.code(204).send();
    });
  });

  // ---- public, unauthenticated: one shared counter of 30 requests / minute / IP for both routes ----
  const publicLimiter = app.createRateLimit({ max: 30, timeWindow: "1 minute" });
  const limit = { onRequest: async (req: FastifyRequest, reply: FastifyReply) => {
    const r = await publicLimiter(req);
    if (!r.isAllowed && r.isExceeded) return reply.code(429).header("retry-after", String(r.ttlInSeconds)).send({ error: "rate_limited" });
  } };
  const gone = (reply: FastifyReply, error: string) => reply.code(410).send({ error });

  /** Loads a link; if it is dead, burns what is left and answers 410/404. Returns the row only when it is alive. */
  async function liveLink(id: string, reply: FastifyReply) {
    const l = await app.prisma.shareLink.findUnique({ where: { id }, include: withRecord });
    if (!l) { await reply.code(404).send({ error: "not_found" }); return null; }
    const dead = deadReason({ ...l, recordDeletedAt: l.record.deletedAt });
    if (dead) {
      if (l.encPayload != null || l.accessHash != null || l.passwordSalt != null) await app.prisma.shareLink.update({ where: { id }, data: BURN });
      await gone(reply, dead);
      return null;
    }
    return l;
  }

  app.get("/public/links/:id", limit, async (req, reply) => {
    const parsed = idParam.safeParse(req.params);
    if (!parsed.success) return reply.code(404).send({ error: "not_found" });
    const l = await liveLink(parsed.data.id, reply);
    if (!l) return reply;
    return { needsPassword: l.accessHash != null, passwordSalt: l.passwordSalt, expiresAt: l.expiresAt.toISOString(), opensLeft: l.maxOpens == null ? null : l.maxOpens - l.opens };
  });

  app.post("/public/links/:id/open", limit, async (req, reply) => {
    const parsed = idParam.safeParse(req.params);
    if (!parsed.success) return reply.code(404).send({ error: "not_found" });
    const { accessHash } = z.object({ accessHash: b64.max(64).optional() }).parse(req.body ?? {});
    const id = parsed.data.id;
    // A dead link says so (410) before any password check.
    const pre = await liveLink(id, reply);
    if (!pre) return reply;
    if (pre.accessHash && !accessMatches(pre.accessHash, accessHash)) return reply.code(403).send({ error: "wrong_password" });
    // Lock the row so concurrent opens are counted one at a time; the last allowed open burns the ciphertext.
    const result = await app.prisma.$transaction(async (tx) => {
      const rows = await tx.$queryRaw<(LinkState & { recordId: string; orgId: string | null })[]>`
        SELECT l."encPayload", l."expiresAt", l."maxOpens", l."opens", l."revokedAt", l."recordId", l."orgId", r."deletedAt" AS "recordDeletedAt"
        FROM "ShareLink" l JOIN "Record" r ON r.id = l."recordId" WHERE l.id = ${id}::uuid FOR UPDATE OF l`;
      const l = rows[0];
      if (!l) return { ok: false as const, error: "not_found" as const };
      const dead = deadReason(l);
      if (dead) {
        await tx.shareLink.update({ where: { id }, data: BURN });
        return { ok: false as const, error: dead };
      }
      const opens = l.opens + 1;
      const last = l.maxOpens != null && opens >= l.maxOpens;
      await tx.shareLink.update({ where: { id }, data: { opens, ...(last ? BURN : {}) } });
      return { ok: true as const, encPayload: l.encPayload!, recordId: l.recordId, orgId: l.orgId, expiresAt: l.expiresAt, opensLeft: l.maxOpens == null ? null : l.maxOpens - opens };
    });
    if (!result.ok) return result.error === "not_found" ? reply.code(404).send({ error: "not_found" }) : gone(reply, result.error);
    await logEvent(app.prisma, { orgId: result.orgId ?? undefined, action: "link.open", recordId: result.recordId });
    // A link with files: a short-lived token for their chunks (they stay downloadable for a while after the last open burned the payload).
    const files = await app.prisma.shareLinkAttachment.count({ where: { linkId: id } });
    const downloadToken = files ? await signLinkDownload(app.config, id) : undefined;
    return { encPayload: result.encPayload, expiresAt: result.expiresAt.toISOString(), opensLeft: result.opensLeft, ...(downloadToken ? { downloadToken } : {}) };
  });

  /**
   * A file's chunk for the recipient of a link that carries it, with the token from /open (30 minutes). Served while the
   * link isn't revoked (revokedAt survives the last open's burn) and its record isn't trashed. Per address, 300 a minute,
   * separate from the 30 a minute of the routes above.
   */
  const chunkLimiter = app.createRateLimit({ max: attachmentConfig(app.config).publicChunkRatePerMinute ?? 300, timeWindow: "1 minute" });
  const chunkParams = z.object({ id: z.string().uuid(), fid: z.string().uuid(), index: z.string().regex(/^\d{1,6}$/).transform(Number) });
  app.get("/public/links/:id/attachments/:fid/chunks/:index", { config: { rateLimit: false }, onRequest: async (req, reply) => {
    const r = await chunkLimiter(req);
    if (!r.isAllowed && r.isExceeded) return reply.code(429).header("retry-after", String(r.ttlInSeconds)).send({ error: "rate_limited" });
  } }, async (req, reply) => {
    const p = chunkParams.safeParse(req.params);
    if (!p.success) return reply.code(404).send({ error: "not_found" });
    const { id, fid, index } = p.data;
    if (!attachmentConfig(app.config).enabled) return reply.code(404).send({ error: "attachments_disabled" });
    const token = req.headers.authorization?.replace(/^Bearer /, "") ?? "";
    if (!(await verifyLinkDownload(app.config, token, id))) return reply.code(401).send({ error: "unauthorized" });
    const l = await app.prisma.shareLink.findUnique({ where: { id }, select: { revokedAt: true, recordId: true, orgId: true, record: { select: { deletedAt: true } } } });
    if (!l) return reply.code(404).send({ error: "not_found" });
    if (l.revokedAt || l.record.deletedAt) return gone(reply, "revoked");
    const f = await app.prisma.attachment.findFirst({ where: { id: fid, recordId: l.recordId, state: "ready", links: { some: { linkId: id } } }, select: { storage: true, chunkCount: true } });
    if (!f || index >= f.chunkCount) return reply.code(404).send({ error: "not_found" });
    const data = await storeFor(app.attachmentStores, f.storage).get(fid, index);
    if (!data) return reply.code(404).send({ error: "not_found" });
    if (index === 0) {
      const seen = await app.prisma.event.findFirst({ where: { action: "link.attachment_download", recordId: l.recordId,
        AND: [{ meta: { path: ["attachmentId"], equals: fid } }, { meta: { path: ["linkId"], equals: id } }] }, select: { id: true } });
      if (!seen) await logEvent(app.prisma, { orgId: l.orgId ?? undefined, action: "link.attachment_download", recordId: l.recordId, meta: { attachmentId: fid, linkId: id } });
    }
    return sendChunk(reply, fid, index, data);
  });
};
