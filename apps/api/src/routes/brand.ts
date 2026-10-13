import type { FastifyInstance, FastifyPluginAsync, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import { BRAND_ID, brandName } from "../lib/brand.js";
import { logEvent } from "../lib/events.js";
import { inspectLogo, LOGO_MAX_BYTES, logoHeaders, logoVersion, type LogoImage } from "../lib/images.js";

/**
 * In the plugin it's called from: every request body is taken as raw bytes, whatever its declared type (the image is
 * recognised by its magic bytes). A bit more than the limit is read so an oversized logo gets a clear "too_large".
 */
export function rawImageBodies(app: FastifyInstance) {
  app.removeAllContentTypeParsers();
  app.addContentTypeParser("*", { parseAs: "buffer", bodyLimit: LOGO_MAX_BYTES * 2 }, (_req, body, done) => done(null, body));
}

/** The uploaded logo, checked; or the 4xx reply already sent. */
export async function readLogo(req: FastifyRequest, reply: FastifyReply): Promise<{ bytes: Uint8Array<ArrayBuffer>; img: LogoImage } | null> {
  const bytes = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
  const img = inspectLogo(bytes);
  if (typeof img === "string") {
    await reply.code(img === "too_large" ? 413 : img === "unsupported_type" ? 415 : 400).send({ error: img });
    return null;
  }
  return { bytes: new Uint8Array(bytes), img };
}

/** Sends a stored logo (304 when the browser has this version). */
export function sendLogo(req: FastifyRequest, reply: FastifyReply, logo: { mime: string; data: Uint8Array; sha256: string }, visibility: "public" | "private") {
  reply.headers(logoHeaders(logo.mime, logo.sha256, visibility));
  if (req.headers["if-none-match"] === `"${logo.sha256}"`) return reply.code(304).send();
  return reply.send(Buffer.from(logo.data));
}

const view = (b: { productName: string | null; shortName: string | null; logoSha256: string | null }) =>
  ({ productName: b.productName, shortName: b.shortName, logoVersion: logoVersion(b.logoSha256) });

/**
 * Public branding (docs/branding.md): the product name and short name an instance admin set (null: the build's own),
 * and whether there's an instance logo. Read before sign-in, so no authentication.
 */
export const publicBrandRoutes: FastifyPluginAsync = async (app) => {
  app.get("/brand", async () => view(await app.brand.get()));

  /** The instance logo: public, it is shown on the sign-in page. */
  app.get("/brand/logo", async (req, reply) => {
    const row = await app.prisma.instanceBrand.findUnique({ where: { id: BRAND_ID }, select: { logoMime: true, logoData: true, logoSha256: true } });
    if (!row?.logoData || !row.logoMime || !row.logoSha256) return reply.code(404).send({ error: "not_found" });
    return sendLogo(req, reply, { mime: row.logoMime, data: row.logoData, sha256: row.logoSha256 }, "public");
  });
};

/** /admin/instance/brand: instance admins only (guarded where it's registered). */
export const instanceBrandRoutes: FastifyPluginAsync = async (app) => {
  const meta = (req: FastifyRequest) => ({ ip: req.ip, userAgent: String(req.headers["user-agent"] ?? "").slice(0, 300) });
  const current = async () => view(await app.brand.get());

  app.get("/", current);

  /** Sets (or, with null, clears) the product name and short name. */
  app.put("/", { config: { rateLimit: { max: 20, timeWindow: "1 minute" } } }, async (req) => {
    const b = z.object({ productName: brandName.nullable(), shortName: brandName.nullable() }).parse(req.body);
    const before = await app.brand.get();
    await app.prisma.instanceBrand.upsert({ where: { id: BRAND_ID }, create: { id: BRAND_ID, ...b, updatedById: req.auth.userId }, update: { ...b, updatedById: req.auth.userId } });
    app.brand.invalidate();
    await logEvent(app.prisma, { actorId: req.auth.userId, action: "instance.brand_change", ...meta(req),
      meta: { productName: { from: before.productName, to: b.productName }, shortName: { from: before.shortName, to: b.shortName } } });
    return current();
  });

  await app.register(async (logo) => {
    rawImageBodies(logo);
    logo.put("/logo", { config: { rateLimit: { max: 10, timeWindow: "1 minute" } } }, async (req, reply) => {
      const up = await readLogo(req, reply);
      if (!up) return;
      const data = { logoMime: up.img.mime, logoData: up.bytes, logoWidth: up.img.width, logoHeight: up.img.height, logoSha256: up.img.sha256, updatedById: req.auth.userId };
      await app.prisma.instanceBrand.upsert({ where: { id: BRAND_ID }, create: { id: BRAND_ID, ...data }, update: data });
      app.brand.invalidate();
      await logEvent(app.prisma, { actorId: req.auth.userId, action: "instance.logo_set", ...meta(req), meta: { mime: up.img.mime, width: up.img.width, height: up.img.height, bytes: up.bytes.length } });
      return current();
    });
  });

  app.delete("/logo", async (req) => {
    const n = await app.prisma.instanceBrand.updateMany({ where: { id: BRAND_ID, logoSha256: { not: null } },
      data: { logoMime: null, logoData: null, logoWidth: null, logoHeight: null, logoSha256: null, updatedById: req.auth.userId } });
    app.brand.invalidate();
    if (n.count) await logEvent(app.prisma, { actorId: req.auth.userId, action: "instance.logo_remove", ...meta(req) });
    return current();
  });
};
