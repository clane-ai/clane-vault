import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { createActiveUser, makeTestApp, resetDb } from "./helpers.js";
import { inspectLogo, LOGO_MAX_BYTES } from "../src/lib/images.js";
import { totpKeyUri } from "../src/lib/totp.js";

// Org logos and the instance's runtime branding (docs/branding.md).

/** Minimal image headers: enough for the server's magic-byte and dimension checks. */
const u32be = (n: number) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
const u16be = (n: number) => { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b; };
const u16le = (n: number) => { const b = Buffer.alloc(2); b.writeUInt16LE(n); return b; };
const u24le = (n: number) => Buffer.from([n & 255, (n >> 8) & 255, (n >> 16) & 255]);
export const png = (w: number, h: number, pad = 0) => Buffer.concat([
  Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), u32be(13), Buffer.from("IHDR"), u32be(w), u32be(h), Buffer.from([8, 6, 0, 0, 0]), u32be(0),
  Buffer.alloc(pad), u32be(0), Buffer.from("IEND"), u32be(0xae426082)]);
const jpeg = (w: number, h: number) => Buffer.concat([
  Buffer.from([0xff, 0xd8]), Buffer.from([0xff, 0xe0]), u16be(16), Buffer.from("JFIF\0"), Buffer.from([1, 1, 0]), u16be(1), u16be(1), Buffer.from([0, 0]),
  Buffer.from([0xff, 0xc0]), u16be(17), Buffer.from([8]), u16be(h), u16be(w), Buffer.from([3, 1, 0x22, 0, 2, 0x11, 1, 3, 0x11, 1]), Buffer.from([0xff, 0xd9])]);
const riff = (chunk: string, body: Buffer) => Buffer.concat([Buffer.from("RIFF"), u32be(0).reverse(), Buffer.from("WEBP"), Buffer.from(chunk), Buffer.from([body.length, 0, 0, 0]), body]);
const webpX = (w: number, h: number) => riff("VP8X", Buffer.concat([Buffer.from([0, 0, 0, 0]), u24le(w - 1), u24le(h - 1)]));
const webpL = (w: number, h: number) => { const v = (w - 1) | ((h - 1) << 14); return riff("VP8L", Buffer.concat([Buffer.from([0x2f]), Buffer.from([v & 255, (v >> 8) & 255, (v >> 16) & 255, (v >>> 24) & 255])])); };
const webpLossy = (w: number, h: number) => riff("VP8 ", Buffer.concat([Buffer.from([0, 0, 0]), Buffer.from([0x9d, 0x01, 0x2a]), u16le(w), u16le(h), Buffer.alloc(4)]));
const SVG = Buffer.from(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`);

describe("logo checks (magic bytes and header dimensions)", () => {
  it("accepts PNG, JPEG and WebP (lossy, lossless, extended) and reads their size", () => {
    expect(inspectLogo(png(64, 32))).toMatchObject({ mime: "image/png", width: 64, height: 32 });
    expect(inspectLogo(jpeg(300, 200))).toMatchObject({ mime: "image/jpeg", width: 300, height: 200 });
    expect(inspectLogo(webpX(1024, 512))).toMatchObject({ mime: "image/webp", width: 1024, height: 512 });
    expect(inspectLogo(webpL(100, 50))).toMatchObject({ mime: "image/webp", width: 100, height: 50 });
    expect(inspectLogo(webpLossy(120, 80))).toMatchObject({ mime: "image/webp", width: 120, height: 80 });
  });

  it("refuses SVG, other types, broken headers, too many pixels and too many bytes", () => {
    expect(inspectLogo(SVG)).toBe("unsupported_type");
    expect(inspectLogo(Buffer.from("GIF89a\x01\x00\x01\x00"))).toBe("unsupported_type");
    expect(inspectLogo(Buffer.from("<html><body>hi</body></html>"))).toBe("unsupported_type");
    expect(inspectLogo(Buffer.alloc(0))).toBe("empty");
    expect(inspectLogo(png(64, 32).subarray(0, 14))).toBe("bad_image");
    expect(inspectLogo(png(0, 32))).toBe("bad_image");
    expect(inspectLogo(png(1025, 10))).toBe("too_many_pixels");
    expect(inspectLogo(jpeg(10, 2000))).toBe("too_many_pixels");
    expect(inspectLogo(webpX(4000, 10))).toBe("too_many_pixels");
    expect(inspectLogo(png(10, 10, LOGO_MAX_BYTES))).toBe("too_large");
  });
});

const t = await makeTestApp();
afterAll(() => t.app.close());
beforeEach(async () => { await resetDb(t.prisma); t.app.brand.invalidate(); });

type U = Awaited<ReturnType<typeof createActiveUser>>;
const auth = (u: U, org: string | null = u.orgId) => ({ authorization: `Bearer ${u.accessToken}`, ...(org ? { "x-org-id": org } : {}) });
/** Each account uploads from its own address (the upload routes have a per-address rate limit). */
const ipOf = (u: U) => `10.${parseInt(u.id.slice(-6, -4), 16)}.${parseInt(u.id.slice(-4, -2), 16)}.${parseInt(u.id.slice(-2), 16)}`;
const upload = (u: U, url: string, body: Buffer, contentType = "image/png", org?: string | null) =>
  t.app.inject({ method: "PUT", url: `/api/v1${url}`, payload: body, remoteAddress: ipOf(u), headers: { ...auth(u, org === undefined ? u.orgId : org), "content-type": contentType } });
const get = (u: U | null, url: string, headers: Record<string, string> = {}) => t.app.inject({ method: "GET", url: `/api/v1${url}`, headers: { ...(u ? auth(u, null) : {}), ...headers } });

describe("organisation logo", () => {
  it("owners and admins upload it; members of the org fetch it with safe headers and a version", async () => {
    const owner = await createActiveUser(t, { role: "owner" });
    const admin = await createActiveUser(t, { role: "admin" });
    const member = await createActiveUser(t);
    const img = png(128, 128);
    const up = await upload(admin, "/org/logo", img);
    expect(up.statusCode).toBe(200);
    const v = up.json().logoVersion as string;
    expect(v).toMatch(/^[0-9a-f]{16}$/);

    const r = await get(member, `/orgs/${member.orgId}/logo?v=${v}`);
    expect(r.statusCode).toBe(200);
    expect(r.rawPayload.equals(img)).toBe(true);
    expect(r.headers["content-type"]).toBe("image/png");
    expect(r.headers["x-content-type-options"]).toBe("nosniff");
    expect(r.headers["content-disposition"]).toBe('inline; filename="logo.png"');
    expect(r.headers["content-security-policy"]).toBe("default-src 'none'; sandbox");
    expect(r.headers["cache-control"]).toBe("private, max-age=86400");
    expect(r.headers.etag).toMatch(new RegExp(`^"${v}`));
    expect((await get(member, `/orgs/${member.orgId}/logo`, { "if-none-match": r.headers.etag as string })).statusCode).toBe(304);

    // The version travels with the org list and the org details.
    const mine = (await get(owner, "/me/orgs")).json().orgs;
    expect(mine[0]).toMatchObject({ id: owner.orgId, logoVersion: v });
    expect((await t.app.inject({ method: "GET", url: "/api/v1/org", headers: auth(owner) })).json()).toMatchObject({ logoVersion: v });

    // Replaced by the owner (JPEG), then removed.
    const j = await upload(owner, "/org/logo", jpeg(200, 100), "application/octet-stream");
    expect(j.statusCode).toBe(200);
    expect(j.json().logoVersion).not.toBe(v);
    expect((await get(member, `/orgs/${member.orgId}/logo`)).headers["content-type"]).toBe("image/jpeg");
    const del = await t.app.inject({ method: "DELETE", url: "/api/v1/org/logo", headers: auth(owner) });
    expect(del.json()).toEqual({ logoVersion: null });
    expect((await get(member, `/orgs/${member.orgId}/logo`)).statusCode).toBe(404);
    expect((await get(owner, "/me/orgs")).json().orgs[0].logoVersion).toBeNull();

    const events = await t.prisma.event.findMany({ where: { orgId: owner.orgId, action: { startsWith: "org.logo" } }, orderBy: { at: "asc" } });
    expect(events.map((e) => [e.action, e.actorId])).toEqual([["org.logo_set", admin.id], ["org.logo_set", owner.id], ["org.logo_remove", owner.id]]);
    expect(events[0]!.meta).toMatchObject({ mime: "image/png", width: 128, height: 128 });
  });

  it("refuses SVG, other types, broken or oversized images, whatever the declared type", async () => {
    const owner = await createActiveUser(t, { role: "owner" });
    expect((await upload(owner, "/org/logo", SVG, "image/svg+xml")).json()).toEqual({ error: "unsupported_type" });
    expect((await upload(owner, "/org/logo", SVG, "image/png")).statusCode).toBe(415);
    expect((await upload(owner, "/org/logo", Buffer.from("GIF89a\x01\x00\x01\x00"), "image/gif")).json()).toEqual({ error: "unsupported_type" });
    expect((await upload(owner, "/org/logo", png(2048, 2048))).json()).toEqual({ error: "too_many_pixels" });
    expect((await upload(owner, "/org/logo", png(10, 10).subarray(0, 20))).json()).toEqual({ error: "bad_image" });
    const big = await upload(owner, "/org/logo", png(10, 10, LOGO_MAX_BYTES));
    expect([big.statusCode, big.json()]).toEqual([413, { error: "too_large" }]);
    const huge = await upload(owner, "/org/logo", png(10, 10, LOGO_MAX_BYTES * 3));
    expect([huge.statusCode, huge.json()]).toEqual([413, { error: "too_large" }]);
    expect(await t.prisma.orgLogo.count()).toBe(0);
  });

  it("members can't set or remove it; other orgs' members and strangers can't fetch it", async () => {
    const owner = await createActiveUser(t, { role: "owner" });
    const member = await createActiveUser(t);
    expect((await upload(member, "/org/logo", png(10, 10))).statusCode).toBe(403);
    expect((await upload(owner, "/org/logo", png(10, 10))).statusCode).toBe(200);
    expect((await t.app.inject({ method: "DELETE", url: "/api/v1/org/logo", headers: auth(member) })).statusCode).toBe(403);
    expect((await upload(owner, "/org/logo", png(10, 10), "image/png", null)).json()).toEqual({ error: "org_required" });

    // Another org's owner: not a member of this one.
    const other = (await t.app.inject({ method: "POST", url: "/api/v1/orgs", payload: { name: "Other org" }, headers: auth(member, null) })).json();
    const outsider = await createActiveUser(t, { role: "owner", orgId: other.id });
    const cross = await get(outsider, `/orgs/${owner.orgId}/logo`);
    expect([cross.statusCode, cross.json()]).toEqual([404, { error: "not_found" }]);
    // A logo upload with X-Org-Id of an org they aren't in.
    expect((await upload(outsider, "/org/logo", png(10, 10), "image/png", owner.orgId)).statusCode).toBe(403);
    expect((await get(null, `/orgs/${owner.orgId}/logo`)).statusCode).toBe(401);
    // A disabled member loses it at once.
    await t.prisma.membership.updateMany({ where: { orgId: owner.orgId, userId: member.id }, data: { status: "disabled" } });
    expect((await get(member, `/orgs/${owner.orgId}/logo`)).statusCode).toBe(404);
  });
});

describe("instance branding", () => {
  it("GET /brand is public and has nulls until an instance admin sets names", async () => {
    const r = await t.app.inject({ method: "GET", url: "/api/v1/brand" });
    expect(r.statusCode).toBe(200);
    expect(r.json()).toEqual({ productName: null, shortName: null, logoVersion: null });
    expect((await t.app.inject({ method: "GET", url: "/api/v1/brand/logo" })).statusCode).toBe(404);
  });

  it("only instance admins change the names; the stored name is what emails and the authenticator issuer use", async () => {
    const admin = await createActiveUser(t, { role: "owner" });
    const orgAdmin = await createActiveUser(t, { role: "admin" });
    const put = (u: U, body: unknown) => t.app.inject({ method: "PUT", url: "/api/v1/admin/instance/brand", payload: body as object, headers: auth(u, null) });
    expect((await put(orgAdmin, { productName: "Mine", shortName: null })).statusCode).toBe(403);
    expect((await put(admin, { productName: "Mine", shortName: null })).statusCode).toBe(403);
    await t.prisma.user.update({ where: { id: admin.id }, data: { instanceAdmin: true } });

    const ok = await put(admin, { productName: "  Acme   Keys ", shortName: "Keys" });
    expect(ok.json()).toEqual({ productName: "Acme Keys", shortName: "Keys", logoVersion: null });
    expect((await t.app.inject({ method: "GET", url: "/api/v1/brand" })).json()).toEqual({ productName: "Acme Keys", shortName: "Keys", logoVersion: null });
    expect(await t.app.brand.productName()).toBe("Acme Keys");
    expect(totpKeyUri(await t.app.brand.productName(), "a@b.test", "JBSWY3DPEHPK3PXP")).toMatch(/^otpauth:\/\/totp\/Acme%20Keys:/);
    const ev = await t.prisma.event.findFirstOrThrow({ where: { action: "instance.brand_change" } });
    expect([ev.orgId, ev.actorId, ev.meta]).toEqual([null, admin.id, { productName: { from: null, to: "Acme Keys" }, shortName: { from: null, to: "Keys" } }]);

    // Validation: 1–40 characters after cleaning, no markup.
    for (const bad of ["", "   ", "x".repeat(41), "<b>Acme</b>", "Acme<script>"]) expect((await put(admin, { productName: bad, shortName: null })).statusCode, bad).toBe(400);
    expect((await put(admin, { productName: "Fine", shortName: "y".repeat(41) })).statusCode).toBe(400);
    expect((await put(admin, { productName: "Fine" })).statusCode).toBe(400);

    // Back to the defaults.
    expect((await put(admin, { productName: null, shortName: null })).json()).toEqual({ productName: null, shortName: null, logoVersion: null });
    expect(await t.app.brand.productName()).toBe("Clane Vault");
  });

  it("the instance logo: instance admins set and remove it; anyone can fetch it (the sign-in page shows it)", async () => {
    const admin = await createActiveUser(t, { role: "owner" });
    const member = await createActiveUser(t);
    await t.prisma.user.update({ where: { id: admin.id }, data: { instanceAdmin: true } });
    expect((await upload(member, "/admin/instance/brand/logo", png(10, 10), "image/png", null)).statusCode).toBe(403);
    expect((await upload(admin, "/admin/instance/brand/logo", SVG, "image/svg+xml", null)).json()).toEqual({ error: "unsupported_type" });
    expect((await upload(admin, "/admin/instance/brand/logo", png(4000, 10), "image/png", null)).json()).toEqual({ error: "too_many_pixels" });
    const img = webpX(256, 64);
    const up = await upload(admin, "/admin/instance/brand/logo", img, "image/webp", null);
    expect(up.statusCode).toBe(200);
    const v = up.json().logoVersion as string;
    expect((await t.app.inject({ method: "GET", url: "/api/v1/brand" })).json().logoVersion).toBe(v);
    const r = await t.app.inject({ method: "GET", url: `/api/v1/brand/logo?v=${v}` });
    expect(r.statusCode).toBe(200);
    expect(r.rawPayload.equals(img)).toBe(true);
    expect([r.headers["content-type"], r.headers["x-content-type-options"], r.headers["cache-control"]]).toEqual(["image/webp", "nosniff", "public, max-age=86400"]);
    expect(r.headers["content-disposition"]).toBe('inline; filename="logo.webp"');
    expect((await t.app.inject({ method: "DELETE", url: "/api/v1/admin/instance/brand/logo", headers: auth(admin, null) })).json().logoVersion).toBeNull();
    expect((await t.app.inject({ method: "GET", url: "/api/v1/brand/logo" })).statusCode).toBe(404);
    expect((await t.prisma.event.findMany({ where: { action: { startsWith: "instance.logo" } }, orderBy: { at: "asc" } })).map((e) => e.action)).toEqual(["instance.logo_set", "instance.logo_remove"]);
  });

  it("other API responses stay no-store", async () => {
    expect((await t.app.inject({ method: "GET", url: "/api/v1/brand" })).headers["cache-control"]).toBe("no-store");
  });
});
