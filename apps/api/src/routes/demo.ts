import type { FastifyPluginAsync } from "fastify";
import { randomBytes } from "node:crypto";
import { z } from "zod";
import { authView, createSession, materialSchema, startAdminAge } from "./auth.js";
import { DEMO_ORG_NAME, demoSkipsTotp } from "../lib/demo.js";
import { logEvent } from "../lib/events.js";
import { displayName } from "../lib/names.js";
import { slugFor } from "../lib/orgs.js";
import { hashToken } from "../lib/tokens.js";

/** The sandbox's sign-up invite is used straight away by the browser that asked for it. */
const INVITE_TTL_MS = 10 * 60e3;
/** Made-up colleagues per sandbox (they make the sharing and member screens worth a look). */
const MAX_COLLEAGUES = 3;
/**
 * A colleague's password hash: not an argon2 hash, so no password ever matches it (argon2.verify throws, which the
 * sign-in treats as a wrong password). Nobody can sign in as a made-up colleague.
 */
const NO_SIGN_IN = "!demo-colleague-no-sign-in";

/** Addresses in the sandbox: example.com is reserved (RFC 2606), so nothing could ever be delivered to them anyway. */
const address = (local: string, tag: string) => `${local.toLowerCase().normalize("NFKD").replace(/[^a-z0-9]+/g, ".").replace(/^\.+|\.+$/g, "").slice(0, 30) || "colleague"}.${tag}@demo.example.com`;

/**
 * Public demo (docs/demo.md), under /api/v1/auth. Registered only when DEMO_MODE=true (otherwise these paths are 404).
 *
 * 1. POST /demo: a new sandbox organisation, "Northwind (demo)", that expires after DEMO_TTL_MINUTES, and a one-time owner
 *    invite for a made-up address. Per client address (the trust-proxy aware one), DEMO_SANDBOXES_PER_IP_PER_HOUR.
 * 2. The browser signs up through that invite with the normal POST /register: it makes the random master password, the
 *    KDF salt, the key pair and the wrapped keys, as any sign-up does. The account gets the sandbox's expiry.
 * 3. POST /demo/session (setup token): a demo account on a demo instance skips the authenticator and gets its session;
 *    made-up colleagues (key pairs from the browser, no way to sign in) join the sandbox.
 */
export const demoRoutes: FastifyPluginAsync = async (app) => {
  const demo = app.config.demo!;
  const material = materialSchema(app.config.kdfMinMemoryKiB);
  const meta = (req: { ip: string; headers: Record<string, unknown> }) => ({ ip: req.ip, userAgent: String(req.headers["user-agent"] ?? "").slice(0, 300) });

  app.post("/demo", { config: { rateLimit: { max: demo.sandboxesPerIpPerHour, timeWindow: "1 hour" } } }, async (req, reply) => {
    const now = Date.now();
    const expiresAt = new Date(now + demo.ttlMinutes * 60e3);
    const tag = randomBytes(5).toString("hex");
    const email = address("visitor", tag);
    const token = randomBytes(24).toString("base64url");
    const org = await app.prisma.organization.create({ data: { name: DEMO_ORG_NAME, slug: slugFor(DEMO_ORG_NAME), demoExpiresAt: expiresAt,
      invites: { create: { email, role: "owner", tokenHash: hashToken(token), expiresAt: new Date(Math.min(now + INVITE_TTL_MS, expiresAt.getTime())) } } } });
    await logEvent(app.prisma, { orgId: org.id, action: "demo.sandbox_create", ...meta(req) });
    return reply.code(201).send({ inviteToken: token, email, expiresAt: expiresAt.toISOString() });
  });

  app.post("/demo/session", { preHandler: app.requireSetup, config: { rateLimit: { max: 10, timeWindow: "1 minute" } } }, async (req, reply) => {
    const body = z.object({ colleagues: z.array(z.object({ name: displayName, material })).max(MAX_COLLEAGUES)
      .refine((cs) => new Set(cs.map((c) => c.name.toLowerCase())).size === cs.length, { message: "duplicate_name" }).default([]) }).parse(req.body ?? {});
    const user = await app.prisma.user.findUniqueOrThrow({ where: { id: req.setupUserId } });
    // Both, on the server: demo mode is on (this route only exists then) and this is a live demo account.
    if (!demoSkipsTotp(app.config, user) || user.status !== "pending_2fa") return reply.code(403).send({ error: "not_demo" });
    const own = await app.prisma.membership.findFirst({ where: { userId: user.id, role: "owner", status: "active", org: { demoExpiresAt: { not: null } } }, select: { orgId: true, org: { select: { slug: true } } } });
    if (!own) return reply.code(403).send({ error: "not_demo" });
    const tag = randomBytes(5).toString("hex");
    const now = new Date();
    const { active, colleagues } = await app.prisma.$transaction(async (tx) => {
      // Only once: a second call with the same setup token finds the account active already.
      const n = await tx.user.updateMany({ where: { id: user.id, status: "pending_2fa" }, data: { status: "active" } });
      if (n.count !== 1) return { active: null, colleagues: [] };
      const colleagues = [];
      for (const c of body.colleagues) {
        colleagues.push(await tx.user.create({ data: {
          email: address(c.name, tag), name: c.name, status: "active", authHash: NO_SIGN_IN, demoExpiresAt: user.demoExpiresAt,
          kdfSalt: c.material.kdfSalt, kdfParams: c.material.kdfParams, wrappedUserKey: c.material.wrappedUserKey, publicKey: c.material.publicKey, wrappedPrivateKey: c.material.wrappedPrivateKey,
          memberships: { create: { orgId: own.orgId, role: "member", status: "active", invitedById: user.id, joinedAt: now } },
        }, select: { id: true, name: true, email: true, publicKey: true } }));
      }
      return { active: await tx.user.findUniqueOrThrow({ where: { id: user.id } }), colleagues };
    });
    if (!active) return reply.code(409).send({ error: "already_set_up" });
    await startAdminAge(app, active, req.log, meta(req));
    await logEvent(app.prisma, { orgId: own.orgId, actorId: user.id, action: "demo.session", ...meta(req), meta: { colleagues: colleagues.length } });
    const { accessToken } = await createSession(app, reply, active, meta(req).userAgent);
    return { ...(await authView(app.prisma, app.config, accessToken, active)), colleagues };
  });
};
