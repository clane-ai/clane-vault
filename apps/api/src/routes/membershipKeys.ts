import type { FastifyPluginAsync, FastifyRequest } from "fastify";
import { z } from "zod";
import { isUniqueViolation, type Db } from "../lib/access.js";
import { logEvent } from "../lib/events.js";
import { lockFolder } from "../lib/groups.js";
import { blockingRows, currentKey, currentKeys, dropUnusedRetiring, isPublicKeyB64, liveKeys, needsAccess, recipientKeyOk } from "../lib/membershipKeys.js";
import { lockedFor, registerFailure } from "../lib/lockout.js";
import { lockUser } from "../lib/orgs.js";
import { isPrivateLocked } from "../lib/privateLock.js";
import { secretBox } from "../lib/secretBox.js";
import { consumeTotp } from "../lib/totp.js";
import { secretValueMatches } from "../lib/recovery.js";
import { kdfView } from "./auth.js";
import argon2 from "argon2";

const pub = z.string().refine(isPublicKeyB64, "public key");
const wrapped = z.string().regex(/^v1\.[A-Za-z0-9_-]+$/).max(1024);
const sealed = z.string().regex(/^s1\.[A-Za-z0-9_.-]+$/).max(4096);
/** What a row was sealed to before (compare-and-set): null, a membership public key or "acct:<key>". */
const from = z.string().max(64).nullable();
const PAGE = 200;

/**
 * Membership keys of the caller in the active org (X-Org-Id), the client-driven migration to them, rotation and
 * escrows (docs/design/2026-10-08-per-org-keypairs.md, section 6). Org-scoped: a session confined to one
 * org (trusted IdP MFA) handles that org's keys only.
 */
export const membershipKeyRoutes: FastifyPluginAsync = async (app) => {
  app.addHook("preHandler", app.requireAuth);
  app.addHook("preHandler", app.orgRequired);
  const orgId = (req: FastifyRequest) => req.org!.id;
  const meta = (req: FastifyRequest) => ({ ip: req.ip, userAgent: String(req.headers["user-agent"] ?? "").slice(0, 300) });
  const acked = (ackAt: Date | null, changedAt: Date | null) => !!ackAt && (!changedAt || ackAt >= changedAt);

  /** Active admins of the org other than `me`, with their current membership keys (null when they have none yet). */
  async function adminsWithKeys(db: Db, org: string, me: string) {
    const admins = await db.user.findMany({ where: { status: "active", id: { not: me }, memberships: { some: { orgId: org, status: "active", role: { in: ["owner", "admin"] } } } }, select: { id: true, name: true } });
    const keys = await currentKeys(db, org, admins.map((a) => a.id));
    return admins.map((a) => ({ ...a, publicKey: keys.get(a.id) ?? null }));
  }

  /** Everything the client needs for this org: its keys, what to migrate, whether to rotate, and the escrows to make. */
  app.get("/membership-key", async (req) => {
    const me = req.auth.userId, org = orgId(req);
    const [user, membership, keys] = await Promise.all([
      app.prisma.user.findUniqueOrThrow({ where: { id: me }, select: { userKeyGen: true } }),
      app.prisma.membership.findUniqueOrThrow({ where: { orgId_userId: { orgId: org, userId: me } }, select: { adminRecoveryAckAt: true, keysRepairedGen: true, org: { select: { adminRecoveryEnabled: true, adminRecoveryChangedAt: true } } } }),
      app.prisma.membershipKey.findMany({ where: { orgId: org, userId: me, state: { in: ["current", "retiring"] } }, orderBy: { createdAt: "asc" } }),
    ]);
    const mine = keys.filter((k) => k.userKeyGen === user.userKeyGen);
    const current = mine.find((k) => k.state === "current") ?? null;
    const pendingRows = await blockingRows(app.prisma, org, me);
    const enabled = membership.org.adminRecoveryEnabled;
    const ackRequired = enabled && !acked(membership.adminRecoveryAckAt, membership.org.adminRecoveryChangedAt);
    const escrows = await app.prisma.membershipEscrow.findMany({ where: { orgId: org, userId: me }, select: { adminId: true, memberPublicKey: true, adminPublicKey: true, createdAt: true } });
    const admins = enabled ? await adminsWithKeys(app.prisma, org, me) : [];
    const valid = (a: { id: string; publicKey: string | null }) => escrows.some((e) => e.adminId === a.id && e.memberPublicKey === current?.publicKey && e.adminPublicKey === a.publicKey);
    const needed = enabled && !ackRequired && current && pendingRows === 0 && !current.escrowOpenedAt
      ? admins.filter((a) => a.publicKey && !valid(a)).map((a) => ({ adminId: a.id, publicKey: a.publicKey! }))
      : [];
    return {
      userKeyGen: user.userKeyGen,
      keys: mine.map((k) => ({ publicKey: k.publicKey, wrappedPrivateKey: k.wrappedPrivateKey, state: k.state, escrowOpenedAt: k.escrowOpenedAt?.toISOString() ?? null })),
      rotateNeeded: !!current?.escrowOpenedAt,
      pendingRows,
      repairNeeded: membership.keysRepairedGen < user.userKeyGen,
      escrow: {
        enabled, ackRequired, needed,
        holders: admins.filter((a) => escrows.some((e) => e.adminId === a.id && e.memberPublicKey === current?.publicKey)).map((a) => ({ adminId: a.id, name: a.name })),
        recoverable: !!current && pendingRows === 0 && admins.some((a) => valid(a)),
      },
    };
  });

  /** Creates the caller's membership key in this org if there is none (idempotent: two devices racing get the same winner). */
  app.post("/membership-key", async (req, reply) => {
    const b = z.object({ publicKey: pub, wrappedPrivateKey: wrapped }).parse(req.body);
    const me = req.auth.userId, org = orgId(req);
    const gen = (await app.prisma.user.findUniqueOrThrow({ where: { id: me }, select: { userKeyGen: true } })).userKeyGen;
    let created = false;
    try {
      if (!(await currentKey(app.prisma, org, me))) { await app.prisma.membershipKey.create({ data: { orgId: org, userId: me, publicKey: b.publicKey, wrappedPrivateKey: b.wrappedPrivateKey, userKeyGen: gen } }); created = true; }
    } catch (e) { if (!isUniqueViolation(e)) throw e; }
    const cur = await currentKey(app.prisma, org, me);
    if (!cur) return reply.code(409).send({ error: "retry" });
    if (created) await logEvent(app.prisma, { orgId: org, actorId: me, action: "membership.key_created", ...meta(req) });
    return reply.code(created ? 201 : 200).send({ created, key: { publicKey: cur.publicKey, wrappedPrivateKey: cur.wrappedPrivateKey, state: cur.state } });
  });

  /** Rotation: a new current key; the old one retires (rows move to the new one, then it goes). The old key's escrows end. */
  app.post("/membership-key/rotate", async (req, reply) => {
    const b = z.object({ from: pub, publicKey: pub, wrappedPrivateKey: wrapped }).parse(req.body);
    const me = req.auth.userId, org = orgId(req);
    const ok = await app.prisma.$transaction(async (tx) => {
      await lockUser(tx, me);
      const gen = (await tx.user.findUniqueOrThrow({ where: { id: me }, select: { userKeyGen: true } })).userKeyGen;
      const n = await tx.membershipKey.updateMany({ where: { orgId: org, userId: me, state: "current", publicKey: b.from }, data: { state: "retiring", retiredAt: new Date() } });
      if (n.count !== 1) return false;
      await tx.membershipKey.create({ data: { orgId: org, userId: me, publicKey: b.publicKey, wrappedPrivateKey: b.wrappedPrivateKey, userKeyGen: gen } });
      await tx.membershipEscrow.deleteMany({ where: { orgId: org, userId: me } });
      return true;
    }).catch((e) => { if (isUniqueViolation(e)) return false; throw e; });
    if (!ok) return reply.code(409).send({ error: "stale_key" });
    await logEvent(app.prisma, { orgId: org, actorId: me, action: "membership.key_rotated", ...meta(req) });
    return { ok: true };
  });

  /**
   * My rows in this org not yet sealed to my current key: on my account key (null), a retiring key, or (with acct=1,
   * after restoring from the archive) an account key a scoped reset replaced. Paged by row id.
   */
  app.get("/membership-key/pending", async (req) => {
    const q = z.object({ folderAfter: z.string().uuid().optional(), shareAfter: z.string().uuid().optional(), acct: z.enum(["0", "1"]).optional() }).parse(req.query);
    const me = req.auth.userId, org = orgId(req);
    const retiring = (await app.prisma.membershipKey.findMany({ where: { orgId: org, userId: me, state: "retiring" }, select: { publicKey: true } })).map((k) => k.publicKey);
    const sealed = [{ sealedTo: null }, { sealedTo: { in: retiring } }, ...(q.acct === "1" ? [{ sealedTo: { startsWith: "acct:" } }] : [])];
    const [folders, shares] = await Promise.all([
      app.prisma.folderMember.findMany({ where: { userId: me, folder: { kind: "team", orgId: org }, OR: sealed, ...(q.folderAfter ? { id: { gt: q.folderAfter } } : {}) }, orderBy: { id: "asc" }, take: PAGE, select: { id: true, folderId: true, sealedTo: true, wrappedFolderKey: true } }),
      app.prisma.recordAccess.findMany({ where: { holderType: "user", holderId: me, permission: { not: "owner" }, orgId: org, OR: sealed, ...(q.shareAfter ? { id: { gt: q.shareAfter } } : {}) }, orderBy: { id: "asc" }, take: PAGE, select: { id: true, recordId: true, sealedTo: true, wrappedRecordKey: true } }),
    ]);
    return {
      folders: folders.map((f) => ({ folderId: f.folderId, sealedTo: f.sealedTo, wrappedFolderKey: f.wrappedFolderKey })),
      shares: shares.map((s) => ({ recordId: s.recordId, sealedTo: s.sealedTo, wrappedRecordKey: s.wrappedRecordKey! })),
      folderAfter: folders.length === PAGE ? folders.at(-1)!.id : null,
      shareAfter: shares.length === PAGE ? shares.at(-1)!.id : null,
    };
  });

  /**
   * Re-sealed rows, each applied only if it is still sealed to what the client read (`from`). `to` is the key the client
   * sealed them to: it must still be my current key, checked under the account lock against a concurrent rotation
   * (otherwise rows sealed to the old key would be labelled with the new one and the old key dropped: access lost).
   */
  app.put("/membership-key/rows", { config: { rateLimit: { max: 120, timeWindow: "1 minute" } } }, async (req, reply) => {
    const b = z.object({
      to: pub,
      folders: z.array(z.object({ folderId: z.string().uuid(), from, wrappedFolderKey: sealed })).max(PAGE).default([]),
      shares: z.array(z.object({ recordId: z.string().uuid(), from, wrappedRecordKey: sealed })).max(PAGE).default([]),
    }).parse(req.body);
    const me = req.auth.userId, org = orgId(req);
    const r = await app.prisma.$transaction(async (tx) => {
      // Rotation takes the same lock: the current key can't change until these rows are written.
      await lockUser(tx, me);
      const cur = await currentKey(tx, org, me);
      if (!cur) return "no_key" as const;
      if (cur.publicKey !== b.to) return "stale_key" as const;
      let updated = 0;
      for (const f of b.folders) {
        const n = await tx.folderMember.updateMany({ where: { folderId: f.folderId, userId: me, folder: { kind: "team", orgId: org }, sealedTo: f.from }, data: { wrappedFolderKey: f.wrappedFolderKey, sealedTo: cur.publicKey } });
        updated += n.count;
      }
      for (const s of b.shares) {
        const n = await tx.recordAccess.updateMany({ where: { recordId: s.recordId, holderType: "user", holderId: me, permission: { not: "owner" }, orgId: org, sealedTo: s.from }, data: { wrappedRecordKey: s.wrappedRecordKey, sealedTo: cur.publicKey } });
        updated += n.count;
      }
      return { updated, retired: await dropUnusedRetiring(tx, org, me) };
    }, { timeout: 30_000 });
    if (typeof r === "string") return reply.code(409).send({ error: r });
    const { updated, retired } = r;
    if (updated) await logEvent(app.prisma, { orgId: org, actorId: me, action: "membership.rows_migrated", meta: { count: updated } });
    return { updated, retired, pendingRows: await blockingRows(app.prisma, org, me) };
  });

  /**
   * Escrows of my current membership key, sealed to admins' current membership keys: only while this org's policy is on,
   * I acknowledged it, every row of mine here is on my current key, and each admin is an active admin with that key.
   */
  app.put("/membership-key/escrows", { config: { rateLimit: { max: 20, timeWindow: "1 minute" } } }, async (req, reply) => {
    const b = z.object({ memberPublicKey: pub, escrows: z.array(z.object({ adminId: z.string().uuid(), adminPublicKey: pub, sealedKey: sealed })).min(1).max(200) }).parse(req.body);
    const me = req.auth.userId, org = orgId(req);
    if (new Set(b.escrows.map((e) => e.adminId)).size !== b.escrows.length) return reply.code(400).send({ error: "invalid_request" });
    const r = await app.prisma.$transaction(async (tx) => {
      // A concurrent rotation (which deletes my escrows) waits, so no escrow of a retired key is left behind.
      await lockUser(tx, me);
      // Locks the policy against a concurrent switch-off (which deletes escrows) until this commits.
      const rows = await tx.$queryRaw<{ adminRecoveryEnabled: boolean; adminRecoveryChangedAt: Date | null }[]>`SELECT "adminRecoveryEnabled", "adminRecoveryChangedAt" FROM "Organization" WHERE id = ${org}::uuid FOR SHARE`;
      if (!rows[0]?.adminRecoveryEnabled) return "policy_off" as const;
      const m = await tx.membership.findFirst({ where: { orgId: org, userId: me, status: "active" }, select: { adminRecoveryAckAt: true } });
      if (!m) return "policy_off" as const;
      if (!acked(m.adminRecoveryAckAt, rows[0].adminRecoveryChangedAt)) return "ack_required" as const;
      const cur = await currentKey(tx, org, me);
      if (!cur || cur.publicKey !== b.memberPublicKey || cur.escrowOpenedAt) return "stale_key" as const;
      if ((await blockingRows(tx, org, me)) > 0) return "migration_pending" as const;
      const admins = new Map((await adminsWithKeys(tx, org, me)).map((a) => [a.id, a.publicKey]));
      for (const e of b.escrows) if (e.adminId === me || !admins.has(e.adminId)) return "not_admin" as const;
      for (const e of b.escrows) if (admins.get(e.adminId) !== e.adminPublicKey) return "stale_admin_key" as const;
      for (const e of b.escrows)
        await tx.membershipEscrow.upsert({ where: { orgId_userId_adminId: { orgId: org, userId: me, adminId: e.adminId } },
          create: { orgId: org, userId: me, adminId: e.adminId, memberPublicKey: cur.publicKey, adminPublicKey: e.adminPublicKey, sealedKey: e.sealedKey },
          update: { memberPublicKey: cur.publicKey, adminPublicKey: e.adminPublicKey, sealedKey: e.sealedKey, createdAt: new Date() } });
      return b.escrows.length;
    });
    if (typeof r === "string") return reply.code(r === "not_admin" ? 400 : 409).send({ error: r });
    await logEvent(app.prisma, { orgId: org, actorId: me, action: "recovery.escrow_created", meta: { count: r } });
    return { stored: r };
  });

  /** After a scoped reset: my own records in this org's team folders, with the folder row to rebuild my owner row from. */
  app.get("/membership-key/owner-repair", async (req) => {
    const me = req.auth.userId, org = orgId(req);
    const teams = (await app.prisma.folderMember.findMany({ where: { userId: me, folder: { kind: "team", orgId: org, deletedAt: null } }, select: { folderId: true } })).map((f) => f.folderId);
    if (!teams.length) return { rows: [] };
    const owners = await app.prisma.recordAccess.findMany({ where: { holderType: "user", holderId: me, permission: "owner", record: { folderId: { in: teams } } }, select: { recordId: true, wrappedRecordKey: true, record: { select: { folderId: true } } } });
    const folderRows = await app.prisma.recordAccess.findMany({ where: { holderType: "folder", recordId: { in: owners.map((o) => o.recordId) } }, select: { recordId: true, holderId: true, wrappedRecordKey: true } });
    const byRecord = new Map(folderRows.map((f) => [`${f.recordId}:${f.holderId}`, f.wrappedRecordKey]));
    return { rows: owners.flatMap((o) => {
      const fw = byRecord.get(`${o.recordId}:${o.record.folderId}`);
      return fw ? [{ recordId: o.recordId, ownerWrapped: o.wrappedRecordKey!, folderId: o.record.folderId!, folderWrapped: fw }] : [];
    }) };
  });

  app.post("/membership-key/repaired", async (req) => {
    const me = req.auth.userId, org = orgId(req);
    const gen = (await app.prisma.user.findUniqueOrThrow({ where: { id: me }, select: { userKeyGen: true } })).userKeyGen;
    await app.prisma.membership.update({ where: { orgId_userId: { orgId: org, userId: me } }, data: { keysRepairedGen: gen } });
    return { ok: true };
  });

  /**
   * Gives a member their folder key again after their key changed (a scoped reset, an archived membership key): an
   * explicit action of someone holding the key (owner or editor), never automatic (a server could otherwise collect
   * folder keys by claiming someone re-keyed). Only rows that really lost their key, only to the member's current key.
   */
  app.put("/folders/:id/members/:userId/key", async (req, reply) => {
    const { id, userId } = z.object({ id: z.string().uuid(), userId: z.string().uuid() }).parse(req.params);
    const b = z.object({ wrappedFolderKey: sealed, sealedTo: pub.nullable() }).parse(req.body);
    const org = orgId(req), me = req.auth.userId;
    const folder = await app.prisma.folder.findFirst({ where: { id, kind: "team", deletedAt: null, orgId: org }, select: { id: true } });
    const mine = folder && await app.prisma.folderMember.findUnique({ where: { folderId_userId: { folderId: id, userId: me } }, select: { permission: true } });
    if (!folder || !mine) return reply.code(404).send({ error: "not_found" });
    if (mine.permission !== "owner" && mine.permission !== "edit") return reply.code(403).send({ error: "forbidden" });
    const r = await app.prisma.$transaction(async (tx) => {
      await lockFolder(tx, id);
      const row = await tx.folderMember.findUnique({ where: { folderId_userId: { folderId: id, userId } }, select: { sealedTo: true } });
      if (!row) return "not_member" as const;
      if (!needsAccess(row.sealedTo, await liveKeys(tx, org, [userId]))) return "has_access" as const;
      if (!(await recipientKeyOk(tx, org, userId, b.sealedTo))) return "stale_recipient_key" as const;
      await tx.folderMember.update({ where: { folderId_userId: { folderId: id, userId } }, data: { wrappedFolderKey: b.wrappedFolderKey, sealedTo: b.sealedTo } });
      return "ok" as const;
    });
    if (r !== "ok") return reply.code(r === "not_member" ? 404 : 409).send({ error: r });
    await logEvent(app.prisma, { orgId: org, actorId: me, action: "folder.access_regranted", folderId: id, targetUserId: userId, ...meta(req) });
    return { ok: true };
  });
};

/**
 * Account-wide re-keying after a scoped reset (no X-Org-Id): the archive of the old account keys, and re-wrapping my
 * owner rows, private folder names and archived membership keys under my current user key. Private items: a session
 * confined to one org (trusted IdP MFA) needs a TOTP step-up first.
 */
export const meKeyRoutes: FastifyPluginAsync = async (app) => {
  app.addHook("preHandler", app.requireAuth);
  app.addHook("preHandler", app.orgOptional);
  const box = secretBox(app.config.serverSecret);
  const meta = (req: FastifyRequest) => ({ ip: req.ip, userAgent: String(req.headers["user-agent"] ?? "").slice(0, 300) });
  const unconfined = (req: FastifyRequest) => !isPrivateLocked(req);

  /**
   * What the archive holds (no key material): for the "restore items from before your reset" banner and settings. The
   * old KDF parameters (public, like prelogin) let the device derive the old auth key to open it with the old password.
   */
  app.get("/me/key-archive", async (req) => {
    const rows = await app.prisma.accountKeyArchive.findMany({ where: { userId: req.auth.userId }, orderBy: { archivedAt: "desc" },
      select: { id: true, userKeyGen: true, archivedAt: true, restoredAt: true, privateItems: true, otherOrgs: true, recoveryWrap: true, kdfSalt: true, kdfParams: true } });
    return { archives: rows.map((r) => ({ id: r.id, userKeyGen: r.userKeyGen, archivedAt: r.archivedAt.toISOString(), restoredAt: r.restoredAt?.toISOString() ?? null,
      privateItems: r.privateItems, otherOrgs: r.otherOrgs, hasKit: !!r.recoveryWrap, kdfSalt: r.kdfSalt, kdfParams: kdfView(r.kdfParams) })) };
  });

  /**
   * One archive's key material (ciphertext only), for a fresh 2FA code plus proof of the old secret: the old master
   * password's auth key or the old kit's auth value, checked here like a sign-in (failures count toward the lockout).
   * A session and a code alone never get the old wrapped user key: whoever completed the reset (an org's admins, in the
   * 2FA-reset path) could otherwise guess the old master password offline and reach private items and other orgs.
   */
  app.post("/me/key-archive/open", { config: { rateLimit: { max: 10, timeWindow: "1 minute" } } }, async (req, reply) => {
    if (!unconfined(req)) return reply.code(403).send({ error: "totp_step_up_required" });
    const b = z.object({ code: z.string().max(10), id: z.string().uuid(), authKey: z.string().max(4096).optional(), recoveryAuth: z.string().regex(/^[A-Za-z0-9_-]{43}$/).optional() }).parse(req.body);
    const user = await app.prisma.user.findUniqueOrThrow({ where: { id: req.auth.userId } });
    const locked = lockedFor(user);
    if (locked) return reply.code(423).send({ error: "locked", retryAfterSeconds: locked });
    const archive = await app.prisma.accountKeyArchive.findFirst({ where: { id: b.id, userId: user.id } });
    if (!archive) return reply.code(404).send({ error: "not_found" });
    const fail = async (error: string) => {
      await registerFailure(app.prisma, user.id);
      await logEvent(app.prisma, { actorId: user.id, action: "auth.reauth_failed", ...meta(req) });
      return reply.code(401).send({ error });
    };
    if (!(await consumeTotp(app.prisma, box, user, b.code))) return fail("totp_invalid");
    // Archives from before the old auth hashes were kept have neither: those open with the 2FA code, as they did.
    const guarded = !!(archive.authHash || archive.recoveryAuthHash);
    const proven = b.authKey ? !!archive.authHash && await argon2.verify(archive.authHash, b.authKey).catch(() => false)
      : b.recoveryAuth ? secretValueMatches(archive.recoveryAuthHash, b.recoveryAuth) : false;
    if (guarded && !proven) return fail("invalid_credentials");
    const rows = [archive];
    const archived = await app.prisma.membershipKey.findMany({ where: { userId: user.id, state: "archived", org: { memberships: { some: { userId: user.id, status: "active" } } } }, select: { orgId: true, publicKey: true, wrappedPrivateKey: true, userKeyGen: true } });
    return { archives: rows.map((r) => ({ id: r.id, userKeyGen: r.userKeyGen, kdfSalt: r.kdfSalt, kdfParams: r.kdfParams, wrappedUserKey: r.wrappedUserKey, publicKey: r.publicKey,
      wrappedPrivateKey: r.wrappedPrivateKey, recoveryWrap: r.recoveryWrap, membershipKeys: archived.filter((k) => k.userKeyGen === r.userKeyGen).map(({ userKeyGen: _g, ...k }) => k) })) };
  });

  /** Archived membership keys, re-wrapped under my current user key: current again (or retiring if the org has a newer one). */
  app.post("/me/key-archive/:id/memberships", async (req, reply) => {
    if (!unconfined(req)) return reply.code(403).send({ error: "totp_step_up_required" });
    const { id } = z.object({ id: z.string().uuid() }).parse(req.params);
    const b = z.object({ keys: z.array(z.object({ orgId: z.string().uuid(), publicKey: pub, wrappedPrivateKey: wrapped })).max(500) }).parse(req.body);
    const me = req.auth.userId;
    const a = await app.prisma.accountKeyArchive.findFirst({ where: { id, userId: me }, select: { userKeyGen: true } });
    if (!a) return reply.code(404).send({ error: "not_found" });
    let restored = 0;
    await app.prisma.$transaction(async (tx) => {
      await lockUser(tx, me);
      const gen = (await tx.user.findUniqueOrThrow({ where: { id: me }, select: { userKeyGen: true } })).userKeyGen;
      for (const k of b.keys) {
        const row = await tx.membershipKey.findFirst({ where: { userId: me, orgId: k.orgId, publicKey: k.publicKey, state: "archived", userKeyGen: a.userKeyGen } });
        if (!row) continue;
        const hasCurrent = !!(await currentKey(tx, k.orgId, me));
        await tx.membershipKey.update({ where: { id: row.id }, data: { wrappedPrivateKey: k.wrappedPrivateKey, userKeyGen: gen, state: hasCurrent ? "retiring" : "current", retiredAt: hasCurrent ? new Date() : null } });
        restored++;
      }
    });
    return { restored };
  });

  app.post("/me/key-archive/:id/restored", async (req, reply) => {
    const { id } = z.object({ id: z.string().uuid() }).parse(req.params);
    const n = await app.prisma.accountKeyArchive.updateMany({ where: { id, userId: req.auth.userId }, data: { restoredAt: new Date() } });
    if (!n.count) return reply.code(404).send({ error: "not_found" });
    await logEvent(app.prisma, { actorId: req.auth.userId, action: "auth.key_archive_restored", ...meta(req) });
    return { ok: true };
  });

  /** Forgets an archive: the old password and old kit no longer open anything. */
  app.delete("/me/key-archive/:id", async (req, reply) => {
    if (!unconfined(req)) return reply.code(403).send({ error: "totp_step_up_required" });
    const { id } = z.object({ id: z.string().uuid() }).parse(req.params);
    const me = req.auth.userId;
    const a = await app.prisma.accountKeyArchive.findFirst({ where: { id, userId: me }, select: { userKeyGen: true } });
    if (!a) return reply.code(404).send({ error: "not_found" });
    await app.prisma.$transaction([
      app.prisma.membershipKey.deleteMany({ where: { userId: me, state: "archived", userKeyGen: a.userKeyGen } }),
      app.prisma.accountKeyArchive.delete({ where: { id } }),
    ]);
    await logEvent(app.prisma, { actorId: me, action: "auth.key_archive_deleted", ...meta(req) });
    return reply.code(204).send();
  });

  /** My owner rows (paged): the restore re-wraps those still under the old user key. */
  app.get("/me/owner-rows", async (req, reply) => {
    if (!unconfined(req)) return reply.code(403).send({ error: "totp_step_up_required" });
    const { after } = z.object({ after: z.string().uuid().optional() }).parse(req.query);
    const rows = await app.prisma.recordAccess.findMany({ where: { holderType: "user", holderId: req.auth.userId, permission: "owner", ...(after ? { id: { gt: after } } : {}) }, orderBy: { id: "asc" }, take: PAGE, select: { id: true, recordId: true, wrappedRecordKey: true } });
    return { rows: rows.map((r) => ({ recordId: r.recordId, wrappedRecordKey: r.wrappedRecordKey! })), after: rows.length === PAGE ? rows.at(-1)!.id : null };
  });

  /** Re-wrapped owner rows, each only if it still holds what the client read. A confined session only for records of its org. */
  app.put("/me/owner-rows", { config: { rateLimit: { max: 120, timeWindow: "1 minute" } } }, async (req) => {
    const b = z.object({ rows: z.array(z.object({ recordId: z.string().uuid(), from: wrapped, wrappedRecordKey: wrapped })).max(PAGE) }).parse(req.body);
    const me = req.auth.userId;
    const confinedTo = req.auth.totpSkippedForOrg ?? null;
    let updated = 0;
    for (const r of b.rows) {
      const where = { recordId: r.recordId, holderType: "user" as const, holderId: me, permission: "owner" as const, wrappedRecordKey: r.from,
        ...(confinedTo ? { record: { folder: { kind: "team" as const, orgId: confinedTo } } } : {}) };
      updated += (await app.prisma.recordAccess.updateMany({ where, data: { wrappedRecordKey: r.wrappedRecordKey } })).count;
    }
    return { updated };
  });

  app.get("/me/private-folders", async (req, reply) => {
    if (!unconfined(req)) return reply.code(403).send({ error: "totp_step_up_required" });
    const rows = await app.prisma.folder.findMany({ where: { ownerId: req.auth.userId, kind: "private" }, select: { id: true, encName: true } });
    return { folders: rows };
  });

  app.put("/me/private-folders", async (req, reply) => {
    if (!unconfined(req)) return reply.code(403).send({ error: "totp_step_up_required" });
    const b = z.object({ folders: z.array(z.object({ folderId: z.string().uuid(), from: wrapped, encName: wrapped })).max(PAGE) }).parse(req.body);
    let updated = 0;
    for (const f of b.folders)
      updated += (await app.prisma.folder.updateMany({ where: { id: f.folderId, ownerId: req.auth.userId, kind: "private", encName: f.from }, data: { encName: f.encName } })).count;
    return { updated };
  });
};
