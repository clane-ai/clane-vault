import type { FastifyPluginAsync, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import { tombstoneAttachments } from "../lib/attachments/sweep.js";
import { logEvent } from "../lib/events.js";
import { BURN } from "../lib/links.js";
import { applyPendingGroups, coolDown, dropPendingGroups, INVITE_TTL_MS, invitedRole } from "../lib/invites.js";
import { displayName } from "../lib/names.js";
import { defaultOrg, dropInstanceAdminIfGone, isInstanceAdmin, lockUser, offboard, orgsOf, slugFor } from "../lib/orgs.js";
import { startAdminAge } from "./auth.js";
import { getEntitlements, PLAN_SELECT } from "../lib/plans.js";
import { readPolicies } from "../lib/policies.js";
import { logoVersion } from "../lib/images.js";
import { rawImageBodies, readLogo, sendLogo } from "./brand.js";
import { TRIAL_MS } from "../lib/plans.js";
import planRoutes from "./plan.js";
import { assertSeat, lockSeats } from "../lib/seats.js";
import { hashToken } from "../lib/tokens.js";

const orgName = displayName;
/** Invitations to existing accounts last as long as invite links. */
const liveInvitation = () => ({ createdAt: { gt: new Date(Date.now() - INVITE_TTL_MS) } });
const orgParam = z.object({ orgId: z.string().uuid() });

/**
 * Organisations (docs/design/2026-10-07-multi-org-design.md): the caller's orgs and invitations, creating
 * one, and the active org's settings (X-Org-Id): rename, transfer ownership, delete, leave.
 */
export const orgRoutes: FastifyPluginAsync = async (app) => {
  app.addHook("preHandler", app.requireAuth);

  app.get("/me/orgs", async (req) => {
    const me = req.auth.userId;
    const invited = await app.prisma.membership.findMany({ where: { userId: me, status: "invited", ...liveInvitation() }, orderBy: { createdAt: "asc" },
      select: { role: true, createdAt: true, invitedById: true, org: { select: { ...PLAN_SELECT, id: true, name: true, policies: true } } } });
    const inviters = new Map((await app.prisma.user.findMany({ where: { id: { in: invited.map((m) => m.invitedById).filter((x): x is string => !!x) } }, select: { id: true, name: true } })).map((u) => [u.id, u.name]));
    const instanceAdmin = await isInstanceAdmin(app.prisma, app.config, me);
    return {
      orgs: await orgsOf(app.prisma, app.config, me),
      invitations: invited.map((m) => {
        // The org's master password rule: the app checks it before accepting (docs/policies.md).
        const p = readPolicies(m.org.policies, getEntitlements(app.config, m.org));
        return { orgId: m.org.id, orgName: m.org.name, role: m.role, invitedBy: m.invitedById ? inviters.get(m.invitedById) ?? null : null, invitedAt: m.createdAt.toISOString(),
          passwordPolicy: { minLength: p.minPasswordLength, minScore: p.minPasswordScore } };
      }),
      // Instance admins (the operator) can always create organisations, e.g. one per customer.
      allowOrgCreation: !app.config.demo && (app.config.allowOrgCreation === true || instanceAdmin), hostedMode: !!app.config.hostedMode,
      instanceAdmin,
    };
  });

  /** Joins the org. Admin recovery is per membership key, so other orgs' recovery is unaffected. */
  app.post("/me/invitations/:orgId/accept", async (req, reply) => {
    const { orgId } = orgParam.parse(req.params);
    // Demo mode (docs/demo.md): a sandbox account belongs to its own sandbox only.
    if (app.config.demo) return reply.code(404).send({ error: "not_found" });
    const me = req.auth.userId;
    const u = await app.prisma.user.findUniqueOrThrow({ where: { id: me }, select: { id: true, name: true, email: true } });
    const ended = await app.prisma.$transaction(async (tx) => {
      await lockSeats(tx, app.config, orgId);
      await lockUser(tx, me);
      const inv = await tx.membership.findFirst({ where: { orgId, userId: me, status: "invited", ...liveInvitation() }, select: { role: true } });
      if (!inv) return null;
      await assertSeat(tx, app.config, orgId, 1, u.email); // a no-op while the invitation still holds its seat
      let role = inv.role;
      if (role === "owner") {
        // An owner invitation (a customer organisation, docs/provisioning.md): one owner per organisation, so it counts
        // only while there is none, and owning it must fit MAX_OWNED_ORGS, as for a transfer.
        if (await tx.membership.findFirst({ where: { orgId, role: "owner", status: { not: "invited" } }, select: { id: true } })) role = "admin";
        else if ((await tx.membership.count({ where: { userId: me, role: "owner", status: { not: "invited" }, orgId: { not: orgId } } })) >= (app.config.maxOwnedOrgs ?? 5)) return "org_limit" as const;
      }
      const n = await tx.membership.updateMany({ where: { orgId, userId: me, status: "invited" }, data: { status: "active", joinedAt: new Date(), role } });
      if (n.count === 0) return null;
      await tx.invite.updateMany({ where: { orgId, email: u.email, acceptedAt: null }, data: { acceptedAt: new Date() } });
      // Groups the invitation put them in (docs/provisioning.md); folder keys still wait for a key holder's approval.
      await applyPendingGroups(tx, orgId, me, u.email);
      return true;
    });
    if (ended === null) return reply.code(404).send({ error: "not_found" });
    if (ended === "org_limit") return reply.code(409).send({ error: "org_limit" });
    await startAdminAge(app, u, req.log);
    await logEvent(app.prisma, { orgId, actorId: req.auth.userId, action: "org.join" });
    return { orgs: await orgsOf(app.prisma, app.config, req.auth.userId) };
  });

  /**
   * Claims an invitation link for the signed-in account (docs/provisioning.md): an email domain auto-join link, or an
   * admin's invite link for an address that already has an account. Only the account with the invited address can
   * claim it (anything else: the same 404 as an unknown link). It becomes an invitation to accept from the organisation
   * menu, where the organisation's master password rule is checked as for any invitation.
   */
  app.post("/me/join", { config: { rateLimit: { max: 10, timeWindow: "1 minute" } } }, async (req, reply) => {
    const { token } = z.object({ token: z.string().min(10).max(200) }).parse(req.body);
    if (app.config.demo) return reply.code(404).send({ error: "not_found" });
    const me = await app.prisma.user.findUniqueOrThrow({ where: { id: req.auth.userId }, select: { id: true, email: true } });
    const inv = await app.prisma.invite.findUnique({ where: { tokenHash: hashToken(token) }, select: { id: true, orgId: true, email: true, role: true, invitedById: true, source: true, acceptedAt: true, expiresAt: true, org: { select: { name: true } } } });
    if (!inv || inv.acceptedAt || inv.expiresAt < new Date() || inv.email !== me.email) return reply.code(404).send({ error: "not_found" });
    const state = await app.prisma.$transaction(async (tx) => {
      await lockSeats(tx, app.config, inv.orgId);
      await lockUser(tx, me.id);
      const m = await tx.membership.findUnique({ where: { orgId_userId: { orgId: inv.orgId, userId: me.id } }, select: { status: true } });
      if (m?.status === "disabled") return "disabled" as const;
      await assertSeat(tx, app.config, inv.orgId, 1, me.email);
      const now = new Date();
      // Single use: a link claimed twice (or raced) counts once.
      const n = await tx.invite.updateMany({ where: { id: inv.id, acceptedAt: null }, data: { acceptedAt: now, emailCodeHash: null } });
      if (!n.count) return "gone" as const;
      if (m?.status === "active") return "member" as const;
      if (!m) await tx.membership.create({ data: { orgId: inv.orgId, userId: me.id, role: invitedRole(inv), status: "invited", invitedById: inv.invitedById, createdAt: now } });
      else await tx.membership.updateMany({ where: { orgId: inv.orgId, userId: me.id, status: "invited" }, data: { createdAt: now } });
      return "invited" as const;
    });
    if (state === "disabled" || state === "gone") return reply.code(404).send({ error: "not_found" });
    await logEvent(app.prisma, { orgId: inv.orgId, actorId: me.id, action: "org.invite_claimed", meta: { source: inv.source } });
    return { orgId: inv.orgId, orgName: inv.org.name, status: state };
  });

  app.post("/me/invitations/:orgId/decline", async (req, reply) => {
    const { orgId } = orgParam.parse(req.params);
    const u = await app.prisma.user.findUniqueOrThrow({ where: { id: req.auth.userId }, select: { email: true } });
    const n = await app.prisma.$transaction(async (tx) => {
      const d = await tx.membership.deleteMany({ where: { orgId, userId: req.auth.userId, status: "invited" } });
      if (d.count) {
        await tx.invite.deleteMany({ where: { orgId, email: u.email, acceptedAt: null } });
        await dropPendingGroups(tx, orgId, u.email);
        await coolDown(tx, orgId, u.email); // no re-invite spam right after a "no"
      }
      return d;
    });
    if (n.count === 0) return reply.code(404).send({ error: "not_found" });
    await logEvent(app.prisma, { orgId, actorId: req.auth.userId, action: "org.decline" });
    return reply.code(204).send();
  });

  /**
   * An organisation's logo (docs/branding.md), for its active members only (the app fetches it with the bearer token
   * and shows it from a blob URL). Anyone else gets the same 404 as for an org without a logo.
   */
  app.get("/orgs/:orgId/logo", async (req, reply) => {
    const { orgId } = orgParam.parse(req.params);
    const member = await app.prisma.membership.findFirst({ where: { orgId, userId: req.auth.userId, status: "active", user: { status: "active" } }, select: { id: true } });
    const logo = member ? await app.prisma.orgLogo.findUnique({ where: { orgId }, select: { mime: true, data: true, sha256: true } }) : null;
    if (!logo) return reply.code(404).send({ error: "not_found" });
    return sendLogo(req, reply, logo, "private");
  });

  /** Any signed-in user may create an organisation when ALLOW_ORG_CREATION=true, instance admins always; the creator becomes its owner. */
  app.post("/orgs", { config: { rateLimit: { max: 10, timeWindow: "1 minute" } } }, async (req, reply) => {
    const me = req.auth.userId;
    const operator = await isInstanceAdmin(app.prisma, app.config, me);
    // Demo mode (docs/demo.md): each visitor has their one sandbox organisation.
    if (app.config.demo || (app.config.allowOrgCreation !== true && !operator)) return reply.code(403).send({ error: "org_creation_disabled" });
    const { name } = z.object({ name: orgName }).parse(req.body);
    // MAX_OWNED_ORGS limits self-service sign-ups, not the operator setting up customers.
    if (!operator && (await app.prisma.membership.count({ where: { userId: me, role: "owner" } })) >= (app.config.maxOwnedOrgs ?? 5)) return reply.code(409).send({ error: "org_limit" });
    const now = new Date();
    const org = await app.prisma.$transaction(async (tx) => {
      await lockUser(tx, me);
      return tx.organization.create({ data: { name, slug: slugFor(name), ...(app.config.billingMode === "hosted" ? { trialEndsAt: new Date(+now + TRIAL_MS) } : {}),
        memberships: { create: { userId: me, role: "owner", status: "active", adminSince: now, joinedAt: now } } } });
    });
    await logEvent(app.prisma, { orgId: org.id, actorId: req.auth.userId, action: "org.create" });
    return reply.code(201).send({ id: org.id, name: org.name, slug: org.slug, role: "owner", isDefault: false });
  });

  // ---- the active org ----
  await app.register(async (o) => {
    o.addHook("preHandler", app.orgRequired);
    const owner = async (req: FastifyRequest, reply: FastifyReply) => {
      if (reply.sent) return;
      if (req.org?.role !== "owner") await reply.code(403).send({ error: "forbidden" });
    };
    const ownerOrAdmin = async (req: FastifyRequest, reply: FastifyReply) => {
      if (reply.sent) return;
      if (req.org?.role !== "owner" && req.org?.role !== "admin") await reply.code(403).send({ error: "forbidden" });
    };
    const meta = (req: FastifyRequest) => ({ ip: req.ip, userAgent: String(req.headers["user-agent"] ?? "").slice(0, 300) });

    if (app.config.billingMode === "hosted") await o.register(planRoutes);

    o.get("/org", async (req) => {
      const id = req.org!.id;
      const [org, members, teamFolders, d] = await Promise.all([
        app.prisma.organization.findUniqueOrThrow({ where: { id }, select: { id: true, name: true, slug: true, createdAt: true, logo: { select: { sha256: true } } } }),
        app.prisma.membership.count({ where: { orgId: id, status: { in: ["active", "disabled"] } } }),
        app.prisma.folder.count({ where: { orgId: id, kind: "team", deletedAt: null } }),
        defaultOrg(app.prisma),
      ]);
      const ownerRow = await app.prisma.membership.findFirst({ where: { orgId: id, role: "owner" }, select: { user: { select: { id: true, name: true } } } });
      const { logo, ...rest } = org;
      return { ...rest, logoVersion: logoVersion(logo?.sha256), createdAt: org.createdAt.toISOString(), isDefault: d?.id === id, myRole: req.org!.role, memberCount: members, teamFolderCount: teamFolders, owner: ownerRow?.user ?? null };
    });

    /** Owners and admins rename the org. */
    o.patch("/org", { preHandler: ownerOrAdmin }, async (req) => {
      const { name } = z.object({ name: orgName }).parse(req.body);
      const before = await app.prisma.organization.findUniqueOrThrow({ where: { id: req.org!.id }, select: { name: true } });
      await app.prisma.organization.update({ where: { id: req.org!.id }, data: { name } });
      await logEvent(app.prisma, { orgId: req.org!.id, actorId: req.auth.userId, action: "org.rename", ...meta(req), meta: { from: before.name, to: name } });
      return { ok: true, name };
    });

    /** Owners and admins set the org's logo: PNG, JPEG or WebP bytes as the request body (docs/branding.md). */
    await o.register(async (logo) => {
      rawImageBodies(logo);
      logo.put("/org/logo", { preHandler: [ownerOrAdmin, app.requireEntitlement("orgLogo")], config: { rateLimit: { max: 10, timeWindow: "1 minute" } } }, async (req, reply) => {
        const up = await readLogo(req, reply);
        if (!up) return;
        const orgId = req.org!.id;
        const data = { mime: up.img.mime, data: up.bytes, width: up.img.width, height: up.img.height, sha256: up.img.sha256, updatedById: req.auth.userId };
        await app.prisma.orgLogo.upsert({ where: { orgId }, create: { orgId, ...data }, update: data });
        await logEvent(app.prisma, { orgId, actorId: req.auth.userId, action: "org.logo_set", ...meta(req), meta: { mime: up.img.mime, width: up.img.width, height: up.img.height, bytes: up.bytes.length } });
        return { logoVersion: logoVersion(up.img.sha256) };
      });
    });

    o.delete("/org/logo", { preHandler: ownerOrAdmin }, async (req) => {
      const n = await app.prisma.orgLogo.deleteMany({ where: { orgId: req.org!.id } });
      if (n.count) await logEvent(app.prisma, { orgId: req.org!.id, actorId: req.auth.userId, action: "org.logo_remove", ...meta(req) });
      return { logoVersion: null };
    });

    /** Ownership moves to another active member; the old owner stays an admin. */
    o.post("/org/transfer", { preHandler: owner }, async (req, reply) => {
      const { userId } = z.object({ userId: z.string().uuid() }).parse(req.body);
      const orgId = req.org!.id;
      if (userId === req.auth.userId) return reply.code(400).send({ error: "self" });
      const t = await app.prisma.membership.findFirst({ where: { orgId, userId, status: "active", user: { status: "active" } }, select: { id: true, user: { select: { id: true, name: true, email: true } } } });
      if (!t) return reply.code(404).send({ error: "not_found" });
      if ((await app.prisma.membership.count({ where: { userId, role: "owner" } })) >= (app.config.maxOwnedOrgs ?? 5)) return reply.code(409).send({ error: "org_limit" });
      await app.prisma.$transaction(async (tx) => {
        await tx.membership.update({ where: { id: t.id }, data: { role: "owner" } });
        await tx.membership.update({ where: { orgId_userId: { orgId, userId: req.auth.userId } }, data: { role: "admin" } });
        await dropInstanceAdminIfGone(tx, orgId, req.auth.userId); // still an admin: kept
      });
      await startAdminAge(app, t.user, req.log);
      await logEvent(app.prisma, { orgId, actorId: req.auth.userId, action: "org.transfer", targetUserId: userId });
      return { ok: true };
    });

    /**
     * Deletes the org (never the default one). The caller types its name; team folders left need `trashTeamFolders`
     * (an explicit yes): its team folders, their records, members and pending members are deleted for good. Memberships,
     * invites, escrows, requests and shares made in the org go with it; its links are revoked.
     */
    o.delete("/org", { preHandler: owner }, async (req, reply) => {
      const b = z.object({ confirmName: z.string().max(200), trashTeamFolders: z.boolean().default(false) }).parse(req.body ?? {});
      const orgId = req.org!.id;
      const org = await app.prisma.organization.findUniqueOrThrow({ where: { id: orgId }, select: { name: true } });
      if ((await defaultOrg(app.prisma))?.id === orgId) return reply.code(409).send({ error: "default_org" });
      if (b.confirmName.trim() !== org.name) return reply.code(400).send({ error: "confirm_name" });
      const live = await app.prisma.folder.count({ where: { orgId, kind: "team", deletedAt: null } });
      if (live && !b.trashTeamFolders) return reply.code(409).send({ error: "org_has_team_folders", teamFolders: live });
      const now = new Date();
      await app.prisma.$transaction(async (tx) => {
        // Every team folder of the org (trashed ones too) and everything in it: nothing is left without an org.
        const folderIds = (await tx.folder.findMany({ where: { orgId }, select: { id: true } })).map((f) => f.id);
        const recordIds = (await tx.record.findMany({ where: { folderId: { in: folderIds } }, select: { id: true } })).map((r) => r.id);
        await tx.shareLink.updateMany({ where: { OR: [{ orgId }, { recordId: { in: recordIds } }], revokedAt: null }, data: { revokedAt: now, ...BURN } });
        await tombstoneAttachments(tx, recordIds); // their S3 files, for the sweep (db chunks cascade)
        await tx.record.deleteMany({ where: { id: { in: recordIds } } }); // access rows, links and attachments cascade
        await tx.recordAccess.deleteMany({ where: { holderType: "folder", holderId: { in: folderIds } } });
        await tx.folder.deleteMany({ where: { id: { in: folderIds } } }); // members and pending members cascade
        // Its events go too: kept, they would become org-less and show in private-context activity elsewhere.
        await tx.event.deleteMany({ where: { orgId } });
        await tx.organization.delete({ where: { id: orgId } });
      }, { timeout: 60_000 });
      await logEvent(app.prisma, { actorId: req.auth.userId, action: "org.delete", meta: { orgId, teamFoldersDeleted: live } });
      return reply.code(204).send();
    });

    /** Leaves the org (offboarding). The owner transfers ownership first. */
    o.post("/org/leave", async (req, reply) => {
      if (req.org!.role === "owner") return reply.code(409).send({ error: "owner_must_transfer" });
      const orgId = req.org!.id;
      await app.prisma.$transaction((tx) => offboard(tx, orgId, req.auth.userId, "remove"), { timeout: 60_000 });
      await logEvent(app.prisma, { orgId, actorId: req.auth.userId, action: "org.leave" });
      return reply.code(204).send();
    });
  });
};
