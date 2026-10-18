import type { FastifyPluginAsync, FastifyRequest } from "fastify";
import { Readable } from "node:stream";
import { z } from "zod";
import { domainJoinChangedEmail, sendEmail } from "../lib/email.js";
import { logEvent } from "../lib/events.js";
import { requestDomainJoin } from "../lib/domainJoin.js";
import { dailyInviteCap, INVITE_TTL_MS, invitesSentToday, resendInvite, sendNewInvite, type ResendResult } from "../lib/invites.js";
import { cleanName, nameProblem } from "../lib/names.js";
import { SeatLimitError } from "../lib/seats.js";
import { csvCell } from "./events.js";

/**
 * User provisioning (docs/provisioning.md), modelled on Keeper's admin console: bulk invitations (pasted addresses or a
 * CSV) with a default role and groups, the pending invitations with resend and revoke, CSV exports, email domain
 * auto-join and the onboarding checklist. Everything here is for the active org's owners and admins (registered in the
 * org-admin group of /admin); changing domain auto-join is for the owner only.
 */

const emailSchema = z.string().trim().toLowerCase().email().max(254);
const MAX_BULK = 500;
const idParam = z.object({ id: z.string().uuid() });

/** Each row's outcome. `valid` only in a dry run (the preview); `invited` after sending. */
export type BulkStatus = "valid" | "invited" | "invalid_email" | "invalid_role" | "unknown_group" | "duplicate" | "member" | "already_invited" | "cooldown" | "over_cap" | "seat_limit" | "failed";

const bulkBody = z.object({
  rows: z.array(z.object({
    email: z.string().max(320),
    name: z.string().max(200).optional().nullable(),
    role: z.string().max(20).optional().nullable(),
    /** Group names or ids: a list, or one string separated by ";" or "|". */
    groups: z.union([z.array(z.string().max(200)).max(50), z.string().max(2000)]).optional().nullable(),
  })).min(1).max(MAX_BULK),
  /** For rows without a role. */
  role: z.enum(["member", "admin"]).default("member"),
  /** Groups every invitee joins when they accept (on top of each row's own). */
  groupIds: z.array(z.string().uuid()).max(50).default([]),
  /** Validate and preview only: nothing is created or sent. */
  dryRun: z.boolean().default(false),
});

export interface PendingInviteView {
  id: string; email: string; role: string; source: string; groups: { id: string; name: string }[];
  createdAt: string; expiresAt: string; expired: boolean; lastSentAt: string | null; resendCount: number; invitedBy: { id: string; name: string } | null;
}

/** Expired invitations stay listed (to resend) for this long after they expire. */
const EXPIRED_LISTED_MS = 30 * 24 * 3600e3;

export const provisioningAdminRoutes: FastifyPluginAsync = async (app) => {
  const orgOf = (req: FastifyRequest) => req.org!.id;
  const meta = (req: FastifyRequest) => ({ ip: req.ip, userAgent: String(req.headers["user-agent"] ?? "").slice(0, 300) });

  /**
   * The org's open invitations (links and invitations to existing accounts, one row per address), with expired ones from
   * the last 30 days. Like GET /admin/people, a row never says whether the address has an account.
   */
  async function pendingInvites(orgId: string): Promise<PendingInviteView[]> {
    const now = Date.now();
    const [rows, invited, joined] = await Promise.all([
      app.prisma.invite.findMany({ where: { orgId, acceptedAt: null, expiresAt: { gt: new Date(now - EXPIRED_LISTED_MS) } },
        select: { id: true, email: true, role: true, source: true, createdAt: true, expiresAt: true, lastSentAt: true, resendCount: true, invitedById: true } }),
      app.prisma.membership.findMany({ where: { orgId, status: "invited", user: { kind: "person" }, createdAt: { gt: new Date(now - INVITE_TTL_MS - EXPIRED_LISTED_MS) } },
        select: { id: true, role: true, createdAt: true, invitedById: true, user: { select: { email: true } } } }),
      app.prisma.membership.findMany({ where: { orgId, status: { not: "invited" }, user: { kind: "person" } }, select: { user: { select: { email: true } } } }),
    ]);
    const members = new Set(joined.map((m) => m.user.email));
    const byEmail = new Map<string, Omit<PendingInviteView, "groups" | "invitedBy"> & { invitedById: string | null }>();
    for (const r of rows) {
      if (members.has(r.email)) continue;
      const cur = byEmail.get(r.email);
      if (cur && cur.createdAt > r.createdAt.toISOString()) continue;
      byEmail.set(r.email, { id: r.id, email: r.email, role: r.role, source: r.source, createdAt: r.createdAt.toISOString(), expiresAt: r.expiresAt.toISOString(), expired: r.expiresAt.getTime() <= now,
        lastSentAt: (r.lastSentAt ?? r.createdAt).toISOString(), resendCount: r.resendCount, invitedById: r.invitedById });
    }
    for (const m of invited) {
      if (byEmail.has(m.user.email)) continue;
      const exp = m.createdAt.getTime() + INVITE_TTL_MS;
      byEmail.set(m.user.email, { id: m.id, email: m.user.email, role: m.role, source: "admin", createdAt: m.createdAt.toISOString(), expiresAt: new Date(exp).toISOString(), expired: exp <= now,
        lastSentAt: m.createdAt.toISOString(), resendCount: 0, invitedById: m.invitedById });
    }
    const list = [...byEmail.values()];
    const [pending, inviters] = await Promise.all([
      app.prisma.pendingGroupMember.findMany({ where: { orgId, email: { in: list.map((l) => l.email) } }, select: { email: true, group: { select: { id: true, name: true } } }, orderBy: { group: { name: "asc" } } }),
      app.prisma.user.findMany({ where: { id: { in: [...new Set(list.map((l) => l.invitedById).filter((x): x is string => !!x))] } }, select: { id: true, name: true } }),
    ]);
    const names = new Map(inviters.map((u) => [u.id, u]));
    return list.map(({ invitedById, ...l }) => ({ ...l, groups: pending.filter((p) => p.email === l.email).map((p) => p.group), invitedBy: invitedById ? names.get(invitedById) ?? null : null }))
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  }

  async function capView(orgId: string) {
    const perDay = dailyInviteCap(app);
    const sentToday = await invitesSentToday(app.prisma, orgId);
    return { perDay, sentToday, remaining: Math.max(0, perDay - sentToday) };
  }

  /**
   * Invites many people in one request (pasted addresses or a CSV): each row gets its own outcome. Rows already in the
   * org, already invited, cooling down after a decline, invalid, or past the daily cap are skipped; nothing about
   * accounts outside the org is revealed. `dryRun` previews without creating or sending anything. One `admin.invite`
   * event per invitation and an `admin.invite_bulk` summary. Groups apply when the invitee joins.
   */
  app.post("/invites/bulk", { config: { rateLimit: { max: 10, timeWindow: "1 minute" } } }, async (req, reply) => {
    const b = bulkBody.parse(req.body);
    const orgId = orgOf(req);
    if (app.config.hostedMode && !(await app.mail.configured(orgId))) return reply.code(409).send({ error: "email_required" });
    const groups = await app.prisma.group.findMany({ where: { orgId }, select: { id: true, name: true } });
    const groupById = new Map(groups.map((g) => [g.id, g]));
    const groupByName = new Map(groups.map((g) => [g.name.toLowerCase(), g]));
    if (b.groupIds.some((id) => !groupById.has(id))) return reply.code(400).send({ error: "group_not_found" });
    const cap = await capView(orgId);

    const parsed = b.rows.map((r) => ({ raw: r, email: emailSchema.safeParse(r.email) }));
    const emails = parsed.flatMap((p) => (p.email.success ? [p.email.data] : []));
    const now = new Date();
    const [users, open, cooling] = await Promise.all([
      app.prisma.user.findMany({ where: { email: { in: emails } }, select: { email: true, memberships: { where: { orgId }, select: { status: true } } } }),
      app.prisma.invite.findMany({ where: { orgId, email: { in: emails }, acceptedAt: null, expiresAt: { gt: now } }, select: { email: true } }),
      app.prisma.inviteCooldown.findMany({ where: { orgId, email: { in: emails }, until: { gt: now } }, select: { email: true } }),
    ]);
    const memberStatus = new Map(users.flatMap((u) => (u.memberships[0] ? [[u.email, u.memberships[0].status] as const] : [])));
    const invitedOpen = new Set(open.map((o) => o.email)), cooldown = new Set(cooling.map((c) => c.email));

    const seen = new Set<string>();
    let accepted = 0;
    type Row = { row: number; email: string; name: string | null; role: string; groups: string[]; status: BulkStatus; detail?: string; emailed?: boolean; inviteUrl?: string; groupIds: string[] };
    const results: Row[] = parsed.map((p, i) => {
      const nameRaw = p.raw.name ? cleanName(p.raw.name) : "";
      const name = nameRaw && !nameProblem(nameRaw) ? nameRaw : null;
      const role = (p.raw.role ?? "").trim().toLowerCase() || b.role;
      const base = { row: i + 1, email: p.email.success ? p.email.data : p.raw.email.trim().slice(0, 254), name, role, groups: [] as string[], groupIds: [] as string[] };
      if (!p.email.success) return { ...base, status: "invalid_email" };
      if (seen.has(p.email.data)) return { ...base, status: "duplicate" };
      seen.add(p.email.data);
      if (role !== "member" && role !== "admin") return { ...base, status: "invalid_role" };
      const wanted = p.raw.groups ? (Array.isArray(p.raw.groups) ? p.raw.groups : p.raw.groups.split(/[;|]/)).map((s) => s.trim()).filter(Boolean) : [];
      const unknown = wanted.filter((w) => !groupById.has(w) && !groupByName.has(w.toLowerCase()));
      const ids = [...new Set([...b.groupIds, ...wanted.filter((w) => !unknown.includes(w)).map((w) => (groupById.get(w) ?? groupByName.get(w.toLowerCase()))!.id)])];
      const withGroups = { ...base, groupIds: ids, groups: ids.map((id) => groupById.get(id)!.name) };
      if (unknown.length) return { ...withGroups, status: "unknown_group", detail: unknown.join(", ").slice(0, 200) };
      const ms = memberStatus.get(p.email.data);
      if (ms === "active" || ms === "disabled") return { ...withGroups, status: "member" };
      if (ms === "invited" || invitedOpen.has(p.email.data)) return { ...withGroups, status: "already_invited" };
      if (cooldown.has(p.email.data)) return { ...withGroups, status: "cooldown" };
      if (accepted >= cap.remaining) return { ...withGroups, status: "over_cap" };
      accepted++;
      return { ...withGroups, status: "valid" };
    });

    if (!b.dryRun) {
      const org = await app.prisma.organization.findUniqueOrThrow({ where: { id: orgId }, select: { id: true, name: true } });
      for (const r of results) {
        if (r.status !== "valid") continue;
        try {
          const out = await sendNewInvite(app, { org, actorId: req.auth.userId, email: r.email, role: r.role as "member" | "admin", groupIds: r.groupIds, nameHint: r.name, bulk: true, log: req.log });
          if (out.already) { r.status = "member"; continue; }
          r.status = "invited"; r.emailed = out.emailed;
          if (!app.config.hostedMode && out.inviteUrl) r.inviteUrl = out.inviteUrl;
        } catch (e) {
          if (e instanceof SeatLimitError) { r.status = "seat_limit"; continue; }
          req.log.warn({ err: e }, "bulk invite row failed"); r.status = "failed";
        }
      }
    }
    const counts: Partial<Record<BulkStatus, number>> = {};
    for (const r of results) counts[r.status] = (counts[r.status] ?? 0) + 1;
    if (!b.dryRun) await logEvent(app.prisma, { orgId, actorId: req.auth.userId, action: "admin.invite_bulk", ...meta(req),
      meta: { requested: results.length, invited: counts.invited ?? 0, emailed: results.filter((r) => r.emailed).length, counts, groups: b.groupIds.length } });
    return {
      dryRun: b.dryRun, counts, cap: b.dryRun ? cap : await capView(orgId),
      results: results.map(({ groupIds: _g, ...r }) => r),
    };
  });

  /** Pending and expired invitations: `status` pending (default), expired or all; `q` filters by address. */
  app.get("/invites", async (req) => {
    const f = z.object({ status: z.enum(["pending", "expired", "all"]).default("pending"), q: z.string().trim().toLowerCase().max(254).default("") }).parse(req.query);
    const orgId = orgOf(req);
    const all = await pendingInvites(orgId);
    const invites = all.filter((i) => (f.status === "all" || (f.status === "expired") === i.expired) && (!f.q || i.email.includes(f.q)));
    return { invites, cap: await capView(orgId), counts: { pending: all.filter((i) => !i.expired).length, expired: all.filter((i) => i.expired).length },
      emailConfigured: await app.mail.configured(orgId), hostedMode: !!app.config.hostedMode };
  });

  const resendError = (r: Extract<ResendResult, { ok: false }>) => ({ not_found: 404, email_required: 409, too_soon: 429, invite_limit: 429 })[r.error];

  /** Sends one invitation again (new link, a fresh 7 days). */
  app.post("/invites/:id/resend", { config: { rateLimit: { max: 30, timeWindow: "1 minute" } } }, async (req, reply) => {
    const { id } = idParam.parse(req.params);
    const r = await resendInvite(app, orgOf(req), id, req.auth.userId, req.log);
    if (!r.ok) return reply.code(resendError(r)).send({ error: r.error });
    const { ok: _ok, ...rest } = r;
    return rest;
  });

  /** Sends every pending invitation again (with `includeExpired`, expired ones too), oldest first, up to the daily cap. */
  app.post("/invites/resend-all", { config: { rateLimit: { max: 5, timeWindow: "1 minute" } } }, async (req, reply) => {
    const b = z.object({ includeExpired: z.boolean().default(false) }).parse(req.body ?? {});
    const orgId = orgOf(req);
    if (app.config.hostedMode && !(await app.mail.configured(orgId))) return reply.code(409).send({ error: "email_required" });
    const list = (await pendingInvites(orgId)).filter((i) => b.includeExpired || !i.expired).sort((a, c) => (a.lastSentAt ?? "").localeCompare(c.lastSentAt ?? ""));
    const results: { id: string; email: string; status: "resent" | "seat_limit" | "too_soon" | "invite_limit" | "not_found" | "email_required"; emailed?: boolean; inviteUrl?: string }[] = [];
    let capped = false;
    for (const i of list) {
      if (capped) { results.push({ id: i.id, email: i.email, status: "invite_limit" }); continue; }
      const r = await resendInvite(app, orgId, i.id, req.auth.userId, req.log).catch((e) => { if (e instanceof SeatLimitError) return "seat_limit" as const; throw e; });
      if (r === "seat_limit") { results.push({ id: i.id, email: i.email, status: "seat_limit" }); continue; }
      if (r.ok) results.push({ id: r.id, email: r.email, status: "resent", emailed: r.emailed, ...(r.inviteUrl ? { inviteUrl: r.inviteUrl } : {}) });
      else { results.push({ id: i.id, email: i.email, status: r.error }); if (r.error === "invite_limit") capped = true; }
    }
    const resent = results.filter((r) => r.status === "resent").length;
    await logEvent(app.prisma, { orgId, actorId: req.auth.userId, action: "admin.invite_resend_all", ...meta(req), meta: { resent, skipped: results.length - resent } });
    return { resent, skipped: results.length - resent, results, cap: await capView(orgId) };
  });

  const csv = (reply: import("fastify").FastifyReply, name: string, header: string[], rows: unknown[][]) => {
    const day = new Date().toISOString().slice(0, 10);
    const lines = function* () { yield `${header.join(",")}\n`; for (const r of rows) yield `${r.map(csvCell).join(",")}\n`; };
    return reply.header("content-type", "text/csv; charset=utf-8").header("content-disposition", `attachment; filename="${name}-${day}.csv"`).send(Readable.from(lines()));
  };

  /** The org's members as CSV (name, email, role, status, two-step sign-in, joined, groups). */
  app.get("/people/export.csv", { config: { rateLimit: { max: 10, timeWindow: "1 minute" } } }, async (req, reply) => {
    const orgId = orgOf(req);
    const ms = await app.prisma.membership.findMany({ where: { orgId, status: { not: "invited" }, user: { kind: "person" } }, orderBy: { createdAt: "asc" },
      select: { role: true, status: true, createdAt: true, joinedAt: true, user: { select: { id: true, name: true, email: true, status: true, totpEnabledAt: true } } } });
    const gm = await app.prisma.groupMember.findMany({ where: { group: { orgId }, userId: { in: ms.map((m) => m.user.id) } }, select: { userId: true, group: { select: { name: true } } }, orderBy: { group: { name: "asc" } } });
    await logEvent(app.prisma, { orgId, actorId: req.auth.userId, action: "admin.export", meta: { what: "members", rows: ms.length }, ...meta(req) });
    return csv(reply, "members", ["name", "email", "role", "status", "two_factor", "joined_at", "groups"], ms.map((m) => [m.user.name, m.user.email, m.role,
      m.status === "disabled" ? "disabled" : m.user.status, m.user.totpEnabledAt ? "yes" : "no", (m.joinedAt ?? m.createdAt).toISOString(),
      gm.filter((g) => g.userId === m.user.id).map((g) => g.group.name).join("; ")]));
  });

  /** Pending and expired invitations as CSV. */
  app.get("/invites/export.csv", { config: { rateLimit: { max: 10, timeWindow: "1 minute" } } }, async (req, reply) => {
    const orgId = orgOf(req);
    const list = await pendingInvites(orgId);
    await logEvent(app.prisma, { orgId, actorId: req.auth.userId, action: "admin.export", meta: { what: "invites", rows: list.length }, ...meta(req) });
    return csv(reply, "invitations", ["email", "role", "status", "source", "groups", "invited_at", "expires_at", "last_sent_at", "resend_count", "invited_by"],
      list.map((i) => [i.email, i.role, i.expired ? "expired" : "pending", i.source, i.groups.map((g) => g.name).join("; "), i.createdAt, i.expiresAt, i.lastSentAt, i.resendCount, i.invitedBy?.name ?? ""]));
  });

  // ---- Email domain auto-join ----

  async function domainJoinView(orgId: string, role: string) {
    const [cfg, domains, groups, emailConfigured] = await Promise.all([
      app.prisma.orgDomainJoin.findUnique({ where: { orgId } }),
      app.prisma.ssoDomain.findMany({ where: { orgId }, orderBy: { domain: "asc" }, select: { domain: true, verifiedAt: true } }),
      app.prisma.group.findMany({ where: { orgId }, select: { id: true, name: true } }),
      app.mail.configured(orgId),
    ]);
    // A domain verified by another org too can't grant anything (one org per domain).
    const contested = new Set((await app.prisma.ssoDomain.findMany({ where: { domain: { in: domains.map((d) => d.domain) }, orgId: { not: orgId }, verifiedAt: { not: null } }, select: { domain: true } })).map((d) => d.domain));
    const by = cfg?.updatedById ? await app.prisma.user.findUnique({ where: { id: cfg.updatedById }, select: { id: true, name: true } }) : null;
    const gname = new Map(groups.map((g) => [g.id, g.name]));
    return {
      enabled: !!cfg?.enabled, role: cfg?.role ?? "member",
      groups: (cfg?.groupIds ?? []).filter((id) => gname.has(id)).map((id) => ({ id, name: gname.get(id)! })),
      domains: domains.map((d) => ({ domain: d.domain, verified: !!d.verifiedAt && !contested.has(d.domain) })),
      emailConfigured, joinUrl: `${app.config.publicUrl}/join`, canEdit: role === "owner",
      updatedAt: cfg?.updatedAt.toISOString() ?? null, updatedBy: by,
    };
  }

  app.get("/settings/domain-join", async (req) => domainJoinView(orgOf(req), req.org!.role));

  /**
   * The owner turns email domain auto-join on or off and picks the groups. Needs a domain verified by this org (and no
   * other) and email delivery (the join link is always emailed). Joiners are members; never admins or owners.
   */
  app.put("/settings/domain-join", { config: { rateLimit: { max: 20, timeWindow: "1 minute" } } }, async (req, reply) => {
    if (req.org!.role !== "owner") return reply.code(403).send({ error: "owner_only" });
    const b = z.object({ enabled: z.boolean(), groupIds: z.array(z.string().uuid()).max(50).default([]) }).parse(req.body);
    if (b.enabled && !(await app.hasEntitlement(req, reply, "domains"))) return;
    const orgId = orgOf(req);
    const ids = [...new Set(b.groupIds)];
    if (ids.length && (await app.prisma.group.count({ where: { orgId, id: { in: ids } } })) !== ids.length) return reply.code(400).send({ error: "group_not_found" });
    const view = await domainJoinView(orgId, "owner");
    if (b.enabled && !view.domains.some((d) => d.verified)) return reply.code(409).send({ error: "domain_not_verified" });
    if (b.enabled && !view.emailConfigured) return reply.code(409).send({ error: "email_required" });
    const cur = await app.prisma.orgDomainJoin.findUnique({ where: { orgId } });
    const data = { enabled: b.enabled, role: "member" as const, groupIds: ids, updatedById: req.auth.userId };
    await app.prisma.orgDomainJoin.upsert({ where: { orgId }, create: { orgId, ...data }, update: data });
    const wasOn = !!cur?.enabled;
    const groupsChanged = JSON.stringify([...(cur?.groupIds ?? [])].sort()) !== JSON.stringify([...ids].sort());
    const action = b.enabled && !wasOn ? "org.domain_join_enabled" : !b.enabled && wasOn ? "org.domain_join_disabled" : "org.domain_join_updated";
    await logEvent(app.prisma, { orgId, actorId: req.auth.userId, action, ...meta(req), meta: { groups: ids.length, domains: view.domains.filter((d) => d.verified).map((d) => d.domain) } });
    // Owners and admins hear about it (the server's own email settings, as for SSO changes).
    if (b.enabled !== wasOn || (b.enabled && groupsChanged)) {
      const [org, actor, admins] = await Promise.all([
        app.prisma.organization.findUniqueOrThrow({ where: { id: orgId }, select: { name: true } }),
        app.prisma.user.findUniqueOrThrow({ where: { id: req.auth.userId }, select: { name: true } }),
        app.prisma.user.findMany({ where: { status: "active", memberships: { some: { orgId, status: "active", role: { in: ["owner", "admin"] } } } }, select: { email: true } }),
      ]);
      const msg = domainJoinChangedEmail(await app.brand.productName(), org.name, actor.name, b.enabled, view.domains.filter((d) => d.verified).map((d) => d.domain));
      for (const a of admins) void sendEmail(app.mail, a.email, msg, req.log);
    }
    return domainJoinView(orgId, "owner");
  });

  // ---- Onboarding checklist ----

  /** The checklist for a new organisation, from what is really set up. Shown for 30 days unless dismissed or done. */
  app.get("/onboarding", async (req) => {
    const orgId = orgOf(req);
    const [org, members, invites, invitedMembers, groups, sso, email, join] = await Promise.all([
      app.prisma.organization.findUniqueOrThrow({ where: { id: orgId }, select: { createdAt: true, onboardingDismissedAt: true, policiesChangedAt: true, adminRecoveryEnabled: true } }),
      app.prisma.membership.count({ where: { orgId, status: { not: "invited" }, user: { kind: "person" } } }),
      app.prisma.invite.count({ where: { orgId, acceptedAt: null, expiresAt: { gt: new Date() } } }),
      app.prisma.membership.count({ where: { orgId, status: "invited", user: { kind: "person" } } }),
      app.prisma.group.count({ where: { orgId } }),
      app.prisma.orgSso.count({ where: { orgId } }),
      app.prisma.emailSettings.count({ where: { orgId } }),
      app.prisma.orgDomainJoin.count({ where: { orgId, enabled: true } }),
    ]);
    const steps = [
      { id: "invite", done: members > 1 || invites > 0 || invitedMembers > 0 },
      { id: "group", done: groups > 0 },
      { id: "policies", done: !!org.policiesChangedAt },
      { id: "recovery", done: org.adminRecoveryEnabled },
      { id: "sso", done: sso > 0 || email > 0 || join > 0 },
    ];
    const isNew = Date.now() - org.createdAt.getTime() < 30 * 24 * 3600e3;
    const dismissed = !!org.onboardingDismissedAt;
    return { steps, dismissed, show: isNew && !dismissed && !steps.every((s) => s.done), done: steps.filter((s) => s.done).length, total: steps.length };
  });

  app.put("/onboarding", async (req) => {
    const { dismissed } = z.object({ dismissed: z.boolean() }).parse(req.body);
    const orgId = orgOf(req);
    await app.prisma.organization.update({ where: { id: orgId }, data: { onboardingDismissedAt: dismissed ? new Date() : null } });
    await logEvent(app.prisma, { orgId, actorId: req.auth.userId, action: dismissed ? "org.onboarding_dismissed" : "org.onboarding_restored" });
    return { dismissed };
  });
};

/**
 * POST /auth/domain-join: "join with my work email". Always the same 202, whatever happens (no enumeration of
 * organisations, accounts or members); an eligible address gets an emailed link. Rate-limited per client address.
 */
export const domainJoinPublicRoutes: FastifyPluginAsync = async (app) => {
  app.post("/domain-join", { config: { rateLimit: { max: 5, timeWindow: "1 minute" } } }, async (req, reply) => {
    const parsed = emailSchema.safeParse((req.body as { email?: unknown } | null)?.email);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_request" });
    const outcome = await requestDomainJoin(app, parsed.data, req.log, { ip: req.ip, userAgent: String(req.headers["user-agent"] ?? "").slice(0, 300) })
      .catch((e: unknown) => { req.log.error(e); return "error" as const; });
    req.log.info({ outcome }, "domain join request");
    return reply.code(202).send({ ok: true });
  });
};

