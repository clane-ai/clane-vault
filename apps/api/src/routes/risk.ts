import type { FastifyPluginAsync, FastifyRequest } from "fastify";
import { Prisma } from "@prisma/client";
import { z } from "zod";
import { logEvent } from "../lib/events.js";
import { INVITE_TTL_MS } from "../lib/invites.js";
import { isInstanceAdmin } from "../lib/orgs.js";
import { getEntitlements, PLAN_SELECT } from "../lib/plans.js";
import { readPolicies, readRiskIgnored, RISK_IGNORED } from "../lib/policies.js";
import { isPublicMailDomain } from "../lib/publicMailDomains.js";
import { ALERTS, alertDef, computeBenchmarks, computeScore, DAY_MS, HEALTH_AT_RISK_SCORE, INACTIVE_ADMIN_DAYS, isBenchmarkKey, STORAGE_ALERT_RATIO, trendPercent, WIDE_DOWNLOAD_ALERT, WINDOW_DAYS } from "../lib/risk.js";
import { attachmentConfig, chargeQuota, orgUsage } from "../lib/attachments/quota.js";
import { csvCell } from "./events.js";

/** One active member of the org, as the dashboard sees them: metadata and counts only. */
interface MemberRow {
  userId: string; name: string; email: string; role: "owner" | "admin" | "member"; userStatus: string; joinedAt: Date;
  hasKit: boolean; owned: number; canOpen: number; lastSeen: Date | null; idpMfa: boolean;
  score: number | null; total: number | null; weak: number | null; reused: number | null; old: number | null; breached: number | null; reportedAt: Date | null;
}

/** The tiles' drill-down filters (and the CSV's `tile`). */
const TILES = ["records", "active", "invites", "idp_mfa", "recovery_kit", "health"] as const;
type Tile = (typeof TILES)[number];

const iso = (d: Date | null) => (d ? d.toISOString() : null);

/**
 * /admin/risk: the organisation risk dashboard (docs/risk-dashboard.md) for its owners and admins. One aggregated
 * answer, drill-downs and CSV exports. Computed per request from configuration, metadata and counts (no cache beyond
 * the request); never a secret, key, item title or password.
 */
export const riskAdminRoutes: FastifyPluginAsync = async (app) => {
  /**
   * Every active member with what the dashboard needs, in one query: records they own and can open in this org (team
   * folders they hold a key for, and direct shares made in it), their last session activity, whether a current session
   * skipped TOTP through this org's identity provider, their recovery kit and their last password health report.
   */
  async function members(orgId: string): Promise<MemberRow[]> {
    const rows = await app.prisma.$queryRaw<MemberRow[]>`
      WITH org_rec AS (
        SELECT r.id, r."ownerId", r."folderId" FROM "Record" r JOIN "Folder" f ON f.id = r."folderId"
        WHERE f."orgId" = ${orgId}::uuid AND f.kind = 'team' AND f."deletedAt" IS NULL AND r."deletedAt" IS NULL
      ), shared AS (
        SELECT ra."holderId" AS "userId", r.id, r."ownerId" FROM "RecordAccess" ra JOIN "Record" r ON r.id = ra."recordId"
        WHERE ra."orgId" = ${orgId}::uuid AND ra."holderType" = 'user' AND ra.state = 'active' AND r."deletedAt" IS NULL
      ), reach AS (
        SELECT fm."userId", o.id FROM "FolderMember" fm JOIN org_rec o ON o."folderId" = fm."folderId"
        UNION SELECT "userId", id FROM shared
        UNION SELECT "ownerId", id FROM shared
      ), owned AS (
        SELECT "ownerId" AS "userId", id FROM org_rec UNION SELECT "ownerId", id FROM shared
      ), reach_n AS (SELECT "userId", COUNT(*)::int AS n FROM reach GROUP BY 1),
         owned_n AS (SELECT "userId", COUNT(*)::int AS n FROM owned GROUP BY 1),
         seen AS (
           SELECT s."userId", MAX(s."lastSeen") AS "lastSeen",
             BOOL_OR(s."totpSkippedForOrg" = ${orgId}::uuid AND s."revokedAt" IS NULL AND s."expiresAt" > now()) AS "idpMfa"
           FROM "Session" s JOIN "Membership" mm ON mm."userId" = s."userId" AND mm."orgId" = ${orgId}::uuid GROUP BY 1)
      SELECT u.id AS "userId", u.name, u.email, m.role::text AS role, u.status::text AS "userStatus", COALESCE(m."joinedAt", m."createdAt") AS "joinedAt",
        (u."recoveryWrap" IS NOT NULL) AS "hasKit", COALESCE(o.n, 0) AS owned, COALESCE(r.n, 0) AS "canOpen",
        s."lastSeen", COALESCE(s."idpMfa", false) AS "idpMfa",
        h.score, h.total, h.weak, h.reused, h.old, h.breached, h."reportedAt"
      FROM "Membership" m JOIN "User" u ON u.id = m."userId"
      LEFT JOIN reach_n r ON r."userId" = m."userId"
      LEFT JOIN owned_n o ON o."userId" = m."userId"
      LEFT JOIN seen s ON s."userId" = m."userId"
      LEFT JOIN "HealthReport" h ON h."orgId" = m."orgId" AND h."userId" = m."userId"
      WHERE m."orgId" = ${orgId}::uuid AND m.status = 'active' AND u.kind = 'person'
      ORDER BY m."createdAt" ASC, u.id ASC`;
    return rows;
  }

  /**
   * Pending invitations, the way People lists them (an invite link and/or an invitation to an existing account; never
   * which). "Resend all pending invites" is People's own POST /admin/invites/resend-all (lib/invites.ts resendInvite).
   */
  async function pendingInvites(orgId: string) {
    const now = new Date();
    const [rows, invited, joined] = await Promise.all([
      app.prisma.invite.findMany({ where: { orgId, acceptedAt: null, expiresAt: { gt: now } }, select: { email: true, role: true, createdAt: true, expiresAt: true }, orderBy: { createdAt: "desc" } }),
      app.prisma.membership.findMany({ where: { orgId, status: "invited", user: { kind: "person" }, createdAt: { gt: new Date(now.getTime() - INVITE_TTL_MS) } }, select: { role: true, createdAt: true, user: { select: { email: true } } } }),
      app.prisma.membership.findMany({ where: { orgId, status: { not: "invited" }, user: { kind: "person" } }, select: { user: { select: { email: true } } } }),
    ]);
    const done = new Set(joined.map((m) => m.user.email));
    const out = new Map<string, { email: string; role: string; createdAt: Date; expiresAt: Date }>();
    for (const r of rows) if (!done.has(r.email) && !out.has(r.email)) out.set(r.email, { email: r.email, role: r.role, createdAt: r.createdAt, expiresAt: r.expiresAt });
    for (const m of invited) {
      if (!done.has(m.user.email) && !out.has(m.user.email)) out.set(m.user.email, { email: m.user.email, role: m.role, createdAt: m.createdAt, expiresAt: new Date(m.createdAt.getTime() + INVITE_TTL_MS) });
    }
    return { pending: [...out.values()].sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime()), accepted: joined.length };
  }

  const since = (days: number, now = Date.now()) => new Date(now - days * DAY_MS);
  const atRisk = (m: MemberRow) => m.score !== null && ((m.breached ?? 0) > 0 || m.score < HEALTH_AT_RISK_SCORE);

  async function alerts(orgId: string, now: Date) {
    const cur = since(WINDOW_DAYS, now.getTime()), prev = since(2 * WINDOW_DAYS, now.getTime());
    const orgActions = ALERTS.filter((a) => a.scope === "org").map((a) => a.action);
    const accActions = ALERTS.filter((a) => a.scope === "account").map((a) => a.action);
    type C = { action: string; cur: number; prev: number };
    const [org, acc, wide] = await Promise.all([
      app.prisma.$queryRaw<C[]>`
        SELECT action, (COUNT(*) FILTER (WHERE at >= ${cur}))::int AS cur, (COUNT(*) FILTER (WHERE at < ${cur}))::int AS prev
        FROM "Event" WHERE "orgId" = ${orgId}::uuid AND at >= ${prev} AND at <= ${now} AND action = ANY(${orgActions}::text[]) GROUP BY action`,
      // Account-level events of the org's current members (active or disabled), only since they joined.
      app.prisma.$queryRaw<C[]>`
        SELECT e.action, (COUNT(*) FILTER (WHERE e.at >= ${cur}))::int AS cur, (COUNT(*) FILTER (WHERE e.at < ${cur}))::int AS prev
        FROM "Event" e JOIN "Membership" m ON m."userId" = e."actorId" AND m."orgId" = ${orgId}::uuid AND m.status <> 'invited'
        WHERE (e."orgId" IS NULL OR e."orgId" = ${orgId}::uuid) AND e.at >= m."createdAt" AND e.at >= ${prev} AND e.at <= ${now}
          AND e.action = ANY(${accActions}::text[]) GROUP BY e.action`,
      // Downloads of files on records many people can open (logged with meta.wide).
      app.prisma.$queryRaw<C[]>`
        SELECT ${WIDE_DOWNLOAD_ALERT} AS action, (COUNT(*) FILTER (WHERE at >= ${cur}))::int AS cur, (COUNT(*) FILTER (WHERE at < ${cur}))::int AS prev
        FROM "Event" WHERE "orgId" = ${orgId}::uuid AND at >= ${prev} AND at <= ${now} AND action = 'attachment.download' AND meta->>'wide' = 'true'`,
    ]);
    const by = new Map([...org, ...acc, ...wide].map((c) => [c.action, c]));
    return ALERTS.map((a) => {
      const c = by.get(a.action) ?? { cur: 0, prev: 0 };
      return { action: a.action, label: a.label, scope: a.scope, current: c.cur, previous: c.prev, trend: trendPercent(c.cur, c.prev) };
    });
  }

  async function overview(req: FastifyRequest) {
    const orgId = req.org!.id;
    const now = new Date();
    const [ms, inv, org, ssoDomains, orgEmail, emailAny, instanceAdmin, alertRows] = await Promise.all([
      members(orgId), pendingInvites(orgId),
      app.prisma.organization.findUniqueOrThrow({ where: { id: orgId }, select: { ...PLAN_SELECT, policies: true, adminRecoveryEnabled: true, sso: { select: { id: true } } } }),
      app.prisma.ssoDomain.findMany({ where: { orgId }, select: { verifiedAt: true } }),
      app.prisma.emailSettings.findUnique({ where: { orgId }, select: { provider: true, m365AuthMode: true, m365ReconnectAt: true } }),
      app.mail.configured(orgId),
      isInstanceAdmin(app.prisma, app.config, req.auth.userId),
      alerts(orgId, now),
    ]);
    const att = attachmentConfig(app.config);
    const storageUsed = att.enabled ? await orgUsage(app.prisma, orgId) : 0;
    const storageFiles = att.enabled ? Number((await app.prisma.$queryRaw<{ n: bigint }[]>`SELECT COUNT(a.id)::bigint AS n FROM "Attachment" a JOIN "Record" r ON r.id = a."recordId"
      JOIN "Folder" f ON f.id = r."folderId" WHERE a.state = 'ready' AND f.kind = 'team' AND f."orgId" = ${orgId}::uuid`)[0]?.n ?? 0) : 0;
    const storage = { used: storageUsed, quota: await chargeQuota(app.prisma, att, { kind: "org", orgId }), files: storageFiles, alertRatio: STORAGE_ALERT_RATIO, enabled: att.enabled };
    const lastBackup = instanceAdmin ? await app.prisma.backupRun.findFirst({ where: { status: "success" }, orderBy: { startedAt: "desc" }, select: { finishedAt: true, startedAt: true, bytes: true, attachmentBytes: true } }) : null;
    const policies = readPolicies(org.policies, getEntitlements(app.config, org));
    const ignored = readRiskIgnored(org.policies);
    const d30 = since(WINDOW_DAYS, now.getTime()), d90 = since(INACTIVE_ADMIN_DAYS, now.getTime());
    const admins = ms.filter((m) => m.role !== "member");
    // A company domain: one the org added for SSO, or one that two or more members' addresses share (not a public provider).
    const domains = new Map<string, number>();
    for (const m of ms) { const d = m.email.slice(m.email.lastIndexOf("@") + 1).toLowerCase(); if (!isPublicMailDomain(d)) domains.set(d, (domains.get(d) ?? 0) + 1); }
    const reported = ms.filter((m) => m.score !== null);
    const benchmarks = computeBenchmarks({
      admins: admins.filter((m) => m.userStatus === "active").length,
      adminRecoveryEnabled: org.adminRecoveryEnabled, policies,
      sso: { hasDomain: ssoDomains.length > 0 || [...domains.values()].some((n) => n >= 2), configured: !!org.sso, verifiedDomains: ssoDomains.filter((d) => d.verifiedAt).length },
      email: { org: !!orgEmail, any: emailAny, reconnect: !!orgEmail && orgEmail.provider === "m365" && orgEmail.m365AuthMode === "delegated" && !!orgEmail.m365ReconnectAt },
      backups: instanceAdmin ? { enabled: app.backups.enabled, lastSuccessAt: lastBackup ? lastBackup.finishedAt ?? lastBackup.startedAt : null,
        ...(lastBackup?.bytes != null ? { bytes: Number(lastBackup.bytes), attachmentBytes: lastBackup.attachmentBytes == null ? null : Number(lastBackup.attachmentBytes) } : {}) } : null,
      health: { reported: reported.length, atRisk: reported.filter(atRisk).length },
      inactiveAdmins: admins.filter((m) => (m.lastSeen ?? m.joinedAt) < d90).length,
      storage: att.enabled ? { used: storage.used, quota: storage.quota } : null,
      ignored, now,
    });
    const sum = (k: "total" | "weak" | "reused" | "old") => reported.reduce((a, m) => a + (m[k] ?? 0), 0);
    const breachedRows = reported.filter((m) => m.breached !== null);
    const n = ms.length;
    return {
      generatedAt: now.toISOString(), windowDays: WINDOW_DAYS, instanceAdmin,
      score: computeScore(benchmarks, reported.map((m) => m.score!)),
      utilisation: {
        members: n,
        withRecords: ms.filter((m) => m.canOpen > 0).length,
        active30d: ms.filter((m) => m.lastSeen && m.lastSeen >= d30).length,
        invitations: { accepted: inv.accepted, pending: inv.pending.length },
        // Every account sets up an authenticator before it can sign in: 2FA is never optional here.
        twoFactor: { required: true, members: n, idpMfaSessions: ms.filter((m) => m.idpMfa).length },
        recoveryKit: ms.filter((m) => m.hasKit).length,
        healthReported30d: ms.filter((m) => m.reportedAt && m.reportedAt >= d30).length,
        storage,
      },
      benchmarks,
      alerts: alertRows,
      health: {
        members: n, reported: reported.length, reported30d: reported.filter((m) => m.reportedAt! >= d30).length,
        averageScore: reported.length ? Math.round(reported.reduce((a, m) => a + m.score!, 0) / reported.length) : null,
        atRisk: reported.filter(atRisk).length, atRiskBelow: HEALTH_AT_RISK_SCORE,
        passwords: sum("total"), weak: sum("weak"), reused: sum("reused"), old: sum("old"),
        breached: breachedRows.length ? breachedRows.reduce((a, m) => a + m.breached!, 0) : null, breachCheckMembers: breachedRows.length,
      },
    };
  }

  const memberView = (m: MemberRow, d30: Date) => ({
    id: m.userId, name: m.name, email: m.email, role: m.role, joinedAt: m.joinedAt.toISOString(),
    records: { owned: m.owned, canOpen: m.canOpen }, lastSeen: iso(m.lastSeen), active30d: !!m.lastSeen && m.lastSeen >= d30,
    idpMfa: m.idpMfa, recoveryKit: m.hasKit,
    health: m.score === null ? null : { score: m.score, weak: m.weak, reused: m.reused, old: m.old, breached: m.breached, reportedAt: iso(m.reportedAt), recent: m.reportedAt! >= d30 },
  });

  app.get("/", { preHandler: app.requireEntitlement("risk") }, async (req) => overview(req));

  /** The tiles' drill-down: every active member with their metrics, and the pending invitations. */
  app.get("/members", { preHandler: app.requireEntitlement("risk") }, async (req) => {
    const orgId = req.org!.id;
    const d30 = since(WINDOW_DAYS);
    const [ms, inv] = await Promise.all([members(orgId), pendingInvites(orgId)]);
    return { members: ms.map((m) => memberView(m, d30)), invites: inv.pending.map((p) => ({ email: p.email, role: p.role, createdAt: p.createdAt.toISOString(), expiresAt: p.expiresAt.toISOString() })) };
  });

  const csvQuery = z.object({ tile: z.enum(TILES).optional(), has: z.enum(["yes", "no"]).optional() });
  const has = (t: Tile, m: ReturnType<typeof memberView>): boolean =>
    t === "records" ? m.records.canOpen > 0 : t === "active" ? m.active30d : t === "idp_mfa" ? m.idpMfa : t === "recovery_kit" ? m.recoveryKit : t === "health" ? !!m.health?.recent : true;
  const send = (reply: import("fastify").FastifyReply, name: string, header: string[], rows: unknown[][]) =>
    reply.header("content-type", "text/csv; charset=utf-8").header("content-disposition", `attachment; filename="${name}-${new Date().toISOString().slice(0, 10)}.csv"`)
      .send([header.join(","), ...rows.map((r) => r.map(csvCell).join(","))].join("\r\n") + "\r\n");

  /** A tile's drill-down as CSV (`tile`, and `has` = yes/no to keep only the members with or without it). */
  app.get("/members.csv", { preHandler: app.requireEntitlement("risk"), config: { rateLimit: { max: 20, timeWindow: "1 minute" } } }, async (req, reply) => {
    const q = csvQuery.parse(req.query);
    const orgId = req.org!.id;
    await logEvent(app.prisma, { orgId, actorId: req.auth.userId, action: "admin.risk_export", ip: req.ip, meta: { what: "members", ...q } });
    if (q.tile === "invites") {
      const inv = await pendingInvites(orgId);
      return send(reply, "pending-invitations", ["email", "role", "invited_at", "expires_at"], inv.pending.map((p) => [p.email, p.role, p.createdAt.toISOString(), p.expiresAt.toISOString()]));
    }
    const d30 = since(WINDOW_DAYS);
    let rows = (await members(orgId)).map((m) => memberView(m, d30));
    if (q.tile && q.has) rows = rows.filter((m) => has(q.tile!, m) === (q.has === "yes"));
    return send(reply, "members", ["name", "email", "role", "joined_at", "records_owned", "records_can_open", "last_seen", "signed_in_30d", "idp_mfa_session", "recovery_kit",
      "health_score", "weak", "reused", "old", "breached", "health_reported_at"],
    rows.map((m) => [m.name, m.email, m.role, m.joinedAt, m.records.owned, m.records.canOpen, m.lastSeen, m.active30d ? "yes" : "no", m.idpMfa ? "yes" : "no", m.recoveryKit ? "yes" : "no",
      m.health?.score, m.health?.weak, m.health?.reused, m.health?.old, m.health?.breached, m.health?.reportedAt]));
  });

  /** The alerts table as CSV. */
  app.get("/alerts.csv", { preHandler: app.requireEntitlement("risk"), config: { rateLimit: { max: 20, timeWindow: "1 minute" } } }, async (req, reply) => {
    const orgId = req.org!.id;
    await logEvent(app.prisma, { orgId, actorId: req.auth.userId, action: "admin.risk_export", ip: req.ip, meta: { what: "alerts" } });
    const rows = await alerts(orgId, new Date());
    return send(reply, "security-alerts", ["action", "alert", "scope", `last_${WINDOW_DAYS}_days`, `previous_${WINDOW_DAYS}_days`, "trend_percent"],
      rows.map((a) => [a.action, a.label, a.scope, a.current, a.previous, a.trend]));
  });

  /** One alert in the last 30 days, per person: how often they did it (actor) and how often it was done to them (target). */
  app.get("/alerts/:action/members", { preHandler: app.requireEntitlement("risk") }, async (req, reply) => {
    const { action } = z.object({ action: z.string().max(64) }).parse(req.params);
    const def = alertDef(action);
    if (!def) return reply.code(404).send({ error: "not_found" });
    const orgId = req.org!.id;
    const cur = since(WINDOW_DAYS);
    type R = { userId: string | null; asActor: number; asTarget: number; last: Date };
    const rows = action === WIDE_DOWNLOAD_ALERT
      ? await app.prisma.$queryRaw<R[]>`
          SELECT "actorId" AS "userId", COUNT(*)::int AS "asActor", 0 AS "asTarget", MAX(at) AS last FROM "Event"
          WHERE "orgId" = ${orgId}::uuid AND action = 'attachment.download' AND meta->>'wide' = 'true' AND at >= ${cur}
          GROUP BY "actorId" ORDER BY COUNT(*) DESC, MAX(at) DESC LIMIT 500`
      : def.scope === "org"
      ? await app.prisma.$queryRaw<R[]>`
          SELECT u AS "userId", SUM(a)::int AS "asActor", SUM(t)::int AS "asTarget", MAX(at) AS last FROM (
            SELECT "actorId" AS u, 1 AS a, 0 AS t, at FROM "Event" WHERE "orgId" = ${orgId}::uuid AND action = ${action} AND at >= ${cur}
            UNION ALL
            SELECT "targetUserId", 0, 1, at FROM "Event" WHERE "orgId" = ${orgId}::uuid AND action = ${action} AND at >= ${cur} AND "targetUserId" IS NOT NULL
          ) x GROUP BY u ORDER BY SUM(a) + SUM(t) DESC, MAX(at) DESC LIMIT 500`
      : await app.prisma.$queryRaw<R[]>`
          SELECT e."actorId" AS "userId", COUNT(*)::int AS "asActor", 0 AS "asTarget", MAX(e.at) AS last
          FROM "Event" e JOIN "Membership" m ON m."userId" = e."actorId" AND m."orgId" = ${orgId}::uuid AND m.status <> 'invited'
          WHERE (e."orgId" IS NULL OR e."orgId" = ${orgId}::uuid) AND e.at >= m."createdAt" AND e.action = ${action} AND e.at >= ${cur}
          GROUP BY e."actorId" ORDER BY COUNT(*) DESC, MAX(e.at) DESC LIMIT 500`;
    const ids = rows.map((r) => r.userId).filter((x): x is string => !!x);
    const who = new Map((await app.prisma.user.findMany({ where: { id: { in: ids } }, select: { id: true, name: true, email: true } })).map((u) => [u.id, u]));
    return { action, label: def.label, scope: def.scope, windowDays: WINDOW_DAYS,
      people: rows.map((r) => ({ user: r.userId ? who.get(r.userId) ?? { id: r.userId, name: null, email: null } : null, asActor: r.asActor, asTarget: r.asTarget, lastAt: r.last.toISOString() })) };
  });

  /** Ignores a benchmark (stored beside the org's policies, logged, reversible) or stops ignoring it. */
  const keyParam = z.object({ key: z.string().max(40) });
  async function setIgnored(req: FastifyRequest, key: string, on: boolean) {
    const orgId = req.org!.id;
    const changed = await app.prisma.$transaction(async (tx) => {
      await tx.$queryRaw`SELECT id FROM "Organization" WHERE id = ${orgId}::uuid FOR UPDATE`;
      const stored = (await tx.organization.findUniqueOrThrow({ where: { id: orgId }, select: { policies: true } })).policies;
      const cur = readRiskIgnored(stored);
      if (cur.includes(key) === on) return false;
      const next = on ? [...cur, key] : cur.filter((k) => k !== key);
      const base = stored && typeof stored === "object" && !Array.isArray(stored) ? (stored as Prisma.JsonObject) : {};
      const { [RISK_IGNORED]: _old, ...rest } = base;
      await tx.organization.update({ where: { id: orgId }, data: { policies: { ...rest, ...(next.length ? { [RISK_IGNORED]: next } : {}) } } });
      return true;
    });
    if (changed) await logEvent(app.prisma, { orgId, actorId: req.auth.userId, action: on ? "risk.benchmark_ignored" : "risk.benchmark_restored", ip: req.ip, meta: { key } });
  }
  app.post("/benchmarks/:key/ignore", async (req, reply) => {
    const { key } = keyParam.parse(req.params);
    if (!isBenchmarkKey(key)) return reply.code(404).send({ error: "not_found" });
    await setIgnored(req, key, true);
    return overview(req);
  });
  app.delete("/benchmarks/:key/ignore", async (req, reply) => {
    const { key } = keyParam.parse(req.params);
    if (!isBenchmarkKey(key)) return reply.code(404).send({ error: "not_found" });
    await setIgnored(req, key, false);
    return overview(req);
  });
};
