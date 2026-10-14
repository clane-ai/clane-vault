import type { PrismaClient } from "@prisma/client";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import type { Config } from "../config.js";
import type { Db } from "./access.js";
import { tombstoneAttachments } from "./attachments/sweep.js";

/**
 * Public demo mode (docs/demo.md). A visitor gets a sandbox: their own account (made in the browser like any sign-up)
 * and an organisation, both stamped with `demoExpiresAt`. Nothing about a sandbox is shared with another one, and the
 * periodic sweep below hard-deletes it once it expires. A demo instance never holds a real account (checkDemoStartup).
 */

/** The sandbox organisation every visitor owns. */
export const DEMO_ORG_NAME = "Northwind (demo)";
/** How often expired sandboxes are looked for and deleted. */
export const DEMO_SWEEP_INTERVAL_MS = 60_000;
/** Sandboxes deleted per sweep (the rest wait for the next one). */
const SWEEP_BATCH = 50;

export const demoOn = (config: Pick<Config, "demo">): boolean => !!config.demo;

/**
 * Whether this account may skip the authenticator (setting one up, and the code at sign-in). Both have to hold, checked
 * here on the server: the instance runs in demo mode AND the account is a live demo account. A real account never
 * skips it, demo mode or not, and a demo account on an instance that is no longer in demo mode doesn't either.
 */
export function demoSkipsTotp(config: Pick<Config, "demo">, user: { demoExpiresAt: Date | null }, now = new Date()): boolean {
  return demoOn(config) && !!user.demoExpiresAt && user.demoExpiresAt > now;
}

/** A demo account past its time: refused everywhere, even before the sweep deletes it. */
export const demoExpired = (user: { demoExpiresAt: Date | null }, now = new Date()): boolean => !!user.demoExpiresAt && user.demoExpiresAt <= now;

/** Sessions of a demo account end when its sandbox does. */
export const sessionEnd = (user: { demoExpiresAt: Date | null }, ttlMs: number, now = Date.now()): Date =>
  new Date(user.demoExpiresAt ? Math.min(now + ttlMs, user.demoExpiresAt.getTime()) : now + ttlMs);

/** preHandler: refuses the route on a demo instance (403 demo_mode). */
export function notInDemo(app: FastifyInstance) {
  return async (_req: FastifyRequest, reply: FastifyReply) => {
    if (reply.sent || !demoOn(app.config)) return;
    await reply.code(403).send({ error: "demo_mode" });
  };
}

/** preHandler: on a demo instance, only reads (GET) get through; changes answer 403 demo_mode. */
export function readOnlyInDemo(app: FastifyInstance) {
  const refuse = notInDemo(app);
  return async (req: FastifyRequest, reply: FastifyReply) => { if (req.method !== "GET" && req.method !== "HEAD") await refuse(req, reply); };
}

export class DemoStartupRefused extends Error {}

/**
 * Run at startup. A demo instance must hold sandboxes only, so a production database can never be switched to demo mode
 * by mistake: any account without `demoExpiresAt` (the bootstrap / instance admin included) stops the start.
 */
export async function checkDemoStartup(prisma: Db, config: Pick<Config, "demo" | "hostedMode">): Promise<void> {
  if (!demoOn(config)) return;
  if (config.hostedMode) throw new DemoStartupRefused("DEMO_MODE=true can't be combined with HOSTED_MODE=true");
  const real = await prisma.user.count({ where: { demoExpiresAt: null } });
  if (real > 0) throw new DemoStartupRefused(`DEMO_MODE=true needs a database without real accounts, and this one has ${real}. Use a separate, empty database for the demo (docs/demo.md).`);
}

/**
 * Deletes one sandbox in the caller's transaction: its organisation (or none, for leftover accounts) and these demo
 * accounts, with every record, attachment, link, folder, event and session they or the organisation hold.
 */
async function deleteSandbox(tx: Db, orgId: string | null, userIds: string[]): Promise<void> {
  const owners = userIds.length ? [{ ownerId: { in: userIds } }] : [];
  const inOrg = orgId ? [{ folder: { orgId } }] : [];
  const recordIds = (await tx.record.findMany({ where: { OR: [...owners, ...inOrg] }, select: { id: true } })).map((r) => r.id);
  // S3 objects don't cascade with their rows: the attachment sweep removes them from these tombstones.
  await tombstoneAttachments(tx, recordIds);
  await tx.event.deleteMany({ where: { OR: [
    ...(orgId ? [{ orgId }] : []),
    ...(userIds.length ? [{ actorId: { in: userIds } }, { targetUserId: { in: userIds } }] : []),
    ...(recordIds.length ? [{ recordId: { in: recordIds } }] : []),
  ] } });
  // Links, record access rows and attachments (with their chunks) cascade with the records.
  if (recordIds.length) await tx.record.deleteMany({ where: { id: { in: recordIds } } });
  await tx.shareLink.deleteMany({ where: { OR: [...(userIds.length ? [{ createdBy: { in: userIds } }] : []), ...(orgId ? [{ orgId }] : [])] } });
  await tx.folder.deleteMany({ where: { OR: [...(userIds.length ? [{ ownerId: { in: userIds } }] : []), ...(orgId ? [{ orgId }] : [])] } });
  // Sessions, memberships, keys, escrows, recovery requests, group memberships and health reports cascade with the accounts
  // and the organisation.
  if (userIds.length) await tx.user.deleteMany({ where: { id: { in: userIds }, demoExpiresAt: { not: null } } });
  if (orgId) await tx.organization.deleteMany({ where: { id: orgId, demoExpiresAt: { not: null } } });
}

export interface DemoSweepReport { sandboxes: number; users: number }

/**
 * Hard-deletes expired sandboxes, one transaction per sandbox, then any expired demo account left without one. Only rows
 * stamped with `demoExpiresAt` are ever touched: an account without it is never deleted here.
 */
export async function sweepExpiredDemos(prisma: PrismaClient, now = new Date(), log?: { warn: (o: object, m: string) => void }): Promise<DemoSweepReport> {
  const report: DemoSweepReport = { sandboxes: 0, users: 0 };
  const orgs = await prisma.organization.findMany({ where: { demoExpiresAt: { lte: now } }, select: { id: true }, orderBy: { demoExpiresAt: "asc" }, take: SWEEP_BATCH });
  for (const o of orgs) {
    try {
      report.users += await prisma.$transaction(async (tx) => {
        const users = (await tx.user.findMany({ where: { demoExpiresAt: { not: null }, memberships: { some: { orgId: o.id } } }, select: { id: true } })).map((u) => u.id);
        await deleteSandbox(tx, o.id, users);
        return users.length;
      });
      report.sandboxes++;
    } catch (e) { log?.warn({ event: "demo.sweep_failed", orgId: o.id, error: e instanceof Error ? e.message.split("\n")[0] : String(e) }, "demo.sweep_failed"); }
  }
  const strays = await prisma.user.findMany({ where: { demoExpiresAt: { lte: now } }, select: { id: true }, take: SWEEP_BATCH * 4 });
  for (const u of strays) {
    try { await prisma.$transaction((tx) => deleteSandbox(tx, null, [u.id])); report.users++; }
    catch (e) { log?.warn({ event: "demo.sweep_failed", userId: u.id, error: e instanceof Error ? e.message.split("\n")[0] : String(e) }, "demo.sweep_failed"); }
  }
  return report;
}
