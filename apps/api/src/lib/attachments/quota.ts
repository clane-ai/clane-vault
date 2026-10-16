import { DEFAULT_ATTACHMENTS, demoAttachments, type AttachmentConfig, type Config } from "../../config.js";
import type { Db } from "../access.js";
import { getPersonalEntitlements, orgEntitlements } from "../plans.js";

/**
 * Attachment quotas and accounting (docs/design/2026-10-12-attachments.md §3.5). Usage is SUM(size) of
 * ciphertext over rows that are uploading (a reservation) or ready. An attachment is charged to its record's
 * organisation (team folder) or, for a private record, to the record's owner.
 */

export const MIB = 1024 * 1024;
/** pg_advisory_xact_lock key for attachment reservations (backups use 7341 with a second key). */
export const QUOTA_LOCK = 7342;

/** The attachment settings in force: a demo instance's are capped small (docs/demo.md). */
export const attachmentConfig = (c: Pick<Config, "attachments" | "demo" | "billingMode">): AttachmentConfig => {
  const a = { ...(c.attachments ?? DEFAULT_ATTACHMENTS), billingMode: c.billingMode };
  return c.demo ? demoAttachments(a) : a;
};

export type Charge = { kind: "org"; orgId: string } | { kind: "user"; userId: string };
export type QuotaScope = "org" | "user" | "instance";

const n = (rows: { n: bigint | number | null }[]) => Number(rows[0]?.n ?? 0);

/** Who pays for a record's files: its team folder's org, else its owner. */
export async function chargeOf(db: Db, recordId: string): Promise<Charge | null> {
  const r = await db.record.findUnique({ where: { id: recordId }, select: { ownerId: true, folder: { select: { kind: true, orgId: true } } } });
  if (!r) return null;
  return r.folder?.kind === "team" && r.folder.orgId ? { kind: "org", orgId: r.folder.orgId } : { kind: "user", userId: r.ownerId };
}

export const orgUsage = async (db: Db, orgId: string) => n(await db.$queryRaw<{ n: bigint }[]>`
  SELECT COALESCE(SUM(a.size), 0)::bigint AS n FROM "Attachment" a JOIN "Record" r ON r.id = a."recordId" JOIN "Folder" f ON f.id = r."folderId"
  WHERE a.state IN ('uploading', 'ready') AND f.kind = 'team' AND f."orgId" = ${orgId}::uuid`);

export const userUsage = async (db: Db, userId: string) => n(await db.$queryRaw<{ n: bigint }[]>`
  SELECT COALESCE(SUM(a.size), 0)::bigint AS n FROM "Attachment" a JOIN "Record" r ON r.id = a."recordId" LEFT JOIN "Folder" f ON f.id = r."folderId"
  WHERE a.state IN ('uploading', 'ready') AND r."ownerId" = ${userId}::uuid AND (f.id IS NULL OR f.kind = 'private')`);

export const instanceUsage = async (db: Db) => n(await db.$queryRaw<{ n: bigint }[]>`
  SELECT COALESCE(SUM(size), 0)::bigint AS n FROM "Attachment" WHERE state IN ('uploading', 'ready')`);

export async function recordUsage(db: Db, recordId: string): Promise<{ files: number; bytes: number }> {
  const rows = await db.$queryRaw<{ files: bigint; bytes: bigint }[]>`
    SELECT COUNT(*)::bigint AS files, COALESCE(SUM(size), 0)::bigint AS bytes FROM "Attachment" WHERE "recordId" = ${recordId}::uuid AND state IN ('uploading', 'ready')`;
  return { files: Number(rows[0]?.files ?? 0), bytes: Number(rows[0]?.bytes ?? 0) };
}

/**
 * Bytes `userId` uploaded in the last 24 h: completed uploads (their attachment.add events, which survive deletes and
 * purges) plus uploads still in progress (their reservations).
 */
export async function dailyUploaded(db: Db, userId: string, now = new Date()): Promise<number> {
  const since = new Date(now.getTime() - 24 * 3600e3);
  const [done, open] = await Promise.all([
    db.$queryRaw<{ n: bigint }[]>`SELECT COALESCE(SUM((meta->>'size')::bigint), 0)::bigint AS n FROM "Event"
      WHERE "actorId" = ${userId}::uuid AND action = 'attachment.add' AND at > ${since}`,
    db.$queryRaw<{ n: bigint }[]>`SELECT COALESCE(SUM(size), 0)::bigint AS n FROM "Attachment" WHERE "createdBy" = ${userId}::uuid AND state = 'uploading'`,
  ]);
  return n(done) + n(open);
}

/**
 * Serialises reservations: the instance-wide advisory lock, then the charged organisation's (or person's) row, so two
 * concurrent uploads can't both squeeze under a limit. Run first thing inside the transaction.
 */
export async function lockQuota(tx: Db, charge: Charge): Promise<void> {
  await tx.$executeRaw`SELECT pg_advisory_xact_lock(${QUOTA_LOCK}::bigint)`;
  if (charge.kind === "org") await tx.$queryRaw`SELECT id FROM "Organization" WHERE id = ${charge.orgId}::uuid FOR UPDATE`;
  else await tx.$queryRaw`SELECT id FROM "User" WHERE id = ${charge.userId}::uuid FOR UPDATE`;
}

/** Bytes a charge may hold: the env per-org / per-user cap, or under hosted plans the pooled plan storage instead (per active member for an org, per user otherwise). */
export async function chargeQuota(db: Db, cfg: AttachmentConfig, charge: Charge): Promise<number> {
  const cap = (charge.kind === "org" ? cfg.orgQuotaMb : cfg.userQuotaMb) * MIB;
  if (cfg.billingMode !== "hosted") return cap;
  const perSeat = charge.kind === "org" ? (await orgEntitlements(db, cfg, charge.orgId)).storageBytesPerSeat : getPersonalEntitlements(cfg).storageBytesPerSeat;
  if (perSeat === null) return cap;
  const seats = charge.kind === "org" ? Math.max(1, await db.membership.count({ where: { orgId: charge.orgId, status: "active" } })) : 1;
  return perSeat * seats;
}

export interface QuotaRefusal { scope: QuotaScope; used: number; quota: number }

/**
 * Whether adding `add` bytes to `charge` stays within its quota and the instance's. Call after lockQuota. A move
 * (`instance: false`) only re-charges bytes the instance already holds.
 */
export async function checkQuota(tx: Db, cfg: AttachmentConfig, charge: Charge, add: number, o: { instance?: boolean } = {}): Promise<QuotaRefusal | null> {
  const [used, quota, scope] = charge.kind === "org"
    ? [await orgUsage(tx, charge.orgId), await chargeQuota(tx, cfg, charge), "org" as const]
    : [await userUsage(tx, charge.userId), await chargeQuota(tx, cfg, charge), "user" as const];
  if (used + add > quota) return { scope, used, quota };
  if (o.instance === false) return null;
  const all = await instanceUsage(tx);
  const instanceQuota = cfg.instanceQuotaMb * MIB;
  if (all + add > instanceQuota) return { scope: "instance", used: all, quota: instanceQuota };
  return null;
}
