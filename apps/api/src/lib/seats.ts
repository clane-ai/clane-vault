import type { Config } from "../config.js";
import type { Db } from "./access.js";
import { INVITE_TTL_MS } from "./invites.js";
import { orgEntitlements } from "./plans.js";

export class SeatLimitError extends Error {
  constructor(public used: number, public allowed: number) { super("seat_limit"); }
}

/**
 * The distinct lower-cased addresses holding a seat: active members, pending invitations, and live invitations to
 * existing accounts (an `invited` membership; hosted mode has no invite row for those). One address is one seat.
 * Agents are never seats (their own limit is agentLimit).
 */
async function seatEmails(db: Db, orgId: string, now: Date): Promise<Set<string>> {
  const rows = await db.$queryRaw<{ e: string }[]>`
    SELECT lower(u.email) AS e FROM "Membership" m JOIN "User" u ON u.id = m."userId" WHERE m."orgId" = ${orgId}::uuid AND m.status = 'active' AND u.kind = 'person'
    UNION SELECT lower(email) FROM "Invite" WHERE "orgId" = ${orgId}::uuid AND "acceptedAt" IS NULL AND "expiresAt" > ${now}
    UNION SELECT lower(u.email) FROM "Membership" m JOIN "User" u ON u.id = m."userId"
      WHERE m."orgId" = ${orgId}::uuid AND m.status = 'invited' AND u.kind = 'person' AND m."createdAt" > ${new Date(now.getTime() - INVITE_TTL_MS)}`;
  return new Set(rows.map((r) => r.e));
}

export async function seatsUsed(db: Db, orgId: string, now = new Date()): Promise<number> {
  return (await seatEmails(db, orgId, now)).size;
}

/** The org row lock alone. Lock order is always Organization then User, so a transaction that also locks the user takes this first. */
export async function lockSeats(tx: Db, cfg: Pick<Config, "billingMode">, orgId: string): Promise<void> {
  if (cfg.billingMode === "hosted") await tx.$queryRaw`SELECT id FROM "Organization" WHERE id = ${orgId}::uuid FOR UPDATE`;
}

/**
 * Call first in the transaction that creates the seat: it locks the org row, so concurrent seat-takers queue up.
 * Throws SeatLimitError if `adding` more seats would pass the allowance. An `email` that already holds a seat adds none.
 */
export async function assertSeat(tx: Db, cfg: Pick<Config, "billingMode">, orgId: string, adding = 1, email?: string): Promise<void> {
  if (cfg.billingMode !== "hosted") return;
  await lockSeats(tx, cfg, orgId);
  const allowed = (await orgEntitlements(tx, cfg, orgId)).seatsAllowed;
  if (allowed === null) return;
  const emails = await seatEmails(tx, orgId, new Date());
  if (email && emails.has(email.toLowerCase())) return;
  if (emails.size + adding > allowed) throw new SeatLimitError(emails.size, allowed);
}

/** Already past the allowance (a downgrade or fewer paid seats): new invitations are refused, nothing else changes. */
export async function seatOverage(db: Db, cfg: Pick<Config, "billingMode">, orgId: string): Promise<{ used: number; allowed: number } | null> {
  if (cfg.billingMode !== "hosted") return null; // hot path (record create, upload): no query when billing is off
  const allowed = (await orgEntitlements(db, cfg, orgId)).seatsAllowed;
  if (allowed === null) return null;
  const used = await seatsUsed(db, orgId);
  return used > allowed ? { used, allowed } : null;
}

export async function overSeatLimit(db: Db, cfg: Pick<Config, "billingMode">, orgId: string): Promise<boolean> {
  return (await seatOverage(db, cfg, orgId)) !== null;
}
