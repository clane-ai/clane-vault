import type { FastifyRequest } from "fastify";
import type { PrismaClient } from "@prisma/client";
import type { Config } from "../config.js";
import { recordOrgOf, type Db } from "./access.js";
import { AgentLimitError } from "./agents.js";
import { lockUser } from "./orgs.js";
import { logEvent } from "./events.js";
import { getEntitlements, getPersonalEntitlements, PLAN_SELECT } from "./plans.js";
import { readPolicies, type Policies } from "./policies.js";

/** Hard ceiling of personal agents per person, whatever the plan or policies say. */
export const PERSONAL_AGENT_CEILING = 20;
export type RevealMode = "off" | "approval" | "standing";
export interface PersonalAgentRules { allowed: boolean; blockedByOrgId: string | null; max: number; write: boolean; reveal: RevealMode }

const REVEAL_ORDER: RevealMode[] = ["off", "approval", "standing"];

/** Pure. allowed = AND, max = min(ceiling, allowance ?? ceiling, every non-null maxPerMember), write = AND, reveal = lowest of off < approval < standing. No policies: allowed, write true, reveal "standing". */
export function strictest(allowance: number | null, policies: { orgId: string; p: Policies["personalAgents"] }[]): PersonalAgentRules {
  const r: PersonalAgentRules = { allowed: true, blockedByOrgId: null, max: Math.min(PERSONAL_AGENT_CEILING, allowance ?? PERSONAL_AGENT_CEILING), write: true, reveal: "standing" };
  for (const { orgId, p } of policies) {
    if (!p.allowed && r.allowed) { r.allowed = false; r.blockedByOrgId = orgId; }
    if (p.maxPerMember !== null) r.max = Math.min(r.max, p.maxPerMember);
    r.write &&= p.write;
    if (REVEAL_ORDER.indexOf(p.reveal) < REVEAL_ORDER.indexOf(r.reveal)) r.reveal = p.reveal;
  }
  return r;
}

/** Active memberships only. Hosted allowance: the highest personalAgentLimit among them, or the Personal plan's with none; billing off: null. cfg.agents.personalAgents false → allowed false, blockedByOrgId null. */
export async function personalAgentRules(db: Db, cfg: Config, userId: string): Promise<PersonalAgentRules> {
  if (!cfg.agents?.personalAgents) return { allowed: false, blockedByOrgId: null, max: 0, write: false, reveal: "off" };
  const ms = await db.membership.findMany({ where: { userId, status: "active" }, orderBy: { createdAt: "asc" }, select: { org: { select: { ...PLAN_SELECT, id: true, policies: true } } } });
  let allowance: number | null = null;
  if (cfg.billingMode === "hosted") {
    const limits = ms.map((m) => getEntitlements(cfg, m.org).personalAgentLimit);
    allowance = !limits.length ? getPersonalEntitlements(cfg).personalAgentLimit : limits.includes(null) ? null : Math.max(...(limits as number[]));
  }
  return strictest(allowance, ms.map((m) => ({ orgId: m.org.id, p: readPolicies(m.org.policies, getEntitlements(cfg, m.org)).personalAgents })));
}

/** Callers check `personalAgentRules(...).allowed` first: with PERSONAL_AGENTS off max is 0 and this would throw agent_limit instead. lockUser, count live (revokedAt null) agents with this owner, throw AgentLimitError(used, rules.max). */
export async function assertPersonalAgentSlot(tx: Db, cfg: Config, ownerUserId: string): Promise<void> {
  await lockUser(tx, ownerUserId);
  const rules = await personalAgentRules(tx, cfg, ownerUserId);
  const used = await tx.agent.count({ where: { ownerUserId, revokedAt: null } });
  if (used >= rules.max) throw new AgentLimitError(used, rules.max);
}

/** One Event per organisation the owner is an active member of: { orgId, actorId: ownerUserId, action: `personal_agent.${what}`, meta: { agentId } } and nothing else. */
export async function logLifecycle(tx: Db, ownerUserId: string, what: "create" | "verify" | "revoke" | "connect" | "suspended", agentId: string): Promise<void> {
  const ms = await tx.membership.findMany({ where: { userId: ownerUserId, status: "active" }, select: { orgId: true } });
  if (ms.length) await tx.event.createMany({ data: ms.map((m) => ({ orgId: m.orgId, actorId: ownerUserId, action: `personal_agent.${what}`, meta: { agentId } })) });
}

/** At most this many items granted to one personal agent. */
export const AGENT_ITEM_LIMIT = 200;
export type GrantRefusal = { code: 400 | 404 | 409; error: "not_found" | "team_record" | "in_trash" | "user_not_active" };

/**
 * Can `callerId` grant `recordId` to their personal agent `agentId`, in this order: the caller holds the owner row and
 * is Record.ownerId (404), the record is private (409 team_record) and not trashed (409 in_trash), the agent is the
 * caller's, verified, live and unexpired (400 user_not_active). Returns the agent's public key (what the box is sealed to).
 */
export async function assertGrantable(tx: Db, callerId: string, recordId: string, agentId: string): Promise<GrantRefusal | { publicKey: string }> {
  const rec = await tx.record.findFirst({ where: { id: recordId, ownerId: callerId, access: { some: { holderType: "user", holderId: callerId, permission: "owner" } } },
    select: { deletedAt: true, folder: { select: { kind: true, orgId: true } } } });
  if (!rec) return { code: 404, error: "not_found" };
  if (recordOrgOf(rec) !== null) return { code: 409, error: "team_record" };
  if (rec.deletedAt) return { code: 409, error: "in_trash" };
  const a = await tx.agent.findFirst({ where: { userId: agentId, ownerUserId: callerId, orgId: null, revokedAt: null, verifiedAt: { not: null },
    OR: [{ expiresAt: null }, { expiresAt: { gt: new Date() } }], user: { status: "active" } }, select: { publicKey: true } });
  return a ? { publicKey: a.publicKey } : { code: 400, error: "user_not_active" };
}

/** GET /agent/sync for a personal agent: its own rows on private records its owner still owns, nothing else (no folders, no members). */
export async function personalAgentSync(db: Db, cfg: Config, agentUserId: string) {
  const a = await db.agent.findUniqueOrThrow({ where: { userId: agentUserId },
    select: { ownerUserId: true, publicKey: true, wrappedPrivateKey: true, kekId: true, expiresAt: true, owner: { select: { publicKey: true } } } });
  const ownerUserId = a.ownerUserId!;
  const [rows, rules, deposits, unkept, stubs] = await Promise.all([
    db.recordAccess.findMany({ where: { holderType: "user", holderId: agentUserId, orgId: null, state: "active", record: { ownerId: ownerUserId } }, orderBy: { createdAt: "asc" },
      select: { wrappedRecordKey: true, agentWrite: true, record: { select: { id: true, encBody: true, revision: true, deletedAt: true, folder: { select: { kind: true, orgId: true } } } } } }),
    personalAgentRules(db, cfg, ownerUserId),
    db.agentDeposit.findMany({ where: { agentId: agentUserId }, orderBy: { createdAt: "asc" }, select: { id: true, encBody: true, revision: true, agentSealedKey: true, signature: true } }),
    db.agentDeposit.count({ where: { ownerUserId } }),
    db.agentRevealGrant.findMany({ where: { agentId: agentUserId, record: { ownerId: ownerUserId, deletedAt: null } }, orderBy: { createdAt: "asc" },
      select: { sealedStub: true, record: { select: { id: true, folder: { select: { kind: true, orgId: true } } } } } }),
  ]);
  return {
    owner: { userId: ownerUserId, publicKey: a.owner!.publicKey }, // current: the gateway refuses when it no longer matches the attestation
    agentId: agentUserId, publicKey: a.publicKey, wrappedPrivateKey: a.wrappedPrivateKey, kekId: a.kekId, expiresAt: a.expiresAt?.toISOString() ?? null,
    records: rows.filter((r) => recordOrgOf(r.record) === null).map(({ wrappedRecordKey, agentWrite, record: r }) => ({
      id: r.id, encBody: r.encBody, revision: r.revision, wrappedRecordKey: wrappedRecordKey!, write: agentWrite && rules.write, deletedAt: r.deletedAt?.toISOString() ?? null })),
    reveal: rules.reveal === "off" ? [] : stubs.filter((s) => recordOrgOf(s.record) === null).map((s) => ({ recordId: s.record.id, sealedStub: s.sealedStub })), deposits,
    inboxFree: Math.max(0, DEPOSIT_INBOX_LIMIT - unkept), // the limit is the owner's, across all their agents (F2)
    policy: { write: rules.write, reveal: rules.reveal },
  };
}

/** Unkept deposits per owner, across all their agents. */
export const DEPOSIT_INBOX_LIMIT = 100;
/** Unkept deposits are deleted this long after they were made. */
export const DEPOSIT_TTL_MS = 90 * 86400e3;

/** The name of what the agent is connected through: the token's label, or the OAuth client's name behind the grant. */
export async function connectedApp(db: Db, a: FastifyRequest["agent"]): Promise<string> {
  if (a.via === "token") return (await db.agentToken.findUnique({ where: { id: a.grantId }, select: { label: true } }))?.label ?? "";
  const g = await db.agentGrant.findUnique({ where: { id: a.grantId }, select: { clientId: true } });
  return (g && (await db.agentOAuthClient.findUnique({ where: { id: g.clientId }, select: { name: true } }))?.name) ?? "";
}

/** Claims a pending or approved request past its expiry as expired (sealed nulled) and logs agent.reveal_expired once. */
/** `ended`: expire it now although its time has not run out (the item stopped being revealable). */
export async function expireReveal(db: PrismaClient, id: string, now = new Date(), ended = false): Promise<boolean> {
  return db.$transaction(async (tx) => {
    const r = await tx.agentRevealRequest.findUnique({ where: { id }, select: { agentId: true, recordId: true, fields: true, connectedApp: true } });
    if (!r || !(await tx.agentRevealRequest.updateMany({ where: { id, status: { in: ["pending", "approved"] }, ...(ended ? {} : { expiresAt: { lte: now } }) }, data: { status: "expired", sealed: null } })).count) return false;
    await logEvent(tx, { actorId: r.agentId, action: "agent.reveal_expired", recordId: r.recordId, meta: { requestId: id, fields: r.fields, app: r.connectedApp } });
    return true;
  });
}

/** Kept overwrites per record (the newest), and how long. */
export const OVERWRITE_KEEP = 5;
export const OVERWRITE_TTL_MS = 30 * 86400e3;

/** The periodic sweep: deletes unkept deposits older than 90 days and overwrites older than 30. Returns how many rows went. */
export async function sweepAgentWrites(prisma: PrismaClient, now = new Date()): Promise<number> {
  const d = await prisma.agentDeposit.deleteMany({ where: { createdAt: { lt: new Date(now.getTime() - DEPOSIT_TTL_MS) } } });
  const o = await prisma.recordAgentOverwrite.deleteMany({ where: { createdAt: { lt: new Date(now.getTime() - OVERWRITE_TTL_MS) } } });
  // Reveal requests past their expiry lose any sealed reply, and log their expiry once.
  let x = 0;
  for (const r of await prisma.agentRevealRequest.findMany({ where: { status: { in: ["pending", "approved"] }, expiresAt: { lte: now } }, select: { id: true } }))
    if (await expireReveal(prisma, r.id, now)) x++;
  return d.count + o.count + x;
}

export interface PersonalRotation { records: { id: string }[]; revealed: { id: string; fields: string[] }[] }

/**
 * In the caller's transaction: lockUser(agent) (the lock a grant takes, so none lands mid-revoke); claim revokedAt (null
 * when already revoked); delete its RecordAccess rows; revoke tokens and grants; wrappedPrivateKey null; User disabled;
 * logLifecycle("revoke"). Returns the records whose keys the agent's gateway held: the owner rotates them.
 */
export async function revokePersonalAgent(tx: Db, agentUserId: string, byUserId: string): Promise<PersonalRotation | null> {
  await lockUser(tx, agentUserId);
  const now = new Date();
  const a = await tx.agent.findFirst({ where: { userId: agentUserId, ownerUserId: { not: null }, revokedAt: null }, select: { ownerUserId: true } });
  if (!a || (await tx.agent.updateMany({ where: { userId: agentUserId, revokedAt: null }, data: { revokedAt: now, revokedById: byUserId, wrappedPrivateKey: null } })).count !== 1) return null;
  const held = await tx.recordAccess.findMany({ where: { holderType: "user", holderId: agentUserId }, select: { recordId: true }, distinct: ["recordId"] });
  await tx.recordAccess.deleteMany({ where: { holderType: "user", holderId: agentUserId } });
  await tx.agentDeposit.deleteMany({ where: { agentId: agentUserId } }); // unkept ones; kept records are the owner's
  await tx.agentRevealGrant.deleteMany({ where: { agentId: agentUserId } });
  await tx.agentRevealRequest.updateMany({ where: { agentId: agentUserId, status: { in: ["pending", "approved"] } }, data: { status: "expired", sealed: null } });
  // What the model was shown: the owner changes these fields (field names only, from the agent's own events).
  const shown = new Map<string, Set<string>>();
  for (const e of await tx.event.findMany({ where: { actorId: agentUserId, action: "agent.reveal", recordId: { not: null } }, select: { recordId: true, meta: true } })) {
    const f = (e.meta as { fields?: unknown } | null)?.fields;
    const set = shown.get(e.recordId!) ?? new Set<string>();
    if (Array.isArray(f)) for (const x of f) if (typeof x === "string") set.add(x);
    shown.set(e.recordId!, set);
  }
  await tx.agentToken.updateMany({ where: { agentId: agentUserId, revokedAt: null }, data: { revokedAt: now } });
  await tx.agentGrant.updateMany({ where: { agentId: agentUserId, revokedAt: null }, data: { revokedAt: now } });
  await tx.user.update({ where: { id: agentUserId }, data: { status: "disabled" } });
  await logLifecycle(tx, a.ownerUserId!, "revoke", agentUserId);
  return { records: held.map((r) => ({ id: r.recordId })), revealed: [...shown].map(([id, f]) => ({ id, fields: [...f].sort() })) };
}

/** Revokes every live personal agent of the owner, then deletes all of that owner's agents' User rows (R3); returns their ids. */
export async function revokePersonalAgentsOf(tx: Db, ownerUserId: string): Promise<string[]> {
  const all = await tx.agent.findMany({ where: { ownerUserId }, select: { userId: true, revokedAt: true } });
  for (const a of all) if (!a.revokedAt) await revokePersonalAgent(tx, a.userId, ownerUserId);
  const ids = all.map((a) => a.userId);
  if (ids.length) await tx.user.deleteMany({ where: { id: { in: ids }, kind: "agent" } });
  return ids;
}
