import type { Config } from "../config.js";
import { recordOrgOf, type Db } from "./access.js";
import { AgentLimitError } from "./agents.js";
import { lockUser } from "./orgs.js";
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
  const [rows, rules] = await Promise.all([
    db.recordAccess.findMany({ where: { holderType: "user", holderId: agentUserId, orgId: null, state: "active", record: { ownerId: ownerUserId } }, orderBy: { createdAt: "asc" },
      select: { wrappedRecordKey: true, record: { select: { id: true, encBody: true, revision: true, deletedAt: true, folder: { select: { kind: true, orgId: true } } } } } }),
    personalAgentRules(db, cfg, ownerUserId),
  ]);
  return {
    owner: { userId: ownerUserId, publicKey: a.owner!.publicKey }, // current: the gateway refuses when it no longer matches the attestation
    agentId: agentUserId, publicKey: a.publicKey, wrappedPrivateKey: a.wrappedPrivateKey, kekId: a.kekId, expiresAt: a.expiresAt?.toISOString() ?? null,
    records: rows.filter((r) => recordOrgOf(r.record) === null).map(({ wrappedRecordKey, record: r }) => ({
      id: r.id, encBody: r.encBody, revision: r.revision, wrappedRecordKey: wrappedRecordKey!, write: false, deletedAt: r.deletedAt?.toISOString() ?? null })),
    reveal: [] as never[], deposits: [] as never[],
    policy: { write: rules.write, reveal: rules.reveal },
  };
}
