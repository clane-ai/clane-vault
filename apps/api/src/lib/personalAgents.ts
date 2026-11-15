import type { Config } from "../config.js";
import type { Db } from "./access.js";
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

/** lockUser, count live (revokedAt null) agents with this owner, throw AgentLimitError(used, rules.max). */
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
