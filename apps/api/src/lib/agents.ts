import { createHash } from "node:crypto";
import type { Config } from "../config.js";
import type { Db } from "./access.js";
import { orgEntitlements } from "./plans.js";
import { lockSeats } from "./seats.js";

export { capForAgent } from "./access.js";

/** An agent's User.email: unique, and never deliverable (reserved TLD). */
export const agentEmail = (userId: string) => `agent+${userId}@agents.invalid`;

export async function isAgentUser(db: Db, userId: string): Promise<boolean> {
  return (await db.user.findUnique({ where: { id: userId }, select: { kind: true } }))?.kind === "agent";
}

export class AgentLimitError extends Error {
  constructor(public used: number, public allowed: number) { super("agent_limit"); }
}

export const liveAgents = (db: Db, orgId: string): Promise<number> => db.agent.count({ where: { orgId, revokedAt: null } });

/** lockSeats(tx, cfg, orgId) then count; throws AgentLimitError. No-op with billing off. */
export async function assertAgentSlot(tx: Db, cfg: Pick<Config, "billingMode">, orgId: string): Promise<void> {
  if (cfg.billingMode !== "hosted") return;
  await lockSeats(tx, cfg, orgId);
  const allowed = (await orgEntitlements(tx, cfg, orgId)).agentLimit;
  if (allowed === null) return;
  const used = await liveAgents(tx, orgId);
  if (used >= allowed) throw new AgentLimitError(used, allowed);
}

/** keyFingerprint from @clane-vault/crypto (which the API can't load at runtime): SHA-256, first 10 bytes, hex in groups of 4. */
export const fingerprintOf = (keyB64: string): string =>
  createHash("sha256").update(Buffer.from(keyB64, "base64url")).digest("hex").slice(0, 20).match(/.{4}/g)!.join("-");

/**
 * The attestation that travels with an agent's public key wherever other members get it to seal to (R41): their
 * browsers verify it against the pinned gateway identity first. Only agent ids need passing.
 */
export async function agentAttestations(db: Db, agentIds: string[]): Promise<Map<string, { attestation: string; gatewayKeyId: string }>> {
  if (!agentIds.length) return new Map();
  const rows = await db.agent.findMany({ where: { userId: { in: agentIds } }, select: { userId: true, attestation: true } });
  return new Map(rows.map((r) => [r.userId, { attestation: r.attestation, gatewayKeyId: r.attestation.split(".")[1] ?? "" }]));
}
