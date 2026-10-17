import type { Db } from "./access.js";

export { capForAgent } from "./access.js";

/** An agent's User.email: unique, and never deliverable (reserved TLD). */
export const agentEmail = (userId: string) => `agent+${userId}@agents.invalid`;

export async function isAgentUser(db: Db, userId: string): Promise<boolean> {
  return (await db.user.findUnique({ where: { id: userId }, select: { kind: true } }))?.kind === "agent";
}
