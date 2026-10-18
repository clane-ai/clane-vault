import type { FastifyPluginAsync } from "fastify";
import { currentKeys } from "../lib/membershipKeys.js";
import { agentAttestations } from "../lib/agents.js";

/** Active members of the active org, for the share and member pickers. Public keys come from the server (spec §5.6). */
export const userRoutes: FastifyPluginAsync = async (app) => {
  app.get("/users", { preHandler: [app.requireAuth, app.orgRequired] }, async (req) => {
    const users = await app.prisma.user.findMany({ where: { status: "active", memberships: { some: { orgId: req.org!.id, status: "active" } } }, select: { id: true, name: true, email: true, publicKey: true, kind: true }, orderBy: { name: "asc" } });
    // Each person's membership key here: what folder keys and shares made in this org are sealed to (null: none yet).
    const keys = await currentKeys(app.prisma, req.org!.id, users.map((u) => u.id));
    // An agent's key comes with the gateway's attestation: browsers verify it before sealing to the agent.
    const att = await agentAttestations(app.prisma, users.filter((u) => u.kind === "agent").map((u) => u.id));
    return { users: users.map((u) => ({ ...u, membershipKey: keys.get(u.id) ?? null, ...att.get(u.id) })) };
  });
};
