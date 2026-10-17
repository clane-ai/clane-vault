import type { PrismaClient } from "@prisma/client";
import { randomUUID } from "node:crypto";
import { b64url, generateKeyPair } from "@clane-vault/crypto";
import { agentEmail } from "../src/lib/agents.js";

/** Inserts the rows enrolment makes (§4.1), with a real X25519 pair; verified → membership active. */
export async function createTestAgent(t: { prisma: PrismaClient }, o: { orgId: string; createdById: string; verified?: boolean; expiresAt?: Date; name?: string }):
  Promise<{ id: string; publicKey: string; privateKey: Uint8Array }> {
  const pair = await generateKeyPair();
  const id = randomUUID(), publicKey = b64url.encode(pair.publicKey), now = new Date();
  await t.prisma.$transaction([
    t.prisma.user.create({ data: { id, kind: "agent", email: agentEmail(id), name: o.name ?? "Test agent", status: "active",
      authHash: "", kdfSalt: "", kdfParams: {}, wrappedUserKey: "", publicKey, wrappedPrivateKey: "" } }),
    t.prisma.membership.create({ data: { orgId: o.orgId, userId: id, role: "member", status: o.verified ? "active" : "invited", invitedById: o.createdById, ...(o.verified ? { joinedAt: now } : {}) } }),
    t.prisma.membershipKey.create({ data: { orgId: o.orgId, userId: id, publicKey, wrappedPrivateKey: "", userKeyGen: 1, state: "current" } }),
    // A placeholder envelope and attestation: nothing in the API opens or checks them.
    t.prisma.agent.create({ data: { userId: id, orgId: o.orgId, createdById: o.createdById, publicKey, wrappedPrivateKey: "k1.test-kek.dek.v1.test", kekId: "test-kek",
      attestation: "g1.test.sig", expiresAt: o.expiresAt ?? null, ...(o.verified ? { verifiedById: o.createdById, verifiedAt: now } : {}) } }),
  ]);
  return { id, publicKey, privateKey: pair.privateKey };
}
