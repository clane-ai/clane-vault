-- CreateEnum
CREATE TYPE "UserKind" AS ENUM ('person', 'agent');

-- AlterTable
ALTER TABLE "User" ADD COLUMN     "kind" "UserKind" NOT NULL DEFAULT 'person';

-- CreateTable
CREATE TABLE "Agent" (
    "userId" UUID NOT NULL,
    "orgId" UUID NOT NULL,
    "createdById" UUID NOT NULL,
    "publicKey" TEXT NOT NULL,
    "wrappedPrivateKey" TEXT,
    "kekId" TEXT NOT NULL,
    "attestation" TEXT NOT NULL,
    "verifiedById" UUID,
    "verifiedAt" TIMESTAMP(3),
    "expiresAt" TIMESTAMPTZ,
    "revokedAt" TIMESTAMP(3),
    "revokedById" UUID,
    "lastUsedAt" TIMESTAMP(3),
    "lastSyncLoggedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Agent_pkey" PRIMARY KEY ("userId")
);

-- CreateTable
CREATE TABLE "AgentToken" (
    "id" UUID NOT NULL,
    "agentId" UUID NOT NULL,
    "label" TEXT NOT NULL,
    "tokenHash" TEXT NOT NULL,
    "createdById" UUID NOT NULL,
    "expiresAt" TIMESTAMPTZ,
    "lastUsedAt" TIMESTAMP(3),
    "revokedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AgentToken_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AgentOAuthClient" (
    "id" UUID NOT NULL,
    "name" TEXT NOT NULL,
    "redirectUris" TEXT[],
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AgentOAuthClient_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AgentOAuthCode" (
    "codeHash" TEXT NOT NULL,
    "clientId" UUID NOT NULL,
    "agentId" UUID NOT NULL,
    "grantedById" UUID NOT NULL,
    "codeChallenge" TEXT NOT NULL,
    "redirectUri" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "usedAt" TIMESTAMP(3),

    CONSTRAINT "AgentOAuthCode_pkey" PRIMARY KEY ("codeHash")
);

-- CreateTable
CREATE TABLE "AgentGrant" (
    "id" UUID NOT NULL,
    "agentId" UUID NOT NULL,
    "clientId" UUID NOT NULL,
    "grantedById" UUID NOT NULL,
    "refreshHash" TEXT NOT NULL,
    "prevRefreshHash" TEXT,
    "rotatedAt" TIMESTAMP(3),
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "revokedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AgentGrant_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "GatewayIdentity" (
    "id" TEXT NOT NULL DEFAULT 'gateway',
    "keyId" TEXT NOT NULL,
    "publicKey" TEXT NOT NULL,
    "firstSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "GatewayIdentity_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "Agent_publicKey_key" ON "Agent"("publicKey");

-- CreateIndex
CREATE INDEX "Agent_orgId_idx" ON "Agent"("orgId");

-- CreateIndex
CREATE UNIQUE INDEX "AgentToken_tokenHash_key" ON "AgentToken"("tokenHash");

-- CreateIndex
CREATE INDEX "AgentOAuthCode_expiresAt_idx" ON "AgentOAuthCode"("expiresAt");

-- CreateIndex
CREATE UNIQUE INDEX "AgentGrant_refreshHash_key" ON "AgentGrant"("refreshHash");

-- CreateIndex
CREATE INDEX "AgentGrant_agentId_idx" ON "AgentGrant"("agentId");

-- CreateIndex
CREATE INDEX "User_kind_idx" ON "User"("kind");

-- AddForeignKey
ALTER TABLE "Agent" ADD CONSTRAINT "Agent_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Agent" ADD CONSTRAINT "Agent_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AgentToken" ADD CONSTRAINT "AgentToken_agentId_fkey" FOREIGN KEY ("agentId") REFERENCES "Agent"("userId") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AgentGrant" ADD CONSTRAINT "AgentGrant_agentId_fkey" FOREIGN KEY ("agentId") REFERENCES "Agent"("userId") ON DELETE CASCADE ON UPDATE CASCADE;

