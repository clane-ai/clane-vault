-- CreateEnum
CREATE TYPE "AgentRevealStatus" AS ENUM ('pending', 'approved', 'denied', 'expired', 'delivered');

-- AlterTable
ALTER TABLE "User" ADD COLUMN     "agentRevealEmail" BOOLEAN NOT NULL DEFAULT true,
ADD COLUMN     "agentRevealEmailedAt" TIMESTAMP(3);

-- AlterTable
ALTER TABLE "Agent" ADD COLUMN     "revealPausedUntil" TIMESTAMP(3);

-- CreateTable
CREATE TABLE "AgentRevealGrant" (
    "id" UUID NOT NULL,
    "recordId" UUID NOT NULL,
    "agentId" UUID NOT NULL,
    "sealedStub" TEXT NOT NULL,
    "fields" TEXT[],
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AgentRevealGrant_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AgentRevealRequest" (
    "id" UUID NOT NULL,
    "agentId" UUID NOT NULL,
    "ownerUserId" UUID NOT NULL,
    "recordId" UUID NOT NULL,
    "fields" TEXT[],
    "reason" TEXT NOT NULL,
    "requestPublicKey" TEXT NOT NULL,
    "signature" TEXT NOT NULL,
    "connectedApp" TEXT NOT NULL,
    "status" "AgentRevealStatus" NOT NULL DEFAULT 'pending',
    "sealed" TEXT,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AgentRevealRequest_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "AgentRevealGrant_agentId_idx" ON "AgentRevealGrant"("agentId");

-- CreateIndex
CREATE UNIQUE INDEX "AgentRevealGrant_recordId_agentId_key" ON "AgentRevealGrant"("recordId", "agentId");

-- CreateIndex
CREATE INDEX "AgentRevealRequest_ownerUserId_status_idx" ON "AgentRevealRequest"("ownerUserId", "status");

-- CreateIndex
CREATE INDEX "AgentRevealRequest_agentId_status_idx" ON "AgentRevealRequest"("agentId", "status");

-- AddForeignKey
ALTER TABLE "AgentRevealGrant" ADD CONSTRAINT "AgentRevealGrant_recordId_fkey" FOREIGN KEY ("recordId") REFERENCES "Record"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AgentRevealGrant" ADD CONSTRAINT "AgentRevealGrant_agentId_fkey" FOREIGN KEY ("agentId") REFERENCES "Agent"("userId") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AgentRevealRequest" ADD CONSTRAINT "AgentRevealRequest_agentId_fkey" FOREIGN KEY ("agentId") REFERENCES "Agent"("userId") ON DELETE CASCADE ON UPDATE CASCADE;

