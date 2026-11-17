-- AlterTable
ALTER TABLE "Record" ADD COLUMN     "createdByAgentId" UUID;

-- CreateTable
CREATE TABLE "AgentDeposit" (
    "id" UUID NOT NULL,
    "ownerUserId" UUID NOT NULL,
    "agentId" UUID NOT NULL,
    "type" TEXT NOT NULL,
    "encBody" TEXT NOT NULL,
    "revision" INTEGER NOT NULL DEFAULT 1,
    "ownerSealedKey" TEXT NOT NULL,
    "agentSealedKey" TEXT NOT NULL,
    "signature" TEXT NOT NULL,
    "connectedApp" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "AgentDeposit_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "AgentDeposit_ownerUserId_idx" ON "AgentDeposit"("ownerUserId");

-- CreateIndex
CREATE INDEX "AgentDeposit_agentId_idx" ON "AgentDeposit"("agentId");

-- AddForeignKey
ALTER TABLE "AgentDeposit" ADD CONSTRAINT "AgentDeposit_ownerUserId_fkey" FOREIGN KEY ("ownerUserId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AgentDeposit" ADD CONSTRAINT "AgentDeposit_agentId_fkey" FOREIGN KEY ("agentId") REFERENCES "Agent"("userId") ON DELETE CASCADE ON UPDATE CASCADE;

-- As Record.type (migration 20261020000000_record_item_type).
ALTER TABLE "AgentDeposit" ADD CONSTRAINT "AgentDeposit_type_check" CHECK ("type" IN ('login', 'item'));
