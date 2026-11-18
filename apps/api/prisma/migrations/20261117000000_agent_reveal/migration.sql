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

-- CreateIndex
CREATE INDEX "AgentRevealGrant_agentId_idx" ON "AgentRevealGrant"("agentId");

-- CreateIndex
CREATE UNIQUE INDEX "AgentRevealGrant_recordId_agentId_key" ON "AgentRevealGrant"("recordId", "agentId");

-- AddForeignKey
ALTER TABLE "AgentRevealGrant" ADD CONSTRAINT "AgentRevealGrant_recordId_fkey" FOREIGN KEY ("recordId") REFERENCES "Record"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AgentRevealGrant" ADD CONSTRAINT "AgentRevealGrant_agentId_fkey" FOREIGN KEY ("agentId") REFERENCES "Agent"("userId") ON DELETE CASCADE ON UPDATE CASCADE;

