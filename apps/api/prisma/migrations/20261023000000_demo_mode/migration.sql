-- Demo mode (docs/demo.md): throwaway sandbox accounts and organisations, deleted with everything they hold at this time.
-- Null on every real account and organisation.
ALTER TABLE "User" ADD COLUMN "demoExpiresAt" TIMESTAMP(3);
ALTER TABLE "Organization" ADD COLUMN "demoExpiresAt" TIMESTAMP(3);

-- CreateIndex
CREATE INDEX "User_demoExpiresAt_idx" ON "User"("demoExpiresAt");

-- CreateIndex
CREATE INDEX "Organization_demoExpiresAt_idx" ON "Organization"("demoExpiresAt");
