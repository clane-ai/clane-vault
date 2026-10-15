-- Customer organisations (docs/provisioning.md): an instance admin creates an organisation with no members and an owner
-- invitation. The address it went to and who created it; null on every other organisation.
ALTER TABLE "Organization" ADD COLUMN "customerOwnerEmail" TEXT;
ALTER TABLE "Organization" ADD COLUMN "customerCreatedById" UUID;

-- CreateIndex
CREATE INDEX "Organization_customerOwnerEmail_idx" ON "Organization"("customerOwnerEmail");
