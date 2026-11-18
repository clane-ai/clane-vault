-- AlterTable
ALTER TABLE "Agent" ALTER COLUMN "orgId" DROP NOT NULL,
ADD COLUMN     "ownerUserId" UUID;

-- CreateIndex
CREATE INDEX "Agent_ownerUserId_idx" ON "Agent"("ownerUserId");

-- AddForeignKey
ALTER TABLE "Agent" ADD CONSTRAINT "Agent_ownerUserId_fkey" FOREIGN KEY ("ownerUserId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- An agent belongs to an organisation or to a person, never both, never neither.
ALTER TABLE "Agent" ADD CONSTRAINT "Agent_one_owner_check" CHECK (("orgId" IS NULL) <> ("ownerUserId" IS NULL));
