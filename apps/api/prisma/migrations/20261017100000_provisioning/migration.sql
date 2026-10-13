-- AlterTable
ALTER TABLE "Invite" ADD COLUMN     "lastSentAt" TIMESTAMP(3),
ADD COLUMN     "nameHint" TEXT,
ADD COLUMN     "resendCount" INTEGER NOT NULL DEFAULT 0,
ADD COLUMN     "source" TEXT NOT NULL DEFAULT 'admin';

-- AlterTable
ALTER TABLE "Organization" ADD COLUMN     "onboardingDismissedAt" TIMESTAMP(3);

-- CreateTable
CREATE TABLE "PendingGroupMember" (
    "id" UUID NOT NULL,
    "orgId" UUID NOT NULL,
    "groupId" UUID NOT NULL,
    "email" TEXT NOT NULL,
    "addedBy" UUID,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "PendingGroupMember_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "OrgDomainJoin" (
    "orgId" UUID NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT false,
    "role" "OrgRole" NOT NULL DEFAULT 'member',
    "groupIds" UUID[] DEFAULT ARRAY[]::UUID[],
    "updatedById" UUID,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "OrgDomainJoin_pkey" PRIMARY KEY ("orgId")
);

-- CreateIndex
CREATE INDEX "PendingGroupMember_orgId_email_idx" ON "PendingGroupMember"("orgId", "email");

-- CreateIndex
CREATE UNIQUE INDEX "PendingGroupMember_groupId_email_key" ON "PendingGroupMember"("groupId", "email");

-- AddForeignKey
ALTER TABLE "PendingGroupMember" ADD CONSTRAINT "PendingGroupMember_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PendingGroupMember" ADD CONSTRAINT "PendingGroupMember_groupId_fkey" FOREIGN KEY ("groupId") REFERENCES "Group"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "OrgDomainJoin" ADD CONSTRAINT "OrgDomainJoin_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

