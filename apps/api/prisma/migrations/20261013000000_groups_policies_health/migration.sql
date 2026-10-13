-- AlterTable
ALTER TABLE "FolderMember" ADD COLUMN     "directPermission" "Permission";

-- Every membership so far was granted directly (groups are new).
UPDATE "FolderMember" SET "directPermission" = "permission";

-- AlterTable
ALTER TABLE "Organization" ADD COLUMN     "policies" JSONB NOT NULL DEFAULT '{}',
ADD COLUMN     "policiesChangedAt" TIMESTAMP(3),
ADD COLUMN     "policiesChangedBy" UUID;

-- CreateTable
CREATE TABLE "Group" (
    "id" UUID NOT NULL,
    "orgId" UUID NOT NULL,
    "name" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Group_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "GroupMember" (
    "id" UUID NOT NULL,
    "groupId" UUID NOT NULL,
    "userId" UUID NOT NULL,
    "addedBy" UUID,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "GroupMember_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "FolderGroup" (
    "id" UUID NOT NULL,
    "folderId" UUID NOT NULL,
    "groupId" UUID NOT NULL,
    "permission" "Permission" NOT NULL,
    "createdBy" UUID NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "FolderGroup_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "HealthReport" (
    "id" UUID NOT NULL,
    "orgId" UUID NOT NULL,
    "userId" UUID NOT NULL,
    "score" INTEGER NOT NULL,
    "total" INTEGER NOT NULL,
    "weak" INTEGER NOT NULL,
    "reused" INTEGER NOT NULL,
    "old" INTEGER NOT NULL,
    "breached" INTEGER,
    "reportedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "HealthReport_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "Group_orgId_name_key" ON "Group"("orgId", "name");

-- CreateIndex
CREATE INDEX "GroupMember_userId_idx" ON "GroupMember"("userId");

-- CreateIndex
CREATE UNIQUE INDEX "GroupMember_groupId_userId_key" ON "GroupMember"("groupId", "userId");

-- CreateIndex
CREATE INDEX "FolderGroup_groupId_idx" ON "FolderGroup"("groupId");

-- CreateIndex
CREATE UNIQUE INDEX "FolderGroup_folderId_groupId_key" ON "FolderGroup"("folderId", "groupId");

-- CreateIndex
CREATE UNIQUE INDEX "HealthReport_orgId_userId_key" ON "HealthReport"("orgId", "userId");

-- AddForeignKey
ALTER TABLE "Group" ADD CONSTRAINT "Group_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "GroupMember" ADD CONSTRAINT "GroupMember_groupId_fkey" FOREIGN KEY ("groupId") REFERENCES "Group"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "GroupMember" ADD CONSTRAINT "GroupMember_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "FolderGroup" ADD CONSTRAINT "FolderGroup_folderId_fkey" FOREIGN KEY ("folderId") REFERENCES "Folder"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "FolderGroup" ADD CONSTRAINT "FolderGroup_groupId_fkey" FOREIGN KEY ("groupId") REFERENCES "Group"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "HealthReport" ADD CONSTRAINT "HealthReport_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "HealthReport" ADD CONSTRAINT "HealthReport_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- CreateIndex
CREATE INDEX "Event_orgId_at_idx" ON "Event"("orgId", "at");
