-- Per-organisation membership key pairs (docs/design/2026-10-08-per-org-keypairs.md).
-- Admin recovery becomes scoped to one organisation: the whole-account escrows (of the user key) are deleted and
-- open account-scope requests end (their wrapped user keys are burned). Members escrow their membership keys again
-- on their next unlock.
UPDATE "RecoveryRequest" SET "status" = 'expired', "wrappedUserKey" = NULL, "proofHash" = NULL
  WHERE "status" IN ('pending', 'approved');

-- CreateEnum
CREATE TYPE "MembershipKeyState" AS ENUM ('current', 'retiring', 'archived');

-- DropForeignKey
ALTER TABLE "AdminRecoveryEscrow" DROP CONSTRAINT "AdminRecoveryEscrow_adminId_fkey";

-- DropForeignKey
ALTER TABLE "AdminRecoveryEscrow" DROP CONSTRAINT "AdminRecoveryEscrow_orgId_fkey";

-- DropForeignKey
ALTER TABLE "AdminRecoveryEscrow" DROP CONSTRAINT "AdminRecoveryEscrow_userId_fkey";

-- AlterTable
ALTER TABLE "FolderMember" ADD COLUMN     "sealedTo" TEXT;

-- AlterTable
ALTER TABLE "Membership" ADD COLUMN     "keysRepairedGen" INTEGER NOT NULL DEFAULT 1;

-- AlterTable
ALTER TABLE "RecordAccess" ADD COLUMN     "sealedTo" TEXT;

-- AlterTable
ALTER TABLE "RecoveryRequest" DROP COLUMN "wrappedUserKey",
ADD COLUMN     "memberPublicKey" TEXT,
ADD COLUMN     "wrappedMembershipKey" TEXT;

-- AlterTable
ALTER TABLE "User" ADD COLUMN     "userKeyGen" INTEGER NOT NULL DEFAULT 1;

-- DropTable
DROP TABLE "AdminRecoveryEscrow";

-- CreateTable
CREATE TABLE "MembershipKey" (
    "id" UUID NOT NULL,
    "orgId" UUID NOT NULL,
    "userId" UUID NOT NULL,
    "publicKey" TEXT NOT NULL,
    "wrappedPrivateKey" TEXT NOT NULL,
    "userKeyGen" INTEGER NOT NULL,
    "state" "MembershipKeyState" NOT NULL DEFAULT 'current',
    "escrowOpenedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "retiredAt" TIMESTAMP(3),

    CONSTRAINT "MembershipKey_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "MembershipEscrow" (
    "id" UUID NOT NULL,
    "orgId" UUID NOT NULL,
    "userId" UUID NOT NULL,
    "adminId" UUID NOT NULL,
    "memberPublicKey" TEXT NOT NULL,
    "adminPublicKey" TEXT NOT NULL,
    "sealedKey" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "MembershipEscrow_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AccountKeyArchive" (
    "id" UUID NOT NULL,
    "userId" UUID NOT NULL,
    "userKeyGen" INTEGER NOT NULL,
    "kdfSalt" TEXT NOT NULL,
    "kdfParams" JSONB NOT NULL,
    "wrappedUserKey" TEXT NOT NULL,
    "publicKey" TEXT NOT NULL,
    "wrappedPrivateKey" TEXT NOT NULL,
    "recoveryWrap" TEXT,
    "privateItems" INTEGER NOT NULL DEFAULT 0,
    "otherOrgs" INTEGER NOT NULL DEFAULT 0,
    "archivedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "restoredAt" TIMESTAMP(3),

    CONSTRAINT "AccountKeyArchive_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "GroupAccessDecline" (
    "id" UUID NOT NULL,
    "folderId" UUID NOT NULL,
    "userId" UUID NOT NULL,
    "declinedBy" UUID NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "GroupAccessDecline_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "MembershipKey_publicKey_key" ON "MembershipKey"("publicKey");

-- CreateIndex
CREATE INDEX "MembershipKey_orgId_userId_idx" ON "MembershipKey"("orgId", "userId");

-- CreateIndex
CREATE INDEX "MembershipEscrow_adminId_idx" ON "MembershipEscrow"("adminId");

-- CreateIndex
CREATE INDEX "MembershipEscrow_userId_idx" ON "MembershipEscrow"("userId");

-- CreateIndex
CREATE UNIQUE INDEX "MembershipEscrow_orgId_userId_adminId_key" ON "MembershipEscrow"("orgId", "userId", "adminId");

-- CreateIndex
CREATE INDEX "AccountKeyArchive_userId_idx" ON "AccountKeyArchive"("userId");

-- CreateIndex
CREATE UNIQUE INDEX "GroupAccessDecline_folderId_userId_key" ON "GroupAccessDecline"("folderId", "userId");

-- AddForeignKey
ALTER TABLE "MembershipKey" ADD CONSTRAINT "MembershipKey_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "MembershipKey" ADD CONSTRAINT "MembershipKey_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "MembershipEscrow" ADD CONSTRAINT "MembershipEscrow_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "MembershipEscrow" ADD CONSTRAINT "MembershipEscrow_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "MembershipEscrow" ADD CONSTRAINT "MembershipEscrow_adminId_fkey" FOREIGN KEY ("adminId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AccountKeyArchive" ADD CONSTRAINT "AccountKeyArchive_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "GroupAccessDecline" ADD CONSTRAINT "GroupAccessDecline_folderId_fkey" FOREIGN KEY ("folderId") REFERENCES "Folder"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "GroupAccessDecline" ADD CONSTRAINT "GroupAccessDecline_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;


-- One current membership key per organisation and user.
CREATE UNIQUE INDEX "MembershipKey_one_current" ON "MembershipKey"("orgId", "userId") WHERE "state" = 'current';
-- At most one open recovery request per organisation and user.
CREATE UNIQUE INDEX "RecoveryRequest_one_open" ON "RecoveryRequest"("orgId", "userId") WHERE "status" IN ('pending', 'approved');
CREATE INDEX "FolderMember_sealedTo_idx" ON "FolderMember"("sealedTo");
