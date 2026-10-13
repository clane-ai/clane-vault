-- CreateEnum
CREATE TYPE "RecoveryRequestStatus" AS ENUM ('pending', 'approved', 'used', 'denied', 'expired');

-- AlterTable
ALTER TABLE "Event" ADD COLUMN     "meta" JSONB;

-- AlterTable
ALTER TABLE "User" ADD COLUMN     "recoveryAuthHash" TEXT,
ADD COLUMN     "recoveryCreatedAt" TIMESTAMP(3),
ADD COLUMN     "recoveryWrap" TEXT;

-- CreateTable
CREATE TABLE "OrgSettings" (
    "id" INTEGER NOT NULL DEFAULT 1,
    "adminRecoveryEnabled" BOOLEAN NOT NULL DEFAULT false,
    "adminRecoveryChangedBy" UUID,
    "adminRecoveryChangedAt" TIMESTAMP(3),

    CONSTRAINT "OrgSettings_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AdminRecoveryEscrow" (
    "id" UUID NOT NULL,
    "userId" UUID NOT NULL,
    "adminId" UUID NOT NULL,
    "sealedUserKey" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AdminRecoveryEscrow_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RecoveryRequest" (
    "id" UUID NOT NULL,
    "userId" UUID NOT NULL,
    "status" "RecoveryRequestStatus" NOT NULL DEFAULT 'pending',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "approvedBy" UUID,
    "approvedAt" TIMESTAMP(3),
    "expiresAt" TIMESTAMP(3),
    "usedAt" TIMESTAMP(3),
    "wrappedUserKey" TEXT,
    "proofHash" TEXT,
    "attempts" INTEGER NOT NULL DEFAULT 0,

    CONSTRAINT "RecoveryRequest_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "AdminRecoveryEscrow_adminId_idx" ON "AdminRecoveryEscrow"("adminId");

-- CreateIndex
CREATE UNIQUE INDEX "AdminRecoveryEscrow_userId_adminId_key" ON "AdminRecoveryEscrow"("userId", "adminId");

-- CreateIndex
CREATE INDEX "RecoveryRequest_userId_idx" ON "RecoveryRequest"("userId");

-- CreateIndex
CREATE INDEX "RecoveryRequest_status_idx" ON "RecoveryRequest"("status");

-- AddForeignKey
ALTER TABLE "AdminRecoveryEscrow" ADD CONSTRAINT "AdminRecoveryEscrow_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AdminRecoveryEscrow" ADD CONSTRAINT "AdminRecoveryEscrow_adminId_fkey" FOREIGN KEY ("adminId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "RecoveryRequest" ADD CONSTRAINT "RecoveryRequest_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;


-- Single-tenant settings: exactly one row.
ALTER TABLE "OrgSettings" ADD CONSTRAINT "OrgSettings_single_row" CHECK ("id" = 1);
