-- AlterTable
ALTER TABLE "User" ADD COLUMN     "adminRecoveryAckAt" TIMESTAMP(3),
ADD COLUMN     "totpEnabledAt" TIMESTAMP(3),
ADD COLUMN     "totpLastStep" INTEGER,
ADD COLUMN     "totpResetAt" TIMESTAMP(3),
ADD COLUMN     "totpResetBy" UUID;

