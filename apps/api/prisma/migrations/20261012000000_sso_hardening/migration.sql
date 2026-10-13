-- AlterTable
ALTER TABLE "Session" ADD COLUMN     "totpSkippedForOrg" UUID;

-- AlterTable
ALTER TABLE "SsoDomain" ADD COLUMN     "checkedAt" TIMESTAMP(3);

-- AlterTable
ALTER TABLE "SsoProof" ADD COLUMN     "idpMfa" BOOLEAN NOT NULL DEFAULT true;

