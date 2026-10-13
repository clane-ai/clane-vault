-- AlterEnum
ALTER TYPE "EmailProvider" ADD VALUE 'm365';

-- AlterTable
ALTER TABLE "EmailSettings" ADD COLUMN     "m365ClientId" TEXT,
ADD COLUMN     "m365TenantId" TEXT;
