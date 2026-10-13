-- AlterTable
ALTER TABLE "Session" ADD COLUMN     "prevRefreshHash" TEXT,
ADD COLUMN     "rotatedAt" TIMESTAMP(3);
