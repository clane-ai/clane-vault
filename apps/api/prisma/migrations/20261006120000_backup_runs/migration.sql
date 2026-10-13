-- CreateEnum
CREATE TYPE "BackupStatus" AS ENUM ('running', 'success', 'failed');

-- CreateEnum
CREATE TYPE "BackupTrigger" AS ENUM ('schedule', 'manual');

-- CreateTable
CREATE TABLE "BackupRun" (
    "id" UUID NOT NULL,
    "startedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "finishedAt" TIMESTAMP(3),
    "status" "BackupStatus" NOT NULL DEFAULT 'running',
    "trigger" "BackupTrigger" NOT NULL,
    "bytes" BIGINT,
    "destinations" JSONB NOT NULL,
    "objectKey" TEXT,
    "error" TEXT,

    CONSTRAINT "BackupRun_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "BackupRun_startedAt_idx" ON "BackupRun"("startedAt");
