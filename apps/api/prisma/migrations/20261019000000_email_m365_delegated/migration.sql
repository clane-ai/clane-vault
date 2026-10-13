-- CreateEnum
CREATE TYPE "M365AuthMode" AS ENUM ('app', 'delegated');

-- AlterTable
ALTER TABLE "EmailSettings" ADD COLUMN     "m365Account" TEXT,
ADD COLUMN     "m365AuthMode" "M365AuthMode",
ADD COLUMN     "m365ConnectedAt" TIMESTAMP(3),
ADD COLUMN     "m365ConnectedById" UUID,
ADD COLUMN     "m365GrantedScope" TEXT,
ADD COLUMN     "m365ReconnectAt" TIMESTAMP(3),
ADD COLUMN     "m365ReconnectReason" TEXT,
ADD COLUMN     "m365RefreshEnc" TEXT,
ADD COLUMN     "m365RefreshVersion" INTEGER NOT NULL DEFAULT 0;

-- CreateTable
CREATE TABLE "M365Connect" (
    "id" UUID NOT NULL,
    "stateHash" TEXT NOT NULL,
    "bindingHash" TEXT NOT NULL,
    "scope" TEXT NOT NULL,
    "orgId" UUID,
    "settingsId" UUID NOT NULL,
    "settingsFp" TEXT NOT NULL,
    "actorId" UUID NOT NULL,
    "sessionId" UUID NOT NULL,
    "nonce" TEXT NOT NULL,
    "codeVerifier" TEXT NOT NULL,
    "requestedScope" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "usedAt" TIMESTAMP(3),

    CONSTRAINT "M365Connect_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "M365Connect_stateHash_key" ON "M365Connect"("stateHash");

-- CreateIndex
CREATE INDEX "M365Connect_expiresAt_idx" ON "M365Connect"("expiresAt");

-- AddForeignKey
ALTER TABLE "M365Connect" ADD CONSTRAINT "M365Connect_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

