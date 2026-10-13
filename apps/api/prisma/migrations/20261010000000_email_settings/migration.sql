-- CreateEnum
CREATE TYPE "EmailProvider" AS ENUM ('resend', 'smtp');

-- CreateEnum
CREATE TYPE "SmtpSecurity" AS ENUM ('none', 'starttls', 'tls');

-- CreateTable
CREATE TABLE "EmailSettings" (
    "id" UUID NOT NULL,
    "scope" TEXT NOT NULL,
    "orgId" UUID,
    "provider" "EmailProvider" NOT NULL,
    "fromName" TEXT,
    "fromAddress" TEXT NOT NULL,
    "smtpHost" TEXT,
    "smtpPort" INTEGER,
    "smtpSecurity" "SmtpSecurity",
    "smtpUsername" TEXT,
    "secretEnc" TEXT,
    "secretLast4" TEXT,
    "updatedById" UUID,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "EmailSettings_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "EmailSettings_scope_key" ON "EmailSettings"("scope");

-- CreateIndex
CREATE UNIQUE INDEX "EmailSettings_orgId_key" ON "EmailSettings"("orgId");

-- AddForeignKey
ALTER TABLE "EmailSettings" ADD CONSTRAINT "EmailSettings_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

