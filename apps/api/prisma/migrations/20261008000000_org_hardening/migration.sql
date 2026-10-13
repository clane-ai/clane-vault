-- Multi-org hardening (security review of 0.6.0): instance admins bound to accounts, emailed sign-up codes
-- (HOSTED_MODE), invite cooldowns, and an owner for a default organisation that has none.

-- AlterTable
ALTER TABLE "Invite" ADD COLUMN     "emailCodeAttempts" INTEGER NOT NULL DEFAULT 0,
ADD COLUMN     "emailCodeExpiresAt" TIMESTAMP(3),
ADD COLUMN     "emailCodeHash" TEXT,
ADD COLUMN     "instanceAdmin" BOOLEAN NOT NULL DEFAULT false;

-- AlterTable
ALTER TABLE "User" ADD COLUMN     "instanceAdmin" BOOLEAN NOT NULL DEFAULT false;

-- CreateTable
CREATE TABLE "InviteCooldown" (
    "id" UUID NOT NULL,
    "orgId" UUID NOT NULL,
    "email" TEXT NOT NULL,
    "until" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "InviteCooldown_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "InviteCooldown_orgId_email_key" ON "InviteCooldown"("orgId", "email");

-- CreateIndex
CREATE INDEX "Invite_orgId_email_idx" ON "Invite"("orgId", "email");

-- AddForeignKey
ALTER TABLE "InviteCooldown" ADD CONSTRAINT "InviteCooldown_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- The default organisation (the oldest) without an owner (no active admin at migration time): its longest-standing
-- active member becomes the owner.
UPDATE "Membership" SET "role" = 'owner', "adminSince" = COALESCE("adminSince", CURRENT_TIMESTAMP)
WHERE "id" = (
  SELECT m."id" FROM "Membership" m JOIN "User" u ON u."id" = m."userId"
  WHERE m."orgId" = (SELECT "id" FROM "Organization" ORDER BY "createdAt", "id" LIMIT 1)
    AND m."status" = 'active' AND u."status" = 'active'
    AND NOT EXISTS (SELECT 1 FROM "Membership" o WHERE o."orgId" = m."orgId" AND o."role" = 'owner')
  ORDER BY (m."role" = 'admin') DESC, u."createdAt" ASC, u."id" ASC LIMIT 1
);

-- The default organisation's owner is the instance admin (Backups); nobody else is until the operator says so.
UPDATE "User" SET "instanceAdmin" = true
WHERE "id" IN (
  SELECT m."userId" FROM "Membership" m
  WHERE m."orgId" = (SELECT "id" FROM "Organization" ORDER BY "createdAt", "id" LIMIT 1) AND m."role" = 'owner' AND m."status" = 'active'
);
