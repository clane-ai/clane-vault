-- Multiple organisations (docs/design/2026-10-07-multi-org-design.md).
-- Existing single-tenant data moves into one default organisation; nothing is deleted except columns and the
-- OrgSettings row whose values are copied first.

-- CreateEnum
CREATE TYPE "OrgRole" AS ENUM ('owner', 'admin', 'member');
CREATE TYPE "MembershipStatus" AS ENUM ('invited', 'active', 'disabled');

-- CreateTable
CREATE TABLE "Organization" (
    "id" UUID NOT NULL,
    "name" TEXT NOT NULL,
    "slug" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "adminRecoveryEnabled" BOOLEAN NOT NULL DEFAULT false,
    "adminRecoveryChangedBy" UUID,
    "adminRecoveryChangedAt" TIMESTAMP(3),

    CONSTRAINT "Organization_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "Organization_slug_key" ON "Organization"("slug");

CREATE TABLE "Membership" (
    "id" UUID NOT NULL,
    "orgId" UUID NOT NULL,
    "userId" UUID NOT NULL,
    "role" "OrgRole" NOT NULL DEFAULT 'member',
    "status" "MembershipStatus" NOT NULL DEFAULT 'active',
    "adminSince" TIMESTAMP(3),
    "adminRecoveryAckAt" TIMESTAMP(3),
    "invitedById" UUID,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "joinedAt" TIMESTAMP(3),

    CONSTRAINT "Membership_pkey" PRIMARY KEY ("id")
);
CREATE INDEX "Membership_userId_idx" ON "Membership"("userId");
CREATE UNIQUE INDEX "Membership_orgId_userId_key" ON "Membership"("orgId", "userId");

-- The default organisation. An empty name means "not named yet": the API names it on start
-- (DEFAULT_ORG_NAME, or "<PRODUCT_NAME> org"). The admin-recovery policy comes from OrgSettings.
INSERT INTO "Organization" ("id", "name", "slug", "createdAt", "adminRecoveryEnabled", "adminRecoveryChangedBy", "adminRecoveryChangedAt")
SELECT gen_random_uuid(), '', 'default', COALESCE((SELECT MIN("createdAt") FROM "User"), CURRENT_TIMESTAMP),
       COALESCE(s."adminRecoveryEnabled", false), s."adminRecoveryChangedBy", s."adminRecoveryChangedAt"
FROM (SELECT 1) AS one LEFT JOIN "OrgSettings" s ON s."id" = 1;

-- Every existing user joins it with their role, admin age and recovery acknowledgement. Disabled users get a disabled
-- membership (and stay disabled globally, as before).
INSERT INTO "Membership" ("id", "orgId", "userId", "role", "status", "adminSince", "adminRecoveryAckAt", "createdAt", "joinedAt")
SELECT gen_random_uuid(), o."id", u."id",
       (CASE WHEN u."role" = 'admin' THEN 'admin' ELSE 'member' END)::"OrgRole",
       (CASE WHEN u."status" = 'disabled' THEN 'disabled' ELSE 'active' END)::"MembershipStatus",
       u."adminSince", u."adminRecoveryAckAt", u."createdAt", u."createdAt"
FROM "User" u CROSS JOIN "Organization" o;

-- The longest-standing active admin becomes the owner.
UPDATE "Membership" SET "role" = 'owner'
WHERE "id" = (
  SELECT m."id" FROM "Membership" m JOIN "User" u ON u."id" = m."userId"
  WHERE m."role" = 'admin' AND m."status" = 'active' AND u."status" = 'active'
  ORDER BY m."adminSince" ASC NULLS LAST, u."createdAt" ASC, u."id" ASC LIMIT 1
);

-- Invites: role becomes an OrgRole, and they belong to the default organisation.
ALTER TABLE "Invite" ADD COLUMN "orgId" UUID;
UPDATE "Invite" SET "orgId" = (SELECT "id" FROM "Organization" LIMIT 1);
ALTER TABLE "Invite" ALTER COLUMN "orgId" SET NOT NULL;
ALTER TABLE "Invite" ALTER COLUMN "role" DROP DEFAULT;
ALTER TABLE "Invite" ALTER COLUMN "role" TYPE "OrgRole" USING ("role"::text::"OrgRole");
ALTER TABLE "Invite" ALTER COLUMN "role" SET DEFAULT 'member';

-- Team folders belong to it; private folders to their owner only.
ALTER TABLE "Folder" ADD COLUMN "orgId" UUID;
UPDATE "Folder" SET "orgId" = (SELECT "id" FROM "Organization" LIMIT 1) WHERE "kind" = 'team';
CREATE INDEX "Folder_orgId_idx" ON "Folder"("orgId");

-- Direct shares (non-owner user rows) were made in it.
ALTER TABLE "RecordAccess" ADD COLUMN "orgId" UUID;
UPDATE "RecordAccess" SET "orgId" = (SELECT "id" FROM "Organization" LIMIT 1) WHERE "holderType" = 'user' AND "permission" <> 'owner';

-- Links on team-folder records, and links made through a direct share, belong to it. Links on the creator's own
-- private records stay personal.
ALTER TABLE "ShareLink" ADD COLUMN "orgId" UUID;
UPDATE "ShareLink" l SET "orgId" = (SELECT "id" FROM "Organization" LIMIT 1)
WHERE EXISTS (SELECT 1 FROM "Record" r JOIN "Folder" f ON f."id" = r."folderId" WHERE r."id" = l."recordId" AND f."kind" = 'team')
   OR EXISTS (SELECT 1 FROM "RecordAccess" a WHERE a."recordId" = l."recordId" AND a."holderType" = 'user' AND a."holderId" = l."createdBy" AND a."permission" <> 'owner');

-- Events, escrows and recovery requests.
ALTER TABLE "Event" ADD COLUMN "orgId" UUID;
UPDATE "Event" SET "orgId" = (SELECT "id" FROM "Organization" LIMIT 1);
CREATE INDEX "Event_orgId_idx" ON "Event"("orgId");

DROP INDEX "AdminRecoveryEscrow_userId_adminId_key";
ALTER TABLE "AdminRecoveryEscrow" ADD COLUMN "orgId" UUID;
UPDATE "AdminRecoveryEscrow" SET "orgId" = (SELECT "id" FROM "Organization" LIMIT 1);
ALTER TABLE "AdminRecoveryEscrow" ALTER COLUMN "orgId" SET NOT NULL;
CREATE INDEX "AdminRecoveryEscrow_userId_idx" ON "AdminRecoveryEscrow"("userId");
CREATE UNIQUE INDEX "AdminRecoveryEscrow_orgId_userId_adminId_key" ON "AdminRecoveryEscrow"("orgId", "userId", "adminId");

ALTER TABLE "RecoveryRequest" ADD COLUMN "orgId" UUID;
UPDATE "RecoveryRequest" SET "orgId" = (SELECT "id" FROM "Organization" LIMIT 1);
ALTER TABLE "RecoveryRequest" ALTER COLUMN "orgId" SET NOT NULL;

-- Copied above: the global role, admin age, acknowledgement and the settings row.
ALTER TABLE "User" DROP COLUMN "adminRecoveryAckAt", DROP COLUMN "adminSince", DROP COLUMN "role";
DROP TABLE "OrgSettings";
DROP TYPE "Role";

-- AddForeignKey
ALTER TABLE "Membership" ADD CONSTRAINT "Membership_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "Membership" ADD CONSTRAINT "Membership_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "Invite" ADD CONSTRAINT "Invite_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "Folder" ADD CONSTRAINT "Folder_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "Organization"("id") ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE "RecordAccess" ADD CONSTRAINT "RecordAccess_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "Event" ADD CONSTRAINT "Event_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "Organization"("id") ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE "ShareLink" ADD CONSTRAINT "ShareLink_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "Organization"("id") ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE "AdminRecoveryEscrow" ADD CONSTRAINT "AdminRecoveryEscrow_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "RecoveryRequest" ADD CONSTRAINT "RecoveryRequest_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;
