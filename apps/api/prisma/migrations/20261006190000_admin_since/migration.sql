-- AlterTable
ALTER TABLE "User" ADD COLUMN     "adminSince" TIMESTAMP(3);

-- Existing admins: admin since their account was created.
UPDATE "User" SET "adminSince" = "createdAt" WHERE "role" = 'admin' AND "adminSince" IS NULL;
