-- CreateEnum
CREATE TYPE "OrgPlan" AS ENUM ('team', 'business');

-- CreateEnum
CREATE TYPE "BillingStatus" AS ENUM ('free', 'active', 'past_due', 'canceled');

-- AlterTable
ALTER TABLE "Organization" ADD COLUMN     "billingStatus" "BillingStatus" NOT NULL DEFAULT 'free',
ADD COLUMN     "currentPeriodEnd" TIMESTAMPTZ,
ADD COLUMN     "plan" "OrgPlan" NOT NULL DEFAULT 'team',
ADD COLUMN     "seatsPaid" INTEGER,
ADD COLUMN     "stripeCustomerId" TEXT,
ADD COLUMN     "stripeSubscriptionId" TEXT,
ADD COLUMN     "trialEndsAt" TIMESTAMPTZ;

-- CreateIndex
CREATE UNIQUE INDEX "Organization_stripeCustomerId_key" ON "Organization"("stripeCustomerId");

-- CreateIndex
CREATE UNIQUE INDEX "Organization_stripeSubscriptionId_key" ON "Organization"("stripeSubscriptionId");
