-- AlterTable
ALTER TABLE "Session" ADD COLUMN     "ssoOrgIds" UUID[] DEFAULT ARRAY[]::UUID[];

-- CreateTable
CREATE TABLE "OrgSso" (
    "id" UUID NOT NULL,
    "orgId" UUID NOT NULL,
    "issuer" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "clientSecretEnc" TEXT,
    "clientSecretLast4" TEXT,
    "requireSso" BOOLEAN NOT NULL DEFAULT false,
    "trustIdpMfa" BOOLEAN NOT NULL DEFAULT false,
    "autoJoin" BOOLEAN NOT NULL DEFAULT false,
    "updatedById" UUID,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "OrgSso_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SsoDomain" (
    "id" UUID NOT NULL,
    "orgId" UUID NOT NULL,
    "domain" TEXT NOT NULL,
    "token" TEXT NOT NULL,
    "verifiedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "SsoDomain_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SsoIdentity" (
    "id" UUID NOT NULL,
    "orgId" UUID NOT NULL,
    "userId" UUID NOT NULL,
    "issuer" TEXT NOT NULL,
    "subject" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastLoginAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "SsoIdentity_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SsoLogin" (
    "id" UUID NOT NULL,
    "stateHash" TEXT NOT NULL,
    "bindingHash" TEXT NOT NULL,
    "orgId" UUID NOT NULL,
    "nonce" TEXT NOT NULL,
    "codeVerifier" TEXT NOT NULL,
    "returnTo" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "usedAt" TIMESTAMP(3),

    CONSTRAINT "SsoLogin_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SsoProof" (
    "id" UUID NOT NULL,
    "tokenHash" TEXT NOT NULL,
    "bindingHash" TEXT NOT NULL,
    "orgId" UUID NOT NULL,
    "mode" TEXT NOT NULL,
    "userId" UUID,
    "email" TEXT NOT NULL,
    "issuer" TEXT NOT NULL,
    "subject" TEXT NOT NULL,
    "nameHint" TEXT,
    "jit" BOOLEAN NOT NULL DEFAULT false,
    "inviteId" UUID,
    "returnTo" TEXT NOT NULL,
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "usedAt" TIMESTAMP(3),

    CONSTRAINT "SsoProof_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "OrgSso_orgId_key" ON "OrgSso"("orgId");

-- CreateIndex
CREATE INDEX "SsoDomain_domain_idx" ON "SsoDomain"("domain");

-- CreateIndex
CREATE UNIQUE INDEX "SsoDomain_orgId_domain_key" ON "SsoDomain"("orgId", "domain");

-- CreateIndex
CREATE UNIQUE INDEX "SsoIdentity_orgId_issuer_subject_key" ON "SsoIdentity"("orgId", "issuer", "subject");

-- CreateIndex
CREATE UNIQUE INDEX "SsoIdentity_orgId_userId_key" ON "SsoIdentity"("orgId", "userId");

-- CreateIndex
CREATE UNIQUE INDEX "SsoLogin_stateHash_key" ON "SsoLogin"("stateHash");

-- CreateIndex
CREATE INDEX "SsoLogin_expiresAt_idx" ON "SsoLogin"("expiresAt");

-- CreateIndex
CREATE UNIQUE INDEX "SsoProof_tokenHash_key" ON "SsoProof"("tokenHash");

-- CreateIndex
CREATE INDEX "SsoProof_expiresAt_idx" ON "SsoProof"("expiresAt");

-- AddForeignKey
ALTER TABLE "OrgSso" ADD CONSTRAINT "OrgSso_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SsoDomain" ADD CONSTRAINT "SsoDomain_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SsoIdentity" ADD CONSTRAINT "SsoIdentity_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SsoIdentity" ADD CONSTRAINT "SsoIdentity_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SsoLogin" ADD CONSTRAINT "SsoLogin_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SsoProof" ADD CONSTRAINT "SsoProof_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

