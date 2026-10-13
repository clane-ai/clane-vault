-- CreateTable
CREATE TABLE "OrgLogo" (
    "orgId" UUID NOT NULL,
    "mime" TEXT NOT NULL,
    "data" BYTEA NOT NULL,
    "width" INTEGER NOT NULL,
    "height" INTEGER NOT NULL,
    "sha256" TEXT NOT NULL,
    "updatedById" UUID,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "OrgLogo_pkey" PRIMARY KEY ("orgId")
);

-- CreateTable
CREATE TABLE "InstanceBrand" (
    "id" TEXT NOT NULL DEFAULT 'instance',
    "productName" TEXT,
    "shortName" TEXT,
    "logoMime" TEXT,
    "logoData" BYTEA,
    "logoWidth" INTEGER,
    "logoHeight" INTEGER,
    "logoSha256" TEXT,
    "updatedById" UUID,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "InstanceBrand_pkey" PRIMARY KEY ("id")
);

-- AddForeignKey
ALTER TABLE "OrgLogo" ADD CONSTRAINT "OrgLogo_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;
