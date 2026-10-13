-- CreateTable
CREATE TABLE "ShareLink" (
    "id" UUID NOT NULL,
    "recordId" UUID NOT NULL,
    "createdBy" UUID NOT NULL,
    "encPayload" TEXT,
    "passwordSalt" TEXT,
    "accessHash" TEXT,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "maxOpens" INTEGER,
    "opens" INTEGER NOT NULL DEFAULT 0,
    "revokedAt" TIMESTAMP(3),
    "labelEnc" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ShareLink_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "ShareLink_createdBy_idx" ON "ShareLink"("createdBy");

-- CreateIndex
CREATE INDEX "ShareLink_recordId_idx" ON "ShareLink"("recordId");

-- AddForeignKey
ALTER TABLE "ShareLink" ADD CONSTRAINT "ShareLink_recordId_fkey" FOREIGN KEY ("recordId") REFERENCES "Record"("id") ON DELETE CASCADE ON UPDATE CASCADE;

