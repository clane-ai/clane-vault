-- File attachments (docs/design/2026-10-12-attachments.md, docs/attachments.md): end-to-end-encrypted
-- files on records. Chunks are AES-GCM ciphertext; their data column is STORAGE EXTERNAL (no TOAST compression attempt).

-- CreateEnum
CREATE TYPE "AttachmentState" AS ENUM ('uploading', 'ready', 'deleted');

-- CreateEnum
CREATE TYPE "AttachmentStorage" AS ENUM ('db', 's3');

-- AlterTable
ALTER TABLE "BackupRun" ADD COLUMN     "attachmentBytes" BIGINT;

-- CreateTable
CREATE TABLE "Attachment" (
    "id" UUID NOT NULL,
    "recordId" UUID NOT NULL,
    "createdBy" UUID NOT NULL,
    "state" "AttachmentState" NOT NULL DEFAULT 'uploading',
    "storage" "AttachmentStorage" NOT NULL DEFAULT 'db',
    "encMeta" TEXT NOT NULL,
    "wrappedFileKey" TEXT NOT NULL,
    "nonceBase" TEXT NOT NULL,
    "chunkSize" INTEGER NOT NULL,
    "chunkCount" INTEGER NOT NULL,
    "size" INTEGER NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "readyAt" TIMESTAMP(3),
    "deletedAt" TIMESTAMP(3),

    CONSTRAINT "Attachment_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AttachmentChunk" (
    "attachmentId" UUID NOT NULL,
    "index" INTEGER NOT NULL,
    "length" INTEGER NOT NULL,
    "sha256" TEXT NOT NULL,
    "data" BYTEA NOT NULL,

    CONSTRAINT "AttachmentChunk_pkey" PRIMARY KEY ("attachmentId","index")
);

-- CreateTable
CREATE TABLE "ShareLinkAttachment" (
    "linkId" UUID NOT NULL,
    "attachmentId" UUID NOT NULL,

    CONSTRAINT "ShareLinkAttachment_pkey" PRIMARY KEY ("linkId","attachmentId")
);

-- CreateTable
CREATE TABLE "AttachmentTombstone" (
    "attachmentId" UUID NOT NULL,
    "storage" "AttachmentStorage" NOT NULL,
    "chunkCount" INTEGER NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AttachmentTombstone_pkey" PRIMARY KEY ("attachmentId")
);

-- CreateIndex
CREATE INDEX "Attachment_recordId_idx" ON "Attachment"("recordId");

-- CreateIndex
CREATE INDEX "Attachment_state_createdAt_idx" ON "Attachment"("state", "createdAt");

-- CreateIndex
CREATE INDEX "Attachment_createdBy_createdAt_idx" ON "Attachment"("createdBy", "createdAt");

-- CreateIndex
CREATE INDEX "ShareLinkAttachment_attachmentId_idx" ON "ShareLinkAttachment"("attachmentId");

-- AddForeignKey
ALTER TABLE "Attachment" ADD CONSTRAINT "Attachment_recordId_fkey" FOREIGN KEY ("recordId") REFERENCES "Record"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AttachmentChunk" ADD CONSTRAINT "AttachmentChunk_attachmentId_fkey" FOREIGN KEY ("attachmentId") REFERENCES "Attachment"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ShareLinkAttachment" ADD CONSTRAINT "ShareLinkAttachment_linkId_fkey" FOREIGN KEY ("linkId") REFERENCES "ShareLink"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ShareLinkAttachment" ADD CONSTRAINT "ShareLinkAttachment_attachmentId_fkey" FOREIGN KEY ("attachmentId") REFERENCES "Attachment"("id") ON DELETE CASCADE ON UPDATE CASCADE;


-- Ciphertext doesn't compress: store chunk data out of line without trying.
ALTER TABLE "AttachmentChunk" ALTER COLUMN "data" SET STORAGE EXTERNAL;
