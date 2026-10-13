-- CreateTable
CREATE TABLE "PendingFolderMember" (
    "id" UUID NOT NULL,
    "folderId" UUID NOT NULL,
    "email" TEXT NOT NULL,
    "permission" "Permission" NOT NULL,
    "createdBy" UUID NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "PendingFolderMember_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "PendingFolderMember_email_idx" ON "PendingFolderMember"("email");

-- CreateIndex
CREATE UNIQUE INDEX "PendingFolderMember_folderId_email_key" ON "PendingFolderMember"("folderId", "email");

-- AddForeignKey
ALTER TABLE "PendingFolderMember" ADD CONSTRAINT "PendingFolderMember_folderId_fkey" FOREIGN KEY ("folderId") REFERENCES "Folder"("id") ON DELETE CASCADE ON UPDATE CASCADE;
