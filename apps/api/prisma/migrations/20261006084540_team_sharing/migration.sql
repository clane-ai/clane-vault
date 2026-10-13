-- CreateTable
CREATE TABLE "FolderMember" (
    "id" UUID NOT NULL,
    "folderId" UUID NOT NULL,
    "userId" UUID NOT NULL,
    "permission" "Permission" NOT NULL,
    "wrappedFolderKey" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "FolderMember_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "FolderMember_userId_idx" ON "FolderMember"("userId");

-- CreateIndex
CREATE UNIQUE INDEX "FolderMember_folderId_userId_key" ON "FolderMember"("folderId", "userId");

-- AddForeignKey
ALTER TABLE "FolderMember" ADD CONSTRAINT "FolderMember_folderId_fkey" FOREIGN KEY ("folderId") REFERENCES "Folder"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "FolderMember" ADD CONSTRAINT "FolderMember_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
