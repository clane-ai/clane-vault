-- CreateTable
CREATE TABLE "ServerSecretCheck" (
    "id" INTEGER NOT NULL DEFAULT 1,
    "sealed" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ServerSecretCheck_pkey" PRIMARY KEY ("id")
);
