-- The key archive (scoped admin recovery) opens only with the old master password or the old recovery kit, checked
-- server-side: the old auth hash and kit auth hash are archived with the old key material.
-- Archives made before this migration have neither and open with a fresh 2FA code alone, as before.
ALTER TABLE "AccountKeyArchive" ADD COLUMN "authHash" TEXT,
ADD COLUMN "recoveryAuthHash" TEXT;
