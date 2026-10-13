-- Hosted sign-up codes: a total wrong-code cap per invite (survives re-issue) and a cap on codes issued.
ALTER TABLE "Invite" ADD COLUMN     "emailCodeIssues" INTEGER NOT NULL DEFAULT 0,
ADD COLUMN     "emailCodeTotalAttempts" INTEGER NOT NULL DEFAULT 0;
