-- Record types (docs/record-types.md): the real type (login, card, server, ...) lives inside the encrypted body; the
-- server keeps only a coarse type: "login" (the extension may fill it) or "item" (everything else). Secure notes
-- written before this release were stored as "note": they become "item".
UPDATE "Record" SET "type" = 'item' WHERE "type" <> 'login';

ALTER TABLE "Record" ADD CONSTRAINT "Record_type_check" CHECK ("type" IN ('login', 'item'));
