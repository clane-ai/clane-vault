// Prints a new age identity in age-keygen's file format; the public key (BACKUP_AGE_RECIPIENT) also goes to stderr.
//   docker compose run --rm --no-deps clane-vault node dist/src/scripts/age-keygen.js > backup-key.txt
import { generateIdentity, identityToRecipient } from "age-encryption";

const identity = await generateIdentity();
const recipient = await identityToRecipient(identity);
process.stdout.write(`# created: ${new Date().toISOString().replace(/\.\d{3}Z$/, "Z")}\n# public key: ${recipient}\n${identity}\n`);
process.stderr.write(`Public key: ${recipient}\n`);
