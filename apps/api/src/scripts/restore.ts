// Restore an encrypted Clane Vault backup into an empty schema.
//   node dist/src/scripts/restore.js --from <S3 object key | local file> --identity <age identity file | -> [--target-schema <name>] [--force]
//   node dist/src/scripts/restore.js --list
import { readFileSync } from "node:fs";
import { loadConfig } from "../config.js";
import { parseIdentityFile } from "../lib/backup/age.js";
import { schemaFromUrl } from "../lib/backup/dsn.js";
import { backupTime } from "../lib/backup/naming.js";
import { RestoreRefused, restoreBackup } from "../lib/backup/restore.js";
import { makeDestinations } from "../lib/backup/service.js";

const USAGE = `Usage:
  node dist/src/scripts/restore.js --from <S3 object key | local file> --identity <age identity file | -> [--target-schema <name>] [--force]
  node dist/src/scripts/restore.js --list

Restores into the schema of DATABASE_URL (or --target-schema), which must be empty unless --force is given.
--identity - reads the identity from standard input (docker compose exec -T ... --identity - < backup-key.txt).`;

const argv = process.argv.slice(2);
const arg = (name: string) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : undefined; };
if (argv.includes("--help") || argv.includes("-h")) { console.log(USAGE); process.exit(0); }

const config = loadConfig();
const destinations = config.backup ? makeDestinations(config.backup) : [];
const schema = schemaFromUrl(config.databaseUrl);

if (argv.includes("--list")) {
  if (!destinations.length) { console.error("No backup destination configured (BACKUP_S3_BUCKET / BACKUP_LOCAL_DIR)."); process.exit(1); }
  for (const d of destinations) {
    const names = (await d.list()).filter((n) => backupTime(n, schema)).sort();
    const where = d.describe();
    console.log(where.type === "s3" ? `s3://${where.bucket}/${where.prefix}` : where.dir);
    for (const n of names) console.log(`  ${d.locate(n)}`);
    if (!names.length) console.log("  (none)");
  }
  process.exit(0);
}

const from = arg("--from");
const identity = arg("--identity");
const target = arg("--target-schema");
if (!from || !identity) { console.error(USAGE); process.exit(1); }
if (target !== undefined && !/^[A-Za-z_][A-Za-z0-9_]{0,62}$/.test(target)) { console.error("--target-schema must be a plain identifier (letters, digits, _)"); process.exit(1); }

try {
  const r = await restoreBackup({
    databaseUrl: config.databaseUrl, from, identities: parseIdentityFile(readFileSync(identity === "-" ? 0 : identity, "utf8")), force: argv.includes("--force"), destinations,
    ...(target ? { targetSchema: target } : {}), log: (l) => console.log(l),
  });
  const url = new URL(config.databaseUrl);
  url.password = url.password ? "****" : "";
  url.searchParams.set("schema", r.targetSchema);
  console.log(`
Restored ${r.tables} tables from schema "${r.sourceSchema}" into "${r.targetSchema}".

Next steps:
  1. Point the app at the restored schema: set DATABASE_URL to ${url.toString()}
     (with the real password), or rename schemas in Postgres so it takes the original name.
  2. Use the same .env as when the backup was taken. SERVER_SECRET must match, or nobody can use their 2FA codes.
  3. Restart the container (docker compose up -d). Pending migrations run automatically on start.
  4. Sign in and open a few records to check them, then remove any old schema you no longer need.`);
  for (const d of destinations) (d as { destroy?: () => void }).destroy?.();
} catch (e) {
  console.error(e instanceof RestoreRefused ? e.message : `Restore failed: ${e instanceof Error ? e.message : String(e)}`);
  process.exit(e instanceof RestoreRefused ? 2 : 1);
}
