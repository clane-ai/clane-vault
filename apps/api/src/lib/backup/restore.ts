import { createReadStream, existsSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { createInterface } from "node:readline";
import type { ChildProcess } from "node:child_process";
import { decryptStream } from "./age.js";
import { streamToFile, type Destination } from "./destinations.js";
import { pgConnection, quoteIdent, type PgConn } from "./dsn.js";
import { spawnPg, waitPg, type PgRunner } from "./pg.js";

export class RestoreRefused extends Error {}

const sqlLiteral = (s: string) => `'${s.replace(/'/g, "''")}'`;
const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/**
 * Rewrites pg_restore's SQL so it lands in `target` instead of `source`, one line at a time: drops the schema-level
 * statements (the schema is created up front; a non-owner can't COMMENT ON or DROP it) and requalifies names. COPY
 * data is passed through untouched, so values that merely contain "source." are never altered. Returns null to drop.
 */
export function schemaRewriter(source: string, target: string): (line: string) => string | null {
  const qs = quoteIdent(source);
  const plain = /^[a-z_][a-z0-9_$]*$/.test(source);
  const names = `(?:${escapeRe(qs)}${plain ? `|${escapeRe(source)}` : ""})`;
  const prefix = new RegExp(`(?<![A-Za-z0-9_$".])${names}\\.`, "g");
  const schemaStmt = new RegExp(`^(?:CREATE SCHEMA|COMMENT ON SCHEMA|ALTER SCHEMA|DROP SCHEMA(?: IF EXISTS)?) ${names}[ ;]`);
  const qt = `${quoteIdent(target)}.`;
  let inCopy = false;
  return (line) => {
    if (inCopy) { if (line === "\\.") inCopy = false; return line; }
    if (schemaStmt.test(line)) return null;
    // pg_dump 17+ emits this; older servers reject it.
    if (line.startsWith("SET transaction_timeout = ")) return null;
    const out = line.replace(prefix, qt);
    if (/^COPY .* FROM stdin;$/.test(out)) inCopy = true;
    return out;
  };
}

async function* rewriteStream(input: Readable, source: string, target: string): AsyncGenerator<string> {
  const rw = schemaRewriter(source, target);
  for await (const line of createInterface({ input, crlfDelay: Infinity })) {
    const out = rw(line);
    if (out !== null) yield `${out}\n`;
  }
}

async function collect(tool: "psql" | "pg_restore", p: ChildProcess, stdin?: string): Promise<string> {
  let out = "";
  p.stdout?.on("data", (d: Buffer) => { out += d.toString(); });
  if (stdin !== undefined) p.stdin?.end(stdin); else p.stdin?.end();
  await waitPg(tool, p);
  return out;
}

export interface RestoreOptions {
  databaseUrl: string; from: string; identities: string[]; targetSchema?: string; force?: boolean;
  /** Used when `from` is not a local file (S3 object key or bare name). */
  destinations?: Destination[]; runner?: PgRunner; log?: (line: string) => void;
}

export interface RestoreResult { sourceSchema: string; targetSchema: string; tables: number }

export async function restoreBackup(o: RestoreOptions): Promise<RestoreResult> {
  const conn: PgConn = pgConnection(o.databaseUrl);
  const run = o.runner ?? spawnPg;
  const log = o.log ?? (() => undefined);
  const target = o.targetSchema ?? conn.schema;
  const psqlArgs = [`--dbname=${conn.url}`, "--no-psqlrc", "-v", "ON_ERROR_STOP=1"];

  const count = async () => Number((await collect("psql", run("psql", [...psqlArgs, "-tAc", `SELECT count(*) FROM information_schema.tables WHERE table_schema = ${sqlLiteral(target)}`], conn))).trim());
  const existing = await count();
  if (existing > 0 && !o.force) throw new RestoreRefused(`Schema "${target}" already has ${existing} table(s). Restore into an empty schema (--target-schema <new name>) or pass --force to replace its contents.`);

  const dir = await mkdtemp(join(tmpdir(), "clane-restore-"));
  try {
    let src: Readable;
    if (existsSync(o.from)) src = createReadStream(o.from);
    else {
      const d = o.destinations?.find((x) => x.describe().type === "s3") ?? o.destinations?.[0];
      if (!d) throw new Error(`${o.from} is not a local file and no backup destination is configured`);
      src = await d.get(o.from);
    }
    log(`Decrypting ${o.from}…`);
    const dump = join(dir, "backup.dump");
    await streamToFile(await decryptStream(src, o.identities), dump);

    // The schema the dump was taken from: from the archive's table of contents, else the file name.
    const toc = await (async () => { const p = run("pg_restore", ["-l"], conn); createReadStream(dump).pipe(p.stdin!); let out = ""; p.stdout?.on("data", (d: Buffer) => { out += d.toString(); }); await waitPg("pg_restore", p); return out; })();
    const m = /^\d+; \d+ \d+ (?:TABLE|TYPE|SEQUENCE) (\S+) /m.exec(toc);
    const fromName = /clane-vault-(.+)-[0-9]{8}-[0-9]{6}[.]dump[.]age$/.exec(o.from)?.[1];
    const source = m?.[1] ?? fromName;
    if (!source) throw new Error("Could not tell which schema the backup was taken from");

    log(`Restoring schema "${source}" into "${target}"…`);
    // CREATE SCHEMA needs CREATE on the database even with IF NOT EXISTS, so only run it when the schema is missing.
    const create = `CREATE SCHEMA ${quoteIdent(target)}`;
    await collect("psql", run("psql", [...psqlArgs, "-qc", `DO $do$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = ${sqlLiteral(target)}) THEN EXECUTE ${sqlLiteral(create)}; END IF; END $do$`], conn));
    const restore = run("pg_restore", ["-f", "-", "--no-owner", "--no-privileges", ...(o.force ? ["--clean", "--if-exists"] : [])], conn);
    const psql = run("psql", [...psqlArgs, "-q", "--single-transaction", "-f", "-"], conn);
    psql.stdout?.resume();
    const done = Promise.all([waitPg("pg_restore", restore), waitPg("psql", psql)]);
    await Promise.all([
      pipeline(createReadStream(dump), restore.stdin!),
      pipeline(Readable.from(rewriteStream(restore.stdout!, source, target)), psql.stdin!),
      done,
    ]);
    const tables = await count();
    return { sourceSchema: source, targetSchema: target, tables };
  } finally {
    await rm(dir, { recursive: true, force: true }).catch(() => undefined);
  }
}
