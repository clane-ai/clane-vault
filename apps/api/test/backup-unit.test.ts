import { Readable } from "node:stream";
import { describe, expect, it } from "vitest";
import { generateIdentity, identityToRecipient } from "age-encryption";
import { loadConfig } from "../src/config.js";
import { decryptStream, encryptStream, parseIdentityFile } from "../src/lib/backup/age.js";
import { describeDb, pgConnection, schemaFromUrl } from "../src/lib/backup/dsn.js";
import { backupName, backupTime, selectExpired } from "../src/lib/backup/naming.js";
import { redact } from "../src/lib/backup/pg.js";
import { schemaRewriter } from "../src/lib/backup/restore.js";
import { shortError } from "../src/lib/backup/service.js";

const read = async (r: Readable) => { const parts: Buffer[] = []; for await (const c of r) parts.push(Buffer.from(c as Uint8Array)); return Buffer.concat(parts); };

describe("backup DSN handling", () => {
  it("takes the schema from ?schema= and defaults to public", () => {
    expect(schemaFromUrl("postgresql://u:p@h:5432/db?schema=clane_vault&sslmode=require")).toBe("clane_vault");
    expect(schemaFromUrl("postgresql://u:p@h:5432/db")).toBe("public");
    expect(schemaFromUrl("postgresql://u:p@h:5432/db?schema=")).toBe("public");
  });

  it("strips Prisma-only params and the password, keeps sslmode and other libpq params", () => {
    const c = pgConnection("postgresql://clane_app:s%40cret%2Fpw@db.example.com:5432/postgres?schema=clane_vault&sslmode=require&connection_limit=5&pgbouncer=true&pool_timeout=10&application_name=cv");
    expect(c.schema).toBe("clane_vault");
    expect(c.password).toBe("s@cret/pw");
    const u = new URL(c.url);
    expect(u.password).toBe("");
    expect(u.username).toBe("clane_app");
    expect([...u.searchParams.keys()].sort()).toEqual(["application_name", "sslmode"]);
    expect(u.searchParams.get("sslmode")).toBe("require");
    expect(c.url).not.toContain("cret");
    expect(pgConnection("postgresql://u@h/db").password).toBeUndefined();
    expect(describeDb("postgresql://u:secret@h:5432/db?schema=x")).toBe("h:5432/db");
  });

  it("redacts URLs and passwords from tool errors", () => {
    expect(redact("pg_dump: error: connection to postgresql://u:pw@h/db failed: password=hunter2")).toBe("pg_dump: error: connection to [url] failed: password=[redacted]");
    expect(shortError(new Error("first line\nsecond postgres://x:y@z"))).toBe("first line");
  });
});

describe("backup naming and retention", () => {
  it("names objects clane-vault-<schema>-<UTC yyyyMMdd-HHmmss>.dump.age and parses them back", () => {
    const at = new Date(Date.UTC(2026, 0, 5, 3, 4, 9));
    const n = backupName("clane_vault", at);
    expect(n).toBe("clane-vault-clane_vault-20260105-030409.dump.age");
    expect(backupTime(n, "clane_vault")?.toISOString()).toBe(at.toISOString());
    expect(backupTime(`clane-vault/${n}`, "clane_vault")?.getTime()).toBe(at.getTime());
    expect(backupTime(n, "public")).toBeNull();
    expect(backupTime("clane-vault-public-2026-bad.dump.age", "public")).toBeNull();
    expect(backupTime("notes.txt", "public")).toBeNull();
  });

  it("selects only this schema's backups older than the retention window, never the one just written", () => {
    const now = new Date(Date.UTC(2026, 9, 20, 2, 30));
    const names = [
      "clane-vault-public-20261001-023000.dump.age", // 19 days: expired
      "clane-vault-public-20261006-023001.dump.age", // 14 days minus a bit: kept
      "clane-vault-public-20261019-023000.dump.age",
      "clane-vault-other-20200101-000000.dump.age", // other schema: never touched
      "README.txt", ".clane-vault-public-20200101-000000.dump.age.partial",
      "clane-vault-public-20200101-000000.dump.age", // expired but it's `keep`
    ];
    expect(selectExpired(names, { schema: "public", days: 14, now, keep: "clane-vault-public-20200101-000000.dump.age" })).toEqual(["clane-vault-public-20261001-023000.dump.age"]);
    expect(selectExpired(names, { schema: "public", days: 1, now })).toEqual([
      "clane-vault-public-20261001-023000.dump.age", "clane-vault-public-20261006-023001.dump.age", "clane-vault-public-20200101-000000.dump.age"]);
  });
});

describe("age encryption", () => {
  it("round-trips a stream and only the matching identity decrypts it", async () => {
    const id = await generateIdentity();
    const recipient = await identityToRecipient(id);
    const data = Buffer.alloc(300_000);
    for (let i = 0; i < data.length; i++) data[i] = (i * 7919) % 251;
    const enc = await read(await encryptStream(Readable.from([data.subarray(0, 100_000), data.subarray(100_000)]), recipient));
    expect(enc.subarray(0, 21).toString()).toBe("age-encryption.org/v1");
    expect(enc.includes(data.subarray(0, 64))).toBe(false);
    const idFile = `# created: 2026-10-06T00:00:00Z\n# public key: ${recipient}\n${id}\n`;
    expect(parseIdentityFile(idFile)).toEqual([id]);
    expect((await read(await decryptStream(Readable.from([enc]), parseIdentityFile(idFile)))).equals(data)).toBe(true);
    const other = await generateIdentity();
    await expect((async () => read(await decryptStream(Readable.from([enc]), [other])))()).rejects.toThrow();
    expect(() => parseIdentityFile("# nothing here\n")).toThrow(/AGE-SECRET-KEY/);
  });
});

describe("restore SQL rewriting", () => {
  it("moves a dump into another schema without touching COPY data", () => {
    const rw = schemaRewriter("public", "restored");
    const sql = [
      "SET transaction_timeout = 0;", "CREATE SCHEMA public;", "COMMENT ON SCHEMA public IS 'standard public schema';",
      `CREATE TYPE public."Role" AS ENUM (`, `ALTER TABLE ONLY public."User" ALTER COLUMN role SET DEFAULT 'member'::public."Role";`,
      `ALTER TABLE ONLY public."Event" ALTER COLUMN id SET DEFAULT nextval('public."Event_id_seq"'::regclass);`,
      `COPY public."User" (id, email) FROM stdin;`, "1\tuser@public.example", "2\tpublic.x", "\\.",
      `CREATE INDEX "User_email_key" ON public."User" USING btree (email);`, "SELECT pg_catalog.set_config('search_path', '', false);",
      `ALTER TABLE ONLY mypublic."X" ADD x;`,
    ];
    expect(sql.map(rw).filter((l) => l !== null)).toEqual([
      `CREATE TYPE "restored"."Role" AS ENUM (`, `ALTER TABLE ONLY "restored"."User" ALTER COLUMN role SET DEFAULT 'member'::"restored"."Role";`,
      `ALTER TABLE ONLY "restored"."Event" ALTER COLUMN id SET DEFAULT nextval('"restored"."Event_id_seq"'::regclass);`,
      `COPY "restored"."User" (id, email) FROM stdin;`, "1\tuser@public.example", "2\tpublic.x", "\\.",
      `CREATE INDEX "User_email_key" ON "restored"."User" USING btree (email);`, "SELECT pg_catalog.set_config('search_path', '', false);",
      `ALTER TABLE ONLY mypublic."X" ADD x;`,
    ]);
    expect(schemaRewriter("Mixed", "t")(`CREATE TABLE "Mixed"."A" ();`)).toBe(`CREATE TABLE "t"."A" ();`);
    expect(schemaRewriter("Mixed", "t")(`CREATE SCHEMA "Mixed";`)).toBeNull();
  });
});

describe("backup config", () => {
  const base = { DATABASE_URL: "postgresql://u:p@h:5432/db", JWT_SECRET: "x".repeat(40), SERVER_SECRET: "y".repeat(40), PUBLIC_URL: "https://vault.example.com" };
  it("is off by default and refuses to enable without a recipient or destination", async () => {
    expect(loadConfig(base).backup).toMatchObject({ enabled: false, schedule: "30 2 * * *", retentionDays: 14 });
    expect(() => loadConfig({ ...base, BACKUP_ENABLED: "true", BACKUP_LOCAL_DIR: "/backups" })).toThrow(/BACKUP_AGE_RECIPIENT is required/);
    expect(() => loadConfig({ ...base, BACKUP_ENABLED: "true", BACKUP_LOCAL_DIR: "/b", BACKUP_AGE_RECIPIENT: "ssh-ed25519 AAAA" })).toThrow(/age public key/);
    const recipient = await identityToRecipient(await generateIdentity());
    expect(() => loadConfig({ ...base, BACKUP_ENABLED: "true", BACKUP_AGE_RECIPIENT: recipient })).toThrow(/BACKUP_S3_BUCKET/);
    expect(() => loadConfig({ ...base, BACKUP_ENABLED: "true", BACKUP_AGE_RECIPIENT: recipient, BACKUP_LOCAL_DIR: "/b", BACKUP_SCHEDULE: "every day" })).toThrow(/BACKUP_SCHEDULE/);
    const c = loadConfig({ ...base, BACKUP_ENABLED: "true", BACKUP_AGE_RECIPIENT: recipient, BACKUP_S3_BUCKET: "b", BACKUP_S3_PREFIX: "team", BACKUP_S3_ENDPOINT: "https://x.r2.cloudflarestorage.com",
      BACKUP_S3_ACCESS_KEY_ID: "AK", BACKUP_S3_SECRET_ACCESS_KEY: "SK", BACKUP_S3_FORCE_PATH_STYLE: "false", BACKUP_RETENTION_DAYS: "30" });
    expect(c.backup).toMatchObject({ enabled: true, retentionDays: 30, s3: { bucket: "b", prefix: "team/", forcePathStyle: false, region: "us-east-1" } });
  });
});
