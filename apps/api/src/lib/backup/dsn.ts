/**
 * DATABASE_URL is a Prisma connection string. pg_dump/psql (libpq) reject Prisma-only query parameters, and a
 * password in a URL would show up in the process list, so the URL is split into a libpq URL and a password.
 */
const PRISMA_ONLY = new Set(["schema", "connection_limit", "pool_timeout", "pgbouncer", "statement_cache_size", "socket_timeout",
  "sslaccept", "sslidentity", "max_connection_lifetime", "max_idle_connection_lifetime", "single_use_connections"]);

/** The Postgres schema the app lives in: `?schema=` of DATABASE_URL, "public" when absent. */
export function schemaFromUrl(databaseUrl: string): string {
  const s = new URL(databaseUrl).searchParams.get("schema");
  return s && s.trim() ? s.trim() : "public";
}

export interface PgConn { /** libpq URL without the password and without Prisma-only params. */ url: string; password?: string; schema: string }

export function pgConnection(databaseUrl: string): PgConn {
  const u = new URL(databaseUrl);
  const schema = schemaFromUrl(databaseUrl);
  const password = u.password ? decodeURIComponent(u.password) : undefined;
  u.password = "";
  for (const k of [...u.searchParams.keys()]) if (PRISMA_ONLY.has(k)) u.searchParams.delete(k);
  return { url: u.toString(), schema, ...(password ? { password } : {}) };
}

/** Safe for logs: host/db only, never credentials. */
export function describeDb(databaseUrl: string): string {
  const u = new URL(databaseUrl);
  return `${u.hostname}${u.port ? `:${u.port}` : ""}${u.pathname}`;
}

/** A schema name as a quoted SQL identifier. */
export const quoteIdent = (s: string) => `"${s.replace(/"/g, '""')}"`;
