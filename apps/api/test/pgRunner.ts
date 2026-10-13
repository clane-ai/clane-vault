import { execFileSync, spawn } from "node:child_process";
import { pgEnv, type PgRunner } from "../src/lib/backup/pg.js";

const hasHostTools = process.env.TEST_PG_TOOLS !== "docker" && (() => {
  try { for (const t of ["pg_dump", "pg_restore", "psql"]) execFileSync(t, ["--version"], { stdio: "ignore" }); return true; } catch { return false; }
})();

/**
 * Real Postgres client tools for tests: the host's when installed, otherwise `docker exec` into the Testcontainers
 * database (same server version, connecting to it on localhost:5432). TEST_PG_TOOLS=docker forces the latter.
 */
export const testPgRunner: PgRunner = hasHostTools ? (tool, args, conn) => spawn(tool, args, { env: pgEnv(conn), stdio: ["pipe", "pipe", "pipe"] }) : (tool, args, conn) => {
  const id = process.env.TEST_PG_CONTAINER;
  if (!id) throw new Error("TEST_PG_CONTAINER is not set");
  const port = new URL(process.env.TEST_DATABASE_URL!).port;
  const inside = args.map((a) => a.replace(/^(--dbname=postgres(?:ql)?:\/\/[^@/]*@?)[^:/]+(?::\d+)?/, (_m, head: string) => `${head}localhost:5432`).replace(`:${port}/`, ":5432/"));
  return spawn("docker", ["exec", "-i", ...(conn.password ? ["-e", `PGPASSWORD=${conn.password}`] : []), id, tool, ...inside], { stdio: ["pipe", "pipe", "pipe"] });
};
export const pgToolsWhere = hasHostTools ? "host" : "docker exec";
