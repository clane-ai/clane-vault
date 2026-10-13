import { spawn, type ChildProcess } from "node:child_process";
import type { PgConn } from "./dsn.js";

export type PgTool = "pg_dump" | "pg_restore" | "psql";

/**
 * Starts a Postgres client tool. The default spawns the binary from PATH; tests can swap in one that runs the tool
 * elsewhere (e.g. `docker exec` in the database container). `conn` is passed so a runner can rewrite the address.
 */
export type PgRunner = (tool: PgTool, args: string[], conn: PgConn) => ChildProcess;

export const pgEnv = (conn: PgConn): NodeJS.ProcessEnv => ({ ...process.env, ...(conn.password ? { PGPASSWORD: conn.password } : {}) });

export const spawnPg: PgRunner = (tool, args, conn) => spawn(tool, args, { env: pgEnv(conn), stdio: ["pipe", "pipe", "pipe"] });

/** Resolves when the process exits 0; rejects with the tool's last stderr line otherwise (never the command line). */
export function waitPg(tool: PgTool, p: ChildProcess): Promise<void> {
  let err = "";
  p.stderr?.on("data", (d: Buffer) => { err = (err + d.toString()).slice(-4000); });
  return new Promise((resolve, reject) => {
    p.once("error", (e: NodeJS.ErrnoException) => reject(new Error(e.code === "ENOENT" ? `${tool} not found (install postgresql-client)` : `${tool} failed to start`)));
    p.once("close", (code) => {
      if (code === 0) return resolve();
      const line = err.trim().split(/\r?\n/).filter(Boolean).pop() ?? "";
      reject(new Error(`${tool} exited with code ${code}${line ? `: ${redact(line)}` : ""}`));
    });
  });
}

/** Strips anything that looks like a connection URL or password from tool output before it is stored or logged. */
export const redact = (s: string) => s.replace(/postgres(?:ql)?:\/\/\S+/gi, "[url]").replace(/password[=:]\s*\S+/gi, "password=[redacted]").slice(0, 300);
