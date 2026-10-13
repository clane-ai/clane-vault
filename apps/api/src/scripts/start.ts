/**
 * The container's entrypoint (Dockerfile CMD; the runtime image has no shell): applies pending database migrations
 * with the Prisma CLI in a child process, stops with its exit code when they fail, then starts the server in this
 * process. SIGTERM / SIGINT during the migration go to the child and this process exits with the child's status.
 */
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { createRequire } from "node:module";
import { constants } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const prismaCli = require.resolve("prisma/build/index.js");
// apps/api (where prisma/schema.prisma lives), from dist/src/scripts/start.js or src/scripts/start.ts.
const apiDir = ["../../../", "../../"].map((p) => fileURLToPath(new URL(p, import.meta.url))).find((d) => existsSync(join(d, "prisma", "schema.prisma"))) ?? process.cwd();

const signals = ["SIGTERM", "SIGINT"] as const;
const code = await new Promise<number>((resolve) => {
  const child = spawn(process.execPath, [prismaCli, "migrate", "deploy"], { cwd: apiDir, stdio: "inherit" });
  const forward = (sig: NodeJS.Signals) => { child.kill(sig); };
  for (const s of signals) process.on(s, forward);
  child.once("error", (e) => { console.error(JSON.stringify({ level: 60, event: "migrate_failed", msg: `couldn't start prisma migrate deploy: ${e.message}` })); resolve(1); });
  child.once("exit", (c, sig) => {
    for (const s of signals) process.off(s, forward);
    resolve(c ?? 128 + (sig ? constants.signals[sig] : 1));
  });
});
if (code !== 0) {
  console.error(JSON.stringify({ level: 60, event: "migrate_failed", msg: `prisma migrate deploy exited with ${code}` }));
  process.exit(code);
}
await import("../server.js");
