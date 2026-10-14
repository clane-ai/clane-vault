// The public demo's end-to-end test (demo/demo.spec.ts) on a throwaway stack: its own Postgres container and its own
// free API/web ports, so it never touches a dev database or dev servers (a demo API refuses a database with real
// accounts anyway, docs/demo.md).
//   npm run demo -w e2e
// Needs Docker. Extra arguments go to Playwright (e.g. --headed). Set DEMO_E2E_KEEP_DB=1 to keep the container.
import { execFileSync, spawnSync } from "node:child_process";
import { createServer } from "node:net";
import path from "node:path";

const root = path.resolve(import.meta.dirname, "../..");
const db = process.env.DEMO_E2E_DB_CONTAINER ?? "clane-vault-demo-e2e-db";

const freePort = () => new Promise((resolve, reject) => {
  const s = createServer().once("error", reject).listen(0, "127.0.0.1", () => { const { port } = s.address(); s.close(() => resolve(port)); });
});
const docker = (...args) => execFileSync("docker", args, { stdio: "pipe" }).toString().trim();
const removeDb = () => { try { docker("rm", "-f", "-v", db); } catch { /* not there */ } };

const [dbPort, apiPort, webPort] = [await freePort(), await freePort(), await freePort()];
removeDb();
docker("run", "-d", "--name", db, "-e", "POSTGRES_USER=vault", "-e", "POSTGRES_PASSWORD=vault", "-e", "POSTGRES_DB=vault",
  "-p", `127.0.0.1:${dbPort}:5432`, "postgres:16-alpine");
let status = 1;
try {
  // TCP readiness: the init-time server only listens on the socket, so this waits for the real one.
  for (let i = 0; ; i++) {
    try { docker("exec", db, "pg_isready", "-h", "127.0.0.1", "-U", "vault", "-d", "vault"); break; }
    catch (e) { if (i > 60) throw e; await new Promise((r) => setTimeout(r, 1000)); }
  }
  const env = { ...process.env, DATABASE_URL: `postgresql://vault:vault@127.0.0.1:${dbPort}/vault`, E2E_DB_CONTAINER: db,
    E2E_API_PORT: String(apiPort), E2E_WEB_PORT: String(webPort) };
  const run = (cmd, args, cwd) => spawnSync(cmd, args, { cwd, env, stdio: "inherit", shell: process.platform === "win32" }).status ?? 1;
  if (run("npx", ["prisma", "migrate", "deploy"], path.join(root, "apps/api")) !== 0) throw new Error("migrations failed");
  status = run("npx", ["playwright", "test", "-c", "playwright.demo.config.ts", ...process.argv.slice(2)], path.join(root, "e2e"));
} finally {
  if (process.env.DEMO_E2E_KEEP_DB !== "1") removeDb();
}
process.exit(status);
