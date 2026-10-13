// Refreshes the sign-in page's showcase screenshots (apps/web/public/showcase/*.webp) on a throwaway stack:
// its own Postgres container and its own free API/web ports, so it never touches a dev database or dev servers.
//   npm run showcase -w e2e
// With --flyer (npm run showcase:flyer -w e2e) it captures the flyer's screenshots instead (showcase/flyer.spec.ts,
// into e2e/showcase/out/flyer/, or FLYER_OUT), in a container of its own.
// Needs Docker. Extra arguments go to Playwright (e.g. --headed). Set SHOWCASE_KEEP_DB=1 to keep the container.
import { execFileSync, spawnSync } from "node:child_process";
import { createServer } from "node:net";
import path from "node:path";

const root = path.resolve(import.meta.dirname, "../..");
const flyer = process.argv.includes("--flyer");
const args = process.argv.slice(2).filter((a) => a !== "--flyer");
const spec = flyer ? "flyer.spec" : "capture.spec";
const db = process.env.SHOWCASE_DB_CONTAINER ?? (flyer ? "clane-vault-flyer-db" : "clane-vault-showcase-db");

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
  status = run("npx", ["playwright", "test", "-c", "playwright.showcase.config.ts", spec, ...args], path.join(root, "e2e"));
} finally {
  if (process.env.SHOWCASE_KEEP_DB !== "1") removeDb();
}
process.exit(status);
