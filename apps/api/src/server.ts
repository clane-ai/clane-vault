import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { buildApp } from "./app.js";
import { loadConfig } from "./config.js";
import { createPrisma } from "./db.js";
import { ensureDefaultOrg } from "./lib/orgs.js";
import { checkServerSecret, ServerSecretMismatch } from "./lib/serverSecretCheck.js";

const config = loadConfig();
// Default matches the repo/image layout: apps/api/dist/src/server.js -> apps/web/dist
const webDist = resolve(process.env.WEB_DIST || fileURLToPath(new URL("../../../web/dist", import.meta.url)));
const prisma = createPrisma(config.databaseUrl);
// A SERVER_SECRET that differs from the one the database was set up with can't open 2FA, email or SSO secrets: stop here.
try {
  await checkServerSecret(prisma, config.serverSecret, { accept: config.acceptNewServerSecret, log: { warn: (m) => console.warn(JSON.stringify({ level: 40, msg: m })) } });
} catch (e) {
  if (!(e instanceof ServerSecretMismatch)) throw e;
  console.error(JSON.stringify({ level: 60, event: "server_secret_mismatch", msg: e.message }));
  process.exit(1);
}
// A fresh install gets its default organisation; the one the multi-org migration made gets its name.
await ensureDefaultOrg(prisma, config);
const app = await buildApp({ config, prisma, logger: true, ...(existsSync(webDist) ? { webDist } : {}) });
await app.listen({ host: "0.0.0.0", port: config.port });
// docker stop / Ctrl+C: stop taking requests, finish the ones in flight, then exit (in a container this is PID 1,
// which ignores signals it has no handler for). A second signal, or 8 s without finishing, exits at once.
for (const sig of ["SIGTERM", "SIGINT"] as const) {
  process.once(sig, () => {
    app.log.info({ signal: sig }, "shutting down");
    process.once(sig, () => process.exit(1));
    setTimeout(() => process.exit(1), 8_000).unref();
    app.close().then(() => prisma.$disconnect()).then(() => process.exit(0), () => process.exit(1));
  });
}
