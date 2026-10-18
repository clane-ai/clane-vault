import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { buildApp } from "./app.js";
import { loadConfig } from "./config.js";
import { createPrisma } from "./db.js";
import { ensureDefaultOrg } from "./lib/orgs.js";
import { checkServerSecret, ServerSecretMismatch } from "./lib/serverSecretCheck.js";
import { checkDemoStartup, DemoStartupRefused } from "./lib/demo.js";
import { checkGatewayAtStart, gatewayClient, GatewayIdentityChanged } from "./lib/gateway.js";

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
// Agent access: pin the gateway's identity key. Unreachable only warns (pinned on first contact); a changed one stops here.
if (config.agents) {
  try {
    await checkGatewayAtStart(prisma, gatewayClient(config.agents), { accept: config.agents.acceptNewGatewayIdentity, log: { warn: (m) => console.warn(JSON.stringify({ level: 40, event: "gateway_check", msg: m })) } });
  } catch (e) {
    if (!(e instanceof GatewayIdentityChanged)) throw e;
    console.error(JSON.stringify({ level: 60, event: "gateway_identity_changed", msg: e.message }));
    process.exit(1);
  }
}
// Demo mode (docs/demo.md) only on a database of demo sandboxes: a real account anywhere stops the start.
try {
  await checkDemoStartup(prisma, config);
} catch (e) {
  if (!(e instanceof DemoStartupRefused)) throw e;
  console.error(JSON.stringify({ level: 60, event: "demo_mode_refused", msg: e.message }));
  process.exit(1);
}
if (config.demo) console.warn(JSON.stringify({ level: 40, event: "demo_mode", msg: `DEMO_MODE is on: anyone can create a throwaway sandbox that is deleted after ${config.demo.ttlMinutes} minutes, without an authenticator. No email is sent; SSO, organisation creation, backups and server settings are off. Never use this instance for real data.` }));
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
