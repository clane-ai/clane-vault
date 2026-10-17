import type { Server } from "node:http";
import { url as inspectorUrl } from "node:inspector";
import { createGateway } from "./app.js";
import { loadConfig } from "./config.js";
import { loadOrCreateIdentity } from "./identity.js";
import { loadKek } from "./kek.js";
import { assertNoInspector, createLogger, HeldSecrets, installCrashHandlers } from "./log.js";

const held = new HeldSecrets();
const log = createLogger(held);
let gateway: Awaited<ReturnType<typeof createGateway>>;
try {
  assertNoInspector(process.execArgv, process.env.NODE_OPTIONS);
  // Backstop for any spelling assertNoInspector misses.
  if (inspectorUrl() !== undefined) throw new Error("refusing to start with the inspector open: it exposes process memory");
  installCrashHandlers(process, log, process.exit);
  const config = loadConfig();
  const kek = await loadKek(config.kek);
  const identity = await loadOrCreateIdentity(config.identityKeyFile, kek);
  gateway = await createGateway(config, { kek, identity, log, held });
  const listen = (s: Server, port: number, host?: string) => new Promise<void>((ok, fail) => { s.once("error", fail); s.listen(port, host, () => ok()); });
  await Promise.all([listen(gateway.publicServer, config.port), listen(gateway.internalServer, config.internalPort, config.internalHost)]);
  log.info({ event: "listening", port: config.port, internalPort: config.internalPort, internalHost: config.internalHost, keyId: identity.keyId });
} catch (e) {
  // Start-up errors (inspector, config, KEK, identity, listen) hold no secrets.
  console.error(JSON.stringify({ event: "config_error", msg: (e as Error).message }));
  process.exit(1);
}

for (const sig of ["SIGTERM", "SIGINT"] as const)
  process.once(sig, () => { void gateway.close().then(() => process.exit(0)); });
