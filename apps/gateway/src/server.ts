import { loadConfig } from "./config.js";
import { loadOrCreateIdentity } from "./identity.js";
import { loadKek } from "./kek.js";

// Start-up checks only; Task 8 adds the HTTP servers.
try {
  const config = loadConfig();
  const identity = await loadOrCreateIdentity(config.identityKeyFile, await loadKek(config.kek));
  console.log(JSON.stringify({ event: "identity", keyId: identity.keyId }));
} catch (e) {
  // Config, KEK and identity errors hold no secrets.
  console.error(JSON.stringify({ event: "config_error", msg: (e as Error).message }));
  process.exit(1);
}
