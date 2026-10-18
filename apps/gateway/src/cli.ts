import { b64url, keyFingerprint } from "@clane-vault/crypto";
import { loadConfig } from "./config.js";
import { loadOrCreateIdentity } from "./identity.js";
import { loadKek } from "./kek.js";

const [cmd] = process.argv.slice(2);
if (cmd !== "identity") {
  console.error("usage: clane-gateway identity");
  process.exit(2);
}
try {
  const config = loadConfig();
  const identity = await loadOrCreateIdentity(config.identityKeyFile, await loadKek(config.kek));
  console.log(`key id:      ${identity.keyId}`);
  console.log(`fingerprint: ${await keyFingerprint(b64url.decode(identity.publicKey))}`);
} catch (e) {
  console.error((e as Error).message);
  process.exit(1);
}
