import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { tmpdir } from "node:os";
import path from "node:path";
import { defineConfig, devices } from "@playwright/test";

// Agent access end to end (agents/agents.spec.ts): the API with agents on, the gateway and the web app.
//   npm run test:agents -w e2e     (the database as for playwright.config.ts: DATABASE_URL, E2E_DB_CONTAINER)
// Its own ports and reuseExistingServer: false, so a running API without agents is never picked up.
const WEB = Number(process.env.E2E_WEB_PORT ?? 5183);
const API = Number(process.env.E2E_API_PORT ?? 3011);
const GW = Number(process.env.E2E_GATEWAY_PORT ?? 3002);
const GW_INTERNAL = Number(process.env.E2E_GATEWAY_INTERNAL_PORT ?? 3003);

// The KEK and identity key stay between runs: the API pins the gateway identity in the database on first contact and
// refuses a changed one, so a new identity per run would stop the API on a kept database.
const keys = path.join(tmpdir(), "clane-vault-e2e-agents");
mkdirSync(keys, { recursive: true });
const kekFile = path.join(keys, "kek.bin");
if (!existsSync(kekFile)) writeFileSync(kekFile, randomBytes(32), { mode: 0o600 });

const gatewayApiToken = randomBytes(32).toString("base64url");
const tokenKey = generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({ type: "pkcs8", format: "pem" }).toString();
const gatewayPublicUrl = `http://localhost:${GW}/mcp`;

export default defineConfig({
  testDir: "agents", timeout: 180_000, retries: 0,
  use: { baseURL: `http://localhost:${WEB}`, trace: "retain-on-failure" },
  projects: [{ name: "desktop", use: { ...devices["Desktop Chrome"], viewport: { width: 1440, height: 900 }, permissions: ["clipboard-read", "clipboard-write"] } }],
  webServer: [
    // Built and started through the hosts fixture (echo.test → 127.0.0.1). The gateway refuses NODE_OPTIONS, so it is cleared.
    { command: "node build.mjs && node --disable-sigusr1 test/fixtures/hosts.mjs", cwd: "../apps/gateway", port: GW, reuseExistingServer: false,
      env: { NODE_OPTIONS: "", API_URL: `http://127.0.0.1:${API}`, PUBLIC_URL: gatewayPublicUrl, GATEWAY_API_TOKEN: gatewayApiToken,
        GATEWAY_KEK: `file:${kekFile}`, GATEWAY_IDENTITY_KEY_FILE: path.join(keys, "identity.json"), PORT: String(GW), INTERNAL_PORT: String(GW_INTERNAL),
        INTERNAL_HOST: "127.0.0.1", GATEWAY_ALLOW_PRIVATE_CIDRS: "127.0.0.0/8" } },
    { command: "npm run dev -w @clane-vault/api", cwd: "..", port: API, reuseExistingServer: false, env: { PORT: String(API), PUBLIC_URL: `http://localhost:${WEB}`,
      RATE_LIMIT_PER_MINUTE: "5000", GATEWAY_INTERNAL_URL: `http://127.0.0.1:${GW_INTERNAL}`, GATEWAY_PUBLIC_URL: gatewayPublicUrl,
      GATEWAY_API_TOKEN: gatewayApiToken, AGENT_TOKEN_PRIVATE_KEY: tokenKey } },
    { command: "npm run dev -w @clane-vault/web", cwd: "..", port: WEB, reuseExistingServer: false, env: { VITE_PORT: String(WEB), VITE_API_PORT: String(API) } },
  ],
});
