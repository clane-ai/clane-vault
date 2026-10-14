import { defineConfig, devices } from "@playwright/test";

// The public demo (docs/demo.md): the API runs with DEMO_MODE=true, which needs a database without real accounts. Run it
// with `npm run demo -w e2e` (demo/run.mjs), which gives this config its own Postgres container and free ports.
const WEB = Number(process.env.E2E_WEB_PORT ?? 5292);
const API = Number(process.env.E2E_API_PORT ?? 3292);

export default defineConfig({
  testDir: "demo", timeout: 180_000, retries: 0, workers: 1,
  use: { baseURL: `http://localhost:${WEB}`, trace: "retain-on-failure" },
  projects: [{ name: "demo", use: { ...devices["Desktop Chrome"], viewport: { width: 1440, height: 900 } } }],
  webServer: [
    // Never reuse a running server: a dev API isn't in demo mode, and its database has real accounts.
    { command: "npm run dev -w @clane-vault/api", cwd: "..", port: API, reuseExistingServer: false, timeout: 120_000,
      env: { PORT: String(API), PUBLIC_URL: `http://localhost:${WEB}`, RATE_LIMIT_PER_MINUTE: "5000", DEMO_MODE: "true", DEMO_TTL_MINUTES: "120", DEMO_SANDBOXES_PER_IP_PER_HOUR: "20" } },
    { command: "npm run dev -w @clane-vault/web", cwd: "..", port: WEB, reuseExistingServer: false, timeout: 120_000,
      env: { VITE_PORT: String(WEB), VITE_API_PORT: String(API) } },
  ],
});
