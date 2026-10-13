import { defineConfig, devices } from "@playwright/test";

// The sign-in page's showcase screenshots (apps/web/public/showcase/*.webp). Run it with `npm run showcase -w e2e`
// (showcase/run.mjs), which gives this config its own Postgres container and free ports; see docs/release.md.
const WEB = Number(process.env.E2E_WEB_PORT ?? 5291);
const API = Number(process.env.E2E_API_PORT ?? 3291);

export default defineConfig({
  testDir: "showcase", timeout: 300_000, retries: 0, workers: 1,
  use: { baseURL: `http://localhost:${WEB}`, trace: "retain-on-failure" },
  projects: [{
    name: "showcase",
    use: {
      ...devices["Desktop Chrome"], viewport: { width: 1280, height: 800 }, deviceScaleFactor: 1,
      colorScheme: "light", reducedMotion: "reduce", locale: "en-US", timezoneId: "Europe/London",
      permissions: ["clipboard-read", "clipboard-write"],
    },
  }],
  webServer: [
    // Never reuse a running server: the screenshots must come from the fresh database run.mjs made.
    { command: "npm run dev -w @clane-vault/api", cwd: "..", port: API, reuseExistingServer: false, timeout: 120_000,
      env: { PORT: String(API), PUBLIC_URL: `http://localhost:${WEB}`, RATE_LIMIT_PER_MINUTE: "5000", DEFAULT_ORG_NAME: "Northwind" } },
    { command: "npm run dev -w @clane-vault/web", cwd: "..", port: WEB, reuseExistingServer: false, timeout: 120_000,
      env: { VITE_PORT: String(WEB), VITE_API_PORT: String(API) } },
  ],
});
