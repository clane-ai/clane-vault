import { defineConfig, devices } from "@playwright/test";

// Ports are overridable so a second checkout can run beside the main one: E2E_WEB_PORT / E2E_API_PORT
// (aliases WEB_PORT / API_PORT). They are passed on to the API (PORT) and Vite (VITE_PORT / VITE_API_PORT).
const WEB = Number(process.env.E2E_WEB_PORT ?? process.env.WEB_PORT ?? 5173);
const API = Number(process.env.E2E_API_PORT ?? process.env.API_PORT ?? 3001);

export default defineConfig({
  testDir: "tests", timeout: 120_000, retries: 0,
  use: { baseURL: `http://localhost:${WEB}`, trace: "retain-on-failure" },
  projects: [
    { name: "desktop", testIgnore: /org-policy\//, use: { ...devices["Desktop Chrome"], viewport: { width: 1440, height: 900 }, permissions: ["clipboard-read", "clipboard-write"] } },
    { name: "phone", testIgnore: /org-policy\//, use: { ...devices["Pixel 7"], permissions: ["clipboard-read", "clipboard-write"] } },
    // Organisation-wide settings (admin recovery): alone, after everything else, so they never change what other tests see.
    { name: "org-policy", testMatch: /org-policy\/.*\.spec\.ts/, dependencies: ["desktop", "phone"],
      use: { ...devices["Desktop Chrome"], viewport: { width: 1440, height: 900 }, permissions: ["clipboard-read", "clipboard-write"] } },
  ],
  webServer: [
    { command: "npm run dev -w @clane-vault/api", cwd: "..", port: API, reuseExistingServer: true, env: { PORT: String(API), PUBLIC_URL: `http://localhost:${WEB}`,
      // Every test browser shares 127.0.0.1, so the per-address API limit would be hit by the suite as a whole.
      RATE_LIMIT_PER_MINUTE: "5000",
      // The mock OpenID Connect provider of the SSO test runs on http://127.0.0.1:<free port>.
      SSO_ALLOW_HTTP_ISSUER: "true" } },
    { command: "npm run dev -w @clane-vault/web", cwd: "..", port: WEB, reuseExistingServer: true, env: { VITE_PORT: String(WEB), VITE_API_PORT: String(API) } },
  ],
});
