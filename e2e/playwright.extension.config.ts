import { defineConfig } from "@playwright/test";

// The browser extension against a self-contained fake API (no dev servers or databases): npm run test:extension.
// Build first: npm run build -w apps/extension -- --e2e
export default defineConfig({ testDir: "extension", timeout: 120_000, retries: 0, workers: 1, use: { trace: "retain-on-failure" } });
