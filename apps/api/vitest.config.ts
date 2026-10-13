import { defineConfig } from "vitest/config";
export default defineConfig({
  test: { include: ["test/**/*.test.ts"], environment: "node", globalSetup: ["test/setup/globalSetup.ts"], fileParallelism: false, testTimeout: 60_000, hookTimeout: 120_000 },
});
