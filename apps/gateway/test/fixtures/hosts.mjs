// Test only (e2e/playwright.agents.config.ts): maps echo.test to 127.0.0.1, then starts the built gateway.
// It is the entry module, not a --import/NODE_OPTIONS preload, because the gateway refuses to start with either (assertSafeRuntime).
// The default resolver reads dns.promises.lookup at call time, so this patch is the one it uses.
import dns from "node:dns";

const real = dns.promises.lookup.bind(dns.promises);
const ECHO = { address: "127.0.0.1", family: 4 };
dns.promises.lookup = (host, opts) => (String(host).toLowerCase() === "echo.test" ? Promise.resolve(opts?.all ? [ECHO] : ECHO) : real(host, opts));

await import("../../dist/server.js");
