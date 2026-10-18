import { describe, expect, it } from "vitest";
import { loadConfig } from "../src/config.js";

const base = { API_URL: "http://api:3001/api/v1", GATEWAY_API_TOKEN: "t".repeat(32), PUBLIC_URL: "https://vault.example/mcp", GATEWAY_KEK: "file:/k", GATEWAY_IDENTITY_KEY_FILE: "/id.json" };

describe("loadConfig", () => {
  it("applies the defaults", () => {
    expect(loadConfig(base)).toEqual({ apiUrl: base.API_URL, apiToken: base.GATEWAY_API_TOKEN, publicUrl: base.PUBLIC_URL, kek: "file:/k", identityKeyFile: "/id.json",
      cacheTtlSeconds: 60, agentRatePerMinute: 60, maxResponseBytes: 4194304, upstreamTimeoutMs: 30000, allowPrivateCidrs: [], port: 3002, internalPort: 3003, internalHost: "0.0.0.0", trustProxy: 0 });
  });
  it("parses overrides", () => {
    expect(loadConfig({ ...base, GATEWAY_CACHE_TTL_SECONDS: "0", GATEWAY_ALLOW_PRIVATE_CIDRS: "10.0.0.0/8, fd00::/8", TRUST_PROXY: "1", INTERNAL_HOST: "10.0.0.5", PUBLIC_URL: "http://localhost:3002/mcp" }))
      .toMatchObject({ cacheTtlSeconds: 0, allowPrivateCidrs: ["10.0.0.0/8", "fd00::/8"], trustProxy: 1, internalHost: "10.0.0.5", publicUrl: "http://localhost:3002/mcp" });
  });
  it("refuses a short token, an http public URL and a missing KEK", () => {
    expect(() => loadConfig({ ...base, GATEWAY_API_TOKEN: "short" })).toThrow();
    expect(() => loadConfig({ ...base, PUBLIC_URL: "http://vault.example/mcp" })).toThrow(/https/);
    expect(() => loadConfig({ ...base, GATEWAY_KEK: "" })).toThrow();
  });
  it("API_URL: https anywhere; http only on loopback, an internal name or a private literal", () => {
    for (const ok of ["https://api.example/app", "http://api:3001", "http://localhost:3001", "http://127.0.0.1:3001", "http://[::1]:3001", "http://vault-api.internal",
      "http://10.1.2.3", "http://172.16.0.1", "http://172.31.255.1", "http://192.168.1.1", "http://[fd00::1]", "http://[fc12::1]"])
      expect(loadConfig({ ...base, API_URL: ok }).apiUrl, ok).toBe(ok);
    for (const bad of ["http://api.example", "http://8.8.8.8", "http://172.32.0.1", "http://11.0.0.1", "http://[2001:db8::1]", "http://internal.example.com", "ftp://api"])
      expect(() => loadConfig({ ...base, API_URL: bad }), bad).toThrow(/API_URL/);
  });
  it("refuses a GATEWAY_ALLOW_PRIVATE_CIDRS entry that isn't a CIDR", () => {
    for (const bad of ["10.0.0.0", "10.0.0.0/8,nope", "10.0.0.0/33", "fd00::/200", "example.com/24"])
      expect(() => loadConfig({ ...base, GATEWAY_ALLOW_PRIVATE_CIDRS: bad }), bad).toThrow(/GATEWAY_ALLOW_PRIVATE_CIDRS/);
  });
  it("never echoes the token in an error", () => {
    const tok = "secret-token-value";
    expect(() => loadConfig({ ...base, GATEWAY_API_TOKEN: tok })).toThrow();
    try { loadConfig({ ...base, GATEWAY_API_TOKEN: tok }); } catch (e) { expect((e as Error).message).not.toContain(tok); }
  });
});
