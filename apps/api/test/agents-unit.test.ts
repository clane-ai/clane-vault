import { describe, expect, it } from "vitest";
import { loadConfig } from "../src/config.js";

const baseEnv = { DATABASE_URL: "postgres://u:p@localhost:5432/db", JWT_SECRET: "j".repeat(32), SERVER_SECRET: "s".repeat(32), PUBLIC_URL: "http://localhost:5173" };
const pem = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg\n-----END PRIVATE KEY-----\n";
const agentEnv = { GATEWAY_INTERNAL_URL: "http://gateway:3003", GATEWAY_PUBLIC_URL: "https://vault.example/mcp", GATEWAY_API_TOKEN: "t".repeat(32), AGENT_TOKEN_PRIVATE_KEY: pem };

describe("agent config", () => {
  it("is off without GATEWAY_* variables", () => {
    expect(loadConfig({ ...baseEnv }).agents).toBeUndefined();
  });
  it("is on with all four, turning a literal \n into a newline", () => {
    const a = loadConfig({ ...baseEnv, ...agentEnv, AGENT_TOKEN_PRIVATE_KEY: pem.replace(/\n/g, "\n") }).agents!;
    expect(a.gatewayPublicUrl).toBe("https://vault.example/mcp");
    expect(a.tokenPrivateKeyPem).toBe(pem);
    expect(a.acceptNewGatewayIdentity).toBe(false);
    expect(loadConfig({ ...baseEnv, ...agentEnv, GATEWAY_ACCEPT_NEW_IDENTITY: "true" }).agents!.acceptNewGatewayIdentity).toBe(true);
  });
  it("throws when only some are set", () => {
    expect(() => loadConfig({ ...baseEnv, GATEWAY_INTERNAL_URL: "http://gateway:3003" })).toThrow(/go together/);
    expect(() => loadConfig({ ...baseEnv, GATEWAY_API_TOKEN: "t".repeat(32) })).toThrow(/go together/);
  });
  it("throws on a short token or a non-PEM key", () => {
    expect(() => loadConfig({ ...baseEnv, ...agentEnv, GATEWAY_API_TOKEN: "t".repeat(31) })).toThrow();
    expect(() => loadConfig({ ...baseEnv, ...agentEnv, AGENT_TOKEN_PRIVATE_KEY: "nope" })).toThrow(/PKCS#8/);
  });
});
