import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { redactInviteUrl, serializeReq } from "../src/app.js";
import { loadConfig } from "../src/config.js";
import { makeTestApp, resetDb, createActiveUser } from "./helpers.js";

const t = await makeTestApp();
afterAll(() => t.app.close());
beforeEach(() => resetDb(t.prisma));

describe("TRUST_PROXY", () => {
  const base = { DATABASE_URL: "postgresql://a:b@localhost/db", JWT_SECRET: "x".repeat(32), SERVER_SECRET: "y".repeat(32), PUBLIC_URL: "http://localhost" };
  it("defaults to false and parses true or a hop count", () => {
    expect(loadConfig(base).trustProxy).toBe(false);
    expect(loadConfig({ ...base, TRUST_PROXY: "true" }).trustProxy).toBe(true);
    expect(loadConfig({ ...base, TRUST_PROXY: "1" }).trustProxy).toBe(1);
    expect(() => loadConfig({ ...base, TRUST_PROXY: "maybe" })).toThrow();
  });
  it("rejects placeholder secrets in production only", () => {
    const ph = { ...base, JWT_SECRET: "change-me-" + "x".repeat(30) };
    expect(() => loadConfig({ ...ph, NODE_ENV: "production" })).toThrow(/JWT_SECRET/);
    expect(() => loadConfig({ ...base, SERVER_SECRET: "change-me-" + "y".repeat(30), NODE_ENV: "production" })).toThrow(/SERVER_SECRET/);
    expect(loadConfig({ ...ph, NODE_ENV: "development" }).jwtSecret).toBe(ph.JWT_SECRET);
    expect(loadConfig({ ...base, NODE_ENV: "production" }).jwtSecret).toBe(base.JWT_SECRET);
  });
  it("ignores a spoofed X-Forwarded-For by default", async () => {
    const u = await createActiveUser(t);
    await t.app.inject({ method: "POST", url: "/api/v1/auth/login", headers: { "x-forwarded-for": "9.9.9.9" }, payload: { email: u.email, authKey: "AAAA", code: "1" } });
    const ev = await t.prisma.event.findFirst({ where: { actorId: u.id, action: "auth.login_failed" } });
    expect(ev?.ip).toBe("127.0.0.1");
  });
});

describe("log redaction", () => {
  it("redacts invite tokens in request urls", () => {
    expect(redactInviteUrl("/api/v1/auth/invite/abc_DEF-123?x=1")).toBe("/api/v1/auth/invite/[redacted]?x=1");
    expect(redactInviteUrl("/api/v1/sync")).toBe("/api/v1/sync");
    const out = serializeReq({ method: "GET", url: "/api/v1/auth/invite/SECRETTOKEN", ip: "1.2.3.4" });
    expect(JSON.stringify(out)).not.toContain("SECRETTOKEN");
    expect(out.url).toBe("/api/v1/auth/invite/[redacted]");
  });
});
