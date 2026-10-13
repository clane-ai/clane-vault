import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { FastifyInstance } from "fastify";
import type { PrismaClient } from "@prisma/client";
import { buildApp } from "../src/app.js";
import type { Config } from "../src/config.js";

const config: Config = { productName: "Clane Vault", databaseUrl: "postgresql://x", jwtSecret: "j".repeat(40), serverSecret: "s".repeat(40), publicUrl: "http://localhost", cookieSecure: false, port: 0, kdfMinMemoryKiB: 1024, trustProxy: true };
let dir: string;
let app: FastifyInstance;

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "web-"));
  writeFileSync(join(dir, "index.html"), "<!doctype html><title>spa</title>");
  mkdirSync(join(dir, "assets"));
  writeFileSync(join(dir, "assets", "app-abc.js"), "console.log(1)");
  writeFileSync(join(dir, "sw.js"), "self.addEventListener('fetch', () => {})");
  writeFileSync(join(dir, "manifest.webmanifest"), JSON.stringify({ name: "Clane Vault" }));
  app = await buildApp({ config, prisma: {} as PrismaClient, webDist: dir });
});
afterAll(async () => { await app.close(); rmSync(dir, { recursive: true, force: true }); });

describe("web serving", () => {
  it("serves index at / and falls back for client routes", async () => {
    // Spaces in the path (/p/..., /o/:org/...), server pages and the older paths that redirect inside the app.
    for (const url of ["/", "/invite/abc", "/s/xyz?k=1", "/p/vault", "/p/vault/record/1", "/p/vault/folder/2", "/p/trash", "/o/acme/vault", "/o/acme/shared/record/1", "/o/acme/admin/people/8b1e5c1a-0c4b-4b8e-9a77-2f2d7a1c0e11",
      "/o/acme/admin/events?actor=a&action=folder.", "/o/acme/admin/org/sso", "/server/backups", "/settings", "/settings/security", "/vault/record/1", "/shared", "/admin", "/admin/server/backups"]) {
      const res = await app.inject({ method: "GET", url });
      expect(res.statusCode, url).toBe(200);
      expect(res.body).toContain("<title>spa</title>");
      expect(res.headers["cache-control"]).toBe("no-cache");
    }
  });
  it("serves assets with long cache and 404s missing files", async () => {
    const ok = await app.inject({ method: "GET", url: "/assets/app-abc.js" });
    expect(ok.statusCode).toBe(200);
    expect(ok.headers["cache-control"]).toContain("immutable");
    expect((await app.inject({ method: "GET", url: "/assets/missing.js" })).statusCode).toBe(404);
  });
  it("serves the service worker uncached and the manifest with its type (installable PWA)", async () => {
    const sw = await app.inject({ method: "GET", url: "/sw.js" });
    expect(sw.statusCode).toBe(200);
    expect(sw.headers["content-type"]).toMatch(/^(text|application)\/javascript/);
    expect(sw.headers["cache-control"]).toBe("no-cache, max-age=0");
    expect(sw.headers["service-worker-allowed"]).toBe("/");
    const m = await app.inject({ method: "GET", url: "/manifest.webmanifest" });
    expect(m.statusCode).toBe(200);
    expect(m.headers["content-type"]).toContain("application/manifest+json");
    expect(m.headers["cache-control"]).toBe("no-cache");
  });
  it("sets security headers, HSTS only over https", async () => {
    const res = await app.inject({ method: "GET", url: "/" });
    expect(res.headers["content-security-policy"]).toContain("frame-ancestors 'none'");
    expect(res.headers["content-security-policy"]).toContain("worker-src 'self'; manifest-src 'self'");
    expect(res.headers["x-content-type-options"]).toBe("nosniff");
    expect(res.headers["referrer-policy"]).toBe("no-referrer");
    expect(res.headers["x-frame-options"]).toBe("DENY");
    expect(res.headers["permissions-policy"]).toBe("camera=(), microphone=(), geolocation=()");
    expect(res.headers["strict-transport-security"]).toBeUndefined();
    const s = await app.inject({ method: "GET", url: "/", headers: { "x-forwarded-proto": "https" } });
    expect(s.headers["strict-transport-security"]).toBe("max-age=31536000");
  });
  it("honours a numeric TRUST_PROXY hop count (Fastify ignores plain numbers)", async () => {
    for (const hops of [1, 2]) {
      const a = await buildApp({ config: { ...config, trustProxy: hops }, prisma: {} as PrismaClient, webDist: dir });
      a.get("/api/v1/_whoami", async (req) => ({ ip: req.ip, protocol: req.protocol }));
      const headers = { "x-forwarded-proto": "https", "x-forwarded-for": "6.6.6.6, 1.2.3.4, 10.10.10.2" };
      const who = (await a.inject({ method: "GET", url: "/api/v1/_whoami", headers, remoteAddress: "172.20.0.5" })).json();
      expect(who).toEqual({ ip: hops === 2 ? "1.2.3.4" : "10.10.10.2", protocol: "https" });
      const page = await a.inject({ method: "GET", url: "/", headers, remoteAddress: "172.20.0.5" });
      expect(page.headers["strict-transport-security"]).toBe("max-age=31536000");
      await a.close();
    }
    const off = await buildApp({ config: { ...config, trustProxy: false }, prisma: {} as PrismaClient, webDist: dir });
    off.get("/api/v1/_whoami", async (req) => ({ ip: req.ip, protocol: req.protocol }));
    expect((await off.inject({ method: "GET", url: "/api/v1/_whoami", headers: { "x-forwarded-proto": "https", "x-forwarded-for": "6.6.6.6" }, remoteAddress: "172.20.0.5" })).json()).toEqual({ ip: "172.20.0.5", protocol: "http" });
    await off.close();
  });
  it("does not swallow /api: unknown routes stay JSON 404 with no-store", async () => {
    const res = await app.inject({ method: "GET", url: "/api/v1/nope" });
    expect(res.statusCode).toBe(404);
    expect(res.headers["content-type"]).toContain("application/json");
    expect(res.headers["cache-control"]).toBe("no-store");
    expect(res.headers["content-security-policy"]).toBeUndefined();
    expect((await app.inject({ method: "POST", url: "/somewhere" })).statusCode).toBe(404);
  });
});
