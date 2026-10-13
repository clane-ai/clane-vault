import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { FastifyInstance } from "fastify";
import type { PrismaClient } from "@prisma/client";
import { createAccount } from "@clane-vault/crypto";
import { buildApp } from "../src/app.js";
import { apiPrefix, loadConfig, normaliseBasePath, resolveBasePath, type Config } from "../src/config.js";
import { renderIndex } from "../src/plugins/web.js";
import { redirectUri, ssoCookiePath } from "../src/lib/sso.js";
import { createInvite, FAST_KDF, freshTotp, makeTestApp } from "./helpers.js";

const env = { DATABASE_URL: "postgresql://u:p@localhost:5432/db", JWT_SECRET: "j".repeat(40), SERVER_SECRET: "s".repeat(40) };

describe("BASE_PATH / PUBLIC_URL", () => {
  it("normalises: leading slash, no trailing slash, root is empty", () => {
    expect(normaliseBasePath("")).toBe("");
    expect(normaliseBasePath("/")).toBe("");
    expect(normaliseBasePath("vault")).toBe("/vault");
    expect(normaliseBasePath("/vault/")).toBe("/vault");
    expect(normaliseBasePath("//a//b.c~_-/")).toBe("/a/b.c~_-");
    for (const bad of ["/va ult", "/v%20", "/a/../b", "/./x", "/x?y", "/x#y", "/ü"]) expect(() => normaliseBasePath(bad), bad).toThrow(/BASE_PATH/);
  });
  it("derives the base path from PUBLIC_URL when BASE_PATH is unset", () => {
    expect(loadConfig({ ...env, PUBLIC_URL: "https://northwind.example.com/vault/" })).toMatchObject({ basePath: "/vault", publicUrl: "https://northwind.example.com/vault" });
    expect(loadConfig({ ...env, PUBLIC_URL: "https://vault.example.com" })).toMatchObject({ basePath: "", publicUrl: "https://vault.example.com" });
    expect(loadConfig({ ...env, PUBLIC_URL: "https://vault.example.com/", BASE_PATH: "" })).toMatchObject({ basePath: "", publicUrl: "https://vault.example.com" });
  });
  it("accepts BASE_PATH that matches PUBLIC_URL's path and refuses one that doesn't", () => {
    expect(loadConfig({ ...env, PUBLIC_URL: "https://h/vault", BASE_PATH: "vault/" })).toMatchObject({ basePath: "/vault", publicUrl: "https://h/vault" });
    expect(() => loadConfig({ ...env, PUBLIC_URL: "https://h", BASE_PATH: "/vault" })).toThrow(/must equal BASE_PATH.*PUBLIC_URL=https:\/\/h\/vault/);
    expect(() => loadConfig({ ...env, PUBLIC_URL: "https://h/other", BASE_PATH: "/vault" })).toThrow(/must equal BASE_PATH/);
    expect(() => loadConfig({ ...env, PUBLIC_URL: "https://h/v?x=1" })).toThrow(/query/);
    expect(() => resolveBasePath("https://h/a b")).toThrow(/BASE_PATH/);
  });
  it("puts the API, cookies and the SSO redirect URI under the base path", () => {
    const c = { basePath: "/vault", publicUrl: "https://h/vault" } as Config;
    expect(apiPrefix(c)).toBe("/vault/api/v1");
    expect(apiPrefix({})).toBe("/api/v1");
    expect(ssoCookiePath(c)).toBe("/vault/api/v1/auth/sso");
    expect(redirectUri(c)).toBe("https://h/vault/api/v1/auth/sso/callback");
  });
});

describe("index.html for a base path", () => {
  const built = `<!doctype html>\n<html lang="en">\n  <head>\n    <meta charset="UTF-8" />\n    <link rel="icon" href="./brand/favicon.ico" />\n    <link rel="manifest" href="./manifest.webmanifest" />\n    <script type="module" crossorigin src="./assets/index-abc.js"></script>\n    <link rel="stylesheet" href="/assets/index-abc.css">\n    <a href="https://example.com/x">x</a><a href="//cdn/x">y</a>\n  </head>\n</html>`;
  it("rewrites local references to the base and adds the meta tag (no <base>, no inline script)", () => {
    const out = renderIndex(built, "/vault");
    expect(out).toContain(`<meta name="clane-base" content="/vault" />`);
    expect(out).toContain(`href="/vault/brand/favicon.ico"`);
    expect(out).toContain(`href="/vault/manifest.webmanifest"`);
    expect(out).toContain(`src="/vault/assets/index-abc.js"`);
    expect(out).toContain(`href="/vault/assets/index-abc.css"`);
    expect(out).toContain(`href="https://example.com/x"`);
    expect(out).toContain(`href="//cdn/x"`);
    expect(out).not.toMatch(/<base|<script>/);
  });
  it("at the root, references are root-absolute as before", () => {
    const out = renderIndex(built, "");
    expect(out).toContain(`<meta name="clane-base" content="" />`);
    expect(out).toContain(`src="/assets/index-abc.js"`);
    expect(out).toContain(`href="/brand/favicon.ico"`);
  });
});

const config: Config = { productName: "Clane Vault", basePath: "/vault", databaseUrl: "postgresql://x", jwtSecret: "j".repeat(40), serverSecret: "s".repeat(40), publicUrl: "http://localhost/vault", cookieSecure: false, port: 0, kdfMinMemoryKiB: 1024, trustProxy: false };

describe("web serving under /vault", () => {
  let dir: string;
  let app: FastifyInstance;
  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), "web-base-"));
    writeFileSync(join(dir, "index.html"), `<!doctype html><html><head><title>spa</title><script type="module" src="./assets/app-abc.js"></script></head></html>`);
    mkdirSync(join(dir, "assets"));
    writeFileSync(join(dir, "assets", "app-abc.js"), "console.log(1)");
    writeFileSync(join(dir, "sw.js"), "self.addEventListener('fetch', () => {})");
    writeFileSync(join(dir, "manifest.webmanifest"), JSON.stringify({ name: "Clane Vault", start_url: "./", scope: "./" }));
    app = await buildApp({ config, prisma: {} as PrismaClient, webDist: dir });
    app.get("/vault/api/v1/_ping", async () => ({ ok: true }));
  });
  afterAll(async () => { await app.close(); rmSync(dir, { recursive: true, force: true }); });

  it("serves index.html with the base injected, for the base and every deep link under it", async () => {
    for (const url of ["/vault/", "/vault/index.html", "/vault/p/vault", "/vault/p/vault/record/1", "/vault/o/acme/admin/people/8b1e", "/vault/settings/security", "/vault/s/xyz?k=1", "/vault/invite/abc", "/vault/sso/complete"]) {
      const res = await app.inject({ method: "GET", url });
      expect(res.statusCode, url).toBe(200);
      expect(res.headers["content-type"], url).toContain("text/html");
      expect(res.body, url).toContain(`<meta name="clane-base" content="/vault" />`);
      expect(res.body, url).toContain(`src="/vault/assets/app-abc.js"`);
      expect(res.headers["cache-control"], url).toBe("no-cache");
      expect(res.headers["content-security-policy"], url).toContain("base-uri 'none'");
    }
  });
  it("redirects the base without a trailing slash to the base with one (keeping the query)", async () => {
    const r = await app.inject({ method: "GET", url: "/vault" });
    expect(r.statusCode).toBe(301);
    expect(r.headers.location).toBe("/vault/");
    expect((await app.inject({ method: "GET", url: "/vault?x=1" })).headers.location).toBe("/vault/?x=1");
  });
  it("serves assets, the service worker (scope /vault/) and the manifest under the base", async () => {
    const a = await app.inject({ method: "GET", url: "/vault/assets/app-abc.js" });
    expect(a.statusCode).toBe(200);
    expect(a.headers["cache-control"]).toContain("immutable");
    expect((await app.inject({ method: "GET", url: "/vault/assets/missing.js" })).statusCode).toBe(404);
    const sw = await app.inject({ method: "GET", url: "/vault/sw.js" });
    expect(sw.statusCode).toBe(200);
    expect(sw.headers["cache-control"]).toBe("no-cache, max-age=0");
    expect(sw.headers["service-worker-allowed"]).toBe("/vault/");
    const m = await app.inject({ method: "GET", url: "/vault/manifest.webmanifest" });
    expect(m.statusCode).toBe(200);
    expect(m.headers["content-type"]).toContain("application/manifest+json");
  });
  it("serves nothing outside the base: the root, root assets and the root API are 404", async () => {
    for (const url of ["/", "/index.html", "/p/vault", "/assets/app-abc.js", "/sw.js", "/manifest.webmanifest", "/api/v1/health", "/api/v1/_ping", "/vaultx", "/vaultx/p"]) {
      expect((await app.inject({ method: "GET", url })).statusCode, url).toBe(404);
    }
  });
  it("the API lives under the base; unknown API routes stay JSON 404 with no-store and no CSP", async () => {
    expect((await app.inject({ method: "GET", url: "/vault/api/v1/_ping" })).json()).toEqual({ ok: true });
    const res = await app.inject({ method: "GET", url: "/vault/api/v1/nope" });
    expect(res.statusCode).toBe(404);
    expect(res.headers["content-type"]).toContain("application/json");
    expect(res.headers["cache-control"]).toBe("no-store");
    expect(res.headers["content-security-policy"]).toBeUndefined();
  });
});

describe("API under /vault with a database", () => {
  let t: Awaited<ReturnType<typeof makeTestApp>>;
  let app: FastifyInstance;
  beforeAll(async () => {
    t = await makeTestApp();
    app = await buildApp({ config: { ...t.config, basePath: "/vault", publicUrl: "http://localhost:5173/vault" }, prisma: t.prisma });
  });
  afterAll(async () => { await app.close(); await t.app.close(); });

  it("health is at /vault/api/v1/health and not at /api/v1/health", async () => {
    expect((await app.inject({ method: "GET", url: "/vault/api/v1/health" })).json()).toEqual({ ok: true, db: true });
    expect((await app.inject({ method: "GET", url: "/api/v1/health" })).statusCode).toBe(404);
  });
  it("scopes the refresh cookie to /vault/api/v1/auth, and refresh and logout work there", async () => {
    const email = "base-path@clane.ai";
    const inviteToken = await createInvite(t.prisma, email);
    const acct = await createAccount("password for base path", FAST_KDF);
    const ip = "10.99.0.1";
    const reg = await app.inject({ remoteAddress: ip, method: "POST", url: "/vault/api/v1/auth/register", payload: { inviteToken, name: "base", authKey: acct.authKey, material: acct.material } });
    expect(reg.statusCode).toBe(201);
    const auth = { authorization: `Bearer ${reg.json().setupToken}` };
    const setup = await app.inject({ remoteAddress: ip, method: "POST", url: "/vault/api/v1/auth/totp/setup", headers: auth, payload: {} });
    const verify = await app.inject({ remoteAddress: ip, method: "POST", url: "/vault/api/v1/auth/totp/verify", headers: auth, payload: { code: await freshTotp(setup.json().secret) } });
    const c = verify.cookies.find((x) => x.name === "cv_refresh")!;
    expect(c).toMatchObject({ httpOnly: true, sameSite: "Strict", path: "/vault/api/v1/auth" });
    const refreshed = await app.inject({ remoteAddress: ip, method: "POST", url: "/vault/api/v1/auth/refresh", headers: { cookie: `cv_refresh=${c.value}` } });
    expect(refreshed.statusCode).toBe(200);
    const c2 = refreshed.cookies.find((x) => x.name === "cv_refresh")!;
    expect(c2.path).toBe("/vault/api/v1/auth");
    const out = await app.inject({ remoteAddress: ip, method: "POST", url: "/vault/api/v1/auth/logout", headers: { cookie: `cv_refresh=${c2.value}` } });
    expect(out.statusCode).toBe(204);
    expect(out.cookies.find((x) => x.name === "cv_refresh")?.path).toBe("/vault/api/v1/auth");
  });
});
