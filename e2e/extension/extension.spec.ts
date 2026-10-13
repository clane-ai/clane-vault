import { chromium, expect, test, type BrowserContext, type Worker } from "@playwright/test";
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import path from "node:path";

/**
 * Loads the unpacked Chromium build (dist/chrome-e2e) and drives it against a tiny fake API that also serves a login
 * page: sign in from the popup, fill the page, lock. The vault data is real ciphertext made by @clane-vault/crypto.
 */
const root = path.resolve(import.meta.dirname, "../..");
const extDir = path.join(root, "apps/extension/dist/chrome-e2e");
const PASSWORD = "e2e master password";
const EMAIL = "ana@example.com";

test.skip(!existsSync(path.join(extDir, "manifest.json")), "build it first: npm run build -w apps/extension -- --e2e");

let server: Server, base: string, ctx: BrowserContext, sw: Worker, extId: string;

test.beforeAll(async () => {
  server = createServer();
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const fx = JSON.parse(execFileSync("npx", ["tsx", "apps/extension/scripts/e2e-fixture.ts"], { cwd: root, shell: true, encoding: "utf8", env: { ...process.env, FIXTURE_PASSWORD: PASSWORD, FIXTURE_URL: base } })) as
    { material: Record<string, unknown>; authKey: string; record: { id: string; encBody: string; wrappedRecordKey: string } };
  let access = "a1", refresh = "r1";
  server.on("request", (req, res) => {
    let raw = "";
    req.on("data", (c) => { raw += c; });
    req.on("end", () => {
      const send = (status: number, body?: unknown, type = "application/json") => { res.writeHead(status, { "content-type": type }); res.end(body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body)); };
      const body = raw ? JSON.parse(raw) as Record<string, string> : {};
      const view = () => ({ accessToken: access, refreshToken: refresh, user: { id: "u1", email: EMAIL, name: "Ana" }, material: fx.material, orgs: [{ id: "6f1c1c2e-0000-4000-8000-000000000001", name: "Acme", slug: "acme", role: "member", isDefault: true }] });
      switch (req.url) {
        case "/login.html": return send(200, `<!doctype html><title>Example sign-in</title><form id="f" onsubmit="return false"><input id="u" name="email" type="email"><input id="p" type="password" name="password"><button>Sign in</button></form>`, "text/html");
        case "/api/v1/auth/prelogin": return send(200, { kdfSalt: fx.material.kdfSalt, kdfParams: fx.material.kdfParams });
        case "/api/v1/auth/login":
          if (body.email !== EMAIL || body.authKey !== fx.authKey) return send(401, { error: "invalid_credentials" });
          if (!body.code) return send(401, { error: "totp_required" });
          if (body.client !== "extension") return send(400, { error: "invalid_request" });
          return send(200, view());
        case "/api/v1/auth/refresh": if (body.refreshToken !== refresh) return send(401, { error: "session_expired" }); access += "x"; refresh += "x"; return send(200, view());
        case "/api/v1/auth/logout": return send(204);
        case "/api/v1/sync":
          if (req.headers.authorization !== `Bearer ${access}`) return send(401, { error: "unauthorized" });
          return send(200, { serverTime: new Date().toISOString(), folders: [], records: [{ ...fx.record, folderId: null, type: "login", revision: 1, updatedAt: new Date().toISOString(), deletedAt: null, permission: "owner", holderType: "user", ownerId: "u1" }] });
        default: return send(404, { error: "not_found" });
      }
    });
  });
  ctx = await chromium.launchPersistentContext("", { channel: "chromium", headless: true, args: [`--disable-extensions-except=${extDir}`, `--load-extension=${extDir}`] });
  sw = ctx.serviceWorkers()[0] ?? await ctx.waitForEvent("serviceworker");
  extId = new URL(sw.url()).host;
});

test.afterAll(async () => { await ctx?.close(); server?.close(); });

test("sign in from the popup, fill a login form after the http warning, lock", async () => {
  const site = await ctx.newPage();
  await site.goto(`${base}/login.html`);
  const tabId = await sw.evaluate(async (u) => (await chrome.tabs.query({ url: u }))[0]!.id!, `${base}/login.html`);

  const popup = await ctx.newPage();
  await popup.setViewportSize({ width: 360, height: 560 });
  await popup.goto(`chrome-extension://${extId}/popup.html?tab=${tabId}`);
  await popup.getByLabel("Server address").fill(base);
  await popup.getByRole("button", { name: "Continue" }).click();

  await popup.getByLabel("Email").fill(EMAIL);
  await popup.getByLabel("Master password").fill(PASSWORD);
  await popup.getByRole("button", { name: "Sign in" }).click();
  await expect(popup.getByText("Enter the 6-digit code from your authenticator app.")).toBeVisible({ timeout: 60_000 });
  await popup.getByLabel("Authenticator code").fill("123456");
  await popup.getByRole("button", { name: "Sign in" }).click();

  await expect(popup.getByText("Example login")).toBeVisible({ timeout: 60_000 });
  await expect(popup.getByText(/^For 127\.0\.0\.1/)).toBeVisible();
  await popup.screenshot({ path: test.info().outputPath("popup-items.png") });
  await popup.getByRole("button", { name: "Fill", exact: true }).click();
  await expect(popup.getByText(/This page is not secure/)).toBeVisible();
  await popup.getByRole("button", { name: "Fill anyway" }).click();
  await expect(popup.getByText("Filled.")).toBeVisible();
  await expect(site.locator("#u")).toHaveValue("ana@example.com");
  await expect(site.locator("#p")).toHaveValue("hunter2-e2e");

  // Keys live in storage.session only; storage.local holds settings.
  const local = await sw.evaluate(async () => JSON.stringify(await chrome.storage.local.get(null)));
  expect(local).not.toMatch(/userKey|privateKey|refreshToken|hunter2/);

  await popup.getByRole("button", { name: "Lock" }).click();
  await expect(popup.getByRole("heading", { name: "Vault locked" })).toBeVisible();
  await popup.getByLabel("Master password").fill(PASSWORD);
  await popup.getByRole("button", { name: "Unlock" }).click();
  await expect(popup.getByText("Example login")).toBeVisible({ timeout: 60_000 });
});
