import { readFileSync } from "node:fs";
import { createServer, type IncomingHttpHeaders, type Server } from "node:http";
import path from "node:path";
import type { AddressInfo } from "node:net";
import { expect, test, type Browser, type Page } from "@playwright/test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { adminPage, newInvite, newOrg, newSharedFolder, saveRecoveryKit, setAgentUse, settingsPage, switchSpace, totp } from "../helpers";

// Personal agents, Phase A end to end (docs/design/2026-11-15-personal-agents.md §3): a member (not an admin) enrols an
// agent of their own, gives it one Personal item at Can use, uses it over MCP; the admin sees lifecycle only, can suspend it
// by policy; Phase B (§4): the agent saves a secret to the owner's inbox, which the owner keeps, updates one it may update
// (the owner restores the previous value) and captures a credential an upstream creates; a move into a team folder takes the
// item away; Phase E (§10): a .env file item whose one entry the agent uses, a newer copy the agent saves that replaces its
// contents, and an entry the agent changes that the owner restores. Phase C (§5): the agent reads a value the owner
// allowed, after the owner approves it in the web app; Phase D (§5.6): reading without approval once the admin's policy,
// the gateway (GATEWAY_REVEAL=standing) and the item's own setting all allow it; revoke ends it.
test.describe.configure({ mode: "serial" });

const PW = "an e2e master password";
const CANARY = "sk_test_PERSONAL_CANARY";
const SAVED = "sk_test_SAVED_CANARY";
const UPDATED = "sk_test_UPDATED_CANARY";
const CAPTURED = "tok_CAPTURED_CANARY";
// CRLF line endings, a comment, export, a two-line quoted value, a duplicate key and a line that isn't KEY=value.
const ENV_FILE = readFileSync(path.join(import.meta.dirname, "fixtures", "sample.env"));
const ENV_CANARY = "sk_test_ENV_CANARY_1";
const ENV_CANARY_2 = "sk_test_ENV_CANARY_2";
const KEY_ID = "acct_e2e_KEYID_42";
const AGENT_WARNING = "Give agents restricted credentials: a Stripe restricted key, a read-only database user, a scoped token. Never a root or owner credential. What you share here can be read by the gateway and used by whatever drives the agent.";
const MCP_URL = `http://localhost:${process.env.E2E_GATEWAY_PORT ?? 3002}/mcp`;
const id = `${Date.now()}-${Math.floor(Math.random() * 1e4)}`;
const MEMBER = `Member ${id}`;

async function register(page: Page, invitePath: string, name: string) {
  await page.goto(invitePath);
  await page.getByLabel("Your name").fill(name);
  await page.getByLabel("Master password", { exact: true }).fill(PW);
  await page.getByLabel("Repeat master password").fill(PW);
  await page.getByRole("button", { name: "Create account" }).click();
  const keyText = await page.getByText(/Enter this key:\s*[A-Z2-7]{16,}/).textContent({ timeout: 60_000 });
  await page.getByLabel("6-digit code").fill(await totp(keyText!.split(":")[1]!.trim()));
  await page.getByRole("button", { name: "Turn on and continue" }).click();
  await saveRecoveryKit(page);
  await expect(page.getByRole("button", { name: "New", exact: true })).toBeVisible({ timeout: 30_000 });
}

async function mcp(token: string): Promise<Client> {
  const client = new Client({ name: "e2e-personal", version: "1.0.0" });
  await client.connect(new StreamableHTTPClientTransport(new URL(MCP_URL), { requestInit: { headers: { Authorization: `Bearer ${token}` } } }));
  return client;
}
/** One tool call on a fresh MCP session: its structured result. */
async function call(token: string, name: string, args: Record<string, unknown>): Promise<Record<string, unknown>> {
  const c = await mcp(token);
  try { return (await c.callTool({ name, arguments: args })).structuredContent as Record<string, unknown>; } finally { await c.close().catch(() => {}); }
}
const listSecrets = async (token: string) => { const c = await mcp(token); try { return JSON.stringify(await c.callTool({ name: "list_secrets", arguments: {} })); } finally { await c.close().catch(() => {}); } };
/**
 * The HTTP status of a tool call on a fresh MCP session: 200 while the agent works, 401 once it is suspended or revoked.
 * A suspension shows at the first call that reaches the API's agent routes, as an expiry does (initialize alone still works).
 */
const callStatus = (token: string) => listSecrets(token).then(() => 200, (e: { code?: number }) => e.code ?? 0);

// Its own upstream on its own (OS-chosen) port, apart from agents.spec.ts's: echo.test maps to 127.0.0.1 in the gateway.
let echo: Server;
let echoPort = 0;
const received: IncomingHttpHeaders[] = [];
let admin: Page;
let member: Page;
let token = "";

test.beforeAll(async ({ browser }: { browser: Browser }) => {
  echo = createServer((req, res) => {
    received.push(req.headers);
    // An upstream that creates a credential: what `capture` saves.
    if (req.method === "POST" && req.url === "/token") return void res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ token: CAPTURED }));
    res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ path: req.url, headers: req.headers }));
  });
  await new Promise<void>((ok) => echo.listen(0, "127.0.0.1", ok));
  echoPort = (echo.address() as AddressInfo).port;
  const ctx = () => browser.newContext({ viewport: { width: 1440, height: 900 }, permissions: ["clipboard-read", "clipboard-write"] });
  admin = await (await ctx()).newPage();
  member = await (await ctx()).newPage();
  const org = newOrg(`Personal agents ${id}`);
  await register(admin, newInvite(`e2e-pa-owner-${id}@clane.ai`, "owner", org), "PA Owner");
  await register(member, newInvite(`e2e-pa-member-${id}@clane.ai`, "member", org), MEMBER);
});
// The member's page is the one most steps drive: keep what it showed when a step fails.
test.afterEach(async ({}, info) => { if (info.status !== info.expectedStatus) await member?.screenshot({ path: info.outputPath("member.png") }).catch(() => {}); });
test.afterAll(async () => {
  await admin?.context().close();
  await member?.context().close();
  await new Promise<void>((ok) => echo.close(() => ok()));
});

async function unlock(p: Page) {
  await p.reload();
  await p.getByLabel("Master password").fill(PW);
  await p.getByRole("button", { name: "Unlock" }).click();
}
const fromAgents = (p: Page) => p.getByRole("link", { name: /^From agents/ });
/** The Personal vault's "No folder" list (opened unless it already is), then the record titled `title`. */
async function openRecord(p: Page, title: string) {
  await p.getByRole("link", { name: /^Vault/ }).click();
  const row = p.getByRole("button", { name: new RegExp(title) });
  if (!(await row.isVisible())) await p.getByRole("button", { name: /^No folder/ }).click();
  await row.click();
  await expect(p.getByRole("heading", { name: title })).toBeVisible({ timeout: 30_000 });
}
const secretShown = async (p: Page, value: string) => {
  const details = p.getByRole("complementary", { name: "Record details" });
  await details.getByRole("button", { name: "Show secret" }).click();
  await expect(details.getByLabel("Secret", { exact: true })).toHaveText(value, { timeout: 30_000 });
};

const myAgentRow = (p: Page) => p.getByRole("list", { name: "My agents" }).getByRole("listitem", { name: "My helper" });

test("1. the member creates and verifies a personal agent", async () => {
  await settingsPage(member, "My agents");
  await member.getByRole("button", { name: "New agent" }).click();
  await member.getByLabel("Name").fill("My helper");
  await member.getByRole("button", { name: "Create" }).click();
  const verify = member.getByRole("dialog", { name: "Verify My helper" });
  const fingerprints = verify.locator("dd");
  await expect(fingerprints).toHaveCount(2, { timeout: 30_000 });
  for (const fp of await fingerprints.all()) await expect(fp).toHaveText(/[0-9A-Za-z]{4}/);
  await verify.getByRole("button", { name: "Matches" }).click();
  await expect(verify).toHaveCount(0, { timeout: 30_000 });
  await expect(myAgentRow(member).getByText("Active", { exact: true })).toBeVisible({ timeout: 30_000 });
});

test("2. a Personal API key item, given to the agent at Can use, under the warning", async () => {
  await member.getByRole("link", { name: /^Vault/ }).click();
  await expect(member).toHaveURL(/\/p\/vault$/);
  await member.getByRole("button", { name: "New", exact: true }).click();
  await member.getByRole("menuitem", { name: "Record", exact: true }).click();
  const newDlg = member.getByRole("dialog");
  await newDlg.getByRole("combobox", { name: "Record Type" }).click();
  await member.getByRole("option", { name: "API key / secret" }).click();
  await newDlg.getByLabel("Title").fill("Echo");
  await newDlg.getByRole("button", { name: "Next" }).click();
  await member.getByLabel("Secret", { exact: true }).and(member.locator("input")).fill(CANARY);
  await member.getByLabel("Key ID", { exact: true }).fill(KEY_ID);
  await member.getByRole("button", { name: "Save" }).click();
  await expect(member.getByRole("button", { name: "Save" })).toHaveCount(0, { timeout: 30_000 });
  await member.getByRole("button", { name: /^No folder/ }).click();
  await member.getByRole("button", { name: /Echo/ }).click();
  await expect(member.getByRole("heading", { name: "Echo" })).toBeVisible({ timeout: 30_000 });
  await setAgentUse(member, `echo.test:${echoPort}`);

  await member.getByRole("button", { name: "Share", exact: true }).click();
  const agents = member.getByRole("dialog").getByRole("region", { name: "Agents" });
  await expect(agents.getByRole("note", { name: "Sharing with an agent" })).toContainText(AGENT_WARNING);
  await agents.getByRole("combobox", { name: "Access for My helper" }).click();
  await member.getByRole("option", { name: "Can use", exact: true }).click();
  await expect(agents.getByRole("combobox", { name: "Access for My helper" })).toHaveText("Can use", { timeout: 30_000 });
  await expect(agents.getByRole("alert")).toHaveCount(0);
  await member.keyboard.press("Escape");
});

test("3. over MCP the agent lists personal/echo without its value and uses it, scrubbed", async () => {
  await settingsPage(member, "My agents");
  await myAgentRow(member).getByRole("button", { name: "Connect My helper" }).click();
  const tokens = member.getByRole("region", { name: "API tokens" });
  await tokens.getByRole("button", { name: "Create API token" }).click();
  token = (await tokens.locator("code").filter({ hasText: /^cvat_/ }).textContent({ timeout: 30_000 }))!.trim();
  expect(token).toMatch(/^cvat_[^_]+_[A-Za-z0-9_-]{43}$/);
  await member.keyboard.press("Escape");

  const client = await mcp(token);
  const listed = JSON.stringify(await client.callTool({ name: "list_secrets", arguments: {} }));
  expect(listed).toContain("personal/echo");
  expect(listed).not.toContain(CANARY);
  const used = JSON.stringify(await client.callTool({ name: "http_request",
    arguments: { item: "personal/echo", method: "GET", url: `http://echo.test:${echoPort}/headers` } }));
  expect(received.at(-1)?.authorization).toBe(`Bearer ${CANARY}`);
  expect(used).toContain("[clane:redacted]");
  expect(used).not.toContain(CANARY);
  await client.close();
});

test("4. the owner sees the use; the admin sees only the lifecycle and a count", async () => {
  await member.reload();
  await member.getByLabel("Master password").fill(PW);
  await member.getByRole("button", { name: "Unlock" }).click();
  await myAgentRow(member).getByRole("button", { name: "Activity of My helper" }).click();
  const activity = member.getByRole("dialog", { name: "My helper: activity" });
  await expect(activity.getByRole("listitem").filter({ hasText: "agent.use" }).filter({ hasText: "Echo" })).toHaveCount(1, { timeout: 30_000 });
  await member.keyboard.press("Escape");

  await adminPage(admin, "Event log");
  await expect(admin.getByRole("row").filter({ hasText: "personal_agent.create" }).filter({ hasText: MEMBER })).toHaveCount(1, { timeout: 30_000 });
  await expect(admin.getByRole("row").filter({ hasText: /Echo|echo\.test/ })).toHaveCount(0);
  await adminPage(admin, "Agents");
  await expect(admin.getByRole("button", { name: "Personal agents: 1 across 1 member" })).toBeVisible({ timeout: 30_000 });
});

async function setPersonalAgents(allowed: boolean) {
  await adminPage(admin, "Policies");
  const block = admin.getByRole("region", { name: "Personal agents" });
  const sw = block.getByRole("switch", { name: "Members may use personal agents" });
  await expect(sw).toBeVisible({ timeout: 30_000 });
  if ((await sw.getAttribute("aria-checked")) !== String(allowed)) await sw.click();
  // The response, not the toast: the previous save's toast can still be showing.
  const saved = admin.waitForResponse((r) => r.url().endsWith("/admin/settings/policies/personal-agents") && r.request().method() === "PUT");
  await block.getByRole("button", { name: "Save personal agents" }).click();
  expect((await saved).ok()).toBe(true);
}

test("5. the organisation's policy suspends the agent, and lifts the suspension", async () => {
  await setPersonalAgents(false);
  expect(await callStatus(token)).toBe(401);
  await member.reload();
  await member.getByLabel("Master password").fill(PW);
  await member.getByRole("button", { name: "Unlock" }).click();
  await expect(myAgentRow(member).getByText(/^Suspended/)).toBeVisible({ timeout: 30_000 });

  await setPersonalAgents(true);
  expect(await callStatus(token)).toBe(200);
  expect(await listSecrets(token)).toContain("personal/echo");
});

let saved = "";

test("6. save_secret puts an item in From agents, not in the vault", async () => {
  const r = await call(token, "save_secret", { title: "Saved by agent", type: "apiKey", fields: { data: { secret: SAVED } } });
  expect(typeof r.item).toBe("string");
  saved = r.item as string;
  await unlock(member);
  await member.getByRole("link", { name: /^Vault/ }).click();
  await member.getByRole("button", { name: /^No folder/ }).click();
  await expect(member.getByRole("button", { name: /Echo/ })).toBeVisible({ timeout: 30_000 });
  await expect(member.getByRole("button", { name: /Saved by agent/ })).toHaveCount(0);
  await expect(fromAgents(member)).toHaveText(/From agents\s*1$/, { timeout: 30_000 });
});

test("7. the owner opens it, sees who saved it, and keeps it", async () => {
  await fromAgents(member).click();
  const card = member.getByRole("article", { name: "Saved by agent" });
  await expect(card).toBeVisible({ timeout: 30_000 });
  // The agent's name and the name of the token it used (step 3's, the default).
  await expect(card).toContainText("From My helper · via API token");
  await card.getByRole("button", { name: "Keep" }).click();
  await expect(member.getByRole("status").filter({ hasText: "Kept." })).toBeVisible({ timeout: 30_000 });
  await openRecord(member, "Saved by agent");
  await expect(member.getByText("Created by agent My helper")).toBeVisible();
  await secretShown(member, SAVED);
});

test("8. update_secret needs Agent can update; Restore previous undoes the change", async () => {
  expect(await call(token, "update_secret", { item: saved, set: { data: { secret: UPDATED } } })).toEqual({ error: "refused", reason: "not_writable" });
  await member.getByRole("button", { name: "Share", exact: true }).click();
  const agents = member.getByRole("dialog").getByRole("region", { name: "Agents" });
  const canUpdate = agents.getByRole("checkbox", { name: "Agent can update this item" });
  await canUpdate.click(); // controlled: checked once the change is saved
  await expect(canUpdate).toBeChecked({ timeout: 30_000 });
  await expect(agents.getByRole("alert")).toHaveCount(0);
  await member.keyboard.press("Escape");

  const r = await call(token, "update_secret", { item: saved, set: { data: { secret: UPDATED } } });
  expect(r).toMatchObject({ item: saved, revision: expect.any(Number) });
  await unlock(member);
  await openRecord(member, "Saved by agent");
  const banner = member.getByRole("note", { name: "Changed by agent" });
  await expect(banner).toContainText("Changed by agent My helper", { timeout: 30_000 });
  await secretShown(member, UPDATED);
  // This device has the gateway pinned: the change's u1 signature was checked, not skipped.
  await expect(banner).not.toContainText("This device hasn't verified your gateway");
  await banner.getByRole("button", { name: "Restore previous" }).click();
  await expect(banner).toHaveCount(0, { timeout: 30_000 });
  await expect(member.getByRole("complementary", { name: "Record details" }).getByLabel("Secret", { exact: true })).toHaveText(SAVED, { timeout: 30_000 });
});

test("9. http_request capture saves the upstream's new credential without showing it", async () => {
  const r = await call(token, "http_request", { item: "personal/echo", method: "POST", url: `http://echo.test:${echoPort}/token`,
    capture: { from: "/token", title: "Captured", type: "apiKey" } });
  expect((r.saved as { item?: unknown } | undefined)?.item).toEqual(expect.any(String));
  expect(JSON.stringify(r)).not.toContain(CAPTURED);
  await unlock(member);
  await fromAgents(member).click();
  const card = member.getByRole("article", { name: "Captured" });
  await expect(card).toBeVisible({ timeout: 30_000 });
  // The inbox shows no values: keep it to read its secret.
  await card.getByRole("button", { name: "Keep" }).click();
  await expect(member.getByRole("status").filter({ hasText: "Kept." })).toBeVisible({ timeout: 30_000 });
  await openRecord(member, "Captured");
  await secretShown(member, CAPTURED);
});

const envHandle = "personal/billing-env";
const details = (p: Page) => p.getByRole("complementary", { name: "Record details" });
/** The Authorization header the echo upstream received for one use of the env item. */
async function echoed(): Promise<string | undefined> {
  const used = JSON.stringify(await call(token, "http_request", { item: envHandle, method: "GET", url: `http://echo.test:${echoPort}/headers` }));
  expect(used).not.toContain("ENV_CANARY");
  return received.at(-1)?.authorization;
}

test("10. a .env file item: entries masked, a byte-identical download, found by key name only", async () => {
  await member.getByRole("link", { name: /^Vault/ }).click();
  await member.getByRole("button", { name: "New", exact: true }).click();
  await member.getByRole("menuitem", { name: ".env file" }).click();
  const newDlg = member.getByRole("dialog");
  await newDlg.getByLabel("Title").fill("Billing env");
  await newDlg.getByRole("button", { name: "Next" }).click();
  await member.getByTestId("env-input").setInputFiles({ name: ".env", mimeType: "text/plain", buffer: ENV_FILE });
  await expect(member.getByLabel("File name", { exact: true })).toHaveValue(".env");
  await expect(member.getByLabel("Environment", { exact: true })).toHaveValue("");
  await member.getByRole("button", { name: "Save" }).click();
  await expect(member.getByRole("button", { name: "Save" })).toHaveCount(0, { timeout: 30_000 });
  await openRecord(member, "Billing env");
  const entries = details(member).getByRole("list", { name: "Entries" });
  for (const k of ["STRIPE_KEY", "PORT", "CERT", "A"]) await expect(entries).toContainText(k);
  expect(await member.locator("body").innerText()).not.toContain(ENV_CANARY);
  await details(member).getByRole("button", { name: "Show STRIPE_KEY" }).click();
  await expect(details(member).getByLabel("STRIPE_KEY value")).toHaveText(ENV_CANARY);
  await details(member).getByRole("button", { name: "Hide STRIPE_KEY" }).click();

  const [dl] = await Promise.all([member.waitForEvent("download"), details(member).getByRole("button", { name: "Download" }).click()]);
  // A dot name follows the title's slug: Chromium would save ".env" as "env".
  expect(dl.suggestedFilename()).toBe("billing-env.env");
  expect(readFileSync(await dl.path()).equals(ENV_FILE)).toBe(true);

  const row = member.getByRole("button", { name: /Billing env/ });
  await member.getByLabel("Search records").fill("STRIPE_KEY");
  await expect(row).toBeVisible();
  await member.getByLabel("Search records").fill("sk_test_ENV");
  await expect(row).toHaveCount(0);
  await member.getByLabel("Search records").fill("");
});

test("11. the agent sees the keys, never a value, and sends the one entry its Agent use names", async () => {
  await openRecord(member, "Billing env");
  await setAgentUse(member, `echo.test:${echoPort}`, "STRIPE_KEY");

  await member.getByRole("button", { name: "Share", exact: true }).click();
  const agents = member.getByRole("dialog").getByRole("region", { name: "Agents" });
  await expect(agents.getByRole("note", { name: "Sharing with an agent" })).toContainText(AGENT_WARNING);
  await agents.getByRole("combobox", { name: "Access for My helper" }).click();
  await member.getByRole("option", { name: "Can use", exact: true }).click();
  await expect(agents.getByRole("combobox", { name: "Access for My helper" })).toHaveText("Can use", { timeout: 30_000 });
  await member.keyboard.press("Escape");

  const listed = await call(token, "list_secrets", {});
  const item = (listed.secrets as Record<string, unknown>[]).find((s) => s.handle === envHandle);
  expect(item).toMatchObject({ type: "envFile", env_keys: expect.arrayContaining(["STRIPE_KEY", "PORT"]), env_injects: "STRIPE_KEY" });
  expect(JSON.stringify(listed)).not.toContain("ENV_CANARY");
  expect(await echoed()).toBe(`Bearer ${ENV_CANARY}`);
});

test("12. a newer copy saved by the agent replaces the contents of Billing env", async () => {
  const r = await call(token, "save_secret", { type: "envFile", title: "Billing env (new)",
    fields: { data: { fileName: ".env", content: `STRIPE_KEY=${ENV_CANARY_2}\nPORT=3000\nNEW=1\n` } } });
  expect(typeof r.item).toBe("string");
  await unlock(member);
  await expect(fromAgents(member)).toHaveText(/From agents\s*1$/, { timeout: 30_000 });
  await fromAgents(member).click();
  const card = member.getByRole("article", { name: "Billing env (new)" });
  await expect(card).toBeVisible({ timeout: 30_000 });
  await expect(card.getByRole("list", { name: "Entries" }).getByRole("listitem")).toHaveCount(3);
  await expect(card.getByRole("radio", { name: "Replace the contents of" })).toBeChecked();
  await expect(card.getByRole("combobox", { name: "Item to replace" })).toHaveText("Billing env");
  const diff = card.getByRole("list", { name: "Differences" });
  await expect(diff).toContainText("Added: NEW");
  await expect(diff).toContainText("Changed: STRIPE_KEY");
  await expect(diff).toContainText("Removed: CERT, A");
  await card.getByRole("button", { name: "Replace", exact: true }).click();
  await expect(member.getByText("Replaced the contents of Billing env.")).toBeVisible({ timeout: 30_000 });
  await expect(fromAgents(member)).toHaveText(/From agents\s*0$/, { timeout: 30_000 });
  await openRecord(member, "Billing env");
  await expect(details(member).getByRole("list", { name: "Entries" })).toContainText("NEW");
  expect(await echoed()).toBe(`Bearer ${ENV_CANARY_2}`);
});

test("13. set.env needs Agent can update; Restore previous puts the entry back", async () => {
  const set = { item: envHandle, set: { env: { PORT: "8080" } } };
  expect(await call(token, "update_secret", set)).toEqual({ error: "refused", reason: "not_writable" });
  await member.getByRole("button", { name: "Share", exact: true }).click();
  const canUpdate = member.getByRole("dialog").getByRole("region", { name: "Agents" }).getByRole("checkbox", { name: "Agent can update this item" });
  await canUpdate.click(); // controlled: checked once the change is saved
  await expect(canUpdate).toBeChecked({ timeout: 30_000 });
  await member.keyboard.press("Escape");

  expect(await call(token, "update_secret", set)).toMatchObject({ item: envHandle, revision: expect.any(Number) });
  await unlock(member);
  await openRecord(member, "Billing env");
  const banner = member.getByRole("note", { name: "Changed by agent" });
  await expect(banner).toContainText("Changed by agent My helper", { timeout: 30_000 });
  await expect(banner).toContainText("Changed: PORT");
  await banner.getByRole("button", { name: "Restore previous" }).click();
  await expect(banner).toHaveCount(0, { timeout: 30_000 });
  await details(member).getByRole("button", { name: "Show PORT" }).click();
  await expect(details(member).getByLabel("PORT value")).toHaveText("3000", { timeout: 30_000 });
});

const revealSheet = (p: Page) => p.getByRole("dialog", { name: "An agent is asking for a secret" });
const ask = (fields: string[]) => call(token, "get_secret", { item: "personal/echo", fields, reason: "e2e" });

test("14. Can use and reveal on Echo: list_secrets shows both modes", async () => {
  await unlock(member);
  await openRecord(member, "Echo");
  await member.getByRole("button", { name: "Share", exact: true }).click();
  const agents = member.getByRole("dialog").getByRole("region", { name: "Agents" });
  await agents.getByRole("combobox", { name: "Access for My helper" }).click();
  await member.getByRole("option", { name: "Can use and reveal" }).click();
  await expect(agents.getByText("Can reveal lets the AI model read these fields. Clane Vault cannot take them back afterwards.")).toBeVisible();
  await agents.getByRole("checkbox", { name: "Key ID" }).check();
  await agents.getByRole("button", { name: "Save" }).click();
  await expect(agents.getByText(/^Can read: Key ID/)).toBeVisible({ timeout: 30_000 });
  await expect(agents.getByRole("alert")).toHaveCount(0);
  await member.keyboard.press("Escape");
  const listed = JSON.parse(await listSecrets(token)) as { structuredContent: { secrets: { handle: string; modes?: string[]; reveal?: unknown }[] } };
  expect(listed.structuredContent.secrets.find((x) => x.handle === "personal/echo")).toMatchObject({ modes: ["use", "reveal"], reveal: { fields: ["data.keyId"], approval: true } });
});

test("15. get_secret waits for the owner; Allow once returns the value; Activity shows both", async () => {
  const pending = ask(["data.keyId"]);
  const sheet = revealSheet(member);
  await expect(sheet).toBeVisible({ timeout: 30_000 });
  await expect(sheet).toContainText("Echo");
  await expect(sheet).toContainText("Key ID");
  await expect(sheet).toContainText("Written by the agent. It may not be true.");
  await sheet.getByRole("button", { name: "Allow once" }).click();
  expect(await pending).toEqual({ fields: { "data.keyId": KEY_ID } });
  await expect(sheet).toHaveCount(0, { timeout: 30_000 });
  await settingsPage(member, "My agents");
  await myAgentRow(member).getByRole("button", { name: "Activity of My helper" }).click();
  const activity = member.getByRole("dialog", { name: "My helper: activity" });
  await expect(activity.getByRole("listitem").filter({ hasText: "agent.reveal_request" })).toHaveCount(1, { timeout: 30_000 });
  await expect(activity.getByRole("listitem").filter({ hasText: /agent\.reveal(?!_)/ })).toHaveCount(1);
  await member.keyboard.press("Escape");
});

test("16. Deny refuses; a field the owner did not allow is refused with no sheet", async () => {
  const pending = ask(["data.keyId"]);
  const sheet = revealSheet(member);
  await sheet.getByRole("button", { name: "Deny" }).click({ timeout: 30_000 });
  expect(await pending).toEqual({ error: "refused", reason: "denied" });
  expect(await ask(["data.secret"])).toEqual({ error: "refused", reason: "field" });
  await member.waitForTimeout(6000); // one poll of the web app
  await expect(sheet).toHaveCount(0);
});

test("17. with the vault locked nobody answers: get_secret says pending, with a request id", async () => {
  await member.reload(); // the lock screen: no unlocked client polls
  await expect(member.getByLabel("Master password")).toBeVisible({ timeout: 30_000 });
  const r = await ask(["data.keyId"]);
  expect(r).toEqual({ status: "pending", request_id: expect.stringMatching(/^[0-9a-f-]{36}$/) });
  await member.getByLabel("Master password").fill(PW);
  await member.getByRole("button", { name: "Unlock" }).click();
  // The request is still open: the sheet shows it; denying clears it for the steps after.
  await revealSheet(member).getByRole("button", { name: "Deny" }).click({ timeout: 30_000 });
  await expect(revealSheet(member)).toHaveCount(0, { timeout: 30_000 });
});

async function setReading(label: "With approval" | "Without approval") {
  await adminPage(admin, "Policies");
  const block = admin.getByRole("region", { name: "Personal agents" });
  await block.getByRole("combobox", { name: "Reading values" }).click();
  await admin.getByRole("option", { name: label, exact: true }).click();
  const saved = admin.waitForResponse((r) => r.url().endsWith("/admin/settings/policies/personal-agents") && r.request().method() === "PUT");
  await block.getByRole("button", { name: "Save personal agents" }).click();
  expect((await saved).ok()).toBe(true);
}

test("18. reading without approval: the admin allows it, the member turns it on by typing the title; no sheet", async () => {
  await setReading("Without approval");
  await unlock(member);
  await openRecord(member, "Echo");
  await member.getByRole("button", { name: "Edit", exact: true }).click();
  const section = member.getByRole("region", { name: "Reading without approval" });
  await expect(section).toContainText("The AI model can read these fields whenever it asks. Nobody is asked first.", { timeout: 30_000 });
  await section.getByRole("button", { name: "Turn on…" }).click();
  await section.getByRole("checkbox", { name: "Key ID" }).check();
  await section.getByRole("textbox", { name: "Type the item's title to let My helper read without approval" }).fill("Echo");
  await section.getByRole("switch", { name: "My helper reads without approval" }).check();
  await member.getByRole("button", { name: "Save" }).click();
  await expect(member.getByRole("button", { name: "Save" })).toHaveCount(0, { timeout: 30_000 });

  expect(await ask(["data.keyId"])).toEqual({ fields: { "data.keyId": KEY_ID } });
  await expect(revealSheet(member)).toHaveCount(0);
  await settingsPage(member, "My agents");
  await myAgentRow(member).getByRole("button", { name: "Activity of My helper" }).click();
  const activity = member.getByRole("dialog", { name: "My helper: activity" });
  await expect(activity.getByRole("listitem").filter({ hasText: /agent\.reveal(?!_)/ })).toHaveCount(2, { timeout: 30_000 });
  await member.keyboard.press("Escape");
});

test("19. back to With approval: the same call opens the sheet again", async () => {
  await setReading("With approval");
  const pending = ask(["data.keyId"]);
  const sheet = revealSheet(member);
  await sheet.getByRole("button", { name: "Allow once" }).click({ timeout: 30_000 });
  expect(await pending).toEqual({ fields: { "data.keyId": KEY_ID } });
});

test("20. moved into a team folder the item leaves the agent; revoke ends it", async () => {
  // A personal record reaches the organisation's space only while it is shared there: share it with the admin, then move it.
  await member.getByRole("link", { name: /^Vault/ }).click();
  await switchSpace(member, { firstOrg: true });
  const folderDlg = await newSharedFolder(member);
  await folderDlg.getByLabel("Folder name").fill("Ops");
  await folderDlg.getByRole("button", { name: "Create" }).click();
  await expect(member.getByRole("button", { name: /^Ops/ })).toBeVisible({ timeout: 30_000 });
  await switchSpace(member, "Personal");
  await member.getByRole("button", { name: /^No folder/ }).click();
  await member.getByRole("button", { name: /Echo/ }).click();
  await member.getByRole("button", { name: "Share", exact: true }).click();
  const share = member.getByRole("dialog");
  await share.getByRole("combobox", { name: "Person", exact: true }).click();
  await member.getByRole("option", { name: /PA Owner/ }).click();
  await share.getByRole("combobox", { name: "Permission for new person" }).click();
  await member.getByRole("option", { name: "Can view" }).click();
  await share.getByRole("button", { name: "Share", exact: true }).click();
  await expect(share.getByRole("link", { name: /^Manage in / })).toBeVisible({ timeout: 30_000 });
  await member.keyboard.press("Escape");

  await switchSpace(member, { firstOrg: true });
  await member.getByRole("button", { name: /^Shared directly/ }).click();
  await member.getByRole("button", { name: /Echo/ }).click();
  await member.getByRole("button", { name: "Options", exact: true }).click();
  await member.getByRole("menuitem", { name: "Move To" }).click();
  await member.getByRole("menuitem", { name: "Ops" }).click();
  await expect(member.getByRole("button", { name: /^Ops/ })).toContainText("1 record", { timeout: 30_000 });
  const listed = await listSecrets(token);
  expect(listed).not.toContain("personal/echo");
  expect(listed).not.toContain('"isError":true');

  await settingsPage(member, "My agents");
  await myAgentRow(member).getByRole("button", { name: "Revoke My helper" }).click();
  const revoke = member.getByRole("dialog", { name: "Revoke My helper?" });
  await revoke.getByRole("button", { name: "Revoke" }).click();
  await expect(revoke.getByText(/couldn't open anything|Change the credentials/)).toBeVisible({ timeout: 30_000 });
  expect(await callStatus(token)).toBe(401);
});
