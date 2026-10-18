import { createServer, type IncomingHttpHeaders, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { expect, test, type Page } from "@playwright/test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { adminPage, newInvite, newOrg, newSharedFolder, saveRecoveryKit, totp } from "../helpers";

// Agent access end to end (docs/design/2026-10-17-agent-access.md §10): enrol, verify, share, MCP use, scrub, revoke.
const PW = "an e2e master password";
const CANARY = "sk_test_E2E_CANARY";
// The restricted-credential warning, exact copy (constraints).
const AGENT_WARNING = "Give agents restricted credentials: a Stripe restricted key, a read-only database user, a scoped token. Never a root or owner credential. What you share here can be read by the gateway and used by whatever drives the agent.";
const AGENT_DISCLOSURE = "Sharing with an agent makes those items readable by the gateway operator. Everything else stays end-to-end encrypted.";
const MCP_URL = `http://localhost:${process.env.E2E_GATEWAY_PORT ?? 3002}/mcp`;

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

/**
 * The upstream the agent calls, on echo.test (the gateway's hosts fixture maps it to 127.0.0.1). Plain http on loopback:
 * the gateway allows it only for an address in GATEWAY_ALLOW_PRIVATE_CIDRS, as here. It answers with the headers it got.
 */
let echo: Server;
let echoPort = 0;
const received: IncomingHttpHeaders[] = [];
test.beforeAll(async () => {
  echo = createServer((req, res) => {
    received.push(req.headers);
    res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ path: req.url, headers: req.headers }));
  });
  await new Promise<void>((ok) => echo.listen(0, "127.0.0.1", ok));
  echoPort = (echo.address() as AddressInfo).port;
});
test.afterAll(() => new Promise<void>((ok) => echo.close(() => ok())));

test("an admin enrols an agent, shares a record at Use, the agent uses it through the gateway, then is revoked", async ({ page }) => {
  const id = `${Date.now()}-${Math.floor(Math.random() * 1e4)}`;
  // A fresh organisation, so its agent list holds only this run's agent.
  const org = newOrg(`Agents ${id}`);
  await register(page, newInvite(`e2e-agents-${id}@clane.ai`, "owner", org), "E2E Owner");

  // 1-2. Admin → Agents → New agent; the verify dialog shows both fingerprints → Matches; the row reads Active.
  await adminPage(page, "Agents");
  await page.getByRole("button", { name: "New agent" }).click();
  await page.getByLabel("Name").fill("Billing bot");
  await page.getByRole("button", { name: "Create" }).click();
  const verify = page.getByRole("dialog", { name: "Verify Billing bot" });
  const fingerprints = verify.locator("dd");
  await expect(fingerprints).toHaveCount(2, { timeout: 30_000 });
  for (const fp of await fingerprints.all()) await expect(fp).toHaveText(/[0-9A-Za-z]{4}/);
  await verify.getByRole("button", { name: "Matches" }).click();
  await expect(verify).toHaveCount(0, { timeout: 30_000 });
  const row = page.getByRole("listitem", { name: "Billing bot" });
  await expect(row.getByText("Active", { exact: true })).toBeVisible({ timeout: 30_000 });

  // 3. A team folder "Payments" with an API key record "Echo": the canary secret, Agent use for echo.test:<port>, bearer.
  await page.getByRole("link", { name: /^Vault/ }).click();
  await expect(page).toHaveURL(/\/o\/[^/]+\/vault$/);
  const folderDlg = await newSharedFolder(page);
  await folderDlg.getByLabel("Folder name").fill("Payments");
  await folderDlg.getByRole("button", { name: "Create" }).click();
  const folderRow = page.getByRole("button", { name: /^Payments/ });
  await expect(folderRow).toBeVisible({ timeout: 30_000 });
  await page.getByRole("button", { name: "New", exact: true }).click();
  await page.getByRole("menuitem", { name: "Record", exact: true }).click();
  const newDlg = page.getByRole("dialog");
  const location = newDlg.getByRole("combobox", { name: "Location" });
  if (!/Payments/.test((await location.textContent()) ?? "")) { await location.click(); await page.getByRole("option", { name: /Payments/ }).click(); }
  await newDlg.getByRole("combobox", { name: "Record Type" }).click();
  await page.getByRole("option", { name: "API key / secret" }).click();
  await newDlg.getByLabel("Title").fill("Echo");
  await newDlg.getByRole("button", { name: "Next" }).click();
  await page.getByLabel("Secret", { exact: true }).and(page.locator("input")).fill(CANARY);
  const agentUse = page.getByRole("region", { name: "Agent use" });
  await agentUse.getByLabel("Allowed hosts").fill(`echo.test:${echoPort}`);
  await expect(agentUse.getByRole("combobox", { name: "Send it as" })).toHaveText("Bearer token");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(folderRow).toContainText("1 record", { timeout: 30_000 });

  // 4. Billing bot joins the folder through the people sheet: the warning shows, the permission is locked to Use only.
  await folderRow.hover();
  await page.getByRole("button", { name: "Options for Payments" }).click();
  await page.getByRole("menuitem", { name: "Manage people" }).click();
  const people = page.getByRole("dialog");
  await people.getByRole("combobox", { name: "Person", exact: true }).click();
  await page.getByRole("option", { name: /Billing bot/ }).click();
  const warning = people.getByRole("note", { name: "Sharing with an agent" });
  await expect(warning).toContainText(AGENT_WARNING);
  await expect(warning).toContainText(AGENT_DISCLOSURE);
  const permission = people.getByRole("combobox", { name: "Permission for new person" });
  await expect(permission).toBeDisabled();
  await expect(permission).toHaveText("Use only");
  await people.getByRole("button", { name: "Add" }).click();
  await expect(people.getByRole("listitem", { name: "Billing bot" })).toBeVisible({ timeout: 30_000 });
  await page.keyboard.press("Escape");

  // 5. Connect → Create API token: shown once, as cvat_….
  await adminPage(page, "Agents");
  await row.getByRole("button", { name: "Connect Billing bot" }).click();
  const tokens = page.getByRole("region", { name: "API tokens" });
  await tokens.getByRole("button", { name: "Create API token" }).click();
  const token = (await tokens.locator("code").filter({ hasText: /^cvat_/ }).textContent({ timeout: 30_000 }))!.trim();
  expect(token).toMatch(/^cvat_[^_]+_[A-Za-z0-9_-]{43}$/);
  await page.keyboard.press("Escape");

  // 6-7. An MCP client: list_secrets shows the handle and no secret; http_request reaches echo with the secret injected,
  // and what comes back to the agent has it scrubbed.
  const auth = { Authorization: `Bearer ${token}` };
  const client = new Client({ name: "e2e", version: "1.0.0" });
  await client.connect(new StreamableHTTPClientTransport(new URL(MCP_URL), { requestInit: { headers: auth } }));
  const listed = JSON.stringify(await client.callTool({ name: "list_secrets", arguments: {} }));
  expect(listed).toContain("payments/echo");
  expect(listed).not.toContain(CANARY);
  const used = JSON.stringify(await client.callTool({ name: "http_request",
    arguments: { item: "payments/echo", method: "GET", url: `http://echo.test:${echoPort}/headers` } }));
  expect(received.at(-1)?.authorization).toBe(`Bearer ${CANARY}`);
  expect(used).toContain("[clane:redacted]");
  expect(used).not.toContain(CANARY);
  await client.close();

  // 8. The event log shows agent.use by the agent (the server never knows record titles).
  await adminPage(page, "Event log");
  await expect(page.getByRole("row").filter({ hasText: "agent.use" }).filter({ hasText: "Billing bot" })).toHaveCount(1, { timeout: 30_000 });

  // 9-10. Revoke: the rotation list names the folder, and the next MCP call is refused with 401.
  await adminPage(page, "Agents");
  await row.getByRole("button", { name: "Revoke Billing bot" }).click();
  const revoke = page.getByRole("dialog", { name: "Revoke Billing bot?" });
  await revoke.getByRole("button", { name: "Revoke" }).click();
  await expect(revoke.getByRole("listitem").filter({ hasText: "Payments" })).toBeVisible({ timeout: 30_000 });
  const after = await fetch(MCP_URL, { method: "POST", headers: { ...auth, "content-type": "application/json", accept: "application/json, text/event-stream" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "e2e", version: "1.0.0" } } }) });
  expect(after.status).toBe(401);
});
