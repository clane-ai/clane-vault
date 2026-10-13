import { expect, test, type Page } from "@playwright/test";
import { newInvite, newOrg, saveRecoveryKit, totp } from "../helpers";

// Risk dashboard (docs/risk-dashboard.md): the owner opens it from its URL, sees the score and benchmarks, and a
// benchmark's Fix button opens the exact settings page; a member on the same URL gets No access.
const PW = "an e2e master password";
const uniq = () => `${Date.now()}-${Math.floor(Math.random() * 1e4)}`;
const shots = process.env.RISK_SHOTS;

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
/** Opens a URL in the app (a full load locks the vault: unlock it). */
async function open(page: Page, path: string) {
  await page.goto(path);
  await expect(page.getByText("Vault locked")).toBeVisible({ timeout: 30_000 });
  await page.getByLabel("Master password").fill(PW);
  await page.getByRole("button", { name: "Unlock" }).click();
  await expect(page.getByRole("button", { name: "Unlock" })).toHaveCount(0, { timeout: 30_000 });
  // The unlock beat (an overlay that fades by itself) is over before anything is checked or captured.
  await expect(page.getByTestId("unlock-flash")).toHaveCount(0, { timeout: 10_000 });
}

test("risk dashboard: the owner sees score and benchmarks, Fix opens the settings page; a member gets No access", async ({ page, browser }, testInfo) => {
  test.setTimeout(240_000);
  const id = uniq();
  const org = newOrg(`Risk ${id}`);
  const slug = `e2e-${org.slice(0, 8)}`;
  await register(page, newInvite(`risk-owner-${id}@riskco.test`, "owner", org), "Rita Owner");

  const ctx = await browser.newContext({ viewport: page.viewportSize() ?? undefined });
  const mp = await ctx.newPage();
  await register(mp, newInvite(`risk-member-${id}@riskco.test`, "member", org), "Max Member");

  await open(page, `/o/${slug}/admin/risk`);
  await expect(page.getByRole("heading", { level: 1, name: "Risk dashboard" })).toBeVisible({ timeout: 30_000 });
  await expect(page.getByTestId("risk-score")).toHaveText(/\d+/);
  // Risk dashboard is the first Admin page (desktop sub-navigation).
  if (testInfo.project.name === "desktop") {
    await expect(page.getByRole("navigation", { name: "Admin sections" }).getByRole("link").first()).toHaveText("Risk dashboard");
  }
  await expect(page.getByRole("button", { name: /^Members with records/ })).toBeVisible();
  const critical = page.getByRole("group", { name: /^Critical/ });
  await expect(critical.getByRole("listitem", { name: "Auto-lock after 15 minutes or less" })).toBeVisible();
  if (shots) {
    await page.screenshot({ path: `${shots}/risk-${testInfo.project.name}-owner.png` });
    for (const r of ["Security benchmarks", "High-priority alerts", "Password health summary"])
      await page.getByRole("region", { name: r }).screenshot({ path: `${shots}/risk-${testInfo.project.name}-${r.toLowerCase().replace(/[^a-z]+/g, "-")}.png` });
  }

  // Drill-down: the members behind a tile.
  await page.getByRole("button", { name: /^Signed in within 30 days/ }).click();
  const drill = page.getByRole("region", { name: "Signed in within 30 days: members" });
  await expect(drill.getByRole("row", { name: "Max Member" })).toBeVisible({ timeout: 30_000 });
  if (shots) await drill.screenshot({ path: `${shots}/risk-${testInfo.project.name}-drilldown.png` });

  // Remediation: Fix opens the exact settings page.
  await critical.getByRole("link", { name: "Fix: Auto-lock after 15 minutes or less" }).click();
  await expect(page).toHaveURL(new RegExp(`/o/${slug}/admin/org/policies$`));
  await expect(page.getByRole("heading", { level: 1, name: "Policies" })).toBeVisible();
  await page.goBack();
  await expect(page.getByRole("heading", { level: 1, name: "Risk dashboard" })).toBeVisible();

  // Ignore and restore a benchmark.
  await page.getByRole("button", { name: "Ignore benchmark: IP allowlist (optional)" }).click();
  await expect(page.getByRole("group", { name: /^Ignored/ }).getByRole("listitem", { name: "IP allowlist (optional)" })).toBeVisible();
  await page.getByRole("button", { name: "Restore benchmark: IP allowlist (optional)" }).click();
  await expect(critical.getByRole("listitem", { name: "IP allowlist (optional)" })).toBeVisible();

  // A member on the dashboard's URL: No access, never the dashboard.
  await open(mp, `/o/${slug}/admin/risk`);
  await expect(mp.getByRole("heading", { name: "You don't have access to this page" })).toBeVisible({ timeout: 30_000 });
  await expect(mp.getByRole("region", { name: "Risk dashboard" })).toHaveCount(0);
  if (shots) await mp.screenshot({ path: `${shots}/risk-${testInfo.project.name}-member-no-access.png` });
  await ctx.close();
});
