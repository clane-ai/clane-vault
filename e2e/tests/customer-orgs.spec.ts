import { expect, test, type Page } from "@playwright/test";
import { adminPage, makeInstanceAdmin, newInvite, newSharedFolder, saveRecoveryKit, switchSpace, totp } from "../helpers";

// Organisations for customers (docs/provisioning.md): the instance admin creates an organisation with an owner
// invitation and never joins it; the customer signs up through the link, becomes its only owner, and their browser
// makes the organisation's keys (a shared folder works). The operator's list then shows the invitation as accepted.
const PW = "an e2e master password";
const uniq = () => `${Date.now()}-${Math.floor(Math.random() * 1e4)}`;

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
async function unlockAfterReload(page: Page) {
  await page.reload();
  await expect(page.getByText("Vault locked")).toBeVisible({ timeout: 30_000 });
  await page.getByLabel("Master password").fill(PW);
  await page.getByRole("button", { name: "Unlock" }).click();
  await expect(page.getByRole("button", { name: "Unlock" })).toHaveCount(0, { timeout: 30_000 });
}

test("an instance admin creates an organisation for a customer, who signs up as its only owner", async ({ page, browser }, testInfo) => {
  test.skip(testInfo.project.name !== "desktop", "multi-user flow runs once, on desktop");
  test.setTimeout(300_000);
  const id = uniq();
  const orgName = `Globex ${id}`;
  const operatorEmail = `e2e-op-${id}@clane.ai`, ownerEmail = `e2e-ceo-${id}@clane.ai`;

  // The operator: an instance admin (the flag, as the instance-admin CLI sets it).
  await register(page, newInvite(operatorEmail, "member"), "Operator");
  makeInstanceAdmin(operatorEmail);
  await unlockAfterReload(page);
  await adminPage(page, "Customer organisations");
  await expect(page).toHaveURL(/\/server\/organisations$/);
  const form = page.getByRole("form", { name: "Create an organisation for a customer" });
  await form.getByLabel("Organisation name").fill(orgName);
  await form.getByLabel("Owner's email address").fill(ownerEmail);
  await form.getByRole("button", { name: "Create and invite owner" }).click();
  // Self-hosted without email: the link to pass on, shown once.
  const done = form.getByRole("status");
  await expect(done).toContainText(`${orgName} was created.`);
  const link = (await done.locator("code").textContent())!;
  expect(link).toMatch(/\/invite\/[A-Za-z0-9_-]{20,}$/);
  const row = page.getByRole("row", { name: orgName });
  await expect(row.getByText("Pending")).toBeVisible();
  await expect(row.getByText(ownerEmail)).toBeVisible();
  // The operator isn't a member: the organisation isn't in their switcher.
  await page.getByRole("button", { name: /^Space:/ }).click();
  await expect(page.getByRole("menu")).not.toContainText(orgName);
  await page.keyboard.press("Escape");

  // The customer signs up through the link and owns the organisation.
  const c = await (await browser.newContext({ viewport: { width: 1440, height: 900 }, permissions: ["clipboard-read", "clipboard-write"] })).newPage();
  await register(c, new URL(link).pathname, "Customer Owner");
  await switchSpace(c, orgName);
  await expect(c.getByTestId("active-org")).toHaveText(orgName);
  await expect(c.getByRole("button", { name: /^Space:/ })).toContainText("Owner");
  // Keys: their browser made the organisation's first membership key, so a shared folder can be created and opened.
  const dlg = await newSharedFolder(c);
  await dlg.getByLabel("Folder name").fill(`Globex Team ${id}`);
  await dlg.getByRole("button", { name: "Create" }).click();
  await expect(c.getByRole("button", { name: new RegExp(`^Globex Team ${id}`) })).toBeVisible({ timeout: 30_000 });
  await adminPage(c, "People");
  // Its only member: them, as owner.
  const everyone = c.getByRole("region", { name: "Everyone" });
  await expect(everyone.getByRole("listitem")).toHaveCount(1);
  await expect(everyone).toContainText(ownerEmail);
  await expect(everyone).toContainText("Owner");

  // The operator's list: accepted, with nothing to resend or cancel.
  await page.reload();
  await expect(page.getByText("Vault locked")).toBeVisible({ timeout: 30_000 });
  await page.getByLabel("Master password").fill(PW);
  await page.getByRole("button", { name: "Unlock" }).click();
  const after = page.getByRole("row", { name: orgName });
  await expect(after.getByText("Accepted")).toBeVisible({ timeout: 30_000 });
  await expect(after.getByRole("button")).toHaveCount(0);
});
