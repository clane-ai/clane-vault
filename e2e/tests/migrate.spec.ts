import { expect, test, type Browser, type Page } from "@playwright/test";
import { newInvite, saveRecoveryKit, totp, accountMenu, switchSpace } from "../helpers";

const PW = "an e2e master password";
const uniq = () => `${Date.now()}-${Math.floor(Math.random() * 1e4)}`;
const DESKTOP = { viewport: { width: 1440, height: 900 }, permissions: ["clipboard-read", "clipboard-write"] };

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
async function newUser(browser: Browser, invitePath: string, name: string) {
  const ctx = await browser.newContext(DESKTOP);
  const page = await ctx.newPage();
  await register(page, invitePath, name);
  return { ctx, page };
}
async function seesTeamRecord(page: Page, folder: string, title: string, password: string) {
  await page.getByRole("button", { name: new RegExp(`^${folder}`) }).click();
  await page.getByRole("button", { name: new RegExp(title) }).click();
  await page.getByRole("button", { name: "Copy password" }).click();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(password);
}

test("admin migrates a Keeper Commander export: B gets the shared folder now, a new person after registering", async ({ page, browser }, testInfo) => {
  test.skip(testInfo.project.name !== "desktop", "multi-user flow runs once, on desktop");
  const id = uniq();
  const adminEmail = `e2e-mig-admin-${id}@clane.ai`, bEmail = `e2e-mig-b-${id}@clane.ai`, newEmail = `e2e-mig-new-${id}@clane.ai`;
  const folder = `Keeper Ops ${id}`;

  await register(page, newInvite(adminEmail, "admin"), "Migrating Admin");
  const b = await newUser(browser, newInvite(bEmail), `Bea ${id}`);

  const file = JSON.stringify({
    shared_folders: [{ path: folder, manage_users: false, manage_records: false, can_edit: true, can_share: false, permissions: [
      { name: adminEmail, manage_users: true, manage_records: true },
      { name: bEmail, manage_users: false, manage_records: true },
      { name: newEmail, manage_users: false, manage_records: false },
      { name: "Ops Team", manage_users: false, manage_records: true },
    ] }],
    records: [
      { title: "Ops DB", login: "ops", password: "ops-db-secret-1", login_url: "https://db.example", folders: [{ shared_folder: folder }] },
      { title: "Ops VPN", login: "vpn", password: "ops-vpn-secret-2", custom_fields: { "TFC:Keeper": "otpauth://totp/VPN?secret=JBSWY3DPEHPK3PXP" }, folders: [{ shared_folder: folder }] },
      { title: "My notes", notes: "personal", folders: [{ folder: "Personal" }] },
    ],
  });

  // + New → Import → Bulk migration (admins) opens the page.
  await page.getByRole("button", { name: "New", exact: true }).click();
  await page.getByRole("menuitem", { name: /Import/ }).click();
  await page.getByRole("button", { name: /Bulk migration \(admins\)/ }).click();
  await expect(page.getByRole("heading", { name: "Migrate from Keeper" })).toBeVisible();
  await expect(page).toHaveURL(/\/admin\/migrate$/);
  // The file input is enabled once the people directory and the vault are loaded.
  await expect(page.getByText("Choose a Keeper JSON export")).toBeVisible({ timeout: 30_000 });
  await page.getByLabel("Keeper export file").setInputFiles({ name: "keeper-export.json", mimeType: "application/json", buffer: Buffer.from(file) });
  await expect(page.getByText(/Keeper Commander \(JSON\)/)).toBeVisible({ timeout: 30_000 });
  const plan = page.getByRole("listitem", { name: folder });
  await expect(plan.getByText(`Bea ${id} · ${bEmail}`).locator("..")).toContainText("Added now");
  await expect(plan.getByText(newEmail).locator("..")).toContainText("Will be invited");
  await expect(plan.getByText("Ops Team").locator("..")).toContainText("Not mapped (Keeper team)");
  await page.getByRole("button", { name: /Start migration \(3 records\)/ }).click();

  const report = page.getByRole("region", { name: "Migration report" });
  await expect(report).toContainText("3 records created · 0 skipped · 0 failed", { timeout: 60_000 });
  await report.getByRole("button", { name: `Copy invite link for ${newEmail}` }).click();
  const link = await page.evaluate(() => navigator.clipboard.readText());
  expect(link).toMatch(/\/invite\/[A-Za-z0-9_-]{20,}$/);
  await expect(report.getByRole("region", { name: "Add after they register" })).toContainText(`${newEmail} → ${folder} (Can view)`);
  await expect(page.getByRole("region", { name: "Pending members" })).toContainText("1 waiting · 0 ready");

  // B (an existing user) opens the migrated records right away.
  await unlockAfterReload(b.page);
  await switchSpace(b.page, { firstOrg: true });
  await seesTeamRecord(b.page, folder, "Ops DB", "ops-db-secret-1");

  // The new person registers through the invite link; the admin completes the pending membership.
  const n = await newUser(browser, new URL(link).pathname, `Nia ${id}`);
  await expect(n.page.getByText("No records yet")).toBeVisible();
  await unlockAfterReload(page);
  // The account menu's avatar gets a dot when something needs doing; Admin and its Migrate page show the count.
  await expect(page.getByRole("button", { name: /^Account menu: .*needs attention/ })).toBeVisible({ timeout: 30_000 });
  await page.getByRole("button", { name: /^Account menu/ }).click();
  await expect(page.getByRole("menuitem", { name: /^Admin/ })).toContainText("1");
  await page.getByRole("menuitem", { name: /^Admin/ }).click();
  const migrate = page.getByRole("navigation", { name: "Admin sections" }).getByRole("link", { name: /^Migrate from Keeper/ });
  await expect(migrate).toContainText("1");
  await migrate.click();
  await expect(page).toHaveURL(/\/admin\/migrate$/);
  const pending = page.getByRole("region", { name: "Pending members" });
  await expect(pending).toContainText("1 waiting · 1 ready", { timeout: 30_000 });
  await pending.getByRole("button", { name: "Complete pending members" }).click();
  await expect(page.getByRole("region", { name: "Pending members" })).toHaveCount(0, { timeout: 30_000 });

  await unlockAfterReload(n.page);
  await switchSpace(n.page, { firstOrg: true });
  await seesTeamRecord(n.page, folder, "Ops VPN", "ops-vpn-secret-2");
  await expect(n.page.getByRole("button", { name: "Edit", exact: true })).toHaveCount(0);
  await b.ctx.close();
  await n.ctx.close();
});
