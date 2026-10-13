import { expect, test, type Page } from "@playwright/test";
import { newInvite, saveRecoveryKit, totp, accountMenu, adminPage, newRecord, newSharedFolder, switchSpace } from "../helpers";

const PW = "an e2e master password";
const uniq = () => `${Date.now()}-${Math.floor(Math.random() * 1e4)}`;

/** Registers through an invite link and finishes 2FA; returns the TOTP secret. */
async function register(page: Page, invitePath: string, name: string): Promise<string> {
  await page.goto(invitePath);
  await page.getByLabel("Your name").fill(name);
  await page.getByLabel("Master password", { exact: true }).fill(PW);
  await page.getByLabel("Repeat master password").fill(PW);
  await page.getByRole("button", { name: "Create account" }).click();
  const keyText = await page.getByText(/Enter this key:\s*[A-Z2-7]{16,}/).textContent({ timeout: 60_000 });
  const secret = keyText!.split(":")[1]!.trim();
  await page.getByLabel("6-digit code").fill(await totp(secret));
  await page.getByRole("button", { name: "Turn on and continue" }).click();
  await saveRecoveryKit(page);
  await expect(page.getByRole("button", { name: "New", exact: true })).toBeVisible({ timeout: 30_000 });
  return secret;
}
async function unlockAfterReload(page: Page) {
  await page.reload();
  await expect(page.getByText("Vault locked")).toBeVisible({ timeout: 30_000 });
  await page.getByLabel("Master password").fill(PW);
  await page.getByRole("button", { name: "Unlock" }).click();
  await expect(page.getByRole("button", { name: "Unlock" })).toHaveCount(0, { timeout: 30_000 });
}
async function newLogin(page: Page, title: string, password: string, folder?: RegExp) {
  await newRecord(page, title, { folder });
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("dialog")).toHaveCount(0);
}
async function pickPerson(page: Page, scope: ReturnType<Page["getByRole"]>, name: string, permission: "Can edit" | "Can view") {
  await scope.getByRole("combobox", { name: "Person", exact: true }).click();
  await page.getByRole("option", { name: new RegExp(name) }).click();
  await scope.getByRole("combobox", { name: "Permission for new person" }).click();
  await page.getByRole("option", { name: permission }).click();
}

test("admin invites B, shares a team folder and a record, then removes B", async ({ page, browser }, testInfo) => {
  test.skip(testInfo.project.name !== "desktop", "multi-user flow runs once, on desktop");
  const id = uniq();
  const adminEmail = `e2e-admin-${id}@clane.ai`, bEmail = `e2e-b-${id}@clane.ai`;
  const bName = `Bea ${id}`;

  // Admin signs up and invites B from the People page, copying the link.
  await register(page, newInvite(adminEmail, "admin"), "E2E Admin");
  await adminPage(page, "People");
  await page.getByLabel("Email").fill(bEmail);
  await page.getByRole("button", { name: "Invite", exact: true }).click();
  const pending = page.getByRole("listitem", { name: bEmail });
  await pending.getByRole("button", { name: "Copy invite link" }).click();
  const link = await page.evaluate(() => navigator.clipboard.readText());
  expect(link).toMatch(/\/invite\/[A-Za-z0-9_-]{20,}$/);

  // B registers in a separate browser context.
  const ctxB = await browser.newContext({ viewport: { width: 1440, height: 900 }, permissions: ["clipboard-read", "clipboard-write"] });
  const b = await ctxB.newPage();
  await register(b, new URL(link).pathname, bName);
  await expect(b.getByText("No records yet")).toBeVisible();

  // Admin, in the organisation (Admin opened it): team folder with B (edit) and a record in it.
  await page.getByRole("link", { name: /^Vault/ }).click();
  await expect(page).toHaveURL(/\/o\/[^/]+\/vault$/);
  const dlg = await newSharedFolder(page);
  await dlg.getByLabel("Folder name").fill("Ops Team");
  await pickPerson(page, dlg, bName, "Can edit");
  await dlg.getByRole("button", { name: "Add" }).click();
  await expect(dlg.getByRole("listitem", { name: bName })).toBeVisible();
  await dlg.getByRole("button", { name: "Create" }).click();
  await expect(page.getByRole("button", { name: /^Ops Team/ })).toBeVisible({ timeout: 30_000 });
  await newLogin(page, "Team DB", "team-db-secret", /Ops Team/);
  // A private record (Personal) shared to B (view) inside the organisation.
  await switchSpace(page, "Personal");
  await expect(page.getByRole("button", { name: /^Ops Team/ })).toHaveCount(0);
  await newLogin(page, "Private API", "private-api-secret");
  await page.getByRole("button", { name: /^No folder/ }).click();
  await page.getByRole("button", { name: /Private API/ }).click();
  await page.getByRole("button", { name: "Share", exact: true }).click();
  const share = page.getByRole("dialog");
  await expect(share.getByRole("combobox", { name: "Share inside" })).toBeVisible();
  await pickPerson(page, share, bName, "Can view");
  await share.getByRole("button", { name: "Share", exact: true }).click();
  // The share belongs to the organisation: managed there.
  await expect(share.getByRole("link", { name: /^Manage in / })).toBeVisible({ timeout: 30_000 });
  await share.getByRole("button", { name: "Done" }).click();

  // B sees the team record and the shared record in the organisation, and can't edit the view-only one.
  await unlockAfterReload(b);
  await switchSpace(b, { firstOrg: true });
  await b.getByRole("button", { name: /^Ops Team/ }).click();
  await b.getByRole("button", { name: /Team DB/ }).click();
  await expect(b.getByRole("button", { name: "Edit", exact: true })).toBeVisible();
  await b.getByRole("button", { name: "Copy password" }).click();
  expect(await b.evaluate(() => navigator.clipboard.readText())).toBe("team-db-secret");
  await b.getByRole("link", { name: /^Shared with me/ }).click();
  await b.getByRole("button", { name: /Private API/ }).click();
  await expect(b.getByRole("heading", { name: "Private API" })).toBeVisible();
  // The list row says it too (its shared marker); the record panel's header line is the one checked here.
  await expect(b.getByRole("complementary", { name: "Record details" }).getByText(/Shared by E2E Admin/)).toBeVisible();
  await expect(b.getByRole("button", { name: "Edit", exact: true })).toHaveCount(0);
  await b.getByRole("button", { name: "Show password" }).click();
  await expect(b.getByText("private-api-secret")).toBeVisible();

  // Admin removes B from the folder and stops sharing the record, in the organisation.
  await switchSpace(page, { firstOrg: true });
  await page.getByRole("button", { name: "Options for Ops Team" }).click();
  await page.getByRole("menuitem", { name: "Manage people" }).click();
  const people = page.getByRole("dialog");
  await people.getByRole("button", { name: `Remove ${bName}` }).click();
  await expect(people.getByRole("listitem", { name: bName })).toHaveCount(0, { timeout: 30_000 });
  await people.getByRole("button", { name: "Done" }).click();
  // The owner's private record shows in the organisation while it is shared there.
  await page.getByRole("button", { name: /^Shared directly/ }).click();
  await page.getByRole("button", { name: /Private API/ }).click();
  await page.getByRole("button", { name: "Share", exact: true }).click();
  await page.getByRole("dialog").getByRole("button", { name: `Stop sharing with ${bName}` }).click();
  // No longer shared there: it leaves the organisation's space (it stays in Personal).
  await expect(page.getByRole("button", { name: /Private API/ })).toHaveCount(0, { timeout: 30_000 });

  // Gone for B. The reload keeps B's page (Shared with me, the record no longer there), then the vault is empty too.
  await unlockAfterReload(b);
  await expect(b.getByText("Nothing shared with you yet")).toBeVisible({ timeout: 30_000 });
  await expect(b).toHaveURL(/\/shared$/);
  await b.getByRole("link", { name: /^Vault/ }).click();
  await expect(b.getByText("No records yet")).toBeVisible({ timeout: 30_000 });
  await expect(b.getByRole("button", { name: /^Ops Team/ })).toHaveCount(0);
  await ctxB.close();
});
