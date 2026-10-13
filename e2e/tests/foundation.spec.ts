import { expect, test } from "@playwright/test";
import { authenticator } from "otplib";
import { BASE, newFolder, newInvite, openNav, saveRecoveryKit, totp, accountMenu } from "../helpers";

test("invite, account, 2FA, add, find, copy, edit, trash, restore, lock, unlock, sign in again", async ({ page }, testInfo) => {
  const email = `e2e-${Date.now()}-${Math.floor(Math.random() * 1e4)}@clane.ai`;
  const pw = "an e2e master password";
  const openInfrastructure = async () => {
    const folder = page.getByRole("button", { name: /^Infrastructure/ });
    await expect(folder).toBeVisible({ timeout: 30_000 });
    if ((await folder.getAttribute("aria-expanded")) !== "true") await folder.click();
  };
  await page.goto(newInvite(email));
  await page.getByLabel("Your name").fill("E2E User");
  await page.getByLabel("Master password", { exact: true }).fill(pw);
  await page.getByLabel("Repeat master password").fill(pw);
  await page.getByRole("button", { name: "Create account" }).click();

  const keyText = await page.getByText(/Enter this key:\s*[A-Z2-7]{16,}/).textContent({ timeout: 60_000 });
  const secret = keyText!.split(":")[1]!.trim();
  await page.getByLabel("6-digit code").fill(await totp(secret));
  await page.getByRole("button", { name: "Turn on and continue" }).click();
  await saveRecoveryKit(page);
  await expect(page.getByText("No records yet")).toBeVisible({ timeout: 30_000 });

  await newFolder(page, "Infrastructure");

  // Open the folder; its Options (list header) → New Record starts there, and Next goes on to the editor.
  await openInfrastructure();
  await page.getByRole("button", { name: "Options", exact: true }).click();
  await page.getByRole("menuitem", { name: "New Record" }).click();
  const newRec = page.getByRole("dialog");
  await expect(newRec.getByRole("combobox", { name: "Location" })).toHaveText("Infrastructure");
  await expect(newRec.getByLabel("Title")).toBeFocused();
  await newRec.getByLabel("Title").fill("AWS root account");
  await newRec.getByLabel("Title").press("Enter");
  await expect(page.getByLabel("Title")).toHaveValue("AWS root account");
  await expect(page.getByRole("combobox", { name: "Folder", exact: true })).toHaveText("Infrastructure");
  await page.getByLabel("Username").fill("ops@clane.ai");
  await page.getByLabel("Password", { exact: true }).fill("Tg7#qL2v!Rm9zW4x");
  await page.getByRole("button", { name: "Save" }).click();

  await page.getByRole("button", { name: /AWS root account/ }).click();
  await page.getByRole("button", { name: "Copy password" }).click();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe("Tg7#qL2v!Rm9zW4x");

  const back = page.getByRole("button", { name: "Back" });
  if (await back.isVisible()) await back.click();
  const aws = page.getByRole("button", { name: /AWS root account/ });
  await page.getByLabel("Search records").fill("zzz-nothing");
  await expect(aws).toHaveCount(0);
  await expect(page.getByText("No records yet")).toBeVisible();
  await page.getByLabel("Search records").fill("");
  if (testInfo.project.name === "desktop") {
    await page.keyboard.press("Escape");
    await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur());
    await page.keyboard.press("/");
    await page.keyboard.type("aws");
  } else {
    await page.getByLabel("Search records").fill("aws");
  }
  await expect(aws).toBeVisible();

  await page.getByRole("button", { name: /AWS root account/ }).click();
  await page.getByRole("button", { name: "Edit", exact: true }).click();
  await page.getByLabel("Title").fill("AWS root (prod)");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("heading", { name: "AWS root (prod)" })).toBeVisible();

  await page.getByRole("button", { name: "Move to trash" }).click();
  await page.getByLabel("Search records").fill("");
  await expect(page.getByRole("button", { name: /AWS root \(prod\)/ })).toHaveCount(0);
  await expect(page.getByRole("complementary", { name: "Record details" })).toHaveCount(0);
  await openNav(page);
  await page.getByRole("link", { name: /^Trash/ }).click();
  await expect(page.getByRole("button", { name: /AWS root \(prod\)/ })).toBeVisible();
  await page.getByRole("button", { name: /AWS root \(prod\)/ }).click();
  await page.getByRole("button", { name: "Restore", exact: true }).click();
  // Restoring closes the record (back to the Trash list, /p/trash) once the server has it: wait, or that navigation
  // would close the phone drawer opened meanwhile.
  await expect(page).toHaveURL(/\/p\/trash$/, { timeout: 30_000 });
  await openNav(page);
  await page.getByRole("link", { name: /^Vault/ }).click();
  await openInfrastructure();
  await expect(page.getByRole("button", { name: /AWS root \(prod\)/ })).toBeVisible();

  await accountMenu(page, "Lock");
  await page.getByLabel("Master password").fill("wrong password!!");
  await page.getByRole("button", { name: "Unlock" }).click();
  await expect(page.getByRole("alert")).toHaveText("That master password is not right.", { timeout: 30_000 });
  await page.getByLabel("Master password").fill(pw);
  await page.getByRole("button", { name: "Unlock" }).click();
  await expect(page.getByRole("button", { name: "Unlock" })).toHaveCount(0, { timeout: 30_000 });
  await expect(page.getByRole("button", { name: /^Infrastructure/ })).toBeVisible({ timeout: 30_000 });
  await openInfrastructure();
  await expect(page.getByRole("button", { name: /AWS root \(prod\)/ })).toBeVisible();

  // Reloading a deep link (served under the base path, if any) brings the app back, locked.
  expect(new URL(page.url()).pathname).toMatch(new RegExp(`^${BASE}/p/`));
  await page.reload();
  await expect(page.getByText("Vault locked")).toBeVisible({ timeout: 30_000 });
  await page.getByLabel("Master password").fill(pw);
  await page.getByRole("button", { name: "Unlock" }).click();
  await expect(page.getByRole("button", { name: /^Infrastructure/ })).toBeVisible({ timeout: 30_000 });

  await accountMenu(page, "Sign out");
  await page.getByLabel("Email address").fill(email);
  await page.getByRole("button", { name: "Next" }).click();
  await expect(page.getByText(email)).toBeVisible();
  await page.getByLabel("Master password").fill(pw);
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.getByLabel("6-digit code from your authenticator app").fill(await totp(secret));
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("button", { name: /^Infrastructure/ })).toBeVisible({ timeout: 30_000 });
  await openInfrastructure();
  await expect(page.getByRole("button", { name: /AWS root \(prod\)/ })).toBeVisible();
});
