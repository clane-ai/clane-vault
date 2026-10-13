import { expect, test, type Browser, type Page } from "@playwright/test";
import { authenticator } from "otplib";
import { newInvite, saveRecoveryKit, totp, accountMenu, newRecord } from "../helpers";

const PW = "an e2e master password";
const NEW_PW = "a fresh master password after recovery";
const uniq = () => `${Date.now()}-${Math.floor(Math.random() * 1e4)}`;
const DESKTOP = { viewport: { width: 1440, height: 900 }, permissions: ["clipboard-read", "clipboard-write"] };

/** Registers through an invite, turns on 2FA, saves the recovery kit. Returns the TOTP secret and the kit code. */
async function register(page: Page, invitePath: string, name: string, opts: { expectDisclosure?: boolean } = {}) {
  await page.goto(invitePath);
  await page.getByLabel("Your name").fill(name);
  if (opts.expectDisclosure) await expect(page.getByRole("note", { name: "Admin recovery" })).toContainText("Your organisation's admins can recover your vault");
  await page.getByLabel("Master password", { exact: true }).fill(PW);
  await page.getByLabel("Repeat master password").fill(PW);
  await page.getByRole("button", { name: "Create account" }).click();
  const keyText = await page.getByText(/Enter this key:\s*[A-Z2-7]{16,}/).textContent({ timeout: 60_000 });
  const secret = keyText!.split(":")[1]!.trim();
  await page.getByLabel("6-digit code").fill(await totp(secret));
  await page.getByRole("button", { name: "Turn on and continue" }).click();
  await expect(page.getByRole("heading", { name: "Save your recovery kit" })).toBeVisible({ timeout: 30_000 });
  const code = await saveRecoveryKit(page);
  await expect(page.getByRole("button", { name: "New", exact: true })).toBeVisible({ timeout: 30_000 });
  return { secret, code };
}

async function newLogin(page: Page, title: string, password: string) {
  await newRecord(page, title);
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("dialog")).toHaveCount(0);
}

/** The private record still decrypts: open it and copy its password. */
async function seesRecord(page: Page, title: string, password: string) {
  await page.getByLabel("Search records").fill(title, { timeout: 30_000 }); // flat results, no folder groups to expand
  await page.getByRole("button", { name: new RegExp(title) }).click({ timeout: 30_000 });
  await page.getByRole("button", { name: "Copy password" }).click();
  await expect.poll(() => page.evaluate(() => navigator.clipboard.readText())).toBe(password);
  const back = page.getByRole("button", { name: "Back" });
  if (await back.isVisible()) await back.click();
  await page.getByLabel("Search records").fill("");
}

async function setNewPassword(page: Page) {
  await page.getByLabel("New master password", { exact: true }).fill(NEW_PW);
  await page.getByLabel("Repeat new master password").fill(NEW_PW);
  await page.getByRole("button", { name: "Set new master password" }).click();
}

async function unlockAfterReload(page: Page, pw = PW) {
  await page.reload();
  await expect(page.getByText("Vault locked")).toBeVisible({ timeout: 30_000 });
  await page.getByLabel("Master password").fill(pw);
  await page.getByRole("button", { name: "Unlock" }).click();
  await expect(page.getByRole("button", { name: "Unlock" })).toHaveCount(0, { timeout: 30_000 });
}

test("recovery kit: saved at sign-up, used after forgetting the password; the private record still decrypts", async ({ page }) => {
  const email = `e2e-kit-${uniq()}@clane.ai`;
  const { secret, code } = await register(page, newInvite(email), "Kit User");
  expect(code).toMatch(/^[0-9A-Z]{4}(-[0-9A-Z]{4}){13}$/);
  await newLogin(page, "Private kit record", "Kt9#vR2!pL6qZ8wX");

  // Forgot the password: Sign in → Need help? → Use your recovery kit.
  await accountMenu(page, "Sign out");
  await page.getByLabel("Email address").fill(email);
  await page.getByRole("button", { name: "Next" }).click();
  await page.getByRole("button", { name: "Need help?" }).click();
  await page.getByRole("menuitem", { name: "Forgot master password? Use your recovery kit" }).click();
  await expect(page.getByRole("heading", { name: "Recover your vault" })).toBeVisible();
  await expect(page.getByLabel("Email address")).toHaveValue(email);
  await page.getByLabel("Recovery code").fill(code.toLowerCase());
  await page.getByRole("button", { name: "Continue" }).click();
  await page.getByLabel("6-digit code from your authenticator app").fill(await totp(secret));
  await page.getByRole("button", { name: "Continue" }).click();
  await setNewPassword(page);

  // The used kit is gone: a new one comes right away.
  await expect(page.getByRole("heading", { name: "Save your new recovery kit" })).toBeVisible({ timeout: 60_000 });
  const code2 = await saveRecoveryKit(page);
  expect(code2).not.toBe(code);
  await seesRecord(page, "Private kit record", "Kt9#vR2!pL6qZ8wX");

  // The new password unlocks; the old one doesn't.
  await page.reload();
  await page.getByLabel("Master password").fill(PW);
  await page.getByRole("button", { name: "Unlock" }).click();
  await expect(page.getByRole("alert")).toHaveText("That master password is not right.", { timeout: 30_000 });
  await page.getByLabel("Master password").fill(NEW_PW);
  await page.getByRole("button", { name: "Unlock" }).click();
  await expect(page.getByRole("button", { name: "Unlock" })).toHaveCount(0, { timeout: 30_000 });
  await seesRecord(page, "Private kit record", "Kt9#vR2!pL6qZ8wX");
});
