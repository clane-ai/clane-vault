import { expect, test, type Page } from "@playwright/test";
import { BASE, newInvite, saveRecoveryKit, totp, accountMenu, newRecord } from "../helpers";

/** Sign-up through an invite, 2FA and the recovery kit; leaves the vault open. */
async function signUp(page: Page, email: string, pw: string) {
  await page.goto(newInvite(email));
  await page.getByLabel("Your name").fill("PWA User");
  await page.getByLabel("Master password", { exact: true }).fill(pw);
  await page.getByLabel("Repeat master password").fill(pw);
  await page.getByRole("button", { name: "Create account" }).click();
  const keyText = await page.getByText(/Enter this key:\s*[A-Z2-7]{16,}/).textContent({ timeout: 60_000 });
  await page.getByLabel("6-digit code").fill(await totp(keyText!.split(":")[1]!.trim()));
  await page.getByRole("button", { name: "Turn on and continue" }).click();
  await saveRecoveryKit(page);
  await expect(page.getByText("No records yet")).toBeVisible({ timeout: 30_000 });
}

/** Records without a folder sit in the collapsible "No folder" group. */
async function openNoFolder(page: Page) {
  const g = page.getByRole("button", { name: /^No folder/ });
  await expect(g).toBeVisible({ timeout: 60_000 });
  if ((await g.getAttribute("aria-expanded")) !== "true") await g.click();
}

test("offline copy: unlock without the server, read-only with a banner, back online on reconnect", async ({ page }) => {
  const email = `pwa-${Date.now()}-${Math.floor(Math.random() * 1e4)}@clane.ai`;
  const pw = "a pwa e2e master password";
  await signUp(page, email, pw);
  await newRecord(page, "Offline GitHub");
  await page.getByLabel("Username").fill("dev@clane.ai");
  await page.getByLabel("Password", { exact: true }).fill("Tg7#qL2v!Rm9zW4x");
  await page.getByRole("button", { name: "Save" }).click();
  await openNoFolder(page);
  await expect(page.getByRole("button", { name: /Offline GitHub/ })).toBeVisible({ timeout: 30_000 });
  // The copy is written after the sync that follows the save.
  // Under a base path the database is named per instance ("clane-offline@/vault").
  const dbName = BASE ? `clane-offline@${BASE}` : "clane-offline";
  await expect.poll(() => page.evaluate((name) => new Promise<number>((res) => {
    const r = indexedDB.open(name);
    r.onsuccess = () => { const q = r.result.transaction("copies").objectStore("copies").getAll(); q.onsuccess = () => res(JSON.stringify(q.result).includes('"records":[{') ? 1 : 0); };
    r.onerror = () => res(0);
  }), dbName), { timeout: 30_000 }).toBe(1);

  // The API goes away (the dev server has no service worker, so the page itself still loads).
  await page.route("**/api/**", (route) => route.abort("internetdisconnected"));
  await page.reload();
  await expect(page.getByText(/You're offline/)).toBeVisible({ timeout: 30_000 });
  await page.getByLabel("Master password").fill(pw);
  await page.getByRole("button", { name: "Unlock offline copy" }).click();
  await expect(page.getByTestId("offline-banner")).toContainText("Offline — read only", { timeout: 60_000 });
  await openNoFolder(page);
  await page.getByRole("button", { name: /Offline GitHub/ }).click();
  await expect(page.getByRole("button", { name: "Copy password" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Edit" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "New", exact: true }).first()).toBeDisabled();

  await page.unroute("**/api/**");
  await page.evaluate(() => window.dispatchEvent(new Event("online")));
  await expect(page.getByTestId("offline-banner")).toHaveCount(0, { timeout: 30_000 });
  await expect(page.getByRole("button", { name: "Edit" })).toBeVisible({ timeout: 30_000 });

  // Signing out wipes the copy.
  const back = page.getByRole("button", { name: "Back" });
  if (await back.isVisible()) await back.click();
  await accountMenu(page, "Sign out");
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible({ timeout: 30_000 });
  expect(await page.evaluate((name) => new Promise<number>((res) => {
    const r = indexedDB.open(name);
    r.onsuccess = () => { const q = r.result.transaction("copies").objectStore("copies").count(); q.onsuccess = () => res(q.result); };
    r.onerror = () => res(-1);
  }), dbName)).toBe(0);
});
