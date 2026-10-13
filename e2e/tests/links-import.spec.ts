import { expect, test, type Page } from "@playwright/test";
import { newInvite, openNav, saveRecoveryKit, totp, newRecord } from "../helpers";

async function register(page: Page) {
  const email = `e2e-p3-${Date.now()}-${Math.floor(Math.random() * 1e4)}@clane.ai`;
  const pw = "an e2e master password";
  await page.goto(newInvite(email));
  await page.getByLabel("Your name").fill("Link Tester");
  await page.getByLabel("Master password", { exact: true }).fill(pw);
  await page.getByLabel("Repeat master password").fill(pw);
  await page.getByRole("button", { name: "Create account" }).click();
  const keyText = await page.getByText(/Enter this key:\s*[A-Z2-7]{16,}/).textContent({ timeout: 60_000 });
  await page.getByLabel("6-digit code").fill(await totp(keyText!.split(":")[1]!.trim()));
  await page.getByRole("button", { name: "Turn on and continue" }).click();
  await saveRecoveryKit(page);
  await expect(page.getByText("No records yet")).toBeVisible({ timeout: 30_000 });
}

/** Record owners make links from the Share sheet's "One-time link" tab. */
async function openLinkTab(page: Page) {
  await page.getByRole("button", { name: "Share", exact: true }).click();
  await page.getByRole("tab", { name: "One-time link" }).click();
}

test("one-time link: create (once), open in a fresh browser, second open is used up", async ({ page, browser }, testInfo) => {
  await register(page);
  await newRecord(page, "Customer portal");
  await page.getByLabel("Username").fill("acme-admin");
  await page.getByLabel("Password", { exact: true }).fill("Tg7#qL2v!Rm9zW4x");
  await page.getByRole("button", { name: "Save" }).click();
  await page.getByLabel("Search records").fill("Customer");
  await page.getByRole("button", { name: /Customer portal/ }).click();

  await openLinkTab(page);
  await page.getByLabel("Who it's for").fill("Acme Ltd");
  await expect(page.getByRole("radio", { name: "Once" })).toHaveAttribute("aria-checked", "true");
  await page.getByRole("button", { name: "Create link" }).click();
  const url = (await page.getByLabel("Link to send").textContent({ timeout: 30_000 }))!;
  expect(url).toMatch(/\/s\/[0-9a-f-]{36}#[A-Za-z0-9_-]{43}$/);
  await page.getByRole("button", { name: "Done" }).click();

  const ctx = await browser.newContext(testInfo.project.use);
  const guest = await ctx.newPage();
  const requests: string[] = [];
  guest.on("request", (r) => requests.push(r.url() + (r.postData() ?? "")));
  await guest.goto(url);
  await expect(guest.getByText(/can be opened 1 more time/)).toBeVisible();
  await guest.getByRole("button", { name: "Show the details" }).click();
  await expect(guest.getByRole("heading", { name: "Customer portal" })).toBeVisible();
  await expect(guest.getByLabel("Username", { exact: true })).toHaveText("acme-admin");
  await guest.getByRole("button", { name: "Show password" }).click();
  await expect(guest.getByLabel("Password", { exact: true })).toHaveText("Tg7#qL2v!Rm9zW4x");
  const key = url.split("#")[1]!;
  expect(requests.some((r) => r.includes(key))).toBe(false);
  await ctx.close();

  const ctx2 = await browser.newContext(testInfo.project.use);
  const again = await ctx2.newPage();
  await again.goto(url);
  await expect(again.getByRole("heading", { name: "This link has been used up" })).toBeVisible();
  await expect(again.getByText("Tg7#qL2v!Rm9zW4x")).toHaveCount(0);
  await ctx2.close();

  // The owner sees it under Share links as used up.
  if (await page.getByRole("button", { name: "Back" }).isVisible()) await page.getByRole("button", { name: "Back" }).click();
  await openNav(page);
  await page.getByRole("link", { name: /Share links/ }).click();
  await expect(page.getByText(/Customer portal · for Acme Ltd/)).toBeVisible();
  await expect(page.getByText(/Used up · Opened 1 of 1/)).toBeVisible();
});

test("password link: needs the full URL and the password", async ({ page, browser }, testInfo) => {
  await register(page);
  await newRecord(page, "Router admin");
  await page.getByLabel("Username").fill("admin");
  await page.getByLabel("Password", { exact: true }).fill("Zq8$wP3n!Lk7xV2m");
  await page.getByRole("button", { name: "Save" }).click();
  await page.getByLabel("Search records").fill("Router");
  await page.getByRole("button", { name: /Router admin/ }).click();
  await openLinkTab(page);
  await page.getByRole("radio", { name: "3 times" }).click();
  await page.getByLabel("Password (optional)").fill("blue cactus");
  await page.getByRole("button", { name: "Create link" }).click();
  const url = (await page.getByLabel("Link to send").textContent({ timeout: 60_000 }))!;
  expect(url).toMatch(/\/s\/[0-9a-f-]{36}#[A-Za-z0-9_-]{43}$/);
  expect(url.endsWith("#p")).toBe(false);

  const ctx = await browser.newContext(testInfo.project.use);
  const guest = await ctx.newPage();
  await guest.goto(url.split("#")[0]!);
  await expect(guest.getByRole("heading", { name: "This link is incomplete" })).toBeVisible();
  await guest.goto("about:blank");
  await guest.goto(url);
  await guest.getByLabel("Password").fill("red cactus");
  await guest.getByRole("button", { name: "Open" }).click();
  await expect(guest.getByText("That password isn't right.")).toBeVisible({ timeout: 60_000 });
  await guest.getByLabel("Password").fill("blue cactus");
  await guest.getByRole("button", { name: "Open" }).click();
  await expect(guest.getByRole("heading", { name: "Router admin" })).toBeVisible({ timeout: 60_000 });
  await guest.getByRole("button", { name: "Show password" }).click();
  await expect(guest.getByLabel("Password", { exact: true })).toHaveText("Zq8$wP3n!Lk7xV2m");
  await expect(guest.getByText(/can be opened 2 more times/)).toBeVisible();
  await ctx.close();
});

test("import a small Keeper JSON export; weak password shows under Needs attention", async ({ page }) => {
  await register(page);
  const file = JSON.stringify({ records: [
    { title: "Figma", login: "design@clane.ai", password: "figma123", login_url: "https://figma.com", folders: [{ folder: "Design" }] },
    { title: "AWS root", login: "ops@clane.ai", password: "Tg7#qL2v!Rm9zW4x", folders: [{ shared_folder: "Infra" }], custom_fields: { "TFC:Keeper": "otpauth://totp/AWS?secret=JBSWY3DPEHPK3PXP" } },
    { title: "Office Wi-Fi", notes: "PSK: correct horse" },
  ] });
  await page.getByRole("button", { name: "New", exact: true }).click();
  await page.getByRole("menuitem", { name: /Import/ }).click();
  await page.getByLabel("Export file").setInputFiles({ name: "keeper.json", mimeType: "application/json", buffer: Buffer.from(file) });
  await expect(page.getByText("3 records from Keeper (JSON).")).toBeVisible();
  await page.getByRole("button", { name: "Import 3" }).click();
  await expect(page.getByText("Imported 3 records")).toBeVisible({ timeout: 30_000 });
  await page.getByRole("button", { name: "Done" }).click();

  await expect(page.getByRole("button", { name: /^Design/ })).toBeVisible({ timeout: 30_000 });
  await expect(page.getByRole("button", { name: /^Infra/ })).toBeVisible();
  await page.getByRole("button", { name: /^Infra/ }).click();
  await page.getByRole("button", { name: /AWS root/ }).click();
  await expect(page.getByLabel("2FA code", { exact: true })).toHaveText(/^\d{3} \d{3}$/);
  if (await page.getByRole("button", { name: "Back" }).isVisible()) await page.getByRole("button", { name: "Back" }).click();

  await openNav(page);
  await page.getByRole("link", { name: /Needs attention/ }).click();
  await page.getByRole("button", { name: /Figma/ }).click();
  await expect(page.getByRole("note", { name: "Needs attention" })).toContainText("This password is weak");
  await expect(page.getByRole("complementary", { name: "Record details" }).getByText("Weak", { exact: true })).toBeVisible();
});
