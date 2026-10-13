// Admin recovery with per-org key pairs (docs/design/2026-10-08-per-org-keypairs.md). It runs in its own
// project after every other test (see playwright.config.ts) and uses organisations of its own, because while admin
// recovery is on, every vault that unlocks there shows a blocking notice.
import { expect, test, type Browser, type Page } from "@playwright/test";
import { newInvite, newOrg, saveRecoveryKit, totp, accountMenu, adminPage, settingsPage, newRecord, newSharedFolder, switchSpace } from "../../helpers";

const PW = "an e2e master password";
const NEW_PW = "a fresh master password after recovery";
const uniq = () => `${Date.now()}-${Math.floor(Math.random() * 1e4)}`;
const DESKTOP = { viewport: { width: 1440, height: 900 }, permissions: ["clipboard-read", "clipboard-write"] };

async function register(page: Page, invitePath: string, name: string) {
  await page.goto(invitePath);
  await page.getByLabel("Your name").fill(name);
  await page.getByLabel("Master password", { exact: true }).fill(PW);
  await page.getByLabel("Repeat master password").fill(PW);
  await page.getByRole("button", { name: "Create account" }).click();
  const keyText = await page.getByText(/Enter this key:\s*[A-Z2-7]{16,}/).textContent({ timeout: 60_000 });
  const secret = keyText!.split(":")[1]!.trim();
  await page.getByLabel("6-digit code").fill(await totp(secret));
  await page.getByRole("button", { name: "Turn on and continue" }).click();
  const kit = await saveRecoveryKit(page);
  await expect(page.getByRole("button", { name: "New", exact: true })).toBeVisible({ timeout: 30_000 });
  return { secret, kit };
}

async function unlockAfterReload(page: Page, pw = PW) {
  await page.reload();
  await expect(page.getByText("Vault locked")).toBeVisible({ timeout: 30_000 });
  await page.getByLabel("Master password").fill(pw);
  await page.getByRole("button", { name: "Unlock" }).click();
  await expect(page.getByRole("button", { name: "Unlock" })).toHaveCount(0, { timeout: 30_000 });
}

async function teamFolder(page: Page, name: string, person: string) {
  const dlg = await newSharedFolder(page);
  await dlg.getByLabel("Folder name").fill(name);
  await dlg.getByRole("combobox", { name: "Person", exact: true }).click();
  await page.getByRole("option", { name: new RegExp(person) }).click();
  await dlg.getByRole("button", { name: "Add" }).click();
  await expect(dlg.getByRole("listitem", { name: person })).toBeVisible();
  await dlg.getByRole("button", { name: "Create" }).click();
  await expect(page.getByRole("button", { name: new RegExp(`^${name}`) })).toBeVisible({ timeout: 30_000 });
}

async function newLogin(page: Page, title: string, password: string, folder?: RegExp) {
  await newRecord(page, title, { folder });
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("dialog")).toHaveCount(0);
}

async function seesRecord(page: Page, title: string, password: string) {
  await page.getByRole("link", { name: /^Vault/ }).first().click();
  await page.getByLabel("Search records").fill(title, { timeout: 30_000 });
  await page.getByRole("button", { name: new RegExp(title) }).click({ timeout: 30_000 });
  await page.getByRole("button", { name: "Copy password" }).click();
  await expect.poll(() => page.evaluate(() => navigator.clipboard.readText())).toBe(password);
  await page.getByLabel("Search records").fill("");
}

async function switchTo(page: Page, org: string) {
  await switchSpace(page, org);
  await expect(page.getByTestId("active-org")).toHaveText(org, { timeout: 30_000 });
}

async function context(browser: Browser) {
  const ctx = await browser.newContext(DESKTOP);
  return { ctx, page: await ctx.newPage() };
}

test("two orgs: admin recovery in A restores only A's team folders; private items and B stay locked until the old kit restores them", async ({ browser }) => {
  test.setTimeout(420_000);
  const id = uniq();
  const alpha = `Alpha ${id}`, beta = `Beta ${id}`;
  const orgA = newOrg(alpha), orgB = newOrg(beta);
  const deeName = `Dee ${id}`, deeEmail = `e2e-po-dee-${id}@clane.ai`;
  const a = await context(browser), b = await context(browser), d = await context(browser);
  try {
    const ownerA = await register(a.page, newInvite(`e2e-po-oa-${id}@clane.ai`, "owner", orgA), "Owner Alpha");
    await register(b.page, newInvite(`e2e-po-ob-${id}@clane.ai`, "owner", orgB), "Owner Beta");
    const dee = await register(d.page, newInvite(deeEmail, "member", orgA), deeName);

    // Dee also joins B (an invitation for an existing account), and keeps a private login.
    await adminPage(b.page, "People");
    await b.page.getByLabel("Email").fill(deeEmail);
    await b.page.getByRole("button", { name: "Invite", exact: true }).click();
    await unlockAfterReload(d.page);
    await d.page.getByRole("button", { name: /^Space: .*1 invitation/ }).click();
    await d.page.getByRole("menuitem", { name: "Accept and switch" }).click();
    await expect(d.page.getByTestId("active-org")).toHaveText(beta, { timeout: 30_000 });
    await switchSpace(d.page, "Personal");
    await newLogin(d.page, `Dee private ${id}`, "Pr1v@te-Dee-pw!");

    // A team folder with a login in each org, both shared with Dee.
    await switchTo(a.page, alpha);
    await teamFolder(a.page, `Alpha Team ${id}`, deeName);
    await newLogin(a.page, `A secret ${id}`, "A-team-s3cret!", new RegExp(`Alpha Team ${id}`));
    await unlockAfterReload(b.page); // B's people list now includes Dee
    await b.page.getByRole("link", { name: /^Vault/ }).click(); // a reload keeps the page (People): back to the vault
    await teamFolder(b.page, `Beta Team ${id}`, deeName);
    await newLogin(b.page, `B secret ${id}`, "B-team-s3cret!", new RegExp(`Beta Team ${id}`));

    // A's owner turns admin recovery on (master password + fresh 2FA).
    await adminPage(a.page, "Admin recovery");
    const sw = a.page.getByRole("switch", { name: "Admin account recovery" });
    await expect(sw).toBeEnabled({ timeout: 30_000 });
    await sw.click();
    const on = a.page.getByRole("dialog");
    await expect(on).toContainText("Never their private items");
    await on.getByLabel("Your master password").fill(PW);
    await on.getByLabel("6-digit code from your authenticator app").fill(await totp(ownerA.secret));
    await on.getByRole("button", { name: "Turn on" }).click();
    await expect(sw).toHaveAttribute("aria-checked", "true", { timeout: 30_000 });
    await unlockAfterReload(a.page); // A's owner has a membership key to be escrowed to

    // Dee acknowledges in A: the notice says what A's admins could restore, then the escrow is made on this device.
    await unlockAfterReload(d.page);
    const notice = d.page.getByRole("dialog");
    await expect(notice).toContainText(`${alpha} turned on admin recovery`, { timeout: 30_000 });
    await expect(notice).toContainText("They can't open your private items or other organisations' items");
    await notice.getByRole("button", { name: "Continue" }).click();
    await expect(notice).toHaveCount(0);
    await switchTo(d.page, alpha); // the escrow is made by this device, in the org it is for
    await settingsPage(d.page, "Security");
    await expect(d.page.getByRole("list", { name: "Who holds your escrow" })).toContainText("held by Owner Alpha", { timeout: 60_000 });

    // Forgot the password: ask an admin.
    await accountMenu(d.page, "Sign out");
    await d.page.getByLabel("Email address").fill(deeEmail);
    await d.page.getByRole("button", { name: "Next" }).click();
    await d.page.getByRole("button", { name: "Need help?" }).click();
    await d.page.getByRole("menuitem", { name: "Ask an admin to reset my password" }).click();
    const ask = d.page.getByRole("note", { name: "Ask an admin to reset my password" });
    await ask.getByRole("button", { name: "Ask admin" }).click();
    await expect(ask.getByRole("status")).toContainText("If that account exists");

    // A's owner approves with a fresh 2FA code.
    await unlockAfterReload(a.page);
    await adminPage(a.page, "People");
    const row = a.page.getByRole("listitem", { name: `Reset request from ${deeEmail}` });
    await expect(row).toBeVisible({ timeout: 30_000 });
    await row.getByRole("button", { name: "Approve" }).click();
    const dialog = a.page.getByRole("dialog");
    await dialog.getByLabel("Your 6-digit authenticator code").fill(await totp(ownerA.secret));
    await dialog.getByRole("button", { name: "Approve and create link" }).click();
    const link = (await dialog.getByTestId("recovery-link").textContent({ timeout: 30_000 }))!.trim();
    await dialog.getByRole("button", { name: "Done" }).click();

    // Dee resets with the link: a new master password restores A only.
    await d.page.goto(new URL(link).pathname + new URL(link).hash);
    await d.page.getByLabel("6-digit code from your authenticator app").fill(await totp(dee.secret));
    await d.page.getByRole("button", { name: "Continue" }).click();
    await expect(d.page.getByText(/This restores what you have in/)).toContainText(alpha, { timeout: 30_000 });
    await d.page.getByLabel("New master password", { exact: true }).fill(NEW_PW);
    await d.page.getByLabel("Repeat new master password").fill(NEW_PW);
    await d.page.getByRole("button", { name: "Set new master password" }).click();
    await saveRecoveryKit(d.page); // the old kit went with the old keys: a new one first
    await expect(d.page.getByTestId("active-org")).toHaveText(alpha, { timeout: 30_000 });

    // A's team folder opens; what stayed locked is said plainly.
    await seesRecord(d.page, `A secret ${id}`, "A-team-s3cret!");
    await expect(d.page.getByRole("status", { name: "Items from before your reset" })).toContainText("1 private item and your access in 1 other organisation are locked");
    await d.page.getByLabel("Search records").fill(`Dee private ${id}`);
    await expect(d.page.getByRole("button", { name: new RegExp(`Dee private ${id}`) })).toHaveCount(0);
    await d.page.getByLabel("Search records").fill("");
    await switchTo(d.page, beta);
    await expect(d.page.getByRole("button", { name: new RegExp(`^Beta Team ${id}`) })).toHaveCount(0, { timeout: 30_000 });

    // The old recovery kit brings back the private login and B.
    await settingsPage(d.page, "Security");
    const restore = d.page.getByRole("region", { name: "From before your reset" });
    await restore.getByLabel("Recovery code from before the reset").fill(dee.kit);
    await restore.getByLabel("6-digit code from your authenticator app").fill(await totp(dee.secret));
    await restore.getByRole("button", { name: "Restore" }).click();
    await expect(d.page.getByText("Restored what was locked from before your reset")).toBeVisible({ timeout: 60_000 });
    await switchSpace(d.page, "Personal");
    await seesRecord(d.page, `Dee private ${id}`, "Pr1v@te-Dee-pw!");
    await switchTo(d.page, beta);
    await d.page.reload();
    await d.page.getByLabel("Master password").fill(NEW_PW);
    await d.page.getByRole("button", { name: "Unlock" }).click();
    await expect(d.page.getByTestId("active-org")).toHaveText(beta, { timeout: 30_000 });
    await seesRecord(d.page, `B secret ${id}`, "B-team-s3cret!");
  } finally {
    await a.ctx.close(); await b.ctx.close(); await d.ctx.close();
  }
});
