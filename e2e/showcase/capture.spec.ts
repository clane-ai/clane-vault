import { writeFileSync } from "node:fs";
import path from "node:path";
import { expect, test, type Browser, type Locator, type Page } from "@playwright/test";
import { newInvite, newRecord, newSharedFolder, saveRecoveryKit, totp } from "../helpers";

// Seeds a small, made-up company vault (Northwind; example.com people) and captures the three sign-in showcase
// slides into apps/web/public/showcase/. Run through `npm run showcase -w e2e` (run.mjs): a fresh database each time.

const OUT = path.resolve(import.meta.dirname, "../../apps/web/public/showcase");
const PW = "showcase master password";
const MAX_BYTES = 150 * 1024;

const SARA = { name: "Sara Okafor", email: "sara@example.com" };
const BEA = { name: "Bea Lindqvist", email: "bea@example.com" };
const PRIYA = { name: "Priya Nair", email: "priya@example.com" };
const TOM = { name: "Tom Reyes", email: "tom@example.com" };

type Login = { title: string; username?: string; password?: string; url?: string; notes?: string; note?: true };
const FOLDERS: { name: string; team?: true; records: Login[] }[] = [
  { name: "Infrastructure", records: [
    { title: "AWS root account", username: "ops@example.com", password: "vR8#tQ2m!Lx6pZ9w", url: "console.aws.amazon.com",
      notes: "Root user. Billing and break-glass only. MFA is on the ops phone." },
    { title: "Cloudflare", username: "ops@example.com", password: "Kd4$wN7q@Hc2yB5e", url: "dash.cloudflare.com" },
    { title: "GitHub org owner", username: "northwind-bot", password: "pF6&zR1x#Mv8sJ3k", url: "github.com" },
    { title: "Google Workspace admin", username: "admin@example.com", password: "Wq3!nT8c$Ge5rY7u", url: "admin.google.com" },
  ] },
  { name: "Marketing", team: true, records: [
    { title: "Customer portal", username: "acme-admin", password: "Tg7#qL2v!Rm9zW4x", url: "portal.example.com" },
    { title: "Figma", username: "design@example.com", password: "Hy5@kP9d&Xn2fC6m", url: "figma.com" },
    { title: "LinkedIn page", username: "marketing@example.com", password: "Zc8%bV3s!Qw7hD1j", url: "linkedin.com" },
  ] },
  { name: "Finance", records: [
    { title: "Stripe dashboard", username: "finance@example.com", password: "Lm2^gS6t#Pk9vE4r", url: "dashboard.stripe.com" },
    { title: "Company bank", username: "northwind-fin", password: "Bx9!rJ4w@Tn7qK2h", url: "bank.example.com" },
  ] },
  { name: "Personal", records: [
    { title: "Office Wi-Fi", note: true, notes: "Network: Northwind-Staff\nPassword: harbour-lantern-42\nGuest network: Northwind-Guest" },
  ] },
];

/** Accepts an invite, sets the master password and 2FA, saves the recovery kit. */
async function register(page: Page, invitePath: string, name: string): Promise<void> {
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

async function newContext(browser: Browser, use: object) {
  const ctx = await browser.newContext(use);
  // No "Backups are off" strip on the shots.
  await ctx.addInitScript(() => { try { localStorage.setItem("cv.backups-off-dismissed", "1"); } catch { /* */ } });
  return ctx;
}

async function pickPerson(page: Page, scope: Locator, name: string, permission: "Can edit" | "Can view") {
  await scope.getByRole("combobox", { name: "Person", exact: true }).click();
  await page.getByRole("option", { name: new RegExp(name) }).click();
  await scope.getByRole("combobox", { name: "Permission for new person" }).click();
  await page.getByRole("option", { name: permission }).click();
}

async function addRecord(page: Page, folder: string, r: Login) {
  await newRecord(page, r.title, { folder: new RegExp(`^${folder}`), type: r.note ? "Secure note" : "Login" });
  if (r.username) await page.getByLabel("Username").fill(r.username);
  if (r.password) await page.getByLabel("Password", { exact: true }).fill(r.password);
  if (r.url) await page.getByLabel("Website").fill(r.url);
  if (r.notes) await page.getByLabel("Notes").fill(r.notes);
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("dialog")).toHaveCount(0);
}

async function expandFolder(page: Page, name: string, open = true) {
  const folder = page.getByRole("button", { name: new RegExp(`^${name}`) }).first();
  await expect(folder).toBeVisible({ timeout: 30_000 });
  if (((await folder.getAttribute("aria-expanded")) === "true") !== open) await folder.click();
}

/** Waits for toasts to leave, moves the mouse out of the way, pins the sync time, and saves a webp under ~150 KB. */
async function capture(page: Page, name: string) {
  await expect(page.locator("[data-sonner-toast]")).toHaveCount(0, { timeout: 30_000 });
  await page.mouse.move(1279, 799);
  await page.evaluate(() => {
    (document.activeElement as HTMLElement | null)?.blur();
    // Deterministic footer: "Synced 09:41 AM" rather than the time of the run.
    for (const el of document.querySelectorAll("span")) if (/^Synced \d/.test(el.textContent ?? "") && el.children.length === 0) el.textContent = "Synced 09:41 AM";
  });
  await page.waitForTimeout(400);
  const png = await page.screenshot({ animations: "disabled", caret: "hide" });
  writeFileSync(test.info().outputPath(`${name}.png`), png);
  // Chromium's own webp encoder (canvas.toDataURL): no image library needed.
  const webp = await page.evaluate(async ({ b64, max }) => {
    const img = new Image();
    img.src = `data:image/png;base64,${b64}`;
    await img.decode();
    const c = document.createElement("canvas");
    c.width = img.naturalWidth; c.height = img.naturalHeight;
    c.getContext("2d")!.drawImage(img, 0, 0);
    let out = "";
    for (const q of [0.9, 0.85, 0.8, 0.75, 0.7, 0.6]) {
      out = c.toDataURL("image/webp", q);
      if (out.length * 0.75 <= max) break;
    }
    return out.split(",")[1]!;
  }, { b64: png.toString("base64"), max: MAX_BYTES });
  const bytes = Buffer.from(webp, "base64");
  expect(bytes.subarray(8, 12).toString()).toBe("WEBP");
  writeFileSync(path.join(OUT, `${name}.webp`), bytes);
  console.log(`${name}.webp: ${(bytes.length / 1024).toFixed(1)} KB`);
}

test("sign-in showcase screenshots", async ({ browser }, testInfo) => {
  const use = testInfo.project.use;
  const ctx = await newContext(browser, use);
  const page = await ctx.newPage();
  await register(page, newInvite(SARA.email, "owner"), SARA.name);

  // Teammates, so the team folder, the Share panel and its people picker have people in them.
  for (const p of [BEA, PRIYA, TOM]) {
    const c = await newContext(browser, use);
    await register(await c.newPage(), newInvite(p.email), p.name);
    await c.close();
  }
  await page.reload();
  await page.getByLabel("Master password").fill(PW);
  await page.getByRole("button", { name: "Unlock" }).click();
  await expect(page.getByRole("button", { name: "New", exact: true })).toBeVisible({ timeout: 30_000 });

  for (const f of FOLDERS) {
    if (f.team) {
      const dlg = await newSharedFolder(page);
      await dlg.getByLabel("Folder name").fill(f.name);
      await pickPerson(page, dlg, BEA.name, "Can edit");
      await dlg.getByRole("button", { name: "Add" }).click();
      await pickPerson(page, dlg, PRIYA.name, "Can view");
      await dlg.getByRole("button", { name: "Add" }).click();
      await dlg.getByRole("button", { name: "Create" }).click();
    } else {
      await page.getByRole("button", { name: "New", exact: true }).click();
      await page.getByRole("menuitem", { name: "Folder", exact: true }).click();
      await page.getByLabel("Folder name").fill(f.name);
      await page.getByRole("button", { name: "Create" }).click();
    }
    await expect(page.getByRole("button", { name: new RegExp(`^${f.name}`) }).first()).toBeVisible({ timeout: 30_000 });
    for (const r of f.records) await addRecord(page, f.name, r);
  }

  // Google Workspace admin: shared directly, Bea can edit, Priya can view.
  await expandFolder(page, "Infrastructure");
  await page.getByRole("button", { name: /Google Workspace admin/ }).click();
  await page.getByRole("button", { name: "Share", exact: true }).click();
  let share = page.getByRole("dialog");
  for (const [p, perm] of [[BEA, "Can edit"], [PRIYA, "Can view"]] as const) {
    await pickPerson(page, share, p.name, perm);
    await share.getByRole("button", { name: "Share", exact: true }).click();
    await expect(share.getByRole("listitem", { name: p.name })).toBeVisible({ timeout: 30_000 });
  }
  await share.getByRole("button", { name: "Done" }).click();
  await expect(page.getByRole("dialog")).toHaveCount(0);

  // AWS root account: Bea can edit it too, so "Who can open this" isn't just you.
  await page.getByRole("button", { name: /AWS root account/ }).click();
  await page.getByRole("button", { name: "Share", exact: true }).click();
  share = page.getByRole("dialog");
  await pickPerson(page, share, BEA.name, "Can edit");
  await share.getByRole("button", { name: "Share", exact: true }).click();
  await expect(share.getByRole("listitem", { name: BEA.name })).toBeVisible({ timeout: 30_000 });
  await share.getByRole("button", { name: "Done" }).click();
  await expect(page.getByRole("dialog")).toHaveCount(0);

  // 1. vault.webp: folders, Infrastructure and Marketing open, AWS root account in the side panel.
  await page.goto("/");
  await page.getByLabel("Master password").fill(PW);
  await page.getByRole("button", { name: "Unlock" }).click();
  await expandFolder(page, "Infrastructure");
  await expandFolder(page, "Marketing");
  await page.getByRole("button", { name: /AWS root account/ }).click();
  await expect(page.getByRole("heading", { name: "AWS root account" })).toBeVisible();
  await capture(page, "vault");

  // 2. share.webp: the Share panel for Google Workspace admin, three people with owner, edit and view.
  await page.getByRole("button", { name: /Google Workspace admin/ }).click();
  await page.getByRole("button", { name: "Share", exact: true }).click();
  share = page.getByRole("dialog");
  await expect(share.getByRole("listitem", { name: PRIYA.name })).toBeVisible();
  await capture(page, "share");
  await share.getByRole("button", { name: "Done" }).click();

  // 3. link.webp: a one-time link for the Customer portal record, ready to copy.
  await expandFolder(page, "Infrastructure", false);
  await expandFolder(page, "Marketing");
  await page.getByRole("button", { name: /Customer portal/ }).click();
  await page.getByRole("button", { name: "Share", exact: true }).click();
  await page.getByRole("tab", { name: "One-time link" }).click();
  await page.getByLabel("Who it's for").fill("Acme Ltd");
  await page.getByRole("button", { name: "Create link" }).click();
  const link = page.getByLabel("Link to send");
  await expect(link).toHaveText(/\/s\//, { timeout: 30_000 });
  // The link carries the dev server's origin; show the address a real install would have.
  await link.evaluate((el) => { el.textContent = el.textContent!.replace(/^https?:\/\/[^/]+/, "https://vault.example.com"); });
  await capture(page, "link");
  await ctx.close();
});
