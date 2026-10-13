import { expect, test, type Page } from "@playwright/test";
import { newInvite, newOrg, saveRecoveryKit, totp, adminPage, newRecord, newSharedFolder, switchSpace } from "../helpers";

// Spaces (docs/design/2026-10-07-multi-org-design.md §11): one account in two orgs plus its Personal space.
// Each org shows only its own team folders and records, Personal only private ones; the URL names the space, and a
// reload or back/forward never shows another space's data. An admin of one org never sees the other org's people.
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
async function saveLogin(page: Page, title: string, folder?: RegExp) {
  await newRecord(page, title, { folder });
  await page.getByLabel("Password", { exact: true }).fill(`${title} password`);
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("dialog")).toHaveCount(0);
}
/**
 * What the vault shows: `present` folders and records are there, `absent` ones never are. Records are found through the
 * search (every title here contains the run id), folders in the folder view.
 */
async function shows(page: Page, id: string, o: { folders?: string[]; noFolders?: string[]; records?: string[]; noRecords?: string[] }) {
  for (const f of o.folders ?? []) await expect(page.getByRole("button", { name: new RegExp(`^${f}`) })).toBeVisible({ timeout: 30_000 });
  for (const f of o.noFolders ?? []) await expect(page.getByRole("button", { name: new RegExp(`^${f}`) })).toHaveCount(0);
  await page.getByLabel("Search records").fill(id);
  for (const r of o.records ?? []) await expect(page.getByRole("button", { name: new RegExp(r) })).toBeVisible({ timeout: 30_000 });
  for (const r of o.noRecords ?? []) await expect(page.getByRole("button", { name: new RegExp(r) })).toHaveCount(0);
  await page.getByLabel("Search records").fill("");
}

test("Personal and two orgs: each space shows only its own items, through switching, reload and back/forward; an org admin sees only their org's people", async ({ page, browser }, testInfo) => {
  test.skip(testInfo.project.name !== "desktop", "multi-user flow runs once, on desktop");
  test.setTimeout(300_000);
  const id = uniq();
  const alpha = `Alpha ${id}`, beta = `Beta ${id}`;
  const orgA = newOrg(alpha), orgB = newOrg(beta);
  const slugA = `e2e-${orgA.slice(0, 8)}`, slugB = `e2e-${orgB.slice(0, 8)}`;
  const ownerAEmail = `e2e-oa-${id}@clane.ai`, ownerBEmail = `e2e-ob-${id}@clane.ai`, dualEmail = `e2e-dual-${id}@clane.ai`;
  const dualName = `Dee ${id}`;
  const ctx = () => browser.newContext({ viewport: { width: 1440, height: 900 }, permissions: ["clipboard-read", "clipboard-write"] });

  // Owners of A and B; Dee joins A through an invite link. A new device opens the Personal space.
  await register(page, newInvite(ownerAEmail, "owner", orgA), "Owner Alpha");
  await expect(page.getByTestId("active-org")).toHaveText("Personal");
  await expect(page).toHaveURL(/\/p\/vault$/);
  const b = await (await ctx()).newPage();
  await register(b, newInvite(ownerBEmail, "owner", orgB), "Owner Beta");
  const d = await (await ctx()).newPage();
  await register(d, newInvite(dualEmail, "member", orgA), dualName);

  // B's owner invites Dee, who already has an account: an invitation, not a new account.
  await adminPage(b, "People");
  await expect(b).toHaveURL(new RegExp(`/o/${slugB}/admin/people$`));
  await b.getByLabel("Email").fill(dualEmail);
  await b.getByRole("button", { name: "Invite", exact: true }).click();
  // Listed by email only (no hint that the address already has an account).
  const invited = b.getByRole("listitem", { name: dualEmail });
  await expect(invited).toBeVisible();
  await expect(invited).not.toContainText(dualName);

  // Dee accepts from the space switcher and lands in B (its URL).
  await unlockAfterReload(d);
  await d.getByRole("button", { name: /^Space: .*1 invitation/ }).click();
  await expect(d.getByRole("menu")).toContainText(beta);
  await d.getByRole("menuitem", { name: "Accept and switch" }).click();
  await expect(d.getByTestId("active-org")).toHaveText(beta, { timeout: 30_000 });
  await expect(d).toHaveURL(new RegExp(`/o/${slugB}/vault$`));

  // A team folder with a record in each org, both with Dee; and a private record of Dee's (Personal).
  await switchSpace(page, alpha);
  await expect(page).toHaveURL(new RegExp(`/o/${slugA}/vault$`));
  await teamFolder(page, `Alpha Team ${id}`, dualName);
  await saveLogin(page, `Alpha Rec ${id}`, new RegExp(`Alpha Team ${id}`));
  await b.getByRole("link", { name: /^Vault/ }).click();
  await teamFolder(b, `Beta Team ${id}`, dualName);
  await saveLogin(b, `Beta Rec ${id}`, new RegExp(`Beta Team ${id}`));
  await switchSpace(d, "Personal");
  // Personal makes private folders, not shared ones.
  await d.getByRole("button", { name: "New", exact: true }).click();
  await expect(d.getByRole("menuitem", { name: "Shared Folder" })).toHaveAttribute("aria-disabled", "true");
  await d.keyboard.press("Escape");
  await saveLogin(d, `Dee Private ${id}`);

  const inA = { folders: [`Alpha Team ${id}`], noFolders: [`Beta Team ${id}`], records: [`Alpha Rec ${id}`], noRecords: [`Beta Rec ${id}`, `Dee Private ${id}`] };
  const inB = { folders: [`Beta Team ${id}`], noFolders: [`Alpha Team ${id}`], records: [`Beta Rec ${id}`], noRecords: [`Alpha Rec ${id}`, `Dee Private ${id}`] };
  const inPersonal = { noFolders: [`Alpha Team ${id}`, `Beta Team ${id}`], records: [`Dee Private ${id}`], noRecords: [`Alpha Rec ${id}`, `Beta Rec ${id}`] };

  // Personal: private only, also after a reload.
  await shows(d, id, inPersonal);
  await unlockAfterReload(d);
  await expect(d).toHaveURL(/\/p\/vault$/);
  await expect(d.getByTestId("active-org")).toHaveText("Personal");
  await shows(d, id, inPersonal);

  // Each org: its own folder and record only, nothing personal; the URL names it and survives a reload.
  await switchSpace(d, beta);
  await shows(d, id, inB);
  await unlockAfterReload(d);
  await expect(d).toHaveURL(new RegExp(`/o/${slugB}/vault$`));
  await expect(d.getByTestId("active-org")).toHaveText(beta);
  await shows(d, id, inB);
  await switchSpace(d, alpha);
  await expect(d).toHaveURL(new RegExp(`/o/${slugA}/vault$`));
  await shows(d, id, inA);

  // Back and forward move between spaces, each showing only its own items.
  await d.goBack();
  await expect(d).toHaveURL(new RegExp(`/o/${slugB}/vault$`));
  await expect(d.getByTestId("active-org")).toHaveText(beta);
  await shows(d, id, inB);
  await d.goForward();
  await expect(d).toHaveURL(new RegExp(`/o/${slugA}/vault$`));
  await shows(d, id, inA);

  // A link straight to a record of the other org switches to it; a record URL of another space shows nothing of it.
  await d.goto(`/o/${slugB}/vault`);
  await unlockAfterReloadIfLocked(d);
  await expect(d.getByTestId("active-org")).toHaveText(beta, { timeout: 30_000 });
  await shows(d, id, inB);

  // An org Dee isn't in (or one that doesn't exist): the same "can't open" page, nothing of any space.
  const outsider = page;
  await outsider.goto(`/o/${slugB}/vault`);
  await unlockAfterReloadIfLocked(outsider);
  await expect(outsider.getByTestId("no-space-access")).toBeVisible({ timeout: 30_000 });
  await expect(outsider.getByText(`Beta Team ${id}`)).toHaveCount(0);
  await outsider.goto("/o/no-such-org/vault");
  await unlockAfterReloadIfLocked(outsider);
  await expect(outsider.getByTestId("no-space-access")).toBeVisible({ timeout: 30_000 });
  await outsider.getByRole("link", { name: "Go to your Personal vault" }).click();
  await expect(outsider).toHaveURL(/\/p\/vault$/);

  // Old paths open the space used last on this device.
  await outsider.goto("/vault");
  await unlockAfterReloadIfLocked(outsider);
  await expect(outsider).toHaveURL(/\/p\/vault$/, { timeout: 30_000 });

  // A's owner sees A's people only, and has no way into B.
  await adminPage(page, "People");
  await expect(page).toHaveURL(new RegExp(`/o/${slugA}/admin/people$`));
  const everyone = page.getByRole("region", { name: "Everyone" });
  await expect(everyone.getByRole("listitem", { name: dualName })).toBeVisible();
  await expect(everyone).not.toContainText(ownerBEmail);
  await expect(everyone).not.toContainText("Owner Beta");
  await page.getByRole("button", { name: /^Space:/ }).click();
  await expect(page.getByRole("menu")).not.toContainText(beta);
  await page.keyboard.press("Escape");
  // Even forcing B's id onto a request is refused, and B's space (with or without ?space=org) is never served.
  const statuses = await page.evaluate(async (org) => {
    const r = await fetch("/api/v1/auth/refresh", { method: "POST", credentials: "same-origin" });
    const { accessToken } = await r.json();
    const h = { authorization: `Bearer ${accessToken}`, "x-org-id": org };
    return [(await fetch("/api/v1/admin/people", { headers: h })).status, (await fetch("/api/v1/sync?space=org", { headers: h })).status, (await fetch("/api/v1/sync", { headers: h })).status];
  }, orgB);
  expect(statuses).toEqual([403, 403, 403]);
});

/** A full page load locks the vault: unlock when it asks. */
async function unlockAfterReloadIfLocked(page: Page) {
  const locked = page.getByText("Vault locked");
  await expect(locked.or(page.getByTestId("app-shell")).or(page.getByTestId("no-space-access")).first()).toBeVisible({ timeout: 30_000 });
  if (await locked.isVisible()) {
    await page.getByLabel("Master password").fill(PW);
    await page.getByRole("button", { name: "Unlock" }).click();
    await expect(page.getByRole("button", { name: "Unlock" })).toHaveCount(0, { timeout: 30_000 });
  }
}
