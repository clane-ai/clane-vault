import { execSync } from "node:child_process";
import { expect, type Page } from "@playwright/test";
import { authenticator } from "otplib";
import { createHash, randomBytes, randomUUID } from "node:crypto";

/** psql against the dev DB: the dev compose service by default, or a plain container named by E2E_DB_CONTAINER. */
const psql = (sql: string) => {
  const target = process.env.E2E_DB_CONTAINER
    ? `docker exec -i ${process.env.E2E_DB_CONTAINER}`
    : "docker compose -f deploy/docker-compose.dev.yml exec -T db";
  execSync(`${target} psql -U vault -d vault -c "${sql}"`, { cwd: "..", stdio: "pipe" });
};

/**
 * The path the app under test is served at (E2E_BASE_PATH, e.g. "/vault" for a BASE_PATH deployment behind a proxy;
 * default the root). Playwright resolves "/x" against the origin, so paths the tests open directly get it prepended.
 */
export const BASE = (process.env.E2E_BASE_PATH ?? "").replace(/\/+$/, "");

/** The default organisation (the oldest), or `org` when given (an id from newOrg). */
const orgSql = (org?: string) => (org ? `'${org}'::uuid` : `(SELECT id FROM \\"Organization\\" ORDER BY \\"createdAt\\", id LIMIT 1)`);

/** Creates a fresh invite (to the default organisation, or `org`) directly in the dev DB and returns its URL path. */
export function newInvite(email: string, role: "member" | "admin" | "owner" = "member", org?: string): string {
  const token = randomBytes(24).toString("base64url");
  const hash = createHash("sha256").update(token).digest("hex");
  psql(`INSERT INTO \\"Invite\\" (id,\\"orgId\\",email,role,\\"tokenHash\\",\\"expiresAt\\") VALUES (gen_random_uuid(),${orgSql(org)},'${email}','${role}','${hash}',now()+interval '1 day')`);
  return `${BASE}/invite/${token}`;
}

/** Creates an organisation directly in the dev DB (no members yet; invite its owner with newInvite(..., "owner", id)). */
export function newOrg(name: string): string {
  const id = randomUUID();
  psql(`INSERT INTO \\"Organization\\" (id,name,slug) VALUES ('${id}','${name}','e2e-${id.slice(0, 8)}')`);
  return id;
}

/** Makes an existing account an instance admin in the dev DB (what the instance-admin CLI does). */
export function makeInstanceAdmin(email: string): void {
  psql(`UPDATE \\"User\\" SET \\"instanceAdmin\\"=true WHERE email='${email}'`);
}

/**
 * Marks an organisation's SSO domain verified in the dev DB (the real check is a DNS TXT lookup, which an e2e run can't
 * publish). The domain must have been added in Settings → Single sign-on first.
 */
export function verifySsoDomain(org: string, domain: string): void {
  psql(`UPDATE \\"SsoDomain\\" SET \\"verifiedAt\\"=now() WHERE \\"orgId\\"='${org}'::uuid AND domain='${domain}'`);
}

/** After sign-up (and after a recovery) the app shows the recovery kit before the vault: read the code, confirm, save. */
export async function saveRecoveryKit(page: Page): Promise<string> {
  const code = (await page.getByTestId("recovery-code").textContent({ timeout: 60_000 }))!.trim();
  await page.getByLabel("I saved my recovery kit somewhere safe").check();
  await page.getByRole("button", { name: "Save recovery kit" }).click();
  await expect(page.getByTestId("recovery-code")).toHaveCount(0, { timeout: 30_000 });
  return code;
}

const usedStep = new Map<string, number>();
/**
 * A TOTP code for a time step this secret hasn't used yet: the server accepts each step once per account. Uses the
 * next step (the server's ±1 window accepts it) and waits only when that one is used too.
 */
export async function totp(secret: string): Promise<string> {
  for (;;) {
    const now = Math.floor(Date.now() / 30_000);
    const step = Math.max(now, (usedStep.get(secret) ?? -Infinity) + 1);
    if (step <= now + 1) {
      usedStep.set(secret, step);
      return authenticator.clone({ epoch: step * 30_000 }).generate(secret);
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
}

/** Phones show the sidebar (sections and the account menu) in a drawer behind the top bar's menu button: open it when it's there. */
export async function openNav(page: Page): Promise<void> {
  const menu = page.getByRole("button", { name: "Open menu" });
  if (await menu.isVisible()) await menu.click();
}

/**
 * + New → Record (Keeper's "New Record"): picks the location (`folder`; "No folder" unless given, whatever folder is
 * open: in an organisation's space give its shared folder) and the type, types the title and goes on (Next) to the
 * record editor, which has the title filled in.
 */
export async function newRecord(page: Page, title: string, opts: { folder?: string | RegExp; type?: "Login" | "Secure note" } = {}): Promise<void> {
  await page.getByRole("button", { name: "New", exact: true }).click();
  await page.getByRole("menuitem", { name: "Record", exact: true }).click();
  const dlg = page.getByRole("dialog");
  const location = dlg.getByRole("combobox", { name: "Location" });
  const folder = opts.folder ?? "No folder";
  if (!(typeof folder === "string" ? (await location.textContent())?.trim() === folder : folder.test((await location.textContent()) ?? ""))) {
    await location.click();
    await page.getByRole("option", { name: folder }).click();
  }
  if (opts.type === "Secure note") {
    await dlg.getByRole("combobox", { name: "Record Type" }).click();
    await page.getByRole("option", { name: "Secure note" }).click();
  }
  await dlg.getByLabel("Title").fill(title);
  await dlg.getByRole("button", { name: "Next" }).click();
  await expect(page.getByRole("heading", { name: opts.type === "Secure note" ? "New secure note" : "New login" })).toBeVisible();
  await expect(page.getByLabel("Title")).toHaveValue(title);
}

/** + New → Folder: a private folder (the Personal space). */
export async function newFolder(page: Page, name: string): Promise<void> {
  await page.getByRole("button", { name: "New", exact: true }).click();
  await page.getByRole("menuitem", { name: "Folder", exact: true }).click();
  await page.getByLabel("Folder name").fill(name);
  await page.getByRole("button", { name: "Create" }).click();
  await expect(page.getByRole("button", { name: new RegExp(`^${name}`) })).toBeVisible({ timeout: 30_000 });
}

/** + New → Shared Folder (an organisation's space): opens the dialog (folder name, then people) and returns it. */
export async function newSharedFolder(page: Page) {
  await page.getByRole("button", { name: "New", exact: true }).click();
  await page.getByRole("menuitem", { name: "Shared Folder", exact: true }).click();
  return page.getByRole("dialog");
}

/**
 * The space switcher at the top of the sidebar (docs/design/2026-10-07-multi-org-design.md §11): "Personal",
 * an organisation by name, or `{ firstOrg: true }` for the first organisation listed (e.g. the default one, whose name
 * depends on the server's product name). Switching navigates to that space's vault (/p/vault or /o/<slug>/vault).
 */
export async function switchSpace(page: Page, to: string | RegExp | { firstOrg: true }): Promise<void> {
  await openNav(page);
  await page.getByRole("button", { name: /^Space:/ }).click();
  const menu = page.getByRole("menu");
  if (typeof to === "object" && "firstOrg" in to) await menu.getByRole("group", { name: "Organisations" }).getByRole("menuitem").first().click();
  else if (to === "Personal") await menu.getByRole("group", { name: "Personal" }).getByRole("menuitem").click();
  else await menu.getByRole("group", { name: "Organisations" }).getByRole("menuitem", { name: to }).click();
  await expect(page).toHaveURL(to === "Personal" ? /\/p\/vault$/ : /\/o\/[^/]+\/vault$/);
  await expect(page.getByRole("button", { name: "New", exact: true })).toBeVisible({ timeout: 30_000 });
}

/**
 * Picks an item from the account menu at the bottom of the sidebar (avatar, name, email): Settings, Password health,
 * Admin (owners, admins, instance admins), Install app, Browser extension, Lock, Sign out. Opens the phone drawer first
 * when there is one. A string matches the item's name exactly; a RegExp as given (Admin shows a count).
 */
export async function accountMenu(page: Page, item: string | RegExp): Promise<void> {
  await openNav(page);
  await page.getByRole("button", { name: /^Account menu/ }).click();
  await page.getByRole("menuitem", typeof item === "string" ? { name: item, exact: true } : { name: item }).click();
}

/** Opens a section from a sub-navigation (desktop: beside the page; phones: the section list at /settings or /admin). */
async function section(page: Page, area: "Settings" | "Admin", name: string | RegExp): Promise<void> {
  const nav = page.getByRole("navigation", { name: `${area} sections` });
  // Prefix match: a section can carry a count (People, Migrate from Keeper).
  const re = typeof name === "string" ? new RegExp(`^${name}`) : name; // section names have no regex characters
  await nav.getByRole("link", { name: re }).first().click();
  await expect(page).toHaveURL(new RegExp(area === "Admin" ? "/(admin|server)/" : "/settings/"));
}

/** Settings (/settings/*, everyone): Account, Security, This device, Browser extension, Password health. */
export async function settingsPage(page: Page, name: string | RegExp): Promise<void> {
  await accountMenu(page, "Settings");
  await section(page, "Settings", name);
}

/**
 * Admin (/o/<org>/admin/*; from Personal, an organisation the user administers): People, Groups, Event log, Password health, Migrate from Keeper; the organisation's General,
 * Policies, Single sign-on, Admin recovery, Email; Server: Customer organisations, Accounts, Branding, Email, Backups (instance admins).
 */
export async function adminPage(page: Page, name: string | RegExp): Promise<void> {
  await accountMenu(page, /^Admin/);
  await section(page, "Admin", name);
}
