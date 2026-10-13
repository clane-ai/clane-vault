import { execSync } from "node:child_process";
import { expect, test, type Page } from "@playwright/test";
import { newInvite, newOrg, newSharedFolder, saveRecoveryKit, totp } from "../helpers";

// User provisioning (docs/provisioning.md): the owner of a new organisation sees the onboarding checklist, bulk-invites
// three people into a group, one of them signs up, and joins the group, while the team folder shared with that group
// still waits for the owner's explicit approval (zero knowledge: provisioning never hands out folder keys).
const PW = "an e2e master password";
const uniq = () => `${Date.now()}-${Math.floor(Math.random() * 1e4)}`;
const SHOTS = process.env.E2E_SHOTS_DIR;

/** One value from the e2e database (the dev compose DB, or the container named by E2E_DB_CONTAINER). */
function sql(query: string): string {
  const target = process.env.E2E_DB_CONTAINER ? `docker exec -i ${process.env.E2E_DB_CONTAINER}` : "docker compose -f deploy/docker-compose.dev.yml exec -T db";
  return execSync(`${target} psql -U vault -d vault -tAc "${query}"`, { cwd: "..", stdio: "pipe" }).toString().trim();
}
/** In-app navigation (a reload would lock the vault). */
async function go(page: Page, path: string) {
  await page.evaluate((p) => { history.pushState({}, "", p); dispatchEvent(new PopStateEvent("popstate")); }, path);
  await expect(page).toHaveURL((u) => u.pathname === path);
}
const shot = async (page: Page, name: string) => {
  if (!SHOTS) return;
  await expect(page.getByTestId("unlock-flash")).toHaveCount(0, { timeout: 10_000 });
  await page.screenshot({ path: `${SHOTS}/${name}.png` });
};

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

test("bulk-invite three people into a group; one joins; the group's folder still needs the owner's approval", async ({ browser, page }, testInfo) => {
  test.skip(testInfo.project.name !== "desktop", "multi-user flow runs once, on desktop");
  test.setTimeout(300_000);
  const id = uniq();
  const org = newOrg(`Prov ${id}`);
  const slug = `e2e-${org.slice(0, 8)}`;
  const owner = `prov-owner-${id}@clane.test`;
  const people = ["ann", "bob", "cara"].map((n) => `prov-${n}-${id}@clane.test`);
  const group = `Eng ${id.slice(-4)}`;
  const folder = `Prov folder ${id.slice(-4)}`;

  await register(page, newInvite(owner, "owner", org), "Olivia Owner");

  // A new organisation: the checklist, computed from the real state.
  await go(page, `/o/${slug}/admin/people`);
  const checklist = page.getByRole("region", { name: "Set up your organisation" });
  await expect(checklist).toBeVisible({ timeout: 30_000 });
  await expect(checklist).toContainText("0/5 done");
  await shot(page, "01-onboarding-checklist");

  // A group, and a team folder shared with it.
  await go(page, `/o/${slug}/admin/groups`);
  await page.getByLabel("New group").fill(group);
  await page.getByRole("button", { name: "Create group" }).click();
  await expect(page.getByRole("listitem", { name: `Group ${group}` })).toBeVisible();
  await go(page, `/o/${slug}/vault`);
  const dlg = await newSharedFolder(page);
  await dlg.getByLabel("Folder name").fill(folder);
  await dlg.getByRole("button", { name: "Create" }).click();
  const row = page.getByRole("button", { name: new RegExp(`^${folder}`) });
  await expect(row).toBeVisible({ timeout: 30_000 });
  await row.hover();
  await page.getByRole("button", { name: `Options for ${folder}` }).click();
  await page.getByRole("menuitem", { name: "Manage people" }).click();
  await page.getByRole("combobox", { name: "Group to share with" }).click();
  await page.getByRole("option", { name: new RegExp(group) }).click();
  await page.getByRole("button", { name: "Share", exact: true }).click();
  await expect(page.getByText(`Shared with ${group}`).first()).toBeVisible({ timeout: 30_000 });
  await page.keyboard.press("Escape");

  // Bulk invite: paste three addresses, pick the group, preview, send.
  await go(page, `/o/${slug}/admin/people`);
  await expect(checklist).toContainText("1/5 done"); // the group
  await page.getByRole("button", { name: "Invite people" }).first().click();
  const inv = page.getByRole("dialog", { name: "Invite people" });
  await inv.getByLabel("Email addresses").fill(`${people[0]}, ${people[1]}\n${people[2]}\n${owner}`);
  await inv.getByRole("checkbox", { name: group }).click();
  await shot(page, "02-invite-dialog");
  await inv.getByRole("button", { name: "Preview" }).click();
  await expect(inv.getByText("3 will be invited")).toBeVisible({ timeout: 30_000 });
  await expect(inv.getByRole("row", { name: owner })).toContainText("Already a member");
  await shot(page, "03-invite-preview");
  await inv.getByRole("button", { name: "Send 3 invitations" }).click();
  const done = page.getByRole("dialog", { name: "Invitations sent" });
  await expect(done.getByText("3 invited")).toBeVisible({ timeout: 30_000 });
  await shot(page, "04-invite-results");
  // Self-hosted: each new link is shown once to copy.
  await done.getByRole("button", { name: `Copy invite link for ${people[0]}` }).click();
  const link = await page.evaluate(() => navigator.clipboard.readText());
  expect(link).toMatch(/\/invite\/[A-Za-z0-9_-]{20,}$/);
  await done.getByRole("button", { name: "Done" }).click();

  const list = page.getByRole("region", { name: "Invitations" });
  for (const p of people) await expect(list.getByRole("listitem", { name: p })).toContainText(`Groups when they join: ${group}`);
  await shot(page, "05-pending-invitations");
  expect(sql(`SELECT count(*) FROM \\"PendingGroupMember\\" WHERE \\"orgId\\"='${org}'`)).toBe("3");
  expect(sql(`SELECT count(*) FROM \\"Event\\" WHERE \\"orgId\\"='${org}' AND action='admin.invite'`)).toBe("3");
  expect(sql(`SELECT count(*) FROM \\"Event\\" WHERE \\"orgId\\"='${org}' AND action='admin.invite_bulk'`)).toBe("1");

  // One of them signs up through the link.
  const ctxB = await browser.newContext();
  const b = await ctxB.newPage();
  await register(b, new URL(link).pathname, "Ann Invitee");
  const annId = sql(`SELECT id FROM \\"User\\" WHERE email='${people[0]}'`);
  // In the group now; the other two still pending; and no folder key yet.
  expect(sql(`SELECT count(*) FROM \\"GroupMember\\" gm JOIN \\"Group\\" g ON g.id=gm.\\"groupId\\" WHERE g.\\"orgId\\"='${org}' AND gm.\\"userId\\"='${annId}'`)).toBe("1");
  expect(sql(`SELECT count(*) FROM \\"PendingGroupMember\\" WHERE \\"orgId\\"='${org}'`)).toBe("2");
  expect(sql(`SELECT count(*) FROM \\"FolderMember\\" WHERE \\"userId\\"='${annId}'`)).toBe("0");

  // The owner approves explicitly, exactly as for anyone added to a group (next time they open the vault).
  await page.goto(`/o/${slug}/vault`);
  await expect(page.getByText("Vault locked")).toBeVisible({ timeout: 30_000 });
  await page.getByLabel("Master password").fill(PW);
  await page.getByRole("button", { name: "Unlock" }).click();
  const banner = page.getByRole("status", { name: "Group access requests" });
  await expect(banner).toContainText("1 person is waiting for access", { timeout: 60_000 });
  await banner.getByRole("button", { name: "Review" }).click();
  const review = page.getByRole("dialog", { name: "Access through groups" });
  await expect(review).toContainText("Ann Invitee");
  await shot(page, "06-group-access-approval");
  await review.getByRole("button", { name: "Approve" }).click();
  await expect(page.getByText("Access given to 1")).toBeVisible({ timeout: 30_000 });
  expect(sql(`SELECT count(*) FROM \\"FolderMember\\" WHERE \\"userId\\"='${annId}'`)).toBe("1");

  // The invitation list no longer shows Ann; the checklist counts the invitations.
  await go(page, `/o/${slug}/admin/people`);
  await expect(list.getByRole("listitem", { name: people[0] })).toHaveCount(0);
  await expect(list.getByRole("listitem", { name: people[1] })).toBeVisible();
  await expect(checklist).toContainText("2/5 done");
  await ctxB.close();
});

test("email domain auto-join settings and the join page", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "desktop", "runs once, on desktop");
  test.setTimeout(180_000);
  const id = uniq();
  const org = newOrg(`Dom ${id}`);
  const slug = `e2e-${org.slice(0, 8)}`;
  await register(page, newInvite(`dom-owner-${id}@clane.test`, "owner", org), "Dana Owner");
  await go(page, `/o/${slug}/admin/org/sso`);
  const section = page.getByRole("region", { name: "Email domain auto-join" });
  await expect(section).toBeVisible({ timeout: 30_000 });
  // No verified domain yet: it can't be switched on.
  await expect(section.getByRole("switch", { name: "Let people with a verified work address join" })).toBeDisabled();
  await expect(section.getByRole("note")).toContainText("Verify a domain above first");
  await section.scrollIntoViewIfNeeded();
  await shot(page, "07-domain-auto-join-settings");
  // The public join page always answers the same.
  const ctx = await page.context().browser()!.newContext();
  const p = await ctx.newPage();
  const joinLink = p.getByRole("link", { name: "Join your organisation with your work email" });
  // A fresh browser on the dev server can stall while Vite optimises dependencies: load again if so.
  for (let i = 0; i < 3; i++) {
    await p.goto("/sign-in");
    if (await joinLink.waitFor({ state: "visible", timeout: 30_000 }).then(() => true, () => false)) break;
  }
  await expect(joinLink).toBeVisible({ timeout: 30_000 });
  await joinLink.click();
  await p.getByLabel("Work email").fill(`someone-${id}@nowhere.test`);
  await shot(p, "08-join-page");
  await p.getByRole("button", { name: "Email me a link" }).click();
  await expect(p.getByRole("status")).toContainText("we've emailed you a link");
  await shot(p, "09-join-page-sent");
  expect(sql(`SELECT count(*) FROM \\"Invite\\" WHERE email='someone-${id}@nowhere.test'`)).toBe("0");
  await ctx.close();
});
