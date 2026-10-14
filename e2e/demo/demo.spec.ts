import { expect, test, type Page } from "@playwright/test";

// The public demo (docs/demo.md), on a DEMO_MODE=true API: "Try the demo" on the sign-in page gives a private sandbox,
// signed in without an authenticator and filled with the Northwind sample data. Run with `npm run demo -w e2e`.

const FOLDERS = ["Infrastructure", "Finance", "Office", "Clients"];

async function seesFolders(page: Page) {
  for (const f of FOLDERS) await expect(page.getByRole("button", { name: new RegExp(`^${f}`) }).first()).toBeVisible({ timeout: 30_000 });
}

test("Try the demo opens a sandbox with the sample folders", async ({ page }) => {
  await page.goto("/sign-in");
  await page.getByRole("button", { name: "Try the demo" }).click();

  const banner = page.getByTestId("demo-banner");
  await expect(banner).toBeVisible({ timeout: 90_000 });
  await expect(banner).toHaveText(/Demo sandbox\. Deleted at \d{2}:\d{2}\. Don't enter real passwords\./);
  await expect(banner.getByRole("link", { name: "Self-host it" })).toHaveAttribute("href", "https://github.com/clane-ai/clane-vault");
  // No authenticator setup and no recovery kit on the way in: straight into the organisation's vault.
  await expect(page).toHaveURL(/\/o\/[^/]+\/vault/);
  await seesFolders(page);

  // Typed records with their details, and the agreement attached to the production server.
  await page.getByRole("searchbox", { name: "Search records" }).fill("Production web server");
  await page.getByTestId("record-row").getByRole("button", { name: /Production web server/ }).first().click();
  const panel = page.getByRole("complementary", { name: "Record details" });
  await expect(panel.getByRole("heading", { name: "Production web server" })).toBeVisible();
  await expect(panel.getByText("Rack", { exact: true })).toBeVisible();
  await expect(panel.getByRole("region", { name: "Files" }).getByTestId("file-row").getByText("maintenance-agreement.pdf")).toBeVisible({ timeout: 30_000 });

  // A reload locks the vault like any other; the sandbox opens again by itself (nobody knows its master password).
  await page.reload();
  await expect(banner).toBeVisible({ timeout: 60_000 });
  await page.getByRole("searchbox", { name: "Search records" }).fill("");
  await seesFolders(page);
});

test("each visitor gets a sandbox of their own", async ({ browser }) => {
  const [a, b] = [await browser.newContext(), await browser.newContext()];
  const pa = await a.newPage(), pb = await b.newPage();
  for (const p of [pa, pb]) {
    await p.goto("/sign-in");
    await p.getByRole("button", { name: "Try the demo" }).click();
    await expect(p.getByTestId("demo-banner")).toBeVisible({ timeout: 90_000 });
  }
  // Two different organisations: neither sees the other's.
  const slug = (p: Page) => new URL(p.url()).pathname.split("/")[2];
  expect(slug(pa)).not.toBe(slug(pb));
  await pa.goto(`/o/${slug(pb)}/vault`);
  await expect(pa.getByTestId("no-space-access")).toBeVisible({ timeout: 30_000 });
  await a.close(); await b.close();
});
