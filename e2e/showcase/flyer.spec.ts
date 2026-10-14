import { execSync } from "node:child_process";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { expect, test, type Browser, type Locator, type Page } from "@playwright/test";
import { newInvite, newSharedFolder, saveRecoveryKit, switchSpace, totp } from "../helpers";
// The made-up company, shared with the public demo's sample data (docs/demo.md).
import {
  agreementPdf, AGREEMENT_PDF_NAME, BEA, CERT_NAME, CERT_PEM, LIAM, MAYA, NORTHWIND_FOLDERS, PRIYA, SARA, TOM, type NorthwindRecord,
} from "../../apps/web/src/features/demo/northwind";

// Marketing screenshots for the flyer and website: seeds a made-up company
// (Northwind, example.com people, invented secrets) in its organisation space and captures the shots into
// e2e/showcase/out/flyer/ (git-ignored; FLYER_OUT overrides it). Run through
// `npm run showcase:flyer -w e2e` (run.mjs --flyer): a fresh database each time. Light theme, 1440×900 at 2× pixels.

const OUT = path.resolve(process.env.FLYER_OUT ?? path.join(import.meta.dirname, "out/flyer"));
const PW = "showcase master password";
const MAX_BYTES = 400 * 1024;
const VIEWPORT = { width: 1440, height: 900 };

function sql(query: string): string {
  const target = process.env.E2E_DB_CONTAINER ? `docker exec -i ${process.env.E2E_DB_CONTAINER}` : "docker compose -f deploy/docker-compose.dev.yml exec -T db";
  return execSync(`${target} psql -U vault -d vault -tAc "${query}"`, { cwd: "..", stdio: "pipe" }).toString().trim();
}

/** A small rack diagram drawn on a canvas in the page (PNG bytes). */
async function rackPng(page: Page): Promise<Buffer> {
  const b64 = await page.evaluate(() => {
    const c = document.createElement("canvas");
    c.width = 480; c.height = 320;
    const g = c.getContext("2d")!;
    g.fillStyle = "#f4f6fa"; g.fillRect(0, 0, 480, 320);
    g.fillStyle = "#1f2a44"; g.font = "bold 18px sans-serif"; g.fillText("Rack A3 · Northwind production", 24, 36);
    const units = [["fw-01  firewall", "#e8743b"], ["sw-01  switch", "#4a7bd0"], ["web-01  10.20.0.5", "#2f9e72"], ["web-02  10.20.0.6", "#2f9e72"], ["db-01  10.20.0.9", "#8a63d2"], ["backup-01", "#7a8597"]];
    units.forEach(([label, color], i) => {
      const y = 60 + i * 40;
      g.fillStyle = "#ffffff"; g.fillRect(24, y, 432, 32);
      g.strokeStyle = "#c9d0dc"; g.strokeRect(24.5, y + 0.5, 431, 31);
      g.fillStyle = color!; g.fillRect(24, y, 8, 32);
      g.fillStyle = "#1f2a44"; g.font = "14px monospace"; g.fillText(label!, 44, y + 21);
      for (let k = 0; k < 4; k++) { g.fillStyle = k < 3 ? "#2f9e72" : "#c9d0dc"; g.beginPath(); g.arc(400 + k * 12, y + 16, 3.5, 0, 7); g.fill(); }
    });
    return c.toDataURL("image/png").split(",")[1]!;
  });
  return Buffer.from(b64, "base64");
}

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

/** Opens a path (a full load locks the vault: unlock it) and waits for the unlock beat to finish. */
async function open(page: Page, to: string) {
  await page.goto(to);
  await expect(page.getByText("Vault locked")).toBeVisible({ timeout: 30_000 });
  await page.getByLabel("Master password").fill(PW);
  await page.getByRole("button", { name: "Unlock" }).click();
  await expect(page.getByRole("button", { name: "Unlock" })).toHaveCount(0, { timeout: 30_000 });
  await expect(page.getByTestId("unlock-flash")).toHaveCount(0, { timeout: 10_000 });
}

async function newContext(browser: Browser, use: object) {
  const ctx = await browser.newContext({ ...use, viewport: VIEWPORT, deviceScaleFactor: 2, colorScheme: "light" });
  // No "Backups are off" strip on the shots.
  await ctx.addInitScript(() => { try { localStorage.setItem("cv.backups-off-dismissed", "1"); } catch { /* */ } });
  return ctx;
}

async function pickPerson(page: Page, scope: Locator, name: string, permission: "Can edit" | "Can view" | "Use only") {
  await scope.getByRole("combobox", { name: "Person", exact: true }).click();
  await page.getByRole("option", { name: new RegExp(name) }).click();
  await scope.getByRole("combobox", { name: "Permission for new person" }).click();
  await page.getByRole("option", { name: permission }).click();
  await scope.getByRole("button", { name: "Add", exact: true }).click();
  await expect(scope.getByRole("listitem", { name })).toBeVisible();
}

async function choose(page: Page, label: string, option: string) {
  await page.getByRole("combobox", { name: label, exact: true }).click();
  await page.getByRole("option", { name: option, exact: true }).click();
}

type Rec = NorthwindRecord;

/** + New → Record of any type in a shared folder; fills the editor by field label and saves. */
async function addRecord(page: Page, folder: string, r: Rec) {
  await page.getByRole("button", { name: "New", exact: true }).click();
  await page.getByRole("menuitem", { name: "Record", exact: true }).click();
  const dlg = page.getByRole("dialog");
  const location = dlg.getByRole("combobox", { name: "Location" });
  if (!new RegExp(`^${folder}`).test(((await location.textContent()) ?? "").trim())) {
    await location.click();
    await page.getByRole("option", { name: new RegExp(`^${folder}`) }).click();
  }
  if (r.type !== "Login") {
    await dlg.getByRole("combobox", { name: "Record Type" }).click();
    await page.getByRole("option", { name: r.type, exact: true }).click();
  }
  await dlg.getByLabel("Title").fill(r.title);
  await dlg.getByRole("button", { name: "Next" }).click();
  await expect(page.getByLabel("Title")).toHaveValue(r.title);
  for (const [label, value] of Object.entries(r.options ?? {})) await choose(page, label, value);
  for (const [label, value] of Object.entries(r.fields ?? {})) await page.getByLabel(label, { exact: true }).fill(value);
  if (r.notes) await page.getByLabel("Notes").fill(r.notes);
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("button", { name: "Save" })).toHaveCount(0, { timeout: 30_000 });
}

const FOLDERS = NORTHWIND_FOLDERS;

async function expandFolder(page: Page, name: string, open = true) {
  const folder = page.getByRole("button", { name: new RegExp(`^${name}`) }).first();
  await expect(folder).toBeVisible({ timeout: 30_000 });
  if (((await folder.getAttribute("aria-expanded")) === "true") !== open) await folder.click();
}

type Clip = { x: number; y: number; width: number; height: number };

/** The record panel from its top down to `edge`'s top (cut before it) or bottom (keep it), with a little margin. */
async function panelClip(panel: Locator, edge: Locator, side: "top" | "bottom"): Promise<Clip> {
  const p = (await panel.boundingBox())!, e = (await edge.boundingBox())!;
  const end = side === "top" ? e.y - 8 : e.y + e.height + 12;
  return { x: p.x, y: p.y, width: p.width, height: Math.min(end, p.y + p.height) - p.y };
}

/**
 * Waits for toasts to leave, moves the mouse away, drops focus, pins the sync time, and saves the shot (clipped to
 * `clip` when given): a PNG when it fits in ~400 KB, else the best WebP that does.
 */
async function capture(page: Page, name: string, clip?: Clip | Locator) {
  await expect(page.locator("[data-sonner-toast]")).toHaveCount(0, { timeout: 30_000 });
  await page.mouse.move(VIEWPORT.width - 1, VIEWPORT.height - 1);
  await page.evaluate(() => {
    (document.activeElement as HTMLElement | null)?.blur();
    for (const el of document.querySelectorAll("span")) if (/^Synced \d/.test(el.textContent ?? "") && el.children.length === 0) el.textContent = "Synced 09:41 AM";
  });
  await page.waitForTimeout(600);
  const rect = clip && "boundingBox" in clip ? (await clip.boundingBox())! : clip;
  const png = await page.screenshot({ animations: "disabled", caret: "hide", ...(rect ? { clip: rect } : {}) });
  writeFileSync(test.info().outputPath(`${name}.png`), png);
  for (const ext of ["png", "webp"]) rmSync(path.join(OUT, `${name}.${ext}`), { force: true });
  if (png.length <= MAX_BYTES) {
    writeFileSync(path.join(OUT, `${name}.png`), png);
    console.log(`${name}.png: ${(png.length / 1024).toFixed(1)} KB`);
    return;
  }
  const webp = await page.evaluate(async ({ b64, max }) => {
    const img = new Image();
    img.src = `data:image/png;base64,${b64}`;
    await img.decode();
    const c = document.createElement("canvas");
    c.width = img.naturalWidth; c.height = img.naturalHeight;
    c.getContext("2d")!.drawImage(img, 0, 0);
    let out = "";
    for (const q of [0.95, 0.92, 0.9, 0.85, 0.8, 0.75]) {
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

test("flyer screenshots", async ({ browser }, testInfo) => {
  test.setTimeout(900_000);
  mkdirSync(OUT, { recursive: true });
  const use = testInfo.project.use;
  const ctx = await newContext(browser, use);
  const page = await ctx.newPage();
  await register(page, newInvite(SARA.email, "owner"), SARA.name);
  for (const [p, role] of [[BEA, "admin"], [PRIYA, "member"], [TOM, "member"], [LIAM, "member"], [MAYA, "member"]] as const) {
    const c = await newContext(browser, use);
    await register(await c.newPage(), newInvite(p.email, role), p.name);
    await c.close();
  }
  newInvite("jonas@example.com"); // one invitation still pending

  await page.reload();
  await page.getByLabel("Master password").fill(PW);
  await page.getByRole("button", { name: "Unlock" }).click();
  await expect(page.getByRole("button", { name: "New", exact: true })).toBeVisible({ timeout: 30_000 });
  await switchSpace(page, { firstOrg: true });
  const slug = new URL(page.url()).pathname.split("/")[2]!;
  // Entering the organisation creates the membership key in the background: let it settle before sealing folder keys.
  await page.waitForLoadState("networkidle");

  for (const f of FOLDERS) {
    const dlg = await newSharedFolder(page);
    await dlg.getByLabel("Folder name").fill(f.name);
    for (const [p, perm] of f.people) await pickPerson(page, dlg, p.name, perm);
    for (let i = 0; i < 3; i++) {
      await dlg.getByRole("button", { name: "Create" }).click();
      if (await dlg.waitFor({ state: "hidden", timeout: 15_000 }).then(() => true, () => false)) break;
    }
    await expect(page.getByRole("button", { name: new RegExp(`^${f.name}`) }).first()).toBeVisible({ timeout: 30_000 });
    for (const r of f.records) await addRecord(page, f.name, r);
  }

  // Files on the production server: a PDF agreement, a rack diagram and the TLS certificate.
  await page.getByRole("searchbox", { name: "Search records" }).fill("Production web server");
  await page.getByTestId("record-row").getByRole("button", { name: /Production web server/ }).first().click();
  const files = page.getByRole("region", { name: "Files" });
  await files.getByTestId("attach-input").setInputFiles([
    { name: AGREEMENT_PDF_NAME, mimeType: "application/pdf", buffer: Buffer.from(agreementPdf()) },
    { name: "rack-a3.png", mimeType: "image/png", buffer: await rackPng(page) },
    { name: CERT_NAME, mimeType: "application/x-pem-file", buffer: Buffer.from(CERT_PEM) },
  ]);
  for (const n of [AGREEMENT_PDF_NAME, "rack-a3.png", CERT_NAME])
    await expect(files.getByTestId("file-row").getByText(n)).toBeVisible({ timeout: 60_000 });

  // Groups, with members.
  await open(page, `/o/${slug}/admin/groups`);
  for (const [group, members] of [["Engineering", [BEA, TOM, LIAM]], ["Finance", [SARA, PRIYA]], ["Client services", [MAYA, PRIYA]]] as const) {
    await page.getByLabel("New group").fill(group);
    await page.getByRole("button", { name: "Create group" }).click();
    await expect(page.getByRole("listitem", { name: `Group ${group}` })).toBeVisible({ timeout: 30_000 });
    for (const m of members) {
      await page.getByRole("combobox", { name: `Add someone to ${group}` }).click();
      await page.getByRole("option", { name: new RegExp(m.name) }).click();
      await page.getByRole("listitem", { name: `Group ${group}` }).getByRole("button", { name: "Add", exact: true }).click();
      await expect(page.getByRole("list", { name: `Members of ${group}` }).getByText(m.name)).toBeVisible({ timeout: 30_000 });
    }
  }

  // 1. vault-list: the organisation's folders open, typed records with their icons and subtitles, the type filter.
  await open(page, `/o/${slug}/vault`);
  for (const f of ["Infrastructure", "Finance", "Office"]) await expandFolder(page, f);
  await expect(page.getByText("•••• 4242").first()).toBeVisible();
  await expect(page.getByText("deploy@10.20.0.5:22").first()).toBeVisible();
  await capture(page, "vault-list");

  // 2. card-record: the payment card in the record panel.
  await page.getByTestId("record-row").getByRole("button", { name: /Company Visa/ }).first().click();
  const panel = page.getByRole("complementary", { name: "Record details" });
  await expect(panel.getByRole("heading", { name: "Company Visa" })).toBeVisible();
  await capture(page, "card-record", await panelClip(panel, panel.getByRole("region", { name: "Files" }), "top"));

  // 3. attachments: the production server's files, with the PDF preview open.
  await page.getByTestId("record-row").getByRole("button", { name: /Production web server/ }).first().click();
  await expect(panel.getByRole("heading", { name: "Production web server" })).toBeVisible();
  await expect(files.getByTestId("file-row")).toHaveCount(3, { timeout: 30_000 });
  // A taller window for this one, so the panel shows the record and all its files without scrolling.
  await page.setViewportSize({ width: VIEWPORT.width, height: 1200 });
  await capture(page, "attachments-panel", await panelClip(panel, files, "bottom"));
  await page.setViewportSize(VIEWPORT);
  await files.getByRole("button", { name: "Preview maintenance-agreement.pdf" }).click();
  await expect(page.getByTestId("pdf-pages").locator("canvas")).toHaveCount(1, { timeout: 30_000 });
  await capture(page, "attachments");
  await page.getByRole("dialog").getByRole("button", { name: "Close" }).click();
  await expect(page.getByRole("dialog")).toHaveCount(0);

  // 5. one-time-link: Acme opens a link to the customer portal login.
  await expandFolder(page, "Clients");
  await page.getByTestId("record-row").getByRole("button", { name: /Acme customer portal/ }).first().click();
  await expect(panel.getByRole("heading", { name: "Acme customer portal" })).toBeVisible();
  await panel.getByRole("button", { name: "Share", exact: true }).click();
  await expect(page.getByRole("dialog")).toBeVisible();
  await page.getByRole("tab", { name: "One-time link" }).click();
  await page.getByLabel("Who it's for").fill("Acme Ltd");
  await page.getByRole("button", { name: "Create link" }).click();
  const url = (await page.getByLabel("Link to send").textContent({ timeout: 30_000 }))!;
  await page.getByRole("button", { name: "Done" }).click();
  const gctx = await newContext(browser, use);
  const guest = await gctx.newPage();
  await guest.goto(url);
  await guest.getByRole("button", { name: "Show the details" }).click();
  await expect(guest.getByRole("heading", { name: "Acme customer portal" })).toBeVisible({ timeout: 30_000 });
  // The page centres a card on a wide empty background: keep the logo, the card and the footer line.
  await capture(guest, "one-time-link", { x: 440, y: 105, width: 560, height: 680 });
  await gctx.close();

  // 4. risk-dashboard.
  // Policies a careful team would set (some benchmarks completed, some still critical): auto-lock, link limits, a
  // master password strength rule (set after everyone signed up with the showcase password).
  sql(`UPDATE \\"Organization\\" SET policies = jsonb_build_object('autoLockMinutes', 10, 'minPasswordScore', 3, 'links', jsonb_build_object('maxExpiryHours', 24))`);

  await open(page, `/o/${slug}/admin/risk`);
  await expect(page.getByRole("heading", { level: 1, name: "Risk dashboard" })).toBeVisible({ timeout: 30_000 });
  await expect(page.getByTestId("risk-score")).toHaveText(/\d+/, { timeout: 30_000 });
  // Tall enough to show the score, the utilisation tiles and the benchmarks (critical and completed) in one shot.
  await page.setViewportSize({ width: VIEWPORT.width, height: 2600 });
  const risk = page.getByRole("region", { name: "Risk dashboard" });
  const r = (await risk.boundingBox())!, bench = (await page.getByRole("group", { name: /^Completed/ }).boundingBox())!;
  await capture(page, "risk-dashboard", { x: r.x, y: r.y, width: r.width, height: bench.y + bench.height + 10 - r.y });
  await page.setViewportSize(VIEWPORT);

  // 6. admin-people: members, roles and the pending invitation; and the groups.
  await open(page, `/o/${slug}/admin/people`);
  const checklist = page.getByRole("button", { name: "Dismiss checklist" });
  if (await checklist.isVisible().catch(() => false)) {
    await checklist.click();
    await expect(page.locator("[data-sonner-toast]")).toHaveCount(1, { timeout: 10_000 });
    await expect(page.locator("[data-sonner-toast]")).toHaveCount(0, { timeout: 30_000 });
  }
  await expect(page.getByRole("region", { name: "Everyone" }).getByText(MAYA.name)).toBeVisible({ timeout: 30_000 });
  // The People page alone (no admin menu), tall enough for every member.
  await page.setViewportSize({ width: VIEWPORT.width, height: 1500 });
  const people = page.getByRole("region", { name: "People" });
  const pr = (await people.boundingBox())!, everyone = (await page.getByRole("region", { name: "Everyone" }).boundingBox())!;
  await capture(page, "admin-people", { x: pr.x, y: pr.y, width: pr.width, height: everyone.y + everyone.height + 24 - pr.y });
  await page.setViewportSize(VIEWPORT);
  await open(page, `/o/${slug}/admin/groups`);
  await expect(page.getByRole("listitem", { name: "Group Engineering" })).toBeVisible({ timeout: 30_000 });
  await capture(page, "admin-groups");
  await ctx.close();
});
