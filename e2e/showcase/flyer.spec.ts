import { execSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { expect, test, type Browser, type Locator, type Page } from "@playwright/test";
import { newInvite, newSharedFolder, saveRecoveryKit, switchSpace, totp } from "../helpers";

// Marketing screenshots for the flyer and website: seeds a made-up company
// (Northwind, example.com people, invented secrets) in its organisation space and captures the shots into
// e2e/showcase/out/flyer/ (git-ignored; FLYER_OUT overrides it). Run through
// `npm run showcase:flyer -w e2e` (run.mjs --flyer): a fresh database each time. Light theme, 1440×900 at 2× pixels.

const OUT = path.resolve(process.env.FLYER_OUT ?? path.join(import.meta.dirname, "out/flyer"));
const PW = "showcase master password";
const MAX_BYTES = 400 * 1024;
const VIEWPORT = { width: 1440, height: 900 };

const SARA = { name: "Sara Okafor", email: "sara@example.com" };
const BEA = { name: "Bea Lindqvist", email: "bea@example.com" };
const PRIYA = { name: "Priya Nair", email: "priya@example.com" };
const TOM = { name: "Tom Reyes", email: "tom@example.com" };
const LIAM = { name: "Liam Chen", email: "liam@example.com" };
const MAYA = { name: "Maya Haddad", email: "maya@example.com" };

function sql(query: string): string {
  const target = process.env.E2E_DB_CONTAINER ? `docker exec -i ${process.env.E2E_DB_CONTAINER}` : "docker compose -f deploy/docker-compose.dev.yml exec -T db";
  return execSync(`${target} psql -U vault -d vault -tAc "${query}"`, { cwd: "..", stdio: "pipe" }).toString().trim();
}

/** Deterministic made-up base64 (fake keys and certificates: they belong to nothing). */
function fakeB64(seed: string, bytes: number): string {
  let out = Buffer.alloc(0), h = seed;
  while (out.length < bytes) { h = createHash("sha256").update(h).digest("hex"); out = Buffer.concat([out, Buffer.from(h, "hex")]); }
  return out.subarray(0, bytes).toString("base64");
}
const wrap = (s: string, n = 64) => s.match(new RegExp(`.{1,${n}}`, "g"))!.join("\n");
const PRIVATE_KEY = `-----BEGIN OPENSSH PRIVATE KEY-----\n${wrap(fakeB64("northwind deploy key", 300), 70)}\n-----END OPENSSH PRIVATE KEY-----`;
const PUBLIC_KEY = `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI${fakeB64("northwind deploy pub", 32).replace(/=+$/, "")} deploy@northwind`;
const CERT = Buffer.from(`-----BEGIN CERTIFICATE-----\n${wrap(fakeB64("northwind wildcard cert", 900))}\n-----END CERTIFICATE-----\n`);

/** A one-page A4 PDF: a made-up maintenance agreement. */
function agreementPdf(): Buffer {
  const esc = (s: string) => s.replace(/[\\()]/g, (c) => `\\${c}`);
  const lines: [number, number, string][] = [
    [20, 790, "Server maintenance agreement"],
    [11, 762, "Northwind Ltd  and  Harbour Hosting Ltd (example.com)"],
    [10, 720, "1. Scope"],
    [10, 702, "Harbour Hosting maintains the production web server (deploy@10.20.0.5) and its"],
    [10, 688, "backups. Patches are applied in the Sunday window, 02:00-04:00 UTC."],
    [10, 656, "2. Response times"],
    [10, 638, "Critical: 1 hour, around the clock.   High: 4 hours.   Normal: next business day."],
    [10, 606, "3. Access"],
    [10, 588, "Credentials are shared through Clane Vault only. No passwords by email or chat."],
    [10, 574, "Engineers get Use only access; nothing is copied out of the vault."],
    [10, 542, "4. Term"],
    [10, 524, "Twelve months from 1 October 2026, renewing yearly unless either side gives notice."],
    [10, 460, "Signed for Northwind Ltd: Sara Okafor          Signed for Harbour Hosting: Tom Reyes"],
  ];
  const stream = lines.map(([size, y, t]) => `BT /F${size >= 20 ? 2 : 1} ${size} Tf 56 ${y} Td (${esc(t)}) Tj ET`).join("\n")
    + "\n0.85 0.86 0.9 RG 56 740 m 539 740 l S 56 476 m 539 476 l S";
  const objs = [
    "<< /Type /Catalog /Pages 2 0 R >>",
    "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R /Resources << /Font << /F1 5 0 R /F2 6 0 R >> >> >>",
    `<< /Length ${stream.length} >>\nstream\n${stream}\nendstream`,
    "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>",
  ];
  let out = "%PDF-1.4\n";
  const offsets: number[] = [];
  objs.forEach((o, i) => { offsets.push(out.length); out += `${i + 1} 0 obj\n${o}\nendobj\n`; });
  const xref = out.length;
  out += `xref\n0 ${objs.length + 1}\n0000000000 65535 f \n${offsets.map((o) => `${String(o).padStart(10, "0")} 00000 n \n`).join("")}`;
  out += `trailer\n<< /Size ${objs.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return Buffer.from(out, "latin1");
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

type Rec = { type: string; title: string; fields?: Record<string, string>; options?: Record<string, string>; notes?: string };

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

const FOLDERS: { name: string; people: [typeof BEA, "Can edit" | "Can view" | "Use only"][]; records: Rec[] }[] = [
  { name: "Infrastructure", people: [[BEA, "Can edit"], [TOM, "Can edit"], [LIAM, "Use only"]], records: [
    { type: "Server credentials", title: "Production web server", options: { Protocol: "SSH" },
      fields: { "Hostname or IP": "10.20.0.5", Port: "22", Username: "deploy", Password: "Qm7#vT2x!Rk9pL4w" },
      notes: "web-01 in rack A3. Harbour Hosting patches it on Sundays." },
    { type: "Login", title: "AWS root account", fields: { Username: "ops@example.com", Password: "vR8#tQ2m!Lx6pZ9w", Website: "console.aws.amazon.com" },
      notes: "Root user. Billing and break-glass only." },
    { type: "SSH key", title: "Deploy key", fields: { Username: "deploy", Host: "git.example.com", "Private key": PRIVATE_KEY, "Public key": PUBLIC_KEY } },
    { type: "Database credentials", title: "Orders database", options: { Type: "PostgreSQL" },
      fields: { Host: "db-01.example.com", Port: "5432", Database: "orders", Username: "app_rw", Password: "Hn4$kW8z@Pc3tF6q" } },
    { type: "API key / secret", title: "Cloudflare API token", fields: { Service: "Cloudflare", "Key ID": "nw-dns-edit", Secret: "cf_9fXq2LmZ7tR4vK8wN3bH6yD1sJ5pG0aE", Endpoint: "https://api.example.com" } },
    { type: "Login", title: "GitHub org owner", fields: { Username: "northwind-bot", Password: "pF6&zR1x#Mv8sJ3k", Website: "github.com" } },
  ] },
  { name: "Finance", people: [[PRIYA, "Can edit"], [BEA, "Can view"]], records: [
    { type: "Payment card", title: "Company Visa", fields: { Cardholder: "Sara Okafor", "Card number": "4242 4242 4242 4242", Expiry: "08/29",
      "Security code": "737", PIN: "4821", "Billing address": "12 Harbour Street\nDublin D02 XY45\nIreland" } },
    { type: "Bank account", title: "Operating account", fields: { "Account name": "Northwind Ltd", Bank: "Example Bank", "IBAN / account number": "IE29 EXMP 9311 5212 3456 78",
      "BIC / sort code / routing": "EXMPIE2D", "Online banking login": "northwind-fin", Password: "Bx9!rJ4w@Tn7qK2h" } },
    { type: "Login", title: "Stripe dashboard", fields: { Username: "finance@example.com", Password: "Lm2^gS6t#Pk9vE4r", Website: "dashboard.stripe.com" } },
  ] },
  { name: "Office", people: [[BEA, "Can view"], [PRIYA, "Can view"], [TOM, "Can view"], [MAYA, "Can view"]], records: [
    { type: "Wi-Fi", title: "Office Wi-Fi", options: { Security: "WPA3" }, fields: { "Network name (SSID)": "Northwind-Staff", Password: "harbour-lantern-42" } },
    { type: "Wi-Fi", title: "Guest Wi-Fi", options: { Security: "WPA2" }, fields: { "Network name (SSID)": "Northwind-Guest", Password: "welcome-tide-17" } },
    { type: "Software licence", title: "Adobe Creative Cloud", fields: { Product: "Creative Cloud Teams", "Licence key": "NW7Q-4KXP-9TZM-2RBC", "Licensed to": "Northwind Ltd", Version: "2026" } },
  ] },
  { name: "Clients", people: [[MAYA, "Can edit"], [PRIYA, "Can view"]], records: [
    { type: "Login", title: "Acme customer portal", fields: { Username: "northwind-support", Password: "Tg7#qL2v!Rm9zW4x", Website: "portal.example.com" },
      notes: "Support login for Acme Ltd's portal. Tickets go to support@example.com." },
    { type: "Contact", title: "Acme IT contact", fields: { Name: "Jordan Blake", Company: "Acme Ltd", Email: "jordan@example.com", Phone: "+353 1 555 0142" } },
  ] },
];

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
    { name: "maintenance-agreement.pdf", mimeType: "application/pdf", buffer: agreementPdf() },
    { name: "rack-a3.png", mimeType: "image/png", buffer: await rackPng(page) },
    { name: "wildcard-example-com.pem", mimeType: "application/x-pem-file", buffer: CERT },
  ]);
  for (const n of ["maintenance-agreement.pdf", "rack-a3.png", "wildcard-example-com.pem"])
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
