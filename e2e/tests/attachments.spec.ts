import { execSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { expect, test, type BrowserContext, type Page } from "@playwright/test";
import { newInvite, newRecord, newSharedFolder, saveRecoveryKit, switchSpace, totp } from "../helpers";

/**
 * File attachments end to end (docs/attachments.md): a file attached to a new record in a shared folder (queued in the
 * editor, uploaded after the first save), shared through the folder: a Can view member downloads the identical bytes,
 * a Use only member sees the file but can't download it, previews of a PNG and a PDF, and removal.
 */
const PW = "an e2e master password";
const SHOTS = process.env.E2E_SHOTS_DIR;
const uniq = () => `${Date.now()}-${Math.floor(Math.random() * 1e4)}`;
const sha = (b: Buffer) => createHash("sha256").update(b).digest("hex");

function sql(query: string): string {
  const target = process.env.E2E_DB_CONTAINER ? `docker exec -i ${process.env.E2E_DB_CONTAINER}` : "docker compose -f deploy/docker-compose.dev.yml exec -T db";
  return execSync(`${target} psql -U vault -d vault -tAc "${query}"`, { cwd: "..", stdio: "pipe" }).toString().trim();
}
const shot = async (page: Page, name: string) => { if (SHOTS) await page.screenshot({ path: `${SHOTS}/${name}.png` }); };

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
async function pickPerson(page: Page, scope: ReturnType<Page["getByRole"]>, name: string, permission: "Can edit" | "Can view" | "Use only") {
  await scope.getByRole("combobox", { name: "Person", exact: true }).click();
  await page.getByRole("option", { name: new RegExp(name) }).click();
  await scope.getByRole("combobox", { name: "Permission for new person" }).click();
  await page.getByRole("option", { name: permission }).click();
  await scope.getByRole("button", { name: "Add" }).click();
  await expect(scope.getByRole("listitem", { name })).toBeVisible();
}
/** Downloads go through <a download> (Blob, application/octet-stream) unless the browser offers the save picker: off here. */
async function context(browser: import("@playwright/test").Browser): Promise<BrowserContext> {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, acceptDownloads: true, permissions: ["clipboard-read", "clipboard-write"],
    // E2E_COLOR_SCHEME=dark: the same run in dark mode (for the screenshots).
    ...(process.env.E2E_COLOR_SCHEME === "dark" ? { colorScheme: "dark" as const } : {}) });
  await ctx.addInitScript(() => { delete (window as unknown as { showSaveFilePicker?: unknown }).showSaveFilePicker; });
  return ctx;
}
async function openRecord(page: Page, title: string) {
  await page.getByRole("searchbox", { name: "Search records" }).fill(title);
  await page.getByTestId("record-row").getByRole("button", { name: new RegExp(title) }).first().click();
  await expect(page.getByRole("heading", { name: title, exact: true })).toBeVisible();
}

// A tiny but valid PNG (1×1) and a one-page PDF with some text.
const PNG = Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR4nGP4z8AAAAMBAQDJ/pLvAAAAAElFTkSuQmCC", "base64");
function pdf(): Buffer {
  const objs = [
    "<< /Type /Catalog /Pages 2 0 R >>",
    "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 144] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
    null,
    "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
  ];
  const stream = "BT /F1 18 Tf 24 72 Td (Lease agreement) Tj ET";
  objs[3] = `<< /Length ${stream.length} >>\nstream\n${stream}\nendstream`;
  let out = "%PDF-1.4\n";
  const offsets: number[] = [];
  objs.forEach((o, i) => { offsets.push(out.length); out += `${i + 1} 0 obj\n${o}\nendobj\n`; });
  const xref = out.length;
  out += `xref\n0 ${objs.length + 1}\n0000000000 65535 f \n${offsets.map((o) => `${String(o).padStart(10, "0")} 00000 n \n`).join("")}`;
  out += `trailer\n<< /Size ${objs.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return Buffer.from(out, "latin1");
}

test("files on a shared record: queued on a new record, identical bytes for a viewer, none for use only, previews, removal", async ({ browser }, testInfo) => {
  test.skip(testInfo.project.name !== "desktop", "multi-user flow runs once, on desktop");
  test.setTimeout(300_000);
  const id = uniq();
  const names = { a: `Ana ${id}`, b: `Bea ${id}`, c: `Cal ${id}` };
  const ctxA = await context(browser), ctxB = await context(browser), ctxC = await context(browser);
  const a = await ctxA.newPage(), b = await ctxB.newPage(), c = await ctxC.newPage();
  await register(a, newInvite(`e2e-att-a-${id}@clane.ai`, "admin"), names.a);
  await register(b, newInvite(`e2e-att-b-${id}@clane.ai`), names.b);
  await register(c, newInvite(`e2e-att-c-${id}@clane.ai`), names.c);

  // A: a shared folder with B (Can view) and C (Use only). (Entering the org creates A's membership key in the background
  // first; let that settle so the folder key isn't sealed to a key that is being replaced.)
  await switchSpace(a, { firstOrg: true });
  await a.waitForLoadState("networkidle");
  const dlg = await newSharedFolder(a);
  await dlg.getByLabel("Folder name").fill("Files Team");
  await pickPerson(a, dlg, names.b, "Can view");
  await pickPerson(a, dlg, names.c, "Use only");
  for (let i = 0; i < 3; i++) {
    await dlg.getByRole("button", { name: "Create" }).click();
    // Created: the dialog closes. "Couldn't create" (the key race above): try again.
    if (await dlg.waitFor({ state: "hidden", timeout: 15_000 }).then(() => true, () => false)) break;
  }
  await expect(a.getByRole("button", { name: /^Files Team/ })).toBeVisible({ timeout: 30_000 });

  // A new secure note with a file picked before it exists: queued, then uploaded right after the first save.
  const contract = randomBytes(2 * 1024 * 1024 + 300_000);
  await newRecord(a, "Lease", { folder: /Files Team/, type: "Secure note" });
  await a.getByTestId("attach-input").setInputFiles({ name: "contract.bin", mimeType: "application/octet-stream", buffer: contract });
  await expect(a.getByTestId("queued-file")).toHaveText(/contract\.bin/);
  await shot(a, "attachments-01-editor-queue");
  await a.getByRole("button", { name: "Save" }).click();
  await expect(a.getByRole("heading", { name: "Lease", exact: true })).toBeVisible({ timeout: 30_000 });
  const files = a.getByRole("region", { name: "Files" });
  await expect(files.getByTestId("file-row").getByText("contract.bin")).toBeVisible({ timeout: 60_000 });
  // More files from the panel: an image and a PDF, both previewable.
  await files.getByTestId("attach-input").setInputFiles([{ name: "tiny.png", mimeType: "image/png", buffer: PNG }, { name: "lease.pdf", mimeType: "application/pdf", buffer: pdf() }]);
  await expect(files.getByTestId("file-row").getByText("tiny.png")).toBeVisible({ timeout: 60_000 });
  await expect(files.getByTestId("file-row").getByText("lease.pdf")).toBeVisible({ timeout: 60_000 });
  // The record list shows a paperclip with the count (open the folder in the tree).
  if (!(await a.getByTestId("file-count").isVisible())) await a.getByRole("button", { name: /^Files Team/ }).first().click();
  await expect(a.getByTestId("file-count")).toContainText("3");
  await shot(a, "attachments-02-panel");
  await files.getByRole("button", { name: "Preview tiny.png" }).click();
  await expect(a.getByTestId("image-preview")).toBeVisible();
  await expect.poll(() => a.getByTestId("image-preview").evaluate((img: HTMLImageElement) => img.complete && img.naturalWidth)).toBe(1);
  await shot(a, "attachments-03-image-preview");
  // Escape closes the preview, not the record behind it.
  await a.keyboard.press("Escape");
  await expect(a.getByTestId("image-preview")).toHaveCount(0);
  await expect(a.getByRole("heading", { name: "Lease", exact: true })).toBeVisible();
  await files.getByRole("button", { name: "Preview lease.pdf" }).click();
  await expect(a.getByTestId("pdf-pages").locator("canvas")).toHaveCount(1, { timeout: 30_000 });
  await shot(a, "attachments-04-pdf-preview");
  await a.getByRole("dialog").getByRole("button", { name: "Close" }).click();
  const fileId = sql(`SELECT a.id FROM \\"Attachment\\" a JOIN \\"User\\" u ON u.id = a.\\"createdBy\\" WHERE a.state = 'ready' AND u.email = 'e2e-att-a-${id}@clane.ai' AND a.size = ${contract.length + 3 * 16}`);
  expect(fileId).toMatch(/^[0-9a-f-]{36}$/);
  // The server holds ciphertext only: nothing of the file or its name.
  expect(sql(`SELECT count(*) FROM \\"Attachment\\" WHERE \\"encMeta\\" LIKE '%contract%'`)).toBe("0");

  // B (Can view) opens the shared folder's record and downloads the very same bytes.
  await switchSpace(b, { firstOrg: true });
  await openRecord(b, "Lease");
  const bFiles = b.getByRole("region", { name: "Files" });
  await expect(bFiles.getByText("contract.bin")).toBeVisible({ timeout: 30_000 });
  await expect(bFiles.getByRole("button", { name: "Remove contract.bin" })).toHaveCount(0);
  const [dl] = await Promise.all([b.waitForEvent("download"), bFiles.getByRole("button", { name: "Download contract.bin" }).click()]);
  expect(dl.suggestedFilename()).toBe("contract.bin");
  expect(sha(readFileSync((await dl.path())!))).toBe(sha(contract));
  await shot(b, "attachments-05-viewer");

  // C (Use only) sees the files with a lock, and can't download them.
  await switchSpace(c, { firstOrg: true });
  await openRecord(c, "Lease");
  const cFiles = c.getByRole("region", { name: "Files" });
  await expect(cFiles.getByText("contract.bin")).toBeVisible({ timeout: 30_000 });
  await expect(cFiles.getByText(/Ask the owner for Can view to download/)).toBeVisible();
  await expect(cFiles.getByRole("button", { name: /Download|Preview/ })).toHaveCount(0);
  // Even asked directly, the server refuses the bytes: the request the app would make answers 403 use_only.
  const refused = await c.evaluate(async ({ rec, fid }) => {
    // C's own session (the app keeps its access token in memory, so get one through the refresh cookie), under any base path.
    const base = document.querySelector('meta[name="clane-base"]')?.getAttribute("content") ?? "";
    const r = await fetch(`${base}/api/v1/auth/refresh`, { method: "POST", credentials: "same-origin" });
    const { accessToken } = (await r.json()) as { accessToken: string };
    const org = (await (await fetch(`${base}/api/v1/me/orgs`, { headers: { authorization: `Bearer ${accessToken}` } })).json()) as { orgs: { id: string }[] };
    const res = await fetch(`${base}/api/v1/records/${rec}/attachments/${fid}/chunks/0`, { headers: { authorization: `Bearer ${accessToken}`, "x-org-id": org.orgs[0]!.id } });
    return { status: res.status, body: await res.json() };
  }, { rec: sql(`SELECT \\"recordId\\" FROM \\"Attachment\\" WHERE id = '${fileId}'`), fid: fileId });
  expect(refused).toEqual({ status: 403, body: { error: "use_only" } });
  await shot(c, "attachments-06-use-only");

  // A removes the file: gone for everyone, chunks and row deleted.
  const aFiles = a.getByRole("region", { name: "Files" });
  await aFiles.getByRole("button", { name: "Remove contract.bin" }).click();
  await aFiles.getByRole("button", { name: "Remove", exact: true }).click();
  await expect(aFiles.getByText("contract.bin")).toHaveCount(0, { timeout: 30_000 });
  expect(sql(`SELECT count(*) FROM \\"AttachmentChunk\\" WHERE \\"attachmentId\\" = '${fileId}'`)).toBe("0");
  expect(sql(`SELECT count(*) FROM \\"Attachment\\" WHERE id = '${fileId}'`)).toBe("0");
  await unlockAfterReload(b);
  await openRecord(b, "Lease");
  await expect(b.getByRole("region", { name: "Files" }).getByText("tiny.png")).toBeVisible({ timeout: 30_000 });
  await expect(b.getByRole("region", { name: "Files" }).getByText("contract.bin")).toHaveCount(0);
  for (const ctx of [ctxA, ctxB, ctxC]) await ctx.close();
});
