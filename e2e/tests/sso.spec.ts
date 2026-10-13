import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { expect, test, type Page } from "@playwright/test";
import { MockOidc } from "../../apps/api/test/mockOidc";
import { newInvite, newOrg, saveRecoveryKit, totp, verifySsoDomain, accountMenu, adminPage, switchSpace } from "../helpers";

// Single sign-on (docs/sso.md): an organisation sets up OpenID Connect against a mock identity provider (run here, on a
// free port), and a member signs in through it, then unlocks with their master password.
const PW = "an e2e master password";
const WEB = Number(process.env.E2E_WEB_PORT ?? process.env.WEB_PORT ?? 5173);
const uniq = () => `${Date.now()}${Math.floor(Math.random() * 1e4)}`;
/** Optional: SSO_SHOTS=<dir> saves screenshots of the screens along the way. */
async function shot(page: Page, name: string) {
  const dir = process.env.SSO_SHOTS;
  if (!dir) return;
  mkdirSync(dir, { recursive: true });
  await expect(page.getByTestId("unlock-flash")).toHaveCount(0, { timeout: 10_000 });
  await page.screenshot({ path: join(dir, `${name}.png`), fullPage: false });
}

async function register(page: Page, invitePath: string, name: string): Promise<string> {
  await page.goto(invitePath);
  await page.getByLabel("Your name").fill(name);
  await page.getByLabel("Master password", { exact: true }).fill(PW);
  await page.getByLabel("Repeat master password").fill(PW);
  await page.getByRole("button", { name: "Create account" }).click();
  const keyText = await page.getByText(/Enter this key:\s*[A-Z2-7]{16,}/).textContent({ timeout: 60_000 });
  const secret = keyText!.split(":")[1]!.trim();
  await page.getByLabel("6-digit code").fill(await totp(secret));
  await page.getByRole("button", { name: "Turn on and continue" }).click();
  await saveRecoveryKit(page);
  await expect(page.getByRole("button", { name: "New", exact: true })).toBeVisible({ timeout: 30_000 });
  return secret;
}

test("SSO sign-in through the identity provider, then the master password opens the vault", async ({ page, browser }, testInfo) => {
  test.skip(testInfo.project.name !== "desktop", "runs once, on desktop");
  test.setTimeout(240_000);
  const idp = await new MockOidc().start();
  const client = idp.addClient({ id: "e2e-clane-vault", secret: "e2e-client-secret-000123", redirectUris: [`http://localhost:${WEB}/api/v1/auth/sso/callback`] });
  try {
    const id = uniq();
    const domain = `sso${id}.test`;
    const orgName = `Sso Org ${id}`;
    const org = newOrg(orgName);
    const ownerEmail = `owner@${domain}`, memberEmail = `sara@${domain}`;

    // Owner and member join through invites (password + 2FA as usual).
    await register(page, newInvite(ownerEmail, "owner", org), "Olga Owner");
    const m = await (await browser.newContext({ viewport: { width: 1440, height: 900 } })).newPage();
    const memberTotp = await register(m, newInvite(memberEmail, "member", org), "Sara Member");

    // The owner sets up SSO: provider, connection test, domain (verified), trust the IdP's MFA.
    await adminPage(page, "Single sign-on");
    const sso = page.getByRole("region", { name: "Single sign-on" });
    await expect(sso.getByText(`http://localhost:${WEB}/api/v1/auth/sso/callback`)).toBeVisible();
    await sso.getByRole("button", { name: "Set up" }).click();
    await sso.getByLabel("Issuer URL").fill(idp.issuer);
    await sso.getByLabel("Client ID").fill(client.id);
    await sso.getByLabel("Client secret").fill(client.secret);
    await sso.getByRole("button", { name: "Test connection" }).click();
    const checks = sso.getByRole("list", { name: "Connection test" });
    await expect(checks).toContainText("The client ID and secret were accepted.");
    await expect(checks.getByLabel("Failed")).toHaveCount(0);
    await sso.getByRole("button", { name: "Save" }).click();
    await expect(sso.getByText(/secret set/)).toBeVisible();
    await sso.getByRole("textbox", { name: "Domain", exact: true }).fill(domain);
    await sso.getByRole("button", { name: "Add domain" }).click();
    await expect(sso.getByRole("listitem", { name: domain })).toContainText("clane-vault-verify=");
    await shot(page, "01-sso-settings-domain-pending");
    verifySsoDomain(org, domain);
    await page.reload();
    await expect(page.getByText("Vault locked")).toBeVisible({ timeout: 30_000 });
    await page.getByLabel("Master password").fill(PW);
    await page.getByRole("button", { name: "Unlock" }).click();
    await adminPage(page, "Single sign-on");
    await expect(sso.getByRole("listitem", { name: domain })).toContainText("Verified");
    await sso.getByRole("switch", { name: "Trust the identity provider's MFA" }).click();
    await expect(sso.getByRole("switch", { name: "Trust the identity provider's MFA" })).toBeChecked();
    await shot(page, "02-sso-settings-configured");
    await adminPage(page, "Email");
    await expect(page.getByRole("region", { name: "Email for this organisation" })).toBeVisible();
    await shot(page, "03-org-email-settings");

    // The member signs out and signs in with SSO: email → "Continue with … SSO" → IdP → master password → vault.
    await accountMenu(m, "Sign out");
    await m.getByLabel("Email address").fill(memberEmail);
    await m.getByRole("button", { name: "Next" }).click();
    const ssoButton = m.getByRole("button", { name: `Continue with ${orgName} SSO` });
    await expect(ssoButton).toBeVisible();
    await shot(m, "04-sign-in-sso-offered");
    idp.addUser({ sub: `idp-${id}-sara`, email: memberEmail, email_verified: true, name: "Sara Member" });
    await ssoButton.click();
    await expect(m).toHaveURL(/\/sso\/complete$/, { timeout: 30_000 });
    await expect(m.getByRole("status")).toContainText(`${orgName} confirmed you as ${memberEmail}`);
    await expect(m.getByText(/already checked your second factor/)).toBeVisible();
    await shot(m, "05-sso-complete-master-password");
    await m.getByLabel("Master password").fill(PW);
    await m.getByRole("button", { name: "Unlock" }).click();
    await expect(m.getByRole("button", { name: "New", exact: true })).toBeVisible({ timeout: 30_000 });
    await expect(m.getByTestId("active-org")).toHaveText(orgName);
    await shot(m, "06-vault-after-sso");

    // Require SSO: a password-only session of the member can't open the org; SSO again can.
    await adminPage(page, "Single sign-on");
    await sso.getByRole("switch", { name: "Require SSO for members" }).click();
    await expect(sso.getByText("Required")).toBeVisible();
    const p2 = await (await browser.newContext({ viewport: { width: 1440, height: 900 } })).newPage();
    await p2.goto("/sign-in");
    await p2.getByLabel("Email address").fill(memberEmail);
    await p2.getByRole("button", { name: "Next" }).click();
    await p2.getByLabel("Master password").fill(PW);
    await p2.getByRole("button", { name: "Sign in" }).click();
    await p2.getByLabel("6-digit code from your authenticator app").fill(await totp(memberTotp));
    await p2.getByRole("button", { name: "Sign in" }).click();
    // A new device opens Personal (the master password is enough there); the organisation needs its SSO.
    await expect(p2.getByTestId("active-org")).toHaveText("Personal", { timeout: 30_000 });
    await expect(p2.getByRole("region", { name: "Single sign-on required" })).toHaveCount(0);
    await switchSpace(p2, orgName);
    const panel = p2.getByRole("region", { name: "Single sign-on required" });
    await expect(panel).toBeVisible({ timeout: 30_000 });
    await shot(p2, "07-sso-required-panel");
    await panel.getByRole("button", { name: `Sign in with ${orgName} SSO` }).click();
    await expect(p2).toHaveURL(/\/sso\/complete$/, { timeout: 30_000 });
    await p2.getByLabel("Master password").fill(PW);
    await p2.getByRole("button", { name: "Unlock" }).click();
    await expect(p2.getByRole("button", { name: "New", exact: true })).toBeVisible({ timeout: 30_000 });
    // Back in the organisation it was asked for.
    await expect(p2).toHaveURL(/\/o\/[^/]+\/vault$/);
    await expect(p2.getByTestId("active-org")).toHaveText(orgName);
    await expect(p2.getByRole("region", { name: "Single sign-on required" })).toHaveCount(0);
  } finally {
    await idp.stop();
  }
});
