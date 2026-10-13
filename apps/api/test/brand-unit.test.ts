import { describe, expect, it } from "vitest";
import { loadConfig } from "../src/config.js";
import { inviteEmail } from "../src/lib/email.js";
import { totpKeyUri } from "../src/lib/totp.js";

const base = { DATABASE_URL: "postgresql://u:p@localhost:5432/db", JWT_SECRET: "j".repeat(40), SERVER_SECRET: "s".repeat(40), PUBLIC_URL: "http://localhost:5173" };

describe("product name (PRODUCT_NAME)", () => {
  it("defaults to Clane Vault; blank means default; set values are trimmed", () => {
    expect(loadConfig(base).productName).toBe("Clane Vault");
    expect(loadConfig({ ...base, PRODUCT_NAME: "  " }).productName).toBe("Clane Vault");
    expect(loadConfig({ ...base, PRODUCT_NAME: " Acme Keys " }).productName).toBe("Acme Keys");
  });

  it("is the issuer in the authenticator otpauth URI", () => {
    const uri = totpKeyUri(loadConfig({ ...base, PRODUCT_NAME: "Acme Keys" }).productName, "sara@acme.test", "JBSWY3DPEHPK3PXP");
    expect(uri).toMatch(/^otpauth:\/\/totp\/Acme%20Keys:sara%40acme\.test\?/);
    expect(new URL(uri).searchParams.get("issuer")).toBe("Acme Keys");
    expect(totpKeyUri(loadConfig(base).productName, "sara@acme.test", "JBSWY3DPEHPK3PXP")).toMatch(/^otpauth:\/\/totp\/Clane%20Vault:/);
  });

  it("names the invite email", () => {
    const m = inviteEmail("Acme Keys", "https://keys.acme.test/invite/abc");
    expect(m.subject).toBe("You're invited to Acme Keys");
    expect(m.text).toContain("You've been invited to Acme Keys, the team password manager.");
    expect(m.text).toContain("https://keys.acme.test/invite/abc");
    expect(inviteEmail("Clane Vault", "x").subject).toBe("You're invited to Clane Vault");
  });
});
