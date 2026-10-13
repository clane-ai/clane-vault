import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from "node:crypto";

/**
 * Secrets in admin settings (email API keys and SMTP passwords, SSO client secrets): AES-256-GCM under a key derived
 * from SERVER_SECRET (HKDF-SHA256), with the setting's own id (and what the secret is) as additional data, so a sealed
 * value copied into another row or field doesn't open. Stored as `v1.<base64url(iv | ciphertext | tag)>`.
 */
export function settingsBox(serverSecret: string) {
  const key = Buffer.from(hkdfSync("sha256", serverSecret, "clane-vault/settings-secrets", "aes-256-gcm v1", 32));
  return {
    seal(plain: string, aad: string): string {
      const iv = randomBytes(12);
      const c = createCipheriv("aes-256-gcm", key, iv);
      c.setAAD(Buffer.from(aad, "utf8"));
      const ct = Buffer.concat([c.update(plain, "utf8"), c.final()]);
      return `v1.${Buffer.concat([iv, ct, c.getAuthTag()]).toString("base64url")}`;
    },
    open(sealed: string, aad: string): string {
      if (!sealed.startsWith("v1.")) throw new Error("unknown sealed format");
      const raw = Buffer.from(sealed.slice(3), "base64url");
      const d = createDecipheriv("aes-256-gcm", key, raw.subarray(0, 12));
      d.setAAD(Buffer.from(aad, "utf8"));
      d.setAuthTag(raw.subarray(raw.length - 16));
      return Buffer.concat([d.update(raw.subarray(12, raw.length - 16)), d.final()]).toString("utf8");
    },
  };
}
export type SettingsBox = ReturnType<typeof settingsBox>;

/** The last four characters of a secret, for "set (…abcd)" displays; nothing for short secrets. */
export const last4 = (s: string) => (s.length >= 12 ? s.slice(-4) : null);
