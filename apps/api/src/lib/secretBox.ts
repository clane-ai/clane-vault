import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";

export function secretBox(serverSecret: string) {
  const key = createHash("sha256").update(`clane-vault/secret-box:${serverSecret}`).digest();
  return {
    seal(plain: string): string {
      const iv = randomBytes(12);
      const c = createCipheriv("aes-256-gcm", key, iv);
      const ct = Buffer.concat([c.update(plain, "utf8"), c.final()]);
      return Buffer.concat([iv, ct, c.getAuthTag()]).toString("base64url");
    },
    open(sealed: string): string {
      const raw = Buffer.from(sealed, "base64url");
      const d = createDecipheriv("aes-256-gcm", key, raw.subarray(0, 12));
      d.setAuthTag(raw.subarray(raw.length - 16));
      return Buffer.concat([d.update(raw.subarray(12, raw.length - 16)), d.final()]).toString("utf8");
    },
  };
}
