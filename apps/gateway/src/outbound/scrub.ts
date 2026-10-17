export const REDACTED = "[clane:redacted]";

/** Every form a secret is likely to be echoed in: raw, base64, base64url (unpadded), encodeURIComponent, hex lower/upper, base64(`user:secret`). */
export function variantsOf(secret: string, basicUser?: string): string[] {
  if (!secret) return [];
  const b = Buffer.from(secret, "utf8");
  const hex = b.toString("hex");
  const all = [secret, b.toString("base64"), b.toString("base64url"), encodeURIComponent(secret), hex, hex.toUpperCase()];
  if (basicUser !== undefined) all.push(Buffer.from(`${basicUser}:${secret}`, "utf8").toString("base64"));
  return [...new Set(all)];
}

/** Replaces every variant, longest first so a shorter one never splits a longer match. */
export function scrub(text: string, variants: string[]): { text: string; hits: number } {
  let hits = 0;
  for (const v of [...variants].filter(Boolean).sort((a, b) => b.length - a.length)) {
    const parts = text.split(v);
    hits += parts.length - 1;
    text = parts.join(REDACTED);
  }
  return { text, hits };
}
