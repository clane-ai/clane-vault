/**
 * Public email providers: nobody can prove they own these domains for an organisation, so they can never be SSO
 * domains (docs/sso.md). Exact names, plus `prefix.*` entries that match the provider under any top-level domain.
 */
export const PUBLIC_MAIL_DOMAINS: readonly string[] = [
  "gmail.com", "googlemail.com",
  "outlook.com", "hotmail.com", "live.com", "msn.com",
  "yahoo.com", "ymail.com",
  "icloud.com", "me.com", "mac.com",
  "proton.me", "protonmail.com", "pm.me",
  "aol.com",
  "gmx.*",
  "yandex.*",
  "mail.ru",
  "zoho.com",
];

/** Whether the domain (or a parent of it) is a public email provider. */
export function isPublicMailDomain(domain: string): boolean {
  const d = domain.toLowerCase();
  return PUBLIC_MAIL_DOMAINS.some((p) => {
    if (p.endsWith(".*")) {
      const base = p.slice(0, -2);
      return new RegExp(`(^|\\.)${base.replace(/\./g, "\\.")}\\.[a-z.]+$`).test(d);
    }
    return d === p || d.endsWith(`.${p}`);
  });
}
