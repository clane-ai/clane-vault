import { api } from "@/lib/api";

/** Single sign-on (docs/sso.md): the organisations offering SSO for an address's domain (verified domains only). */
export interface SsoOrg { slug: string; name: string }

export async function discoverSso(email: string): Promise<SsoOrg[]> {
  try { return (await api.post<{ orgs: SsoOrg[] }>("/auth/sso/discover", { email })).orgs; } catch { return []; }
}

/** A path inside the app, or "/": never another site (`//host`, `/\host`, absolute URLs). */
export function safeReturnTo(v: string | null | undefined): string {
  if (!v || !v.startsWith("/") || v.startsWith("//") || v.startsWith("/\\") || /[\u0000-\u001f\\]/.test(v)) return "/";
  return v;
}

/** Starts SSO for the org and leaves for the identity provider. */
export async function startSso(org: string, opts: { email?: string; returnTo?: string } = {}, go: (url: string) => void = (u) => window.location.assign(u)): Promise<void> {
  const { url } = await api.post<{ url: string }>("/auth/sso/start", { org, ...(opts.email ? { email: opts.email } : {}), ...(opts.returnTo ? { returnTo: safeReturnTo(opts.returnTo) } : {}) });
  go(url);
}

/** What `/sign-in?sso_error=…` means. */
export const SSO_ERRORS: Record<string, string> = {
  sso_state: "That single sign-on attempt expired or was started in another browser. Try again.",
  sso_denied: "Single sign-on was cancelled at your identity provider.",
  sso_failed: "Single sign-on didn't work. Try again, or ask your admin to check the SSO settings.",
  sso_email_unverified: "Your identity provider didn't confirm your email address, so single sign-on can't be used.",
  sso_domain: "Your email address isn't one this organisation's single sign-on is for.",
  sso_not_member: "Your account isn't a member of this organisation. Ask an admin to invite you.",
  sso_no_account: "There's no account for this address yet. Ask an admin of the organisation to invite you.",
  sso_identity_mismatch: "This address is linked to a different account at your identity provider. Ask your admin for help.",
  sso_org_full: "This organisation has no free seats. Ask an admin of the organisation to add seats.",
  sso_not_configured: "That organisation doesn't use single sign-on. Check the organisation ID.",
  sso_unavailable: "The organisation's identity provider isn't reachable right now. Try again, or use your master password.",
};
