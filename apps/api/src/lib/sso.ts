import { createHash, randomBytes } from "node:crypto";
import { resolveTxt as dnsResolveTxt } from "node:dns/promises";
import * as oidc from "openid-client";
import { apiPrefix, type Config } from "../config.js";
import { PrivateHostError, publicOnlyFetch } from "./netGuard.js";
import type { SettingsBox } from "./settingsBox.js";

/** Single sign-on through OpenID Connect (docs/sso.md). */
export const SSO_TIMEOUT_S = 10;
export const SSO_LOGIN_TTL_MS = 10 * 60e3;
export const SSO_PROOF_TTL_MS = 5 * 60e3;
export const SSO_PROOF_MAX_ATTEMPTS = 5;
export const SSO_COOKIE = "cv_sso";
/** The SSO binding cookie only goes back to the SSO routes (under the base path, if any). */
export const ssoCookiePath = (cfg: Pick<Config, "basePath">) => `${apiPrefix(cfg)}/auth/sso`;
export const SSO_SCOPES = "openid email profile";
export const VERIFY_PREFIX = "clane-vault-verify=";

export const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");
export const randomToken = (n = 32) => randomBytes(n).toString("base64url");
export const redirectUri = (cfg: Config) => `${cfg.publicUrl}/api/v1/auth/sso/callback`;
export const clientSecretAad = (row: { id: string; orgId: string }) => `org-sso:${row.id}:${row.orgId}:client-secret`;

/** A same-origin path to go back to after sign-in; anything else (absolute URLs, `//host`, `/\host`) becomes "/". */
export function safeReturnTo(v: unknown): string {
  if (typeof v !== "string" || v.length > 512) return "/";
  if (!v.startsWith("/") || v.startsWith("//") || v.startsWith("/\\") || /[\p{Cc}\\]/u.test(v)) return "/";
  try {
    const u = new URL(v, "http://x.invalid");
    return u.origin === "http://x.invalid" ? `${u.pathname}${u.search}${u.hash}` : "/";
  } catch { return "/"; }
}

/** A domain name as people type it: lower case, no scheme, path or trailing dot; at least two labels. */
export function normalizeDomain(raw: string): string | null {
  const d = raw.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/\.$/, "");
  return /^(?=.{3,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/.test(d) ? d : null;
}
export const emailDomain = (email: string) => email.slice(email.lastIndexOf("@") + 1).toLowerCase();

/**
 * Whether the identity provider vouches for the email address: `email_verified: true` (Google, Okta, Keycloak, Auth0…),
 * or Microsoft Entra's `xms_edov: true` (the email's domain is verified in the tenant; Entra doesn't send email_verified).
 */
export function emailVerified(claims: Record<string, unknown>, issuer: string): boolean {
  if (claims.email_verified === true || claims.email_verified === "true") return true;
  const entra = /^https:\/\/login\.microsoftonline\.(com|us)\//.test(issuer) || /^https:\/\/sts\.windows\.net\//.test(issuer);
  return entra && (claims.xms_edov === true || claims.xms_edov === "true" || claims.xms_edov === 1);
}

export class SsoConfigError extends Error {
  constructor(public code: "issuer_insecure" | "issuer_invalid" | "private_host" | "discovery_failed", message: string) { super(message); this.name = "SsoConfigError"; }
}

/** Checks an issuer URL before anything is fetched: https (unless SSO_ALLOW_HTTP_ISSUER), no credentials or fragment. */
export function checkIssuerUrl(cfg: Config, raw: string): URL {
  let u: URL;
  try { u = new URL(raw); } catch { throw new SsoConfigError("issuer_invalid", "That isn't a URL."); }
  if (u.username || u.password || u.hash || u.search) throw new SsoConfigError("issuer_invalid", "The issuer URL can't contain credentials, a query or a fragment.");
  if (u.protocol !== "https:" && !(u.protocol === "http:" && cfg.ssoAllowHttpIssuer)) throw new SsoConfigError("issuer_insecure", "The issuer URL must use https.");
  return u;
}

export interface SsoDeps {
  /** DNS TXT lookup (tests replace it). */
  resolveTxt: (domain: string) => Promise<string[][]>;
}
export const defaultSsoDeps = (): SsoDeps => ({ resolveTxt: (d) => dnsResolveTxt(d) });

/** Error text for admins: no secrets, no tokens; short. */
export function describeOidcError(e: unknown): string {
  if (e instanceof SsoConfigError) return e.message;
  if (e instanceof PrivateHostError) return `${e.host} resolves to a private network address, which isn't allowed on this server.`;
  const x = e as { name?: string; code?: string; error?: string; error_description?: string; message?: string; cause?: unknown; status?: number };
  if (x.name === "TimeoutError" || x.name === "AbortError") return `No answer within ${SSO_TIMEOUT_S} s.`;
  if (x.error) return `The identity provider answered ${cleanText(x.error).slice(0, 60)}.`;
  const cause = x.cause as { code?: string; cause?: { code?: string } } | undefined;
  const code = cause?.code ?? cause?.cause?.code;
  if (code === "EPRIVATE" || cause instanceof PrivateHostError) return "The host resolves to a private network address, which isn't allowed on this server.";
  if (code === "ENOTFOUND") return "The host name can't be found.";
  if (code === "ECONNREFUSED") return "Connection refused.";
  // Generic on purpose: raw errors could describe the server's network.
  return "The identity provider couldn't be reached or answered something unexpected.";
}

/** Text from outside (an IdP's error parameter) without control characters, for logs and events. */
export const cleanText = (s: unknown) => String(s ?? "").replace(/[\p{Cc}\p{Cf}]+/gu, " ").trim();

/**
 * OpenID Connect client configurations by (issuer, client id, secret), from discovery, cached for 10 minutes. HTTP goes
 * through a fetch that, in HOSTED_MODE, refuses hosts on private addresses (issuer, token endpoint and JWKS alike).
 */
export class OidcClients {
  private cache = new Map<string, { at: number; conf: oidc.Configuration }>();
  constructor(private cfg: Config) {}

  /** HOSTED_MODE: connections only to public addresses, checked on the address actually connected to (no rebinding gap). */
  private fetcher(): oidc.CustomFetch {
    const hosted = !!this.cfg.hostedMode;
    return async (url, options) => (hosted ? publicOnlyFetch : fetch)(url, { ...options, redirect: "manual" } as RequestInit);
  }

  async get(issuer: string, clientId: string, clientSecret: string | null, opts: { fresh?: boolean } = {}): Promise<oidc.Configuration> {
    const key = `${issuer}\n${clientId}\n${sha256(clientSecret ?? "")}`;
    const hit = this.cache.get(key);
    if (hit && !opts.fresh && Date.now() - hit.at < 10 * 60e3) return hit.conf;
    const url = checkIssuerUrl(this.cfg, issuer);
    const conf = await oidc.discovery(url, clientId, clientSecret ? { client_secret: clientSecret } : undefined,
      clientSecret ? oidc.ClientSecretPost(clientSecret) : oidc.None(), {
        [oidc.customFetch]: this.fetcher(), timeout: SSO_TIMEOUT_S,
        ...(url.protocol === "http:" ? { execute: [oidc.allowInsecureRequests] } : {}),
      });
    // Check id_token signatures against the provider's JWKS (fetched through the same guarded fetch) on top of the
    // iss/aud/exp/nonce checks: the token endpoint's TLS alone isn't taken as proof.
    oidc.enableNonRepudiationChecks(conf);
    this.cache.set(key, { at: Date.now(), conf });
    if (this.cache.size > 500) this.cache.delete(this.cache.keys().next().value!);
    return conf;
  }
  forget(issuer: string) { for (const k of this.cache.keys()) if (k.startsWith(`${issuer}\n`)) this.cache.delete(k); }
}

/** The client secret of an org's SSO configuration, opened in memory (null when none or unreadable). */
export function openClientSecret(box: SettingsBox, row: { id: string; orgId: string; clientSecretEnc: string | null }): string | null {
  if (!row.clientSecretEnc) return null;
  try { return box.open(row.clientSecretEnc, clientSecretAad(row)); } catch { return null; }
}

export interface TestCheck { name: string; ok: boolean; detail: string }
/**
 * "Test connection": discovery, the metadata this app needs, and a sanity check of the client credentials (a token
 * request with a made-up code: `invalid_grant` means the provider accepted the client, `invalid_client` that it didn't).
 */
export async function testConnection(clients: OidcClients, cfg: Config, issuer: string, clientId: string, secret: string | null): Promise<TestCheck[]> {
  const checks: TestCheck[] = [];
  let conf: oidc.Configuration;
  try { conf = await clients.get(issuer, clientId, secret, { fresh: true }); }
  catch (e) { return [{ name: "discovery", ok: false, detail: describeOidcError(e) }]; }
  const m = conf.serverMetadata();
  checks.push({ name: "discovery", ok: true, detail: `Found ${m.issuer}.` });
  const missing = (["authorization_endpoint", "token_endpoint", "jwks_uri"] as const).filter((k) => !m[k]);
  const s256 = !m.code_challenge_methods_supported || m.code_challenge_methods_supported.includes("S256");
  const code = !m.response_types_supported || m.response_types_supported.includes("code");
  checks.push({ name: "metadata", ok: !missing.length && s256 && code,
    detail: missing.length ? `Missing ${missing.join(", ")}.` : !code ? "The provider doesn't offer the authorization code flow." : !s256 ? "The provider doesn't support PKCE with S256." : "Authorization code flow with PKCE (S256) is available." });
  if (!secret) { checks.push({ name: "client", ok: false, detail: "No client secret is set." }); return checks; }
  try {
    await oidc.genericGrantRequest(conf, "authorization_code", { code: `clane-vault-connection-test-${randomToken(8)}`, redirect_uri: redirectUri(cfg), code_verifier: oidc.randomPKCECodeVerifier() });
    checks.push({ name: "client", ok: false, detail: "The provider accepted a made-up code; check the issuer." });
  } catch (e) {
    const err = (e as { error?: string }).error;
    if (err === "invalid_grant") checks.push({ name: "client", ok: true, detail: "The client ID and secret were accepted." });
    else if (err === "invalid_client" || err === "unauthorized_client") checks.push({ name: "client", ok: false, detail: "The provider rejected the client ID or secret." });
    else checks.push({ name: "client", ok: false, detail: `Couldn't check the client: ${describeOidcError(e)}` });
  }
  return checks;
}

/** Whether the domain's TXT records carry the verification token right now ("error": DNS failed or timed out). */
export async function txtHasToken(deps: SsoDeps, domain: string, token: string): Promise<"yes" | "no" | "error"> {
  try {
    const txt = await Promise.race([deps.resolveTxt(domain), new Promise<never>((_, rej) => setTimeout(() => rej(Object.assign(new Error("timeout"), { code: "ETIMEOUT" })), SSO_TIMEOUT_S * 1000).unref())]);
    return txt.some((parts) => parts.join("").trim() === `${VERIFY_PREFIX}${token}`) ? "yes" : "no";
  } catch (e) {
    const code = (e as { code?: string }).code;
    return code === "ENODATA" || code === "ENOTFOUND" ? "no" : "error";
  }
}

export const DOMAIN_RECHECK_MS = 24 * 3600e3;
/**
 * Before a domain grants something new (a just-in-time join, an SSO sign-up): still verified, with the TXT record seen
 * in the last 24 hours, else looked up again. A record that is gone un-verifies the domain; a DNS failure refuses
 * (fails closed) without un-verifying.
 */
export async function domainStillVerified(prisma: import("@prisma/client").PrismaClient, deps: SsoDeps, orgId: string, domain: string): Promise<boolean> {
  const d = await prisma.ssoDomain.findUnique({ where: { orgId_domain: { orgId, domain } } });
  if (!d?.verifiedAt) return false;
  if (Date.now() - (d.checkedAt ?? d.verifiedAt).getTime() < DOMAIN_RECHECK_MS) return true;
  const r = await txtHasToken(deps, domain, d.token);
  if (r === "yes") { await prisma.ssoDomain.update({ where: { id: d.id }, data: { checkedAt: new Date() } }); return true; }
  if (r === "no") {
    await prisma.ssoDomain.update({ where: { id: d.id }, data: { verifiedAt: null, checkedAt: null } });
    await prisma.event.create({ data: { orgId, action: "sso.domain_unverified", meta: { domain, reason: "txt_missing" } } });
    // Without a verified domain, "Require SSO", just-in-time joining and email domain auto-join can't apply.
    if (!(await prisma.ssoDomain.count({ where: { orgId, verifiedAt: { not: null } } }))) {
      await prisma.orgSso.updateMany({ where: { orgId }, data: { requireSso: false, autoJoin: false } });
      await prisma.orgDomainJoin.updateMany({ where: { orgId }, data: { enabled: false } });
    }
  }
  return false;
}
