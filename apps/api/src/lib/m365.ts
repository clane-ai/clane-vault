import { createHash, randomBytes } from "node:crypto";

/**
 * Microsoft 365 email through Microsoft Graph (docs/email.md, "Microsoft 365 (Graph)"): an Entra app registration with
 * the Mail.Send application permission gets a token with the client-credentials grant and sends as one mailbox with
 * POST /users/{sender}/sendMail. Replaces SMTP AUTH with a password, which Microsoft has retired for Exchange Online.
 *
 * Delegated mode (docs/email.md, "Microsoft 365 — delegated sign-in"): an admin signs in once with the authorization code
 * flow (PKCE, confidential Web client); the server keeps the sealed refresh token, refreshes it (rotating it on every
 * refresh) and sends with POST /me/sendMail, setting `from` for a shared mailbox (Mail.Send.Shared + Send As / Send on
 * behalf in Exchange Online, as Microsoft documents for delegated shared-mailbox sending).
 *
 * Only these two hosts are ever called (global Azure only; national clouds are out of scope). Nothing about them comes
 * from settings: the tenant and sender are validated and URL-encoded into the path.
 */
export const M365_LOGIN_HOST = "https://login.microsoftonline.com";
export const M365_GRAPH_HOST = "https://graph.microsoft.com";
export const M365_TIMEOUT_MS = 10_000;
/** A cached token is used until this long before it expires. */
export const M365_TOKEN_MARGIN_MS = 5 * 60_000;

const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const DOMAIN = /^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/i;
/** A directory (tenant) ID: a GUID, or one of the tenant's verified domains (e.g. contoso.onmicrosoft.com). */
export const isTenantId = (s: string) => GUID.test(s) || DOMAIN.test(s);
/** An application (client) ID: always a GUID. */
export const isClientId = (s: string) => GUID.test(s);

export interface M365Transport {
  source: "org" | "instance"; provider: "m365";
  /** The sender mailbox (UPN or primary address): the From address and the mailbox sent as. */
  sender: string; fromName?: string | null;
  tenantId: string; clientId: string; clientSecret: string;
  /** What the token is cached under (the settings row's id). */
  cacheId: string;
  /** app (default): client credentials. delegated: the signed-in account's refresh token from `store`. */
  mode?: "app" | "delegated";
  /** Delegated: the signed-in account (UPN). */
  account?: string;
  /** Delegated: the scopes asked for at sign-in (asked for again on refresh). */
  scope?: string;
  store?: DelegatedStore;
}

/**
 * Where a delegated connection's refresh token lives (the settings row; the Mailer implements it with Prisma and the
 * settings box). Versions make rotation a compare-and-swap: a lost race never overwrites a newer token.
 */
export interface DelegatedStore {
  load(): Promise<{ refreshToken: string; version: number } | null>;
  /** Persists a rotated refresh token if the row is still at `version`. False: someone else rotated it first. */
  rotate(version: number, refreshToken: string): Promise<boolean>;
  /** Microsoft refused the refresh token (invalid_grant): the connection needs an admin to sign in again. */
  broken(version: number, reason: string): Promise<void>;
}

type Fetch = (url: string, init: RequestInit) => Promise<Response>;
let fetchImpl: Fetch | null = null;
/** Test seam: replaces fetch for the two Microsoft hosts (production code never sets it). */
export function setM365FetchForTests(f: Fetch | null): void { fetchImpl = f; }
const doFetch: Fetch = (url, init) => (fetchImpl ?? fetch)(url, { ...init, signal: AbortSignal.timeout(M365_TIMEOUT_MS) });

// ---- tokens: cached per settings row until ~5 minutes before expiry ----
interface Cached { fp: string; token: string; refreshAt: number }
const tokens = new Map<string, Cached>();
const inflight = new Map<string, Promise<string>>();
/** Ties a cached token to the exact tenant, app and secret it was issued for (a changed setting never reuses it). */
const fingerprint = (t: M365Transport) => createHash("sha256").update(`${t.tenantId}\0${t.clientId}\0${t.clientSecret}\0${t.mode ?? "app"}\0${t.account ?? ""}`).digest("hex");

/** Drops the cached token of a settings row (its settings changed or were removed). No id: every token. */
export function invalidateM365Token(cacheId?: string): void {
  if (cacheId) { tokens.delete(cacheId); inflight.delete(cacheId); } else { tokens.clear(); inflight.clear(); }
}

class M365Error extends Error {
  constructor(public detail: string) { super(detail); this.name = "M365Error"; }
}

/** AADSTS codes from the token endpoint, as short and secret-free reasons. */
function tokenErrorSummary(status: number, body: unknown): string {
  const b = (body ?? {}) as { error?: unknown; error_codes?: unknown; error_description?: unknown };
  const codes = Array.isArray(b.error_codes) ? b.error_codes.filter((c): c is number => typeof c === "number") : [];
  const fromText = typeof b.error_description === "string" ? /AADSTS(\d+)/.exec(b.error_description)?.[1] : undefined;
  const code = codes[0] ?? (fromText ? Number(fromText) : undefined);
  switch (code) {
    case 7000215: return "Microsoft 365 rejected the client secret (AADSTS7000215). Copy the secret's Value (not its Secret ID) into Client secret.";
    case 7000222: return "The client secret has expired (AADSTS7000222). Create a new one under Certificates & secrets and enter it here.";
    case 700016: return "The application (client) ID wasn't found in this tenant (AADSTS700016). Check the client ID and the tenant ID, and that the app registration is in that directory.";
    case 90002: return "Microsoft 365 can't find that tenant (AADSTS90002). Check the directory (tenant) ID or domain.";
    case 900023: return "The tenant ID isn't valid (AADSTS900023). Use the Directory (tenant) ID GUID or a verified domain.";
    case 90023: case 50126: return `Microsoft 365 refused the sign-in (AADSTS${code}). Check the tenant ID, client ID and secret.`;
    case 7000112: return "The app registration is disabled (AADSTS7000112).";
    case 50020: case 50034: return `Microsoft 365 refused the sign-in (AADSTS${code}). Check the tenant ID.`;
  }
  if (code) return `Microsoft 365 sign-in failed (AADSTS${code}). Check the tenant ID, client ID and secret.`;
  if (b.error === "invalid_client") return "Microsoft 365 rejected the app's credentials. Check the client ID and secret.";
  return `Microsoft 365 sign-in failed (HTTP ${status}).`;
}

const graphCode = (body: unknown) => {
  const raw = ((body ?? {}) as { error?: { code?: unknown } }).error?.code;
  return typeof raw === "string" && /^[A-Za-z0-9_.]{1,64}$/.test(raw) ? raw : "";
};

/** Graph error codes from sendMail, as short reasons naming what to fix in Entra or Exchange Online. */
function graphErrorSummary(status: number, body: unknown, sender: string): string {
  const code = graphCode(body);
  if (code === "ErrorAccessDenied" || status === 403)
    return `Microsoft 365 denied sending as ${sender} (${code || "HTTP 403"}): the app needs the Microsoft Graph Mail.Send application permission with admin consent, and if an Application Access Policy (or RBAC for Applications) limits the app, it must include this mailbox. Or use delegated sign-in (Sign in with Microsoft) instead.`;
  if (code === "ResourceNotFound" || code === "ErrorInvalidUser" || code === "MailboxNotEnabledForRESTAPI" || status === 404)
    return `The sender mailbox ${sender} wasn't found in this tenant, or it has no Exchange Online mailbox (licence) (${code || "HTTP 404"}). Use an existing user or shared mailbox.`;
  if (code === "ErrorSendAsDenied") return `The app may not send as ${sender} (ErrorSendAsDenied). Use the mailbox's own address as the sender.`;
  if (code === "ErrorInvalidRecipients") return "Microsoft 365 refused the recipient address (ErrorInvalidRecipients).";
  if (status === 401) return `Microsoft Graph didn't accept the app's token (${code || "HTTP 401"}). Check that Mail.Send is an application permission (not delegated) and admin consent was granted.`;
  if (status === 429) return "Microsoft 365 is throttling this app (HTTP 429). Try again in a minute.";
  return `Microsoft 365 refused the email (${code ? `${code}, ` : ""}HTTP ${status}).`;
}

/** Graph errors when sending as the signed-in account (delegated). */
function delegatedGraphErrorSummary(status: number, body: unknown, account: string, sender: string): string {
  const code = graphCode(body);
  const shared = sender.toLowerCase() !== account.toLowerCase();
  if (code === "ErrorSendAsDenied")
    return `${account} has no Send As permission on ${sender} (ErrorSendAsDenied). In the Exchange admin center give ${account} Send As (or Send on behalf) on that mailbox, then try again (changes can take up to an hour).`;
  if (code === "ErrorAccessDenied" || status === 403)
    return `Microsoft 365 denied sending as ${shared ? `${sender} through ${account}` : account} (${code || "HTTP 403"}): the sign-in needs the Microsoft Graph Mail.Send delegated permission${shared ? " and Mail.Send.Shared" : ""}. Add it to the app registration and sign in again.`;
  if (code === "ResourceNotFound" || code === "ErrorInvalidUser" || code === "MailboxNotEnabledForRESTAPI" || status === 404)
    return `${shared ? `The mailbox ${sender}` : account} wasn't found or has no Exchange Online mailbox (${code || "HTTP 404"}).`;
  if (code === "ErrorInvalidRecipients") return "Microsoft 365 refused the recipient address (ErrorInvalidRecipients).";
  if (status === 401) return `Microsoft Graph didn't accept the signed-in account's token (${code || "HTTP 401"}). Sign in with Microsoft again.`;
  if (status === 429) return "Microsoft 365 is throttling this app (HTTP 429). Try again in a minute.";
  return `Microsoft 365 refused the email (${code ? `${code}, ` : ""}HTTP ${status}).`;
}

function networkSummary(e: unknown, host: string): string {
  const name = (e as Error)?.name;
  return name === "TimeoutError" || name === "AbortError" ? `No answer from ${host} within ${M365_TIMEOUT_MS / 1000} s.` : `Couldn't reach ${host}.`;
}

const json = async (res: Response): Promise<unknown> => { try { return await res.json(); } catch { return null; } };

async function requestToken(t: M365Transport): Promise<{ token: string; expiresInS: number }> {
  if (t.mode === "delegated") return refreshDelegated(t);
  let res: Response;
  try {
    res = await doFetch(`${M365_LOGIN_HOST}/${encodeURIComponent(t.tenantId)}/oauth2/v2.0/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "client_credentials", client_id: t.clientId, client_secret: t.clientSecret, scope: `${M365_GRAPH_HOST}/.default` }).toString(),
    });
  } catch (e) { throw new M365Error(networkSummary(e, "login.microsoftonline.com")); }
  const b = await json(res);
  if (!res.ok) throw new M365Error(tokenErrorSummary(res.status, b));
  const { access_token, expires_in } = (b ?? {}) as { access_token?: unknown; expires_in?: unknown };
  if (typeof access_token !== "string" || !access_token) throw new M365Error("Microsoft 365 sign-in returned no access token.");
  return { token: access_token, expiresInS: Number(expires_in) > 0 ? Number(expires_in) : 3599 };
}

/** An access token for Graph: the cached one while it has more than ~5 minutes left, else a new one. */
async function getToken(t: M365Transport, fresh = false): Promise<string> {
  const fp = fingerprint(t);
  const c = tokens.get(t.cacheId);
  if (!fresh && c && c.fp === fp && Date.now() < c.refreshAt) return c.token;
  const pending = inflight.get(t.cacheId);
  if (!fresh && pending) return pending;
  const p = requestToken(t).then(({ token, expiresInS }) => {
    tokens.set(t.cacheId, { fp, token, refreshAt: Date.now() + expiresInS * 1000 - M365_TOKEN_MARGIN_MS });
    return token;
  }).finally(() => { if (inflight.get(t.cacheId) === p) inflight.delete(t.cacheId); });
  inflight.set(t.cacheId, p);
  return p;
}

/** Delegated: whether the sender is another mailbox than the signed-in account (a shared mailbox: `from` is set). */
const sendsAsOther = (t: M365Transport) => t.mode === "delegated" && !!t.account && t.sender.toLowerCase() !== t.account.toLowerCase();

async function postSendMail(t: M365Transport, token: string, to: string, msg: { subject: string; text: string }): Promise<Response> {
  // Delegated: always /me/sendMail; a shared mailbox is the `from` (Microsoft's documented way for delegated tokens).
  const url = t.mode === "delegated" ? `${M365_GRAPH_HOST}/v1.0/me/sendMail` : `${M365_GRAPH_HOST}/v1.0/users/${encodeURIComponent(t.sender)}/sendMail`;
  const from = sendsAsOther(t) || t.fromName ? { from: { emailAddress: { address: t.sender, ...(t.fromName ? { name: t.fromName } : {}) } } } : {};
  return doFetch(url, {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: JSON.stringify({
      message: {
        subject: msg.subject,
        body: { contentType: "Text", content: msg.text },
        toRecipients: [{ emailAddress: { address: to } }],
        ...from,
      },
      saveToSentItems: false,
    }),
  });
}

/** Sends one plain-text email. Never throws; failures come back as a short reason without secrets or tokens. */
export async function sendM365(t: M365Transport, to: string, msg: { subject: string; text: string }): Promise<{ ok: true } | { ok: false; detail: string }> {
  try {
    let token = await getToken(t);
    let res: Response;
    try { res = await postSendMail(t, token, to, msg); }
    catch (e) { return { ok: false, detail: networkSummary(e, "graph.microsoft.com") }; }
    // A cached token can be revoked early: one retry with a new one.
    if (res.status === 401) {
      invalidateM365Token(t.cacheId);
      token = await getToken(t, true);
      try { res = await postSendMail(t, token, to, msg); }
      catch (e) { return { ok: false, detail: networkSummary(e, "graph.microsoft.com") }; }
    }
    if (res.status === 202 || res.ok) return { ok: true };
    const body = await json(res);
    return { ok: false, detail: t.mode === "delegated" ? delegatedGraphErrorSummary(res.status, body, t.account ?? t.sender, t.sender) : graphErrorSummary(res.status, body, t.sender) };
  } catch (e) {
    return { ok: false, detail: e instanceof M365Error ? e.detail : "Sending with Microsoft 365 failed." };
  }
}

// ---- delegated: refresh with rotation ----

const tokenUrl = (tenantId: string) => `${M365_LOGIN_HOST}/${encodeURIComponent(tenantId)}/oauth2/v2.0/token`;
const aadsts = (body: unknown): number | undefined => {
  const b = (body ?? {}) as { error_codes?: unknown; error_description?: unknown };
  const codes = Array.isArray(b.error_codes) ? b.error_codes.filter((c): c is number => typeof c === "number") : [];
  const fromText = typeof b.error_description === "string" ? /AADSTS(\d+)/.exec(b.error_description)?.[1] : undefined;
  return codes[0] ?? (fromText ? Number(fromText) : undefined);
};
/** Token endpoint errors that mean the saved sign-in is gone for good: an admin has to sign in again. */
const RECONNECT_ERRORS = new Set(["invalid_grant", "interaction_required", "consent_required"]);

/** Why a refresh token stopped working, in a few words (stored on the settings row and shown to admins). */
export function reconnectReason(body: unknown): string {
  const code = aadsts(body);
  switch (code) {
    case 50173: case 50133: return `The account's password changed or its sign-ins were revoked (AADSTS${code}).`;
    case 70043: case 700082: return `The sign-in expired after a long time unused (AADSTS${code}).`;
    case 65001: return "Consent for the app was removed (AADSTS65001).";
    case 50076: case 50079: return `Multi-factor authentication or a Conditional Access policy now requires signing in again (AADSTS${code}).`;
    case 50057: return "The account is disabled (AADSTS50057).";
    case 50053: return "The account is locked (AADSTS50053).";
    case 50034: return "The account no longer exists in the tenant (AADSTS50034).";
  }
  if (code) return `Microsoft refused the saved sign-in (AADSTS${code}).`;
  const err = ((body ?? {}) as { error?: unknown }).error;
  return `Microsoft refused the saved sign-in (${typeof err === "string" ? err.slice(0, 40).replace(/[^a-z_]/g, "") : "invalid_grant"}).`;
}

/** Delegated: a new access token from the stored refresh token, persisting the rotated refresh token. */
async function refreshDelegated(t: M365Transport, retried = false): Promise<{ token: string; expiresInS: number }> {
  const store = t.store!;
  const cur = await store.load();
  if (!cur) throw new M365Error("Microsoft 365 isn't connected: an admin needs to sign in with Microsoft in the email settings.");
  let res: Response;
  try {
    res = await doFetch(tokenUrl(t.tenantId), {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "refresh_token", client_id: t.clientId, client_secret: t.clientSecret, refresh_token: cur.refreshToken, scope: t.scope ?? delegatedScope(false) }).toString(),
    });
  } catch (e) { throw new M365Error(networkSummary(e, "login.microsoftonline.com")); }
  const b = await json(res);
  if (!res.ok) {
    const err = ((b ?? {}) as { error?: unknown }).error;
    if (typeof err === "string" && RECONNECT_ERRORS.has(err)) {
      // Another server may have rotated the token meanwhile: try once with the newer one before giving up.
      const now = await store.load();
      if (!retried && now && now.version !== cur.version) return refreshDelegated(t, true);
      const reason = reconnectReason(b);
      await store.broken(cur.version, reason);
      throw new M365Error(`The Microsoft 365 sign-in for ${t.account ?? "the mailbox"} stopped working: ${reason} An admin needs to reconnect it (Sign in with Microsoft) in the email settings.`);
    }
    throw new M365Error(tokenErrorSummary(res.status, b));
  }
  const { access_token, expires_in, refresh_token } = (b ?? {}) as { access_token?: unknown; expires_in?: unknown; refresh_token?: unknown };
  if (typeof access_token !== "string" || !access_token) throw new M365Error("Microsoft 365 sign-in returned no access token.");
  // Rotation: the new refresh token replaces the old one (compare-and-swap; losing the race is harmless, the winner's is as new).
  if (typeof refresh_token === "string" && refresh_token && refresh_token !== cur.refreshToken) await store.rotate(cur.version, refresh_token);
  return { token: access_token, expiresInS: Number(expires_in) > 0 ? Number(expires_in) : 3599 };
}

// ---- delegated sign-in: authorization code flow with PKCE (confidential Web client) ----

export const M365_GRAPH_SCOPE = {
  send: `${M365_GRAPH_HOST}/Mail.Send`,
  sendShared: `${M365_GRAPH_HOST}/Mail.Send.Shared`,
  userRead: `${M365_GRAPH_HOST}/User.Read`,
};
/** What delegated sign-in asks for: a refresh token, sending (also from shared mailboxes when `shared`), and who signed in. */
export const delegatedScope = (shared: boolean) =>
  ["openid", "email", "profile", "offline_access", M365_GRAPH_SCOPE.userRead, M365_GRAPH_SCOPE.send, ...(shared ? [M365_GRAPH_SCOPE.sendShared] : [])].join(" ");
/** Whether a granted scope string (as the token endpoint returns it) includes a permission (with or without the Graph prefix). */
export function hasScope(granted: string | null | undefined, full: string): boolean {
  const short = full.slice(full.lastIndexOf("/") + 1).toLowerCase();
  return (granted ?? "").split(/\s+/).some((s) => s.toLowerCase() === full.toLowerCase() || s.toLowerCase() === short);
}

export const randomUrlToken = (n = 32) => randomBytes(n).toString("base64url");
export const pkceChallenge = (verifier: string) => createHash("sha256").update(verifier).digest("base64url");

/** The authorize URL the browser goes to (login.microsoftonline.com only; the tenant is validated and URL-encoded). */
export function authorizeUrl(p: { tenantId: string; clientId: string; redirectUri: string; scope: string; state: string; nonce: string; codeChallenge: string }): string {
  const u = new URL(`${M365_LOGIN_HOST}/${encodeURIComponent(p.tenantId)}/oauth2/v2.0/authorize`);
  u.search = new URLSearchParams({ client_id: p.clientId, response_type: "code", redirect_uri: p.redirectUri, response_mode: "query", scope: p.scope,
    state: p.state, nonce: p.nonce, code_challenge: p.codeChallenge, code_challenge_method: "S256", prompt: "select_account" }).toString();
  return u.toString();
}

/** Why a delegated sign-in failed, as a code the settings page explains. `aadsts`: Microsoft's AADSTS number, if any. */
export type ConnectError = "consent_required" | "redirect_uri_mismatch" | "app_not_found" | "bad_secret" | "secret_expired" | "tenant_not_found"
  | "spa_platform" | "code_expired" | "access_denied" | "no_refresh_token" | "send_scope_missing" | "shared_scope_missing" | "id_token"
  | "unreachable" | "failed";

export function connectErrorOf(error: unknown, body: unknown): { error: ConnectError; aadsts?: number } {
  const code = aadsts(body);
  switch (code) {
    case 65001: return { error: "consent_required", aadsts: code };
    case 50011: case 500113: return { error: "redirect_uri_mismatch", aadsts: code };
    case 700016: return { error: "app_not_found", aadsts: code };
    case 7000215: case 7000218: return { error: "bad_secret", aadsts: code };
    case 7000222: return { error: "secret_expired", aadsts: code };
    case 90002: case 900023: return { error: "tenant_not_found", aadsts: code };
    case 9002327: return { error: "spa_platform", aadsts: code };
    case 70008: case 54005: return { error: "code_expired", aadsts: code };
  }
  const extra = code ? { aadsts: code } : {};
  if (error === "access_denied") return { error: "access_denied", ...extra };
  if (error === "consent_required") return { error: "consent_required", ...extra };
  return { error: "failed", ...extra };
}

/** An id_token's payload. It comes straight from the token endpoint over TLS, so its signature isn't checked (OIDC Core 3.1.3.7). */
export function idTokenClaims(idToken: unknown): Record<string, unknown> | null {
  if (typeof idToken !== "string") return null;
  const parts = idToken.split(".");
  if (parts.length !== 3) return null;
  try {
    const c = JSON.parse(Buffer.from(parts[1]!, "base64url").toString("utf8")) as unknown;
    return c && typeof c === "object" && !Array.isArray(c) ? c as Record<string, unknown> : null;
  } catch { return null; }
}

export type CodeExchange =
  | { ok: true; accessToken: string; refreshToken: string; expiresInS: number; scope: string; account: string }
  | { ok: false; error: ConnectError; aadsts?: number };

/**
 * The callback side of delegated sign-in: redeems the code (client secret + PKCE verifier), checks the id_token (nonce,
 * audience, tenant, expiry) and asks Graph who signed in (GET /me), whose object ID must match the id_token's.
 */
export async function exchangeCode(p: { tenantId: string; clientId: string; clientSecret: string; code: string; codeVerifier: string; redirectUri: string; scope: string; nonce: string }): Promise<CodeExchange> {
  let res: Response;
  try {
    res = await doFetch(tokenUrl(p.tenantId), {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "authorization_code", client_id: p.clientId, client_secret: p.clientSecret, code: p.code,
        redirect_uri: p.redirectUri, code_verifier: p.codeVerifier, scope: p.scope }).toString(),
    });
  } catch { return { ok: false, error: "unreachable" }; }
  const b = await json(res);
  if (!res.ok) return { ok: false, ...connectErrorOf(((b ?? {}) as { error?: unknown }).error, b) };
  const r = (b ?? {}) as { access_token?: unknown; refresh_token?: unknown; id_token?: unknown; expires_in?: unknown; scope?: unknown };
  if (typeof r.access_token !== "string" || !r.access_token) return { ok: false, error: "failed" };
  if (typeof r.refresh_token !== "string" || !r.refresh_token) return { ok: false, error: "no_refresh_token" };
  const granted = typeof r.scope === "string" ? r.scope : "";
  if (granted && !hasScope(granted, M365_GRAPH_SCOPE.send)) return { ok: false, error: "send_scope_missing" };
  const claims = idTokenClaims(r.id_token);
  const tenantOk = !GUID.test(p.tenantId) || String(claims?.tid ?? "").toLowerCase() === p.tenantId.toLowerCase();
  if (!claims || claims.nonce !== p.nonce || claims.aud !== p.clientId || !tenantOk || !(Number(claims.exp) > Date.now() / 1000 - 300)) return { ok: false, error: "id_token" };
  let me: Response;
  try { me = await doFetch(`${M365_GRAPH_HOST}/v1.0/me?$select=id,userPrincipalName`, { method: "GET", headers: { authorization: `Bearer ${r.access_token}` } }); }
  catch { return { ok: false, error: "unreachable" }; }
  const mb = ((await json(me)) ?? {}) as { id?: unknown; userPrincipalName?: unknown };
  const upn = typeof mb.userPrincipalName === "string" ? mb.userPrincipalName.trim().toLowerCase() : "";
  if (!me.ok || !upn || upn.length > 254 || /[\s<>"]/.test(upn) || typeof mb.id !== "string" || (claims.oid !== undefined && claims.oid !== mb.id)) return { ok: false, error: "failed" };
  return { ok: true, accessToken: r.access_token, refreshToken: r.refresh_token, expiresInS: Number(r.expires_in) > 0 ? Number(r.expires_in) : 3599, scope: granted, account: upn };
}
