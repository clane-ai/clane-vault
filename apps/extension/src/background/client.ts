/**
 * The extension's API client: like the web's lib/api.ts, but against a chosen server and with the refresh token held
 * by the extension (sent in the body, docs/extension.md) instead of an httpOnly cookie.
 */
export class ApiError extends Error {
  constructor(public status: number, public code: string, public body: unknown) { super(code); this.name = "ApiError"; }
}

export interface Tokens { accessToken: string | null; refreshToken: string | null }
export interface ClientDeps {
  serverUrl: () => string | null;
  tokens: () => Tokens;
  /** Persists rotated tokens (both, or only the access token after a grace-window refresh) and the fresh org list. */
  saveTokens: (t: Partial<Tokens>, body: { orgs?: unknown[] }) => Promise<void>;
  /** The refresh token was refused: the session is over. */
  sessionEnded: () => Promise<void>;
  fetch?: typeof fetch;
}

export function createClient(d: ClientDeps) {
  const f = d.fetch ?? ((...a: Parameters<typeof fetch>) => fetch(...a));
  let refreshing: Promise<boolean> | null = null;

  async function raw(method: string, path: string, body?: unknown, org?: string | null, bearer = true): Promise<Response> {
    const base = d.serverUrl();
    if (!base) throw new ApiError(0, "no_server", null);
    const t = d.tokens();
    return f(`${base}/api/v1${path}`, {
      method, credentials: "omit", cache: "no-store",
      headers: { ...(body !== undefined ? { "content-type": "application/json" } : {}), ...(bearer && t.accessToken ? { authorization: `Bearer ${t.accessToken}` } : {}), ...(org ? { "x-org-id": org } : {}) },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  }

  /** One refresh at a time: a second caller waits for the first instead of presenting an already-rotated token. */
  function refresh(): Promise<boolean> {
    refreshing ??= (async () => {
      const refreshToken = d.tokens().refreshToken;
      if (!refreshToken) return false;
      const res = await raw("POST", "/auth/refresh", { refreshToken }, null, false).catch(() => null);
      if (!res) return false; // offline: keep the session, the caller sees the error
      if (res.status === 401) { await d.sessionEnded(); return false; }
      if (!res.ok) return false; // server trouble: try again later
      const j = (await res.json()) as { accessToken: string; refreshToken?: string; orgs?: unknown[] };
      await d.saveTokens(j.refreshToken ? { accessToken: j.accessToken, refreshToken: j.refreshToken } : { accessToken: j.accessToken }, j);
      return true;
    })().finally(() => { refreshing = null; });
    return refreshing;
  }

  async function request<T>(method: string, path: string, body?: unknown, org?: string | null): Promise<T> {
    let res = await raw(method, path, body, org).catch(() => { throw new ApiError(0, "offline", null); });
    if (res.status === 401 && !path.startsWith("/auth/")) {
      if (await refresh()) res = await raw(method, path, body, org);
      // Still holding a refresh token means the server couldn't be reached, not that the session ended.
      else throw d.tokens().refreshToken ? new ApiError(0, "offline", null) : new ApiError(401, "session_expired", null);
    }
    if (res.status === 204) return undefined as T;
    const data = (await res.json().catch(() => null)) as { error?: string } | null;
    if (!res.ok) throw new ApiError(res.status, data?.error ?? "server_error", data);
    return data as T;
  }

  return {
    request, refresh,
    get: <T>(p: string, org?: string | null) => request<T>("GET", p, undefined, org),
    post: <T>(p: string, b: unknown = {}, org?: string | null) => request<T>("POST", p, b, org),
    put: <T>(p: string, b: unknown, org?: string | null) => request<T>("PUT", p, b, org),
    /** Revokes the session on the server; failures are ignored (signing out locally always works). */
    async logout() {
      const refreshToken = d.tokens().refreshToken;
      if (refreshToken) await raw("POST", "/auth/logout", { refreshToken }, null, false).catch(() => undefined);
    },
  };
}
export type Client = ReturnType<typeof createClient>;
