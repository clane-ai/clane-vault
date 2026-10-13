import { apiUrl } from "@/lib/base";

export class ApiError extends Error {
  constructor(public status: number, public code: string, public body: unknown) { super(code); this.name = "ApiError"; }
}

let accessToken: string | null = null;
/** The active organisation: sent as X-Org-Id on every request (the server checks it against the caller's memberships). */
let orgId: string | null = null;
let sessionEnded: () => void = () => {};
let refreshing: Promise<boolean> | null = null;
let orgForbidden: () => void = () => {};
let ssoRequired: (orgId: string) => void = () => {};
let stepUpRequired: () => void = () => {};

/** `org`: undefined → the active org; a value (or null for none) pins the request to that org. */
async function raw(method: string, path: string, body?: unknown, org?: string | null): Promise<Response> {
  const o = org === undefined ? orgId : org;
  return fetch(apiUrl(path), {
    method, credentials: "same-origin",
    headers: { ...(body !== undefined ? { "content-type": "application/json" } : {}), ...(accessToken ? { authorization: `Bearer ${accessToken}` } : {}), ...(o ? { "x-org-id": o } : {}) },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
}

async function refresh(): Promise<boolean> {
  refreshing ??= (async () => {
    const res = await raw("POST", "/auth/refresh");
    if (!res.ok) return false;
    accessToken = ((await res.json()) as { accessToken: string }).accessToken;
    return true;
  })().finally(() => { refreshing = null; });
  return refreshing;
}

async function request<T>(method: string, path: string, body?: unknown, org?: string | null): Promise<T> {
  let res = await raw(method, path, body, org);
  if (res.status === 401 && !path.startsWith("/auth/")) {
    if (await refresh()) res = await raw(method, path, body, org);
    else { accessToken = null; sessionEnded(); throw new ApiError(401, "session_expired", null); }
  }
  if (res.status === 204) return undefined as T;
  const data = await res.json().catch(() => null);
  // The active org is no longer ours (removed, disabled, deleted): let the session pick another.
  if (res.status === 403 && (data as { error?: string } | null)?.error === "org_forbidden" && (org === undefined || org === orgId)) orgForbidden();
  // The org requires its single sign-on and this session didn't come from it: the app offers "Sign in with <org> SSO".
  // The session skipped the authenticator code (trusted IdP MFA): other orgs and the private vault need a TOTP step-up.
  if (res.status === 403 && (data as { error?: string } | null)?.error === "totp_step_up_required") stepUpRequired();
  if (res.status === 403 && (data as { error?: string } | null)?.error === "sso_required") { const o = (data as { orgId?: string }).orgId ?? (org === undefined ? orgId : org); if (o) ssoRequired(o); }
  if (!res.ok) throw new ApiError(res.status, (data as { error?: string } | null)?.error ?? "server_error", data);
  return data as T;
}

/** A GET whose answer is text (the event log's CSV export), with the same token refresh and org header. */
async function requestText(path: string, org?: string | null): Promise<string> {
  let res = await raw("GET", path, undefined, org);
  if (res.status === 401 && (await refresh())) res = await raw("GET", path, undefined, org);
  if (!res.ok) { const d = (await res.json().catch(() => null)) as { error?: string } | null; throw new ApiError(res.status, d?.error ?? "server_error", d); }
  return res.text();
}

/**
 * A GET whose answer is a file (org logos): fetched with the bearer token, since an <img> can't send it. Null on 404.
 */
async function requestBlob(path: string): Promise<Blob | null> {
  let res = await raw("GET", path, undefined, null);
  if (res.status === 401 && (await refresh())) res = await raw("GET", path, undefined, null);
  if (res.status === 404) return null;
  if (!res.ok) throw new ApiError(res.status, "server_error", null);
  return res.blob();
}

/** Uploads a file as the raw request body (logos: the server reads the type from the bytes). */
async function requestUpload<T>(method: "PUT", path: string, file: Blob, org?: string | null): Promise<T> {
  const bytes = await file.arrayBuffer();
  const send = () => {
    const o = org === undefined ? orgId : org;
    return fetch(apiUrl(path), { method, credentials: "same-origin", body: bytes,
      headers: { "content-type": file.type || "application/octet-stream", ...(accessToken ? { authorization: `Bearer ${accessToken}` } : {}), ...(o ? { "x-org-id": o } : {}) } });
  };
  let res = await send();
  if (res.status === 401 && (await refresh())) res = await send();
  const data = await res.json().catch(() => null);
  if (!res.ok) throw new ApiError(res.status, (data as { error?: string } | null)?.error ?? "server_error", data);
  return data as T;
}

/**
 * Raw bytes both ways (attachment chunks, docs/attachments.md): `application/octet-stream`, the same token refresh and
 * org header, abortable. The answer of a PUT is JSON; of a GET, the bytes.
 */
async function requestBytes(method: "GET" | "PUT", path: string, org: string | null | undefined, body?: Uint8Array, signal?: AbortSignal): Promise<Response> {
  const send = () => {
    const o = org === undefined ? orgId : org;
    return fetch(apiUrl(path), { method, credentials: "same-origin", signal, cache: "no-store", ...(body ? { body: body as BodyInit } : {}),
      headers: { ...(body ? { "content-type": "application/octet-stream" } : {}), ...(accessToken ? { authorization: `Bearer ${accessToken}` } : {}), ...(o ? { "x-org-id": o } : {}) } });
  };
  let res = await send();
  if (res.status === 401) {
    if (await refresh()) res = await send();
    else { accessToken = null; sessionEnded(); throw new ApiError(401, "session_expired", null); }
  }
  if (!res.ok) { const d = (await res.json().catch(() => null)) as { error?: string } | null; throw new ApiError(res.status, d?.error ?? "server_error", d); }
  return res;
}

/** Requests pinned to one org: an operation started in org A keeps talking to A even if the user switches mid-way. */
export function forOrg(org: string | null) {
  return {
    get: <T>(p: string) => request<T>("GET", p, undefined, org),
    post: <T>(p: string, b?: unknown) => request<T>("POST", p, b ?? {}, org),
    put: <T>(p: string, b: unknown) => request<T>("PUT", p, b, org),
    patch: <T>(p: string, b: unknown) => request<T>("PATCH", p, b, org),
    del: (p: string) => request<void>("DELETE", p, undefined, org),
    delReq: (p: string, b: unknown) => request<void>("DELETE", p, b, org),
    text: (p: string) => requestText(p, org),
    upload: <T>(p: string, file: Blob) => requestUpload<T>("PUT", p, file, org),
    /** PUT raw bytes; the JSON answer. */
    putBytes: async <T>(p: string, bytes: Uint8Array, signal?: AbortSignal) => (await (await requestBytes("PUT", p, org, bytes, signal)).json()) as T,
    /** GET raw bytes. */
    getBytes: async (p: string, signal?: AbortSignal) => new Uint8Array(await (await requestBytes("GET", p, org, undefined, signal)).arrayBuffer()),
  };
}
export type OrgApi = ReturnType<typeof forOrg>;

export const api = {
  /** Pins the requests to the org that's active right now. */
  pinned: (): OrgApi => forOrg(orgId),
  get: <T>(p: string) => request<T>("GET", p),
  post: <T>(p: string, b?: unknown) => request<T>("POST", p, b ?? {}),
  put: <T>(p: string, b: unknown) => request<T>("PUT", p, b),
  patch: <T>(p: string, b: unknown) => request<T>("PATCH", p, b),
  del: (p: string) => request<void>("DELETE", p),
  /** DELETE with a JSON body (confirmations). */
  delReq: (p: string, b: unknown) => request<void>("DELETE", p, b),
  /** A file (org logo) as a Blob, with the bearer token; null when there is none. */
  blob: (p: string) => requestBlob(p),
  /** Uploads a file as the request body. */
  upload: <T>(p: string, file: Blob) => requestUpload<T>("PUT", p, file),
  setAccessToken(t: string | null) { accessToken = t; },
  setOrg(id: string | null) { orgId = id; },
  org: () => orgId,
  onSessionEnded(cb: () => void) { sessionEnded = cb; },
  onOrgForbidden(cb: () => void) { orgForbidden = cb; },
  onSsoRequired(cb: (orgId: string) => void) { ssoRequired = cb; },
  onStepUpRequired(cb: () => void) { stepUpRequired = cb; },
};
