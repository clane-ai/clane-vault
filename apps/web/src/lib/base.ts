/**
 * The path the app is served under: "" at the site root, or e.g. "/vault" (BASE_PATH on the server; docs in
 * deploy/client/README.md). The server writes it into index.html as <meta name="clane-base" content="/vault"> (not an
 * inline script: the CSP forbids those). The dev server and tests have no tag, which means the root.
 */
const VALID = /^(\/[A-Za-z0-9._~-]+)*$/;

export function readBasePath(doc: Document | undefined = typeof document !== "undefined" ? document : undefined): string {
  const v = doc?.querySelector('meta[name="clane-base"]')?.getAttribute("content")?.trim() ?? "";
  const b = v.replace(/\/+$/, "");
  return VALID.test(b) && !/\/\.\.?(\/|$)/.test(b) ? b : "";
}

let cached: string | null = null;
/** "" or "/vault" (read once). */
export function basePath(): string { return (cached ??= readBasePath()); }
/** Tests: forget the cached base so the next call reads the document again. */
export function resetBasePath(): void { cached = null; }

/** A same-origin path under the base: withBase("/showcase/a.webp") → "/vault/showcase/a.webp". */
export const withBase = (path: string): string => `${basePath()}${path.startsWith("/") ? path : `/${path}`}`;
/** The API: apiUrl("/auth/refresh") → "/vault/api/v1/auth/refresh". */
export const apiUrl = (path: string): string => withBase(`/api/v1${path}`);
/** An absolute link into the app, for copying or emailing: appUrl("/s/x") → "https://host/vault/s/x". */
export const appUrl = (path = "", origin: string = window.location.origin): string => `${origin}${basePath()}${path}`;
/**
 * A browser-storage key (localStorage, the IndexedDB name) for this instance: unchanged at the root, suffixed with the
 * base otherwise, so two instances on one origin (https://host/a and https://host/b) never share sessions or copies.
 */
export const storageKey = (key: string): string => (basePath() ? `${key}@${basePath()}` : key);
