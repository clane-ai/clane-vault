import { getDomain, parse } from "tldts";

export const DEFAULT_SERVER = "https://vault.clane.si";

/** A URL from an item ("example.com/login", "https://a.example.com") or a page; null when it has no usable host. */
export function parseUrl(raw: string | undefined | null): URL | null {
  const s = (raw ?? "").trim();
  if (!s) return null;
  try {
    const u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(s) ? s : `https://${s}`);
    return (u.protocol === "https:" || u.protocol === "http:") && u.hostname ? u : null;
  } catch { return null; }
}

/**
 * A page (tab or frame) URL: only an absolute http(s) URL counts. Unlike item URLs nothing is guessed, so about:,
 * data:, blob:, file: and other pages never look like a web origin.
 */
export function parsePageUrl(raw: string | undefined | null): URL | null {
  const s = (raw ?? "").trim();
  if (!/^https?:\/\//i.test(s)) return null;
  try {
    const u = new URL(s);
    return (u.protocol === "https:" || u.protocol === "http:") && u.hostname ? u : null;
  } catch { return null; }
}

/**
 * The registrable domain (eTLD+1, public suffix list via tldts): "login.example.co.uk" → "example.co.uk". IP addresses
 * and single-label hosts (localhost) are their own site. Private suffixes (github.io, …) count as public suffixes so
 * two different github.io sites never match each other.
 */
export function siteOf(host: string): string {
  const h = host.toLowerCase().replace(/\.$/, "");
  const p = parse(h, { allowPrivateDomains: true });
  if (p.isIp || !h.includes(".")) return h;
  return getDomain(h, { allowPrivateDomains: true }) ?? h;
}

export type Match = "exact" | "site" | "none";
/** How an item's URL relates to a page: same host, same registrable domain, or not at all. */
export function matchUrl(itemUrl: string | undefined, pageUrl: string | undefined): Match {
  const a = parseUrl(itemUrl), b = parsePageUrl(pageUrl);
  if (!a || !b) return "none";
  if (a.hostname === b.hostname) return "exact";
  return siteOf(a.hostname) === siteOf(b.hostname) ? "site" : "none";
}

/** Server URLs the extension accepts: https anywhere, plain http only for this machine (development). */
export function normaliseServerUrl(raw: string): string | null {
  const s = raw.trim().replace(/\/+$/, "");
  let u: URL;
  try { u = new URL(/^https?:\/\//i.test(s) ? s : `https://${s}`); } catch { return null; }
  if (u.username || u.password || u.search || u.hash) return null;
  const local = u.hostname === "localhost" || u.hostname === "127.0.0.1" || u.hostname === "[::1]";
  if (u.protocol !== "https:" && !(u.protocol === "http:" && local)) return null;
  return `${u.origin}${u.pathname.replace(/\/+$/, "")}`;
}

/** The host-permission pattern for a server (ports are not part of match patterns). */
export const originPattern = (serverUrl: string) => `${new URL(serverUrl).protocol}//${new URL(serverUrl).hostname}/*`;
