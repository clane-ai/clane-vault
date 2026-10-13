import type { VaultRecord } from "@/features/vault/types";
import { storageKey } from "@/lib/base";

/**
 * Have I Been Pwned "Pwned Passwords" range API (k-anonymity): only the first 5 hex characters of a password's SHA-1
 * leave the device; the answer lists every known suffix with that prefix (padded), and the match happens here.
 * https://haveibeenpwned.com/API/v3#PwnedPasswords
 */
export const HIBP_RANGE = "https://api.pwnedpasswords.com/range/";

export async function sha1Hex(text: string): Promise<string> {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-1", new TextEncoder().encode(text)));
  return [...d].map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
}

/** Parses a range response: suffix → count (padding rows have count 0). */
export function parseRange(body: string): Map<string, number> {
  const out = new Map<string, number>();
  for (const line of body.split(/\r?\n/)) {
    const [suffix, count] = line.trim().split(":");
    if (suffix && count) out.set(suffix.toUpperCase(), Number(count));
  }
  return out;
}

type Fetch = (url: string, init?: RequestInit) => Promise<Response>;
/** Ranges already fetched in this tab (an hour), so re-renders and re-syncs don't ask again. Prefixes only. */
const cache = new Map<string, { at: number; range: Map<string, number> }>();
export const clearBreachCache = () => cache.clear();

/** Record ids whose password appears in a known breach. One request per distinct 5-character prefix. */
export async function breachedRecords(records: VaultRecord[], fetcher: Fetch = (u, i) => fetch(u, i)): Promise<Set<string>> {
  const live = records.filter((r) => !r.deleted && r.body?.password);
  const byHash = new Map<string, string[]>();
  for (const r of live) {
    const h = await sha1Hex(r.body!.password!);
    byHash.set(h, [...(byHash.get(h) ?? []), r.id]);
  }
  const prefixes = new Set([...byHash.keys()].map((h) => h.slice(0, 5)));
  const ranges = new Map<string, Map<string, number>>();
  for (const p of prefixes) {
    const hit = cache.get(p);
    if (hit && Date.now() - hit.at < 3600e3) { ranges.set(p, hit.range); continue; }
    // No credentials or referrer go to the third party; padding hides how many suffixes matched.
    const url = `${HIBP_RANGE}${p}`, base: RequestInit = { credentials: "omit", referrerPolicy: "no-referrer" };
    // If the padding header's CORS preflight is refused, ask again without it (the prefix is all that is sent either way).
    const res = await fetcher(url, { ...base, headers: { "Add-Padding": "true" } }).catch(() => fetcher(url, base));
    if (!res.ok) throw new Error(`breach check failed (${res.status})`);
    const range = parseRange(await res.text());
    cache.set(p, { at: Date.now(), range });
    ranges.set(p, range);
  }
  const out = new Set<string>();
  for (const [h, ids] of byHash) if ((ranges.get(h.slice(0, 5))?.get(h.slice(5)) ?? 0) > 0) ids.forEach((id) => out.add(id));
  return out;
}

const OPT_KEY = (userId: string) => storageKey(`cv.hibp.${userId}`);
/** The per-user opt-in, remembered on this device. */
export function breachOptIn(userId: string | undefined): boolean {
  if (!userId) return false;
  try { return localStorage.getItem(OPT_KEY(userId)) === "1"; } catch { return false; }
}
export function setBreachOptIn(userId: string, on: boolean) {
  try { if (on) localStorage.setItem(OPT_KEY(userId), "1"); else localStorage.removeItem(OPT_KEY(userId)); } catch { /* private mode */ }
}
