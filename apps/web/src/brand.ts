import { useSyncExternalStore } from "react";
import { resolveBrand, splitProductName, type Brand } from "./brand-core.ts";
import { apiUrl, storageKey } from "@/lib/base";

export type { Brand } from "./brand-core.ts";
export { resolveBrand, splitProductName } from "./brand-core.ts";

/**
 * The product's names. Build-time defaults come from env: VITE_PRODUCT_NAME (default "Clane Vault"), VITE_PRODUCT_SHORT
 * (default "Vault"), VITE_PRODUCT_URL and VITE_VENDOR_URL (default none). At boot the app asks the server for the names
 * an instance admin set (GET /api/v1/brand, docs/branding.md) and uses those instead; if that fails, the build's stay.
 *
 * The exports are live bindings: code that reads `productName` after `applyBrand` sees the new value. Components that
 * must re-render when it changes later (an admin renaming the product) read it through `useBrand()`.
 */
export const buildBrand: Readonly<Brand> = resolveBrand(import.meta.env);

/** `demo`: the server is a public demo (docs/demo.md): sign-in offers "Try the demo", sandboxes last `ttlMinutes`. */
export interface ServerBrand { productName: string | null; shortName: string | null; logoVersion: string | null; demo?: DemoInfo | null }
export interface DemoInfo { ttlMinutes: number }

export let brand: Brand = { ...buildBrand };
export let productName = brand.productName;
export let shortName = brand.shortName;
export const { vendor, vendorUrl, productUrl } = buildBrand;
export let nameParts = splitProductName(productName);
/** The instance logo (public, shown on the sign-in page), or null for the built-in mark. */
export let instanceLogoUrl: string | null = null;

/** Whether the server is a public demo (null: no, or not known yet). Never cached: only the server's answer counts. */
export let demo: DemoInfo | null = null;

export interface BrandSnapshot { productName: string; shortName: string; nameParts: { clane: boolean; rest: string }; instanceLogoUrl: string | null; custom: boolean; demo: DemoInfo | null }
let snapshot: BrandSnapshot = { productName, shortName, nameParts, instanceLogoUrl, custom: false, demo };
const listeners = new Set<() => void>();

const clean = (v: unknown, max = 40): string | null => {
  if (typeof v !== "string") return null;
  const s = v.replace(/[\p{Cc}\p{Cf}]+/gu, " ").replace(/\s+/g, " ").trim();
  return s && s.length <= max && !/[<>]/.test(s) ? s : null;
};

/** Applies the server's branding (null fields: the build's). Updates the live exports, the page title and subscribers. */
export function applyBrand(b: Partial<ServerBrand> | null) {
  const name = clean(b?.productName), short = clean(b?.shortName);
  const version = typeof b?.logoVersion === "string" && /^[0-9a-f]{1,64}$/.test(b.logoVersion) ? b.logoVersion : null;
  brand = { ...buildBrand, productName: name ?? buildBrand.productName, shortName: short ?? buildBrand.shortName };
  productName = brand.productName;
  shortName = brand.shortName;
  nameParts = splitProductName(productName);
  instanceLogoUrl = version ? apiUrl(`/brand/logo?v=${version}`) : null;
  const ttl = b?.demo && typeof b.demo === "object" ? Number(b.demo.ttlMinutes) : NaN;
  demo = Number.isFinite(ttl) && ttl > 0 ? { ttlMinutes: ttl } : null;
  snapshot = { productName, shortName, nameParts, instanceLogoUrl, custom: !!(name || short), demo };
  if (typeof document !== "undefined") document.title = productName;
  for (const l of listeners) l();
}

/** Loads the server's branding; never throws (the build's names stay when the server can't be asked). */
export async function loadBrand(timeoutMs = 2500): Promise<void> {
  // The last names seen, for offline starts (the installed app); replaced by the server's answer when there is one.
  try { const c = localStorage.getItem(CACHE_KEY); if (c) applyBrand(JSON.parse(c) as ServerBrand); } catch { /* no storage */ }
  try {
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), timeoutMs);
    const res = await fetch(apiUrl("/brand"), { credentials: "same-origin", signal: ctl.signal }).finally(() => clearTimeout(t));
    if (!res.ok) return;
    const b = (await res.json()) as ServerBrand;
    applyBrand(b);
    try { localStorage.setItem(CACHE_KEY, JSON.stringify({ productName: b.productName ?? null, shortName: b.shortName ?? null, logoVersion: null })); } catch { /* no storage */ }
  } catch { /* offline or an older server: keep the build's (or the cached) names */ }
}
const CACHE_KEY = storageKey("cv-brand");

const subscribe = (l: () => void) => { listeners.add(l); return () => { listeners.delete(l); }; };
/** The current names, re-rendering when an instance admin changes them. */
export function useBrand(): BrandSnapshot {
  return useSyncExternalStore(subscribe, () => snapshot, () => snapshot);
}
