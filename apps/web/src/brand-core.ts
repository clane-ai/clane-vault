/**
 * Product naming, resolved from build-time env. Pure (no import.meta) so vite.config.ts can use it for index.html and
 * the web manifest, and tests can feed it any env. `brand.ts` applies it to Vite's env for the app.
 */
export interface Brand {
  /** Full product name, e.g. "Clane Vault". */
  productName: string;
  /** Short name for tight spaces and the home-screen label, e.g. "Vault". */
  shortName: string;
  /** Who makes it; shown as a small "by …" credit. */
  vendor: string;
  /** Link for the vendor credit; empty means the credit is plain text. */
  vendorUrl: string;
  /** Public product page; empty means none. */
  productUrl: string;
}

export const DEFAULT_PRODUCT_NAME = "Clane Vault";
export const DEFAULT_SHORT_NAME = "Vault";
export const VENDOR = "Clane AI Labs";

type Env = Record<string, string | boolean | undefined>;
const str = (v: string | boolean | undefined) => (typeof v === "string" ? v.trim() : "");

export function resolveBrand(env: Env = {}): Brand {
  return {
    productName: str(env.VITE_PRODUCT_NAME) || DEFAULT_PRODUCT_NAME,
    shortName: str(env.VITE_PRODUCT_SHORT) || DEFAULT_SHORT_NAME,
    vendor: VENDOR,
    vendorUrl: str(env.VITE_VENDOR_URL),
    productUrl: str(env.VITE_PRODUCT_URL),
  };
}

/**
 * How the logo spells the name: a name that starts with "Clane" uses the CLANE pixel wordmark followed by the rest as
 * text ("Clane Vault" → wordmark + "Vault"); any other name is set as plain text.
 */
export function splitProductName(productName: string): { clane: boolean; rest: string } {
  const m = /^clane(?=\s|$)\s*(.*)$/i.exec(productName.trim());
  return m ? { clane: true, rest: m[1]! } : { clane: false, rest: productName.trim() };
}

/**
 * The web app manifest, named from the brand. Icons live in brand/. Every URL is relative to the manifest, so the same
 * build installs at the root and under a base path (BASE_PATH, e.g. /vault/).
 */
export function webManifest(b: Brand) {
  return {
    name: b.productName,
    short_name: b.shortName,
    description: `${b.productName}, the team password manager by ${b.vendor}.`,
    start_url: "./",
    scope: "./",
    display: "standalone",
    theme_color: "#0B0E14",
    background_color: "#0B0E14",
    icons: [
      { src: "brand/icon-192.png", sizes: "192x192", type: "image/png", purpose: "any" },
      { src: "brand/icon-512.png", sizes: "512x512", type: "image/png", purpose: "any" },
      { src: "brand/icon-maskable-512.png", sizes: "512x512", type: "image/png", purpose: "maskable" },
      { src: "brand/favicon.svg", sizes: "any", type: "image/svg+xml" },
    ],
  };
}
