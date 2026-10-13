import { afterEach, describe, expect, it, vi } from "vitest";
import { DEFAULT_PRODUCT_NAME, resolveBrand, splitProductName, webManifest } from "./brand-core";

describe("brand config", () => {
  afterEach(() => { vi.unstubAllEnvs(); vi.resetModules(); });

  it("defaults to Clane Vault by Clane AI Labs", () => {
    expect(resolveBrand({})).toEqual({ productName: "Clane Vault", shortName: "Vault", vendor: "Clane AI Labs", vendorUrl: "", productUrl: "" });
    expect(resolveBrand({ VITE_PRODUCT_NAME: "  ", VITE_PRODUCT_SHORT: "" }).productName).toBe(DEFAULT_PRODUCT_NAME);
  });

  it("takes the names and URLs from env; the vendor stays Clane AI Labs", () => {
    expect(resolveBrand({ VITE_PRODUCT_NAME: " Acme Keys ", VITE_PRODUCT_SHORT: "Keys", VITE_PRODUCT_URL: "https://keys.acme.test", VITE_VENDOR_URL: "https://clane.test" }))
      .toEqual({ productName: "Acme Keys", shortName: "Keys", vendor: "Clane AI Labs", vendorUrl: "https://clane.test", productUrl: "https://keys.acme.test" });
  });

  it("the app module reads Vite env (default and override)", async () => {
    expect((await import("./brand")).brand.productName).toBe("Clane Vault");
    vi.resetModules();
    vi.stubEnv("VITE_PRODUCT_NAME", "Acme Keys");
    vi.stubEnv("VITE_PRODUCT_SHORT", "Keys");
    const b = await import("./brand");
    expect(b.productName).toBe("Acme Keys");
    expect(b.shortName).toBe("Keys");
    expect(b.nameParts).toEqual({ clane: false, rest: "Acme Keys" });
  });

  it("uses the CLANE wordmark only for names that start with the word Clane", () => {
    expect(splitProductName("Clane Vault")).toEqual({ clane: true, rest: "Vault" });
    expect(splitProductName("Clane")).toEqual({ clane: true, rest: "" });
    expect(splitProductName("CLANE Keeper")).toEqual({ clane: true, rest: "Keeper" });
    expect(splitProductName("Claneous Vault")).toEqual({ clane: false, rest: "Claneous Vault" });
    expect(splitProductName("Acme Keys")).toEqual({ clane: false, rest: "Acme Keys" });
  });

  it("names the web manifest after the product", () => {
    const m = webManifest(resolveBrand({ VITE_PRODUCT_NAME: "Acme Keys", VITE_PRODUCT_SHORT: "Keys" }));
    expect(m).toMatchObject({ name: "Acme Keys", short_name: "Keys", display: "standalone" });
    expect(m.icons.map((i) => i.src)).toContain("brand/icon-maskable-512.png");
    // Relative to the manifest, so the same build installs under a base path (BASE_PATH).
    expect(m).toMatchObject({ start_url: "./", scope: "./" });
  });
});
