import { readFileSync } from "node:fs";
import path from "node:path";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { precacheList, swSource } from "./sw-build";

const template = readFileSync(path.resolve(import.meta.dirname, "../../pwa/sw.js"), "utf8");
const ORIGIN = "https://vault.example.com";

/** Runs the service worker in a fake worker scope with an in-memory Cache Storage. */
function boot(online: { ok: boolean }, base = "") {
  const stores = new Map<string, Map<string, Response>>();
  const key = (r: Request | string) => { const u = new URL(typeof r === "string" ? r : r.url, ORIGIN); return u.pathname; };
  const open = async (name: string) => {
    if (!stores.has(name)) stores.set(name, new Map());
    const m = stores.get(name)!;
    return {
      addAll: async (urls: string[]) => { for (const u of urls) m.set(key(u), new Response(`cached ${key(u)}`, { headers: { "content-type": "text/html" } })); },
      put: async (r: Request | string, res: Response) => { m.set(key(r), res); },
      match: async (r: Request | string) => m.get(key(r))?.clone(),
    };
  };
  const listeners: Record<string, (e: unknown) => void> = {};
  const fetchMock = vi.fn(async (r: Request) => {
    if (!online.ok) throw new TypeError("Failed to fetch");
    const res = new Response(`network ${new URL(r.url).pathname}`, { headers: { "content-type": new URL(r.url).pathname.startsWith("/assets/") ? "text/javascript" : "text/html" } });
    Object.defineProperty(res, "type", { value: "basic" });
    return res;
  });
  const self = {
    location: new URL(`${ORIGIN}${base}/sw.js`), skipWaiting: vi.fn(), clients: { claim: vi.fn() },
    addEventListener: (t: string, cb: (e: unknown) => void) => { listeners[t] = cb; },
  };
  const caches = { open, keys: async () => [...stores.keys()], delete: async (k: string) => stores.delete(k) };
  const code = swSource(template, "v1", precacheList(["index.html", "assets/app-1.js", "assets/app-1.css"]));
  new Function("self", "caches", "fetch", "Response", code)(self, caches, fetchMock, Response);
  const fire = async (url: string, mode: RequestMode | "navigate" = "cors", method = "GET") => {
    let responded: Promise<Response> | null = null;
    const request = { url: new URL(url, ORIGIN).href, mode, method };
    listeners.fetch!({ request, respondWith: (p: Promise<Response>) => { responded = p; } });
    return responded ? await (responded as Promise<Response>) : null;
  };
  const install = async () => { let w: Promise<unknown> = Promise.resolve(); listeners.install!({ waitUntil: (p: Promise<unknown>) => { w = p; } }); await w; };
  return { fire, install, fetchMock, stores, listeners };
}

describe("service worker", () => {
  let online: { ok: boolean };
  beforeEach(() => { online = { ok: true }; });

  it("precaches the shell: index, built assets, manifest and icons", () => {
    expect(precacheList(["index.html", "assets/a.js", "assets/a.js.map", "assets/f-latin-400-normal-x.woff2", "assets/f-latin-400-normal-x.woff", "assets/f-cyrillic-400-normal-y.woff2", "sw.js", "showcase/x.webp"])).toEqual(
      ["index.html", "assets/a.js", "assets/f-latin-400-normal-x.woff2", "manifest.webmanifest", "brand/favicon.svg", "brand/favicon.ico", "brand/icon-192.png", "brand/apple-touch-icon.png"]);
  });

  it("never handles API requests, non-GET requests or other origins", async () => {
    const sw = boot(online);
    await sw.install();
    expect(await sw.fire("/api/v1/sync")).toBeNull();
    expect(await sw.fire("/api/v1/auth/prelogin", "cors", "POST")).toBeNull();
    expect(await sw.fire("/api/v1/sync", "navigate")).toBeNull();
    expect(await sw.fire("https://other.example.org/assets/x.js")).toBeNull();
    expect(await sw.fire("/assets/app-1.js", "cors", "POST")).toBeNull();
    expect(await sw.fire("/sw.js")).toBeNull();
    // Nothing from /api ever lands in the cache.
    expect([...sw.stores.values()].flatMap((m) => [...m.keys()]).some((k) => k.startsWith("/api"))).toBe(false);
  });

  it("never handles or caches attachment traffic: chunk uploads and downloads, the link chunk route (docs/attachments.md)", async () => {
    for (const base of ["", "/vault"]) {
      const sw = boot(online, base);
      await sw.install();
      sw.fetchMock.mockClear();
      const id = "6b0e9a4c-3c1f-4f7e-9a51-0d6c1b2a3f40", fid = "0f1e2d3c-4b5a-4687-9a8b-7c6d5e4f3a2b";
      for (const [url, mode, method] of [
        [`${base}/api/v1/records/${id}/attachments/${fid}/chunks/0`, "cors", "GET"],
        [`${base}/api/v1/records/${id}/attachments/${fid}/chunks/7`, "cors", "PUT"],
        [`${base}/api/v1/records/${id}/attachments`, "cors", "GET"],
        [`${base}/api/v1/public/links/${id}/attachments/${fid}/chunks/0`, "cors", "GET"],
        // Even a navigation to a chunk URL (someone pasting it) is left to the network, never the shell.
        [`${base}/api/v1/records/${id}/attachments/${fid}/chunks/0`, "navigate", "GET"],
      ] as const) expect(await sw.fire(url, mode, method)).toBeNull();
      expect(sw.fetchMock).not.toHaveBeenCalled();
      expect([...sw.stores.values()].flatMap((m) => [...m.keys()]).some((k) => k.includes("/attachments/"))).toBe(false);
    }
  });

  it("serves pages from the network and falls back to the cached shell offline", async () => {
    const sw = boot(online);
    await sw.install();
    expect(await (await sw.fire("/o/acme/vault", "navigate"))!.text()).toBe("network /o/acme/vault");
    online.ok = false;
    expect(await (await sw.fire("/p/vault/record/1", "navigate"))!.text()).toBe("network /o/acme/vault");
  });

  it("serves built assets cache-first", async () => {
    const sw = boot(online);
    await sw.install();
    sw.fetchMock.mockClear();
    expect(await (await sw.fire("/assets/app-1.js"))!.text()).toBe("cached /assets/app-1.js");
    expect(sw.fetchMock).not.toHaveBeenCalled();
    expect(await (await sw.fire("/assets/lazy-2.js"))!.text()).toBe("network /assets/lazy-2.js");
    online.ok = false;
    expect(await (await sw.fire("/assets/lazy-2.js"))!.text()).toBe("network /assets/lazy-2.js");
  });

  it("under a base path (/vault/): precaches below it, handles only its own paths, and falls back to its own shell", async () => {
    const sw = boot(online, "/vault");
    await sw.install();
    const cached = [...sw.stores.get("shell@/vault/-v1")!.keys()];
    expect(cached).toEqual(expect.arrayContaining(["/vault/index.html", "/vault/assets/app-1.js", "/vault/manifest.webmanifest", "/vault/brand/favicon.svg"]));
    expect(cached.every((k) => k.startsWith("/vault/"))).toBe(true);
    expect(await sw.fire("/vault/api/v1/sync")).toBeNull();
    expect(await sw.fire("/vault/sw.js")).toBeNull();
    expect(await sw.fire("/assets/app-1.js")).toBeNull();
    expect(await sw.fire("/other/p/vault", "navigate")).toBeNull();
    sw.fetchMock.mockClear();
    expect(await (await sw.fire("/vault/assets/app-1.js"))!.text()).toBe("cached /vault/assets/app-1.js");
    expect(sw.fetchMock).not.toHaveBeenCalled();
    expect(await (await sw.fire("/vault/o/acme/vault", "navigate"))!.text()).toBe("network /vault/o/acme/vault");
    online.ok = false;
    expect(await (await sw.fire("/vault/p/vault/record/1", "navigate"))!.text()).toBe("network /vault/o/acme/vault");
  });

  it("an instance under a path keeps other instances' caches on activate", async () => {
    const sw = boot(online, "/vault");
    await sw.install();
    for (const k of ["shell-root1", "shell@/vault/-old", "shell@/other/-x"]) sw.stores.set(k, new Map());
    let w: Promise<unknown> = Promise.resolve();
    sw.listeners.activate!({ waitUntil: (p: Promise<unknown>) => { w = p; } });
    await w;
    expect([...sw.stores.keys()].sort()).toEqual(["shell-root1", "shell@/other/-x", "shell@/vault/-v1"]);
  });

  it("drops old shell caches on activate", async () => {
    const sw = boot(online);
    await sw.install();
    sw.stores.set("shell-old", new Map());
    let w: Promise<unknown> = Promise.resolve();
    sw.listeners.activate!({ waitUntil: (p: Promise<unknown>) => { w = p; } });
    await w;
    expect([...sw.stores.keys()]).toEqual(["shell-v1"]);
  });
});
