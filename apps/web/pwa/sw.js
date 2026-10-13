/* Service worker for the installable app (docs/install-app.md). Built by the "clane-pwa" plugin in vite.config.ts,
 * which fills in __VERSION__ and __PRECACHE__. It caches the app shell and static files only: API requests are never
 * intercepted, so nothing the server returns about the vault is ever stored by the service worker. */
const VERSION = "__VERSION__";
const PRECACHE = __PRECACHE__;
// The app may live under a path (BASE_PATH, e.g. https://host/vault/): this worker is served at <base>/sw.js with scope
// <base>/, so every URL here is relative to where it was loaded from. PRECACHE entries are relative ("assets/x.js").
const BASE = new URL("./", self.location.href);
const INDEX = new URL("index.html", BASE).href;
// Caches are per origin: an instance under a path names its own, so two instances on one origin never drop each other's.
const PREFIX = BASE.pathname === "/" ? "shell-" : `shell@${BASE.pathname}-`;
const CACHE = `${PREFIX}${VERSION}`;
/** The path below the base ("/assets/x.js"), or null for anything outside it. */
const below = (p) => (p.startsWith(BASE.pathname) ? p.slice(BASE.pathname.length - 1) : null);

/** "skip" (not handled: the browser goes to the network), "shell" (network first, cached index.html offline), "static". */
function strategyFor(url, mode, method) {
  if (method !== "GET" || url.origin !== self.location.origin) return "skip";
  const p = below(url.pathname);
  if (p === null) return "skip";
  if (p === "/api" || p.startsWith("/api/") || p === "/sw.js") return "skip";
  if (mode === "navigate") return "shell";
  if (p.startsWith("/assets/") || p.startsWith("/brand/") || p === "/manifest.webmanifest") return "static";
  return "skip";
}

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE).then((c) => c.addAll(PRECACHE.map((u) => new URL(u, BASE).href))).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (event) => {
  event.waitUntil(caches.keys()
    .then((keys) => Promise.all(keys.filter((k) => k.startsWith(PREFIX) && k !== CACHE).map((k) => caches.delete(k))))
    .then(() => self.clients.claim()));
});

async function shell(request) {
  const cache = await caches.open(CACHE);
  try {
    const res = await fetch(request);
    if (res.ok && res.type === "basic" && (res.headers.get("content-type") ?? "").includes("text/html")) await cache.put(INDEX, res.clone());
    return res;
  } catch {
    return (await cache.match(INDEX)) ?? Response.error();
  }
}

async function staticFile(request) {
  const cache = await caches.open(CACHE);
  const hit = await cache.match(request, { ignoreSearch: true });
  if (hit) return hit;
  const res = await fetch(request);
  if (res.ok && res.type === "basic") await cache.put(request, res.clone());
  return res;
}

self.addEventListener("fetch", (event) => {
  const s = strategyFor(new URL(event.request.url), event.request.mode, event.request.method);
  if (s === "shell") event.respondWith(shell(event.request));
  else if (s === "static") event.respondWith(staticFile(event.request));
});
