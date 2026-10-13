import type { FastifyInstance, FastifyReply } from "fastify";
import fastifyStatic from "@fastify/static";
import { readFileSync } from "node:fs";
import { join } from "node:path";

// Same policy as apps/web/index.html (meta tag), plus frame-ancestors, which only works as a header.
export const WEB_CSP = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; font-src 'self'; connect-src 'self' https://api.pwnedpasswords.com; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; worker-src 'self'; manifest-src 'self'";

const pathOf = (url: string) => url.split("?")[0]!;
const escapeAttr = (s: string) => s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]!);

/**
 * index.html for a base path ("" or "/vault"). The build is path-neutral (Vite `base: "./"`): its `./assets/…`,
 * `./brand/…` and `./manifest.webmanifest` references become `${base}/…` (absolute, so deep links like
 * /vault/p/vault/record/1 still load them; no <base> element, which `base-uri 'none'` forbids), and the app reads the
 * base from <meta name="clane-base"> (an inline script would break the CSP).
 */
export function renderIndex(html: string, base: string): string {
  const meta = `<meta name="clane-base" content="${escapeAttr(base)}" />`;
  const out = html
    .replace(/(\s(?:src|href)=")\.?\/(?!\/)/g, `$1${base}/`)
    .replace(/<meta name="clane-base"[^>]*>\s*/g, "");
  const charset = /<meta charset[^>]*>/i;
  if (charset.test(out)) return out.replace(charset, (m) => `${m}\n    ${meta}`);
  if (/<head[^>]*>/i.test(out)) return out.replace(/<head[^>]*>/i, (h) => `${h}\n    ${meta}`);
  const doctype = /^\s*<!doctype[^>]*>/i;
  return doctype.test(out) ? out.replace(doctype, (d) => `${d}${meta}`) : `${meta}${out}`;
}

/**
 * Serves the built SPA from `root` under `base` ("" = the site root, else e.g. "/vault"), with history fallback to
 * index.html for everything under the base outside its /api. Nothing is served outside the base path.
 */
export async function registerWeb(app: FastifyInstance, root: string, base = ""): Promise<void> {
  const indexHtml = renderIndex(readFileSync(join(root, "index.html"), "utf8"), base);
  // Path relative to the base ("/p/vault"), or null outside it.
  const rel = (url: string): string | null => { const p = pathOf(url); return base === "" ? p : p.startsWith(`${base}/`) ? p.slice(base.length) : null; };
  const isApi = (url: string) => { const r = rel(url); return r !== null && (r === "/api" || r.startsWith("/api/")); };
  const sendIndex = (reply: FastifyReply) => reply.type("text/html; charset=utf-8").send(indexHtml);

  // index.html is never sent from disk: always with the base filled in.
  await app.register(fastifyStatic, { root, prefix: `${base}/`, index: false, wildcard: true, cacheControl: false, etag: true, allowedPath: (p) => p !== "/index.html" });
  app.get(`${base}/`, (_req, reply) => sendIndex(reply));
  app.get(`${base}/index.html`, (_req, reply) => sendIndex(reply));
  // https://host/vault -> https://host/vault/ (relative URLs and the service worker scope need the slash).
  if (base) app.get(base, (req, reply) => { const q = req.url.indexOf("?"); return reply.redirect(`${base}/${q >= 0 ? req.url.slice(q) : ""}`, 301); });

  app.setNotFoundHandler((req, reply) => {
    const r = rel(req.url);
    const spaRoute = (req.method === "GET" || req.method === "HEAD") && r !== null && !isApi(req.url) && !/\.[A-Za-z0-9]+$/.test(r);
    if (spaRoute) return sendIndex(reply);
    return reply.code(404).send({ error: "not_found" });
  });
  app.addHook("onSend", async (req, reply) => {
    if (isApi(req.url)) return; // API responses keep their no-store headers
    const r = rel(req.url);
    reply.header("cache-control", r?.startsWith("/assets/") && reply.statusCode === 200 ? "public, max-age=31536000, immutable" : r === "/sw.js" ? "no-cache, max-age=0" : "no-cache");
    // The service worker (installable PWA, docs/install-app.md) is always revalidated so updates reach clients quickly.
    if (r === "/sw.js") reply.header("service-worker-allowed", `${base}/`);
    if (r?.endsWith(".webmanifest") && reply.statusCode === 200) reply.header("content-type", "application/manifest+json; charset=utf-8");
    reply.header("content-security-policy", WEB_CSP);
    reply.header("x-frame-options", "DENY");
    reply.header("permissions-policy", "camera=(), microphone=(), geolocation=()");
    if (req.protocol === "https") reply.header("strict-transport-security", "max-age=31536000");
  });
}
