import { defineConfig, loadEnv, type Plugin } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "node:path";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { resolveBrand, webManifest, type Brand } from "./src/brand-core.ts";
import { precacheList, swSource } from "./src/pwa/sw-build.ts";

const escapeHtml = (s: string) => s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]!);

/** Names index.html and the web manifest after the product (VITE_PRODUCT_NAME / VITE_PRODUCT_SHORT). */
function brandPlugin(brand: Brand): Plugin {
  const manifest = JSON.stringify(webManifest(brand), null, 2);
  return {
    name: "clane-brand",
    transformIndexHtml: (html) => html.replaceAll("%PRODUCT_NAME%", escapeHtml(brand.productName)),
    configureServer(server) {
      server.middlewares.use("/manifest.webmanifest", (_req, res) => { res.setHeader("content-type", "application/manifest+json"); res.end(manifest); });
    },
    generateBundle() { this.emitFile({ type: "asset", fileName: "manifest.webmanifest", source: manifest }); },
  };
}

/** Writes /sw.js (from pwa/sw.js) after the build, precaching the shell; its version changes with every asset hash. */
function pwaPlugin(): Plugin {
  return {
    name: "clane-pwa",
    apply: "build",
    writeBundle(options, bundle) {
      const files = precacheList(Object.keys(bundle));
      const version = createHash("sha256").update(files.join(",")).digest("hex").slice(0, 12);
      const template = readFileSync(path.resolve(import.meta.dirname, "pwa/sw.js"), "utf8");
      writeFileSync(path.join(options.dir ?? path.resolve(import.meta.dirname, "dist"), "sw.js"), swSource(template, version, files));
    },
  };
}

export default defineConfig(({ mode, command }) => ({
  // The build is path-neutral ("./"): the server serves it at the root or under BASE_PATH (e.g. /vault) and rewrites
  // index.html's references for that path at serve time (apps/api/src/plugins/web.ts). The dev server stays at "/".
  base: command === "build" ? "./" : "/",
  plugins: [react(), tailwindcss(), brandPlugin(resolveBrand({ ...loadEnv(mode, process.cwd(), "VITE_"), ...process.env })), pwaPlugin()],
  resolve: { alias: { "@": path.resolve(import.meta.dirname, "src") } },
  // Ports are overridable so a second checkout can run side by side: VITE_PORT (alias WEB_PORT) for the dev server,
  // VITE_API_PORT for the proxied API (or API_URL for a full origin). Defaults are the usual dev ports.
  server: {
    port: Number(process.env.VITE_PORT ?? process.env.WEB_PORT ?? 5173),
    strictPort: true,
    proxy: { "/api": process.env.API_URL ?? `http://localhost:${process.env.VITE_API_PORT ?? 3001}` },
  },
  build: { target: "es2022", sourcemap: false },
}));
