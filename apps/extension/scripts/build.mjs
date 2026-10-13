// Builds the extension: dist/chrome (Chrome + Edge), dist/firefox and a zip of each for the stores.
// `--e2e` builds dist/chrome-e2e only: like chrome, plus host access to localhost for the Playwright test.
import { build as vite } from "vite";
import { build as esbuild } from "esbuild";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { cpSync, mkdirSync, readFileSync, readdirSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import path from "node:path";
import { crc32, deflateRawSync } from "node:zlib";
import { resolveBrand } from "../../web/src/brand-core.ts";

const root = path.resolve(import.meta.dirname, "..");
const dist = path.join(root, "dist");
const stage = path.join(dist, ".stage");
const e2e = process.argv.includes("--e2e");
const { version } = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8"));
const brand = resolveBrand(process.env);

rmSync(stage, { recursive: true, force: true });
mkdirSync(stage, { recursive: true });

// Popup: React + Tailwind through Vite, relative asset paths, no inline scripts (MV3 CSP).
await vite({
  configFile: false, logLevel: "warn", root: path.join(root, "src/popup"), base: "./",
  plugins: [react(), tailwindcss()],
  resolve: { alias: { "@": path.resolve(root, "../web/src") } },
  build: { outDir: stage, emptyOutDir: false, target: "es2022", minify: false, modulePreload: { polyfill: false }, assetsDir: "assets" },
});
renameSync(path.join(stage, "index.html"), path.join(stage, "popup.html"));
cpSync(path.join(root, "src/offscreen/offscreen.html"), path.join(stage, "offscreen.html"));

// Background, content, fill and offscreen scripts: single classic files (content scripts can't be modules).
await esbuild({
  entryPoints: { background: "src/background/index.ts", content: "src/content/index.ts", fill: "src/content/fill.ts", offscreen: "src/offscreen/offscreen.ts" },
  absWorkingDir: root, outdir: stage, bundle: true, format: "iife", target: "es2022", minify: false, legalComments: "none", logLevel: "warning",
  define: { "process.env.NODE_ENV": '"production"' },
});
cpSync(path.join(root, "public/icons"), path.join(stage, "icons"), { recursive: true });

const icons = { 16: "icons/icon-16.png", 32: "icons/icon-32.png", 48: "icons/icon-48.png", 128: "icons/icon-128.png" };
function manifest(target) {
  const chrome = target !== "firefox";
  return {
    manifest_version: 3,
    name: brand.productName, short_name: brand.shortName, version,
    description: `${brand.productName}: fill and save passwords from your end-to-end encrypted team vault.`,
    icons,
    action: { default_popup: "popup.html", default_title: brand.productName, default_icon: { 16: icons[16], 32: icons[32] } },
    // activeTab + scripting: fill only the tab the user acted on. storage: session keys / local settings.
    // alarms + idle: auto-lock. clipboardWrite (+ offscreen on Chrome): clear copied secrets after 30 s.
    permissions: ["activeTab", "scripting", "storage", "alarms", "idle", "clipboardWrite", ...(chrome ? ["offscreen"] : [])],
    // Asked at run time: the chosen server, and every site only when the user switches on save offers.
    optional_host_permissions: ["https://*/*", "http://localhost/*", "http://127.0.0.1/*", "<all_urls>"],
    ...(target === "chrome-e2e" ? { host_permissions: ["http://127.0.0.1/*", "http://localhost/*"] } : {}),
    content_security_policy: { extension_pages: "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'" },
    background: chrome ? { service_worker: "background.js" } : { scripts: ["background.js"] },
    ...(chrome ? { minimum_chrome_version: "121" } : {
      browser_specific_settings: { gecko: { id: "vault-extension@clane.si", strict_min_version: "128.0", data_collection_permissions: { required: ["none"] } } },
    }),
  };
}

// Stored zip (deflate) without dependencies: local headers, central directory, end record.
function zip(dir, file) {
  const files = [];
  const walk = (d) => { for (const n of readdirSync(d).sort()) { const p = path.join(d, n); statSync(p).isDirectory() ? walk(p) : files.push(p); } };
  walk(dir);
  const chunks = [], central = [];
  let offset = 0;
  for (const p of files) {
    const name = Buffer.from(path.relative(dir, p).split(path.sep).join("/"));
    const data = readFileSync(p), packed = deflateRawSync(data, { level: 9 }), crc = crc32(data);
    const head = Buffer.alloc(30);
    head.writeUInt32LE(0x04034b50, 0); head.writeUInt16LE(20, 4); head.writeUInt16LE(0x0800, 6); head.writeUInt16LE(8, 8);
    head.writeUInt32LE(0, 10); head.writeUInt32LE(crc, 14); head.writeUInt32LE(packed.length, 18); head.writeUInt32LE(data.length, 22);
    head.writeUInt16LE(name.length, 26); head.writeUInt16LE(0, 28);
    const cen = Buffer.alloc(46);
    cen.writeUInt32LE(0x02014b50, 0); cen.writeUInt16LE(20, 4); cen.writeUInt16LE(20, 6); cen.writeUInt16LE(0x0800, 8); cen.writeUInt16LE(8, 10);
    cen.writeUInt32LE(0, 12); cen.writeUInt32LE(crc, 16); cen.writeUInt32LE(packed.length, 20); cen.writeUInt32LE(data.length, 24);
    cen.writeUInt16LE(name.length, 28); cen.writeUInt32LE(offset, 42);
    chunks.push(head, name, packed); central.push(cen, name);
    offset += head.length + name.length + packed.length;
  }
  const cd = Buffer.concat(central), end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(files.length, 8); end.writeUInt16LE(files.length, 10);
  end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(offset, 16);
  writeFileSync(file, Buffer.concat([...chunks, cd, end]));
}

const slug = brand.productName.toLowerCase().replace(/[^a-z0-9]+/g, "-");
for (const target of e2e ? ["chrome-e2e"] : ["chrome", "firefox"]) {
  const out = path.join(dist, target);
  rmSync(out, { recursive: true, force: true });
  cpSync(stage, out, { recursive: true });
  writeFileSync(path.join(out, "manifest.json"), JSON.stringify(manifest(target), null, 2));
  if (!e2e) zip(out, path.join(dist, `${slug}-${target}-${version}.zip`));
  console.log(`built ${path.relative(root, out)}`);
}
rmSync(stage, { recursive: true, force: true });
