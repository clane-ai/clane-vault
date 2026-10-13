/**
 * Builds sw.js from pwa/sw.js (pure, so vite.config.ts and the tests share it). The precache list is the app shell:
 * index.html, every emitted file under assets/, the manifest and the icons. Never anything under api/. Entries are
 * relative to the worker's scope, so the same build works at the root and under a base path (BASE_PATH).
 */
export const SHELL_EXTRAS = ["manifest.webmanifest", "brand/favicon.svg", "brand/favicon.ico", "brand/icon-192.png", "brand/apple-touch-icon.png"];

export function precacheList(bundleFiles: string[]): string[] {
  // Code, styles and images up front; of the fonts only the Latin woff2 files (others are cached the first time they load).
  const shell = (f: string) => /\.(js|css|svg|png|webp)$/.test(f) || (/\.woff2$/.test(f) && /-latin-/.test(f));
  const assets = bundleFiles.filter((f) => f.startsWith("assets/") && shell(f)).sort();
  return ["index.html", ...assets, ...SHELL_EXTRAS];
}

export function swSource(template: string, version: string, precache: string[]): string {
  return template.replace('const VERSION = "__VERSION__"', `const VERSION = ${JSON.stringify(version)}`).replace("const PRECACHE = __PRECACHE__", `const PRECACHE = ${JSON.stringify(precache)}`);
}
