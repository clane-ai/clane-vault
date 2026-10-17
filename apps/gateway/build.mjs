import { writeFileSync } from "node:fs";
import { build } from "esbuild";

await build({
  entryPoints: ["src/server.ts", "src/cli.ts"],
  outdir: "dist",
  bundle: true,
  platform: "node",
  format: "esm",
  splitting: true,
  target: "node22",
  // Bundled CommonJS dependencies call require() for node built-ins; ESM output has none.
  banner: { js: "import { createRequire as __cr } from 'node:module'; const require = __cr(import.meta.url);" },
});
// dist/ runs on its own in the image, without the workspace package.json.
writeFileSync("dist/package.json", JSON.stringify({ type: "module" }) + "\n");
