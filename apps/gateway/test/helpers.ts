import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { loadKek } from "../src/kek.js";

export const tempDir = () => mkdtempSync(join(tmpdir(), "gw-"));
export function fileKek(dir = tempDir(), name = "kek") {
  const p = join(dir, name);
  writeFileSync(p, randomBytes(32));
  return loadKek(`file:${p}`);
}
