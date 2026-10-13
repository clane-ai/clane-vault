/**
 * Container health check (Dockerfile HEALTHCHECK, deploy/docker-compose.yml; no shell needed): GET
 * `${BASE_PATH}/api/v1/health` on the local port. Exits 0 when the server and its database answer, 1 otherwise.
 */
import { normaliseBasePath, resolveBasePath } from "../config.js";

const e = process.env;
let base = "";
try { base = e.PUBLIC_URL ? resolveBasePath(e.PUBLIC_URL, e.BASE_PATH === "" ? undefined : e.BASE_PATH).basePath : normaliseBasePath(e.BASE_PATH ?? ""); }
catch { base = ""; }
const port = Number(e.PORT) || 3001;
try {
  const res = await fetch(`http://127.0.0.1:${port}${base}/api/v1/health`, { signal: AbortSignal.timeout(4000) });
  process.exit(res.ok ? 0 : 1);
} catch {
  process.exit(1);
}
