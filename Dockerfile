# Clane Vault: API + built web app in one image. Postgres is external (DATABASE_URL).
# Build context: repository root.
#
# The runtime stage is distroless Node.js 22 on Debian 13: no shell, no package manager, no npm. It holds the built
# app, the API's production dependencies (with the Prisma CLI and engines, for `migrate deploy` at start) and
# pg_dump / pg_restore / psql 17 with the shared libraries they need (in-app backups and the restore CLI).
# Bump the digests below to pick up base image security fixes.

FROM node:22.23.3-trixie-slim@sha256:154ba2f4d6fec323d28e4f4bb86bba4677f1223391a1979cf521304e03a98dfa AS base
RUN apt-get update && apt-get install -y --no-install-recommends openssl python3 make g++ ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /repo
COPY package.json package-lock.json tsconfig.base.json ./
COPY packages/crypto/package.json packages/crypto/
COPY apps/api/package.json apps/api/
COPY apps/web/package.json apps/web/
# The browser extension is a workspace too: npm ci needs its manifest to match the lockfile (it isn't built here).
COPY apps/extension/package.json apps/extension/
COPY e2e/package.json e2e/
COPY apps/api/prisma apps/api/prisma

# Everything (dev dependencies included) to build the web app and the API.
FROM base AS build
RUN npm ci
COPY packages/crypto packages/crypto
COPY apps/api apps/api
COPY apps/web apps/web
# Product naming is baked into the web build (see apps/web/src/brand.ts); empty means the defaults ("Clane Vault" / "Vault").
ARG VITE_PRODUCT_NAME="" VITE_PRODUCT_SHORT="" VITE_PRODUCT_URL="" VITE_VENDOR_URL=""
RUN npm run build -w @clane-vault/web \
 && npx -w @clane-vault/api prisma generate \
 && npm run build -w @clane-vault/api

# The API's production dependencies only. Install scripts run: argon2's native binding, the Prisma engines and the
# generated Prisma client (binaryTargets in schema.prisma include debian-openssl-3.0.x).
FROM base AS deps
RUN npm ci --omit=dev --workspace @clane-vault/api \
 && mkdir -p apps/api/node_modules \
 && test -f node_modules/.prisma/client/libquery_engine-debian-openssl-3.0.x.so.node \
 && test -x node_modules/@prisma/engines/schema-engine-debian-openssl-3.0.x \
 && rm -rf /root/.npm
# In a workspace repo, npm ci --omit=dev still installs the other workspaces' dependencies (the web app's build tools)
# and optional peers such as typescript. Keep only what the API's dependencies reach (dependencies, installed
# optional dependencies, required peers) and remove the rest.
RUN node <<'EOF'
const fs = require("node:fs"), path = require("node:path");
const root = "/repo", keep = new Set();
const find = (name, from) => {
  for (let d = from; ; d = path.dirname(d)) {
    const c = path.join(d, "node_modules", name);
    if (fs.existsSync(path.join(c, "package.json"))) return fs.realpathSync(c);
    if (d === root || d === "/") return null;
  }
};
const visit = (dir) => {
  if (keep.has(dir)) return;
  keep.add(dir);
  const p = JSON.parse(fs.readFileSync(path.join(dir, "package.json"), "utf8"));
  const optPeer = (n) => p.peerDependenciesMeta?.[n]?.optional;
  const names = [...Object.keys(p.dependencies ?? {}), ...Object.keys(p.optionalDependencies ?? {}), ...Object.keys(p.peerDependencies ?? {}).filter((n) => !optPeer(n))];
  for (const n of names) {
    const d = find(n, dir);
    if (d) visit(d);
    else if (!p.optionalDependencies?.[n]) throw new Error(`${p.name} needs ${n}, which isn't installed`);
  }
};
visit(path.join(root, "apps/api"));
let removed = 0;
const sweep = (nm) => {
  if (!fs.existsSync(nm)) return;
  for (const e of fs.readdirSync(nm)) {
    const full = path.join(nm, e);
    if (e === ".prisma" || e === ".package-lock.json") continue;
    if (e === ".bin" || e === ".cache") { fs.rmSync(full, { recursive: true, force: true }); continue; }
    const dirs = e.startsWith("@") ? fs.readdirSync(full).map((s) => path.join(full, s)) : [full];
    for (const d of dirs) {
      let real = null;
      try { real = fs.realpathSync(d); } catch {}
      if (real && keep.has(real)) { sweep(path.join(d, "node_modules")); continue; }
      fs.rmSync(d, { recursive: true, force: true });
      removed++;
    }
    if (e.startsWith("@") && fs.readdirSync(full).length === 0) fs.rmdirSync(full);
  }
};
sweep(path.join(root, "node_modules"));
sweep(path.join(root, "apps/api/node_modules"));
console.log(`kept ${keep.size - 1} packages, removed ${removed}`);
EOF

FROM gcr.io/distroless/nodejs22-debian13:nonroot@sha256:ec2313763dd43931543bd03830466e0c409ce73a487e8d46f10db72d3b816c1c AS runtime-base

# pg_dump / pg_restore / psql 17 from the PGDG repo (pg_dump must be at least as new as the server: 17 dumps 9.2
# through 17), copied with the shared libraries the distroless image lacks. Each package they come from gets its
# dpkg record in /var/lib/dpkg/status.d (the distroless layout), so image scanners see them.
FROM node:22.23.3-trixie-slim@sha256:154ba2f4d6fec323d28e4f4bb86bba4677f1223391a1979cf521304e03a98dfa AS pgclient
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
 && install -d /usr/share/postgresql-common/pgdg \
 && curl -fsSL -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc https://www.postgresql.org/media/keys/ACCC4CF8.asc \
 && echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt trixie-pgdg main" > /etc/apt/sources.list.d/pgdg.list \
 && apt-get update && apt-get install -y --no-install-recommends postgresql-client-17 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=runtime-base /var/lib/dpkg/status.d /tmp/distroless/status.d
COPY --from=runtime-base /etc/passwd /etc/group /tmp/distroless/
RUN set -eu; \
    bin=/usr/lib/postgresql/17/bin; out=/out; lib=/out/usr/lib/x86_64-linux-gnu; \
    mkdir -p "$out/usr/local/bin" "$lib" "$out/var/lib/dpkg/status.d" "$out/etc" /home-node; \
    for t in pg_dump pg_restore psql; do cp "$bin/$t" "$out/usr/local/bin/"; done; \
    ln -s /nodejs/bin/node "$out/usr/local/bin/node"; \
    have=" $(ls /tmp/distroless/status.d | grep -v '\.md5sums$' | tr '\n' ' ') "; \
    pkgs=""; \
    for so in $(ldd "$bin/pg_dump" "$bin/pg_restore" "$bin/psql" | awk '$2 == "=>" && $3 ~ /^\// { print $3 }' | sort -u); do \
      real=$(readlink -f "$so"); \
      pkg=$(dpkg -S "$real" | head -n1 | cut -d: -f1); \
      [ -n "$pkg" ] || { echo "no package owns $real" >&2; exit 1; }; \
      case "$have" in *" $pkg "*) continue ;; esac; \
      cp "$real" "$lib/$(basename "$so")"; \
      pkgs="$pkgs $pkg"; \
    done; \
    for p in $(echo $pkgs | tr ' ' '\n' | sort -u); do dpkg-query -s "$p" > "$out/var/lib/dpkg/status.d/$p"; done; \
    echo "bundled packages:" $(ls "$out/var/lib/dpkg/status.d"); \
    # The runtime user stays uid 1000 ("node"), as in earlier images, so mounted backup folders keep working.
    cat /tmp/distroless/passwd > "$out/etc/passwd"; echo 'node:x:1000:1000:node:/home/node:/sbin/nologin' >> "$out/etc/passwd"; \
    cat /tmp/distroless/group > "$out/etc/group"; echo 'node:x:1000:' >> "$out/etc/group"

FROM runtime-base
COPY --from=pgclient /out/ /
COPY --from=pgclient --chown=1000:1000 /home-node /home/node
LABEL org.opencontainers.image.title="Clane Vault" \
      org.opencontainers.image.description="Zero-knowledge team password manager (API + web app). Postgres is external." \
      org.opencontainers.image.vendor="Clane AI Labs" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.source="https://github.com/clane-ai/clane-vault"
# The engine paths are explicit: Prisma's platform detection runs `uname` and `ldconfig` through a shell, which this
# image doesn't have.
ENV NODE_ENV=production PORT=3001 \
    PRISMA_QUERY_ENGINE_LIBRARY=/repo/node_modules/.prisma/client/libquery_engine-debian-openssl-3.0.x.so.node \
    PRISMA_SCHEMA_ENGINE_BINARY=/repo/node_modules/@prisma/engines/schema-engine-debian-openssl-3.0.x
WORKDIR /repo
# App files are owned by root and read-only for the runtime user.
COPY --from=deps /repo/node_modules node_modules
COPY --from=deps /repo/apps/api/node_modules apps/api/node_modules
COPY --from=build /repo/package.json ./
COPY --from=build /repo/apps/api/package.json apps/api/package.json
COPY --from=build /repo/apps/api/prisma apps/api/prisma
COPY --from=build /repo/apps/api/dist apps/api/dist
COPY --from=build /repo/apps/web/dist apps/web/dist
WORKDIR /repo/apps/api
USER node
EXPOSE 3001
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 CMD ["node", "dist/src/scripts/healthcheck.js"]
# start.js runs `prisma migrate deploy`, stops if it fails, then starts the server (no shell needed).
ENTRYPOINT []
CMD ["node", "dist/src/scripts/start.js"]
