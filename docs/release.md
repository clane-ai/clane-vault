# Releasing Clane Vault

Images are published to `ghcr.io/clane-ai/clane-vault` (public) with the tags `X.Y.Z`, `X.Y`, `latest` and
`sha-<commit>`. They are built from the tagged commit, so uncommitted work never ends up in an image.

## Build, check and push a version

1. Move `## Unreleased` in `CHANGELOG.md` to `## X.Y.Z — <date>` with an **Upgrading** line, and bump the default
   `CLANE_VAULT_VERSION` in `deploy/client/.env.example` and `deploy/client/docker-compose.yml`.
2. Run the checks: `npm run typecheck` and `npm test` (the API tests need Docker).
3. Tag and build from the tag:

       git tag -a vX.Y.Z -m "Clane Vault X.Y.Z"
       git archive --format=tar vX.Y.Z | docker build -t ghcr.io/clane-ai/clane-vault:X.Y.Z -

4. Smoke-test the image against a throwaway Postgres, at the root and with `BASE_PATH=/vault`: health answers
   `{"ok":true,"db":true}`, the web app loads, Docker reports the container healthy, `bootstrap.js` prints an invite
   link, and a wrong `SERVER_SECRET` stops it with `server_secret_mismatch`.
5. Scan it (below), then push the tag and the four image tags.

The runtime image is distroless (`gcr.io/distroless/nodejs22-debian13:nonroot`, pinned by digest in the `Dockerfile`): no shell, no package manager, no npm. A Debian 13 build stage installs `postgresql-client-17` from the PGDG apt repo (apt.postgresql.org) and copies `pg_dump`, `pg_restore` and `psql` into it with the shared libraries they need (and their dpkg records, so scanners see them); the build fails if that repo is unreachable. Only the API's production dependencies are copied (the Prisma CLI and engines included, for `migrate deploy` at start). Before a release, run the API tests (they back up and restore a real database and upload to a MinIO container), and scan the image: `docker run --rm -v trivy-cache:/root/.cache -v //var/run/docker.sock:/var/run/docker.sock aquasec/trivy:0.57.1 image --scanners vuln --severity HIGH,CRITICAL <image>`. Base image fixes arrive by bumping the digests at the top of the `Dockerfile` (`docker buildx imagetools inspect gcr.io/distroless/nodejs22-debian13:nonroot` shows the current one). After pushing, check the tools are in the image: `docker run --rm ghcr.io/clane-ai/clane-vault:<version> pg_dump --version`. Backups are off by default (`BACKUP_ENABLED=false`), so upgrading changes nothing for a client until they opt in; point them at the README's Backups section. When a client's database moves to Postgres 18, the image needs `postgresql-client-18` (change the version in the `pgclient` stage).

## Sign-in showcase screenshots

The three images in the sign-in page's carousel (`apps/web/public/showcase/{vault,share,link}.webp`, 1280×800) are made by a script. Refresh them whenever the vault list, the record panel or the Share panel changes:

    npm run showcase -w e2e

It needs Docker. It starts its own Postgres container (`clane-vault-showcase-db`) on a free port, runs the migrations, starts the API and web dev servers on their own free ports (never your 5173/3001 ones), seeds a made-up company vault (Northwind, `@example.com` people), captures the slides at 1280×800 in the light theme, and removes the container. The webp files are encoded by Chromium itself, at the best quality that stays under 150 KB each. The PNGs are kept under `e2e/test-results/` for a closer look. Look at the images before committing them, and if a slide's content changes, update its alt text in `apps/web/src/features/auth/Showcase.tsx`. The seed and the shots are in `e2e/showcase/capture.spec.ts`. Extra arguments go to Playwright (e.g. `-- --headed`), and `SHOWCASE_KEEP_DB=1` keeps the database container for debugging.
