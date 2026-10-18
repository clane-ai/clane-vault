# Clane Vault agent gateway (docs/agents.md): the MCP server that holds KMS-wrapped agent keys. Never the API process.
# Build context: repository root. Image: ghcr.io/clane-ai/clane-gateway.
#
# The runtime stage is distroless Node.js 22 on Debian 13: no shell, no package manager, no npm. It holds only the
# bundled dist/ (esbuild inlines every dependency, the AWS KMS SDK included). Core dumps are turned off by the compose
# file (`ulimits: core: 0`): distroless has no prlimit. Bump the digests below to pick up base image security fixes.

FROM node:22.23.3-trixie-slim@sha256:154ba2f4d6fec323d28e4f4bb86bba4677f1223391a1979cf521304e03a98dfa AS build
RUN apt-get update && apt-get install -y --no-install-recommends openssl python3 make g++ ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /repo
# Every workspace manifest, so npm ci matches the lockfile (same list as the root Dockerfile).
COPY package.json package-lock.json tsconfig.base.json ./
COPY packages/crypto/package.json packages/crypto/
COPY apps/api/package.json apps/api/
COPY apps/web/package.json apps/web/
COPY apps/extension/package.json apps/extension/
COPY apps/gateway/package.json apps/gateway/
COPY e2e/package.json e2e/
COPY apps/api/prisma apps/api/prisma
RUN npm ci
COPY packages/crypto packages/crypto
COPY apps/gateway apps/gateway
RUN npm run build -w @clane-vault/gateway && mkdir -p /out/data

FROM gcr.io/distroless/nodejs22-debian13:nonroot@sha256:ec2313763dd43931543bd03830466e0c409ce73a487e8d46f10db72d3b816c1c
LABEL org.opencontainers.image.title="Clane Vault gateway" \
      org.opencontainers.image.description="Agent access gateway for Clane Vault: a remote MCP server that uses vault credentials without showing them." \
      org.opencontainers.image.vendor="Clane AI Labs" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.source="https://github.com/clane-ai/clane-vault"
ENV NODE_ENV=production
WORKDIR /app
# Owned by root and read-only for the runtime user; /data (the identity key) is the only writable path besides /tmp.
COPY --from=build /repo/apps/gateway/dist dist
COPY --from=build --chown=nonroot:nonroot /out/data /data
USER nonroot
EXPOSE 3002 3003
# The base image's entrypoint is node. The gateway refuses to start without --disable-sigusr1 (SIGUSR1 would open the
# inspector), with NODE_OPTIONS set, or with any Node flag outside its allowlist.
CMD ["--disable-sigusr1", "dist/server.js"]
