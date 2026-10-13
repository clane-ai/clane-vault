#!/usr/bin/env bash
# Clane Vault installer. Safe to re-run: never overwrites an existing .env.
set -euo pipefail
cd "$(dirname "$0")"
# The image is public on ghcr.io. A private registry (set CLANE_VAULT_IMAGE in .env) needs REGISTRY, REGISTRY_USERNAME and REGISTRY_TOKEN.
REGISTRY="${REGISTRY:-ghcr.io}"

command -v docker >/dev/null || { echo "Docker is required."; exit 1; }
docker compose version >/dev/null || { echo "Docker Compose v2 is required."; exit 1; }

if [ -n "${REGISTRY_USERNAME:-}" ]; then
  if [ -z "${REGISTRY_TOKEN:-}" ]; then read -r -s -p "Registry token: " REGISTRY_TOKEN; echo; fi
  printf '%s' "$REGISTRY_TOKEN" | docker login "$REGISTRY" -u "$REGISTRY_USERNAME" --password-stdin
fi

if [ ! -f .env ]; then
  read -r -p "Use bundled Postgres? (y/n): " BUNDLED
  read -r -p "Public URL users will open (https://vault.example.com): " URL
  JWT="$(openssl rand -hex 48)"; SRV="$(openssl rand -hex 48)"; PG="$(openssl rand -hex 24)"
  cp .env.example .env
  sed -i.bak -e "s|^JWT_SECRET=.*|JWT_SECRET=$JWT|" -e "s|^SERVER_SECRET=.*|SERVER_SECRET=$SRV|" \
    -e "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$PG|" -e "s|^PUBLIC_URL=.*|PUBLIC_URL=${URL:-https://vault.example.com}|" .env
  if [[ "$BUNDLED" =~ ^[Yy] ]]; then
    sed -i.bak -e "s|^DATABASE_URL=.*|DATABASE_URL=postgresql://vault:$PG@postgres:5432/vault|" .env
    echo "COMPOSE_PROFILES=bundled-db" >> .env
  else
    read -r -p "DATABASE_URL of your Postgres: " DBURL
    sed -i.bak -e "s|^DATABASE_URL=.*|DATABASE_URL=$DBURL|" .env
  fi
  rm -f .env.bak; chmod 600 .env
  echo "Created .env"
else
  echo ".env exists; keeping it."
fi

# COMPOSE_PROFILES in .env enables the bundled database for every later compose command too.
docker compose pull
docker compose up -d

PORT="$(grep -E '^HTTP_PORT=' .env | cut -d= -f2 || true)"; PORT="${PORT:-8080}"
# Under a path (PUBLIC_URL=https://host/vault, or BASE_PATH) the API is at <path>/api/v1.
BASE="$(grep -E '^BASE_PATH=' .env | cut -d= -f2- || true)"
[ -n "$BASE" ] || BASE="$(grep -E '^PUBLIC_URL=' .env | cut -d= -f2- | sed -E 's|^[A-Za-z]+://[^/]*||' || true)"
BASE="/$(printf '%s' "$BASE" | sed -E 's|^/+||; s|/+$||')"; BASE="${BASE%/}"
echo "Waiting for the server..."
OK=0
for _ in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:$PORT$BASE/api/v1/health" >/dev/null 2>&1; then OK=1; break; fi
  sleep 2
done
[ "$OK" = 1 ] || { echo "Server did not become healthy. Check: docker compose logs clane-vault"; exit 1; }
echo "Clane Vault is running on 127.0.0.1:$PORT. Put an HTTPS reverse proxy in front of it."
echo
echo "Create the first admin with:"
echo "  docker compose exec clane-vault node dist/src/scripts/bootstrap.js --email <admin@yourcompany.com>"
