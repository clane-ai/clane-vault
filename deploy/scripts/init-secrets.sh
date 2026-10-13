#!/usr/bin/env bash
# Generates deploy/.env with random secrets. Never overwrites an existing file.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
if [ -f "$HERE/.env" ]; then
  echo "deploy/.env already exists; not overwriting."
  exit 0
fi
PG="$(openssl rand -hex 24)"
JWT="$(openssl rand -hex 48)"
SRV="$(openssl rand -hex 48)"
sed -e "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$PG|" \
    -e "s|^DATABASE_URL=.*|DATABASE_URL=postgresql://vault:$PG@db:5432/vault|" \
    -e "s|^JWT_SECRET=.*|JWT_SECRET=$JWT|" \
    -e "s|^SERVER_SECRET=.*|SERVER_SECRET=$SRV|" \
    "$HERE/.env.example" > "$HERE/.env"
chmod 600 "$HERE/.env" 2>/dev/null || true
echo "Wrote deploy/.env"
