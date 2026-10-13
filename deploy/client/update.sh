#!/usr/bin/env bash
# Usage: ./update.sh [version]   e.g. ./update.sh 0.2.0
set -euo pipefail
cd "$(dirname "$0")"
[ -f .env ] || { echo "No .env here; run install.sh first."; exit 1; }
if [ $# -ge 1 ]; then
  if grep -q '^CLANE_VAULT_VERSION=' .env; then
    sed -i.bak "s|^CLANE_VAULT_VERSION=.*|CLANE_VAULT_VERSION=$1|" .env && rm -f .env.bak
  else
    echo "CLANE_VAULT_VERSION=$1" >> .env
  fi
fi
docker compose pull
docker compose up -d
echo "Running version: $(grep '^CLANE_VAULT_VERSION=' .env | cut -d= -f2)"
