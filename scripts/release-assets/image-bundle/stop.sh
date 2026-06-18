#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/.env"
COMPOSE_FILE="$SCRIPT_DIR/compose.release.yml"

die() { echo "[stop] $*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || die "docker is required"
docker compose version >/dev/null 2>&1 || die "docker compose v2 is required"
[[ -f "$COMPOSE_FILE" ]] || die "missing compose.release.yml"

if [[ -f "$ENV_FILE" ]]; then
  set -a
  . "$ENV_FILE"
  set +a
fi

APP_SERVER_VERSION="${APP_SERVER_VERSION:-latest}"
FRONTEND_PORT="${FRONTEND_PORT:-11950}"

export APP_SERVER_VERSION FRONTEND_PORT
docker compose --project-directory "$SCRIPT_DIR" -f "$COMPOSE_FILE" down --remove-orphans

echo "[stop] stopped identity-center $APP_SERVER_VERSION"
