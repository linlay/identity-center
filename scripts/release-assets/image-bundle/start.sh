#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/.env"
COMPOSE_FILE="$SCRIPT_DIR/compose.release.yml"
LOAD_SCRIPT="$SCRIPT_DIR/load-image.sh"

die() { echo "[start] $*" >&2; exit 1; }

[[ -f "$ENV_FILE" ]] || die "missing .env (copy from .env.example first)"
[[ -f "$COMPOSE_FILE" ]] || die "missing compose.release.yml"
[[ -x "$LOAD_SCRIPT" ]] || die "missing load-image.sh"

command -v docker >/dev/null 2>&1 || die "docker is required"
docker compose version >/dev/null 2>&1 || die "docker compose v2 is required"

set -a
. "$ENV_FILE"
set +a

IDENTITY_CENTER_VERSION="${IDENTITY_CENTER_VERSION:-latest}"
FRONTEND_PORT="${FRONTEND_PORT:-11950}"
BACKEND_IMAGE="identity-center-backend:$IDENTITY_CENTER_VERSION"
FRONTEND_IMAGE="identity-center-frontend:$IDENTITY_CENTER_VERSION"

if ! docker image inspect "$BACKEND_IMAGE" >/dev/null 2>&1 || ! docker image inspect "$FRONTEND_IMAGE" >/dev/null 2>&1; then
  "$LOAD_SCRIPT"
fi

mkdir -p "$SCRIPT_DIR/data"

export IDENTITY_CENTER_VERSION FRONTEND_PORT
docker compose --project-directory "$SCRIPT_DIR" -f "$COMPOSE_FILE" up -d

echo "[start] started identity-center $IDENTITY_CENTER_VERSION"
echo "[start] browser: http://127.0.0.1:${FRONTEND_PORT}/admin/"
