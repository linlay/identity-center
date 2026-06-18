#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/.env"

die() { echo "[load-image] $*" >&2; exit 1; }

[[ -f "$ENV_FILE" ]] || die "missing .env (copy from .env.example first)"
command -v docker >/dev/null 2>&1 || die "docker is required"

set -a
. "$ENV_FILE"
set +a

APP_SERVER_VERSION="${APP_SERVER_VERSION:-latest}"
shopt -s nullglob
matches=("$SCRIPT_DIR"/images/identity-center-image-"${APP_SERVER_VERSION}"-linux-*.tar.gz)
shopt -u nullglob
[[ "${#matches[@]}" -eq 1 ]] || die "expected exactly one image archive for version ${APP_SERVER_VERSION} in images/"
IMAGE_ARCHIVE="${matches[0]}"

gzip -dc "$IMAGE_ARCHIVE" | docker load >/dev/null
echo "[load-image] loaded image archive: $(basename "$IMAGE_ARCHIVE")"
