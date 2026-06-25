#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
die() { echo "[load-image] $*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || die "docker is required"

shopt -s nullglob
matches=("$SCRIPT_DIR"/images/identity-center-image-*-linux-*.tar.gz)
shopt -u nullglob
[[ "${#matches[@]}" -eq 1 ]] || die "expected exactly one image archive in images/"
IMAGE_ARCHIVE="${matches[0]}"

gzip -dc "$IMAGE_ARCHIVE" | docker load >/dev/null
echo "[load-image] loaded image archive: $(basename "$IMAGE_ARCHIVE")"
