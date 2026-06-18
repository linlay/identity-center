#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BACKEND_BIN="$ROOT_DIR/backend/identity-center"

if [ ! -x "$BACKEND_BIN" ]; then
  echo "Backend binary not found or not executable at $BACKEND_BIN. Please build the backend first." >&2
  exit 1
fi

exec "$BACKEND_BIN" setup-public-key "$@"
