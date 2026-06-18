#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_BIN="$SCRIPT_DIR/backend/identity-center"

if [ ! -x "$BACKEND_BIN" ]; then
  echo "Backend binary not found or not executable at $BACKEND_BIN. Please build the backend first." >&2
  exit 1
fi

exec "$BACKEND_BIN" issue-bridge-access-token "$@"
