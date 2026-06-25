#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

. "$SCRIPT_DIR/scripts/program-common.sh"
if [[ $# -gt 0 ]]; then
  program_die "unsupported argument: $1"
fi

cd "$SCRIPT_DIR"
program_stop_backend
