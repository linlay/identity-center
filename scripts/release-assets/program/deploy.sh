#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

. "$SCRIPT_DIR/scripts/program-common.sh"

auth_issuer=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --auth-issuer)
      [[ $# -ge 2 ]] || program_die "missing value for --auth-issuer"
      auth_issuer="$2"
      shift 2
      ;;
    *)
      program_die "unsupported argument: $1"
      ;;
  esac
done

cd "$SCRIPT_DIR"
program_initialize_config
if [[ -n "$auth_issuer" ]]; then
  program_set_env_value "AUTH_ISSUER" "$auth_issuer"
fi

echo "[program-deploy] config initialized: $ENV_FILE"
if [[ -n "$auth_issuer" ]]; then
  echo "[program-deploy] AUTH_ISSUER=$auth_issuer"
fi
