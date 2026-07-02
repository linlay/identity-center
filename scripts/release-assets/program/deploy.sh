#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

. "$SCRIPT_DIR/scripts/program-common.sh"

auth_issuer=""
output_dir=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --auth-issuer)
      [[ $# -ge 2 ]] || program_die "missing value for --auth-issuer"
      auth_issuer="$2"
      shift 2
      ;;
    --output-dir)
      [[ $# -ge 2 ]] || program_die "missing value for --output-dir"
      output_dir="$2"
      shift 2
      ;;
    --config-dir|--data-dir|--state-dir|--log-dir|--port|--daemon)
      program_die "$1 is a start/runtime argument; pass it to start.sh instead of deploy.sh"
      ;;
    *)
      program_die "unsupported deploy argument: $1"
      ;;
  esac
done

cd "$SCRIPT_DIR"
if [[ -n "$output_dir" ]]; then
  CONFIG_DIR="$output_dir"
  program_refresh_layout_paths
fi
program_initialize_config
if [[ -n "$auth_issuer" ]]; then
  program_set_env_value "AUTH_ISSUER" "$auth_issuer"
fi

echo "[program-deploy] config initialized: $ENV_FILE"
if [[ -n "$auth_issuer" ]]; then
  echo "[program-deploy] AUTH_ISSUER=$auth_issuer"
fi
