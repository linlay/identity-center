#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

. "$SCRIPT_DIR/scripts/program-common.sh"

auth_issuer=""
output_dir=""
desktop_config_reset=0
desktop_config_backup_dir=""
desktop_version_from=""
desktop_version_to=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --auth-issuer)
      [[ $# -ge 2 ]] || program_die "missing value for --auth-issuer"
      auth_issuer="$2"
      shift 2
      ;;
    --desktop-config-reset)
      desktop_config_reset=1
      shift
      ;;
    --desktop-config-backup-dir)
      [[ $# -ge 2 ]] || program_die "missing value for --desktop-config-backup-dir"
      desktop_config_backup_dir="$2"
      shift 2
      ;;
    --desktop-version-from)
      [[ $# -ge 2 ]] || program_die "missing value for --desktop-version-from"
      desktop_version_from="$2"
      shift 2
      ;;
    --desktop-version-to)
      [[ $# -ge 2 ]] || program_die "missing value for --desktop-version-to"
      desktop_version_to="$2"
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
admin_password_bcrypt=""
if [[ "$desktop_config_reset" == "1" ]]; then
  program_validate_desktop_config_reset_args \
    "$desktop_config_backup_dir" \
    "$desktop_version_from" \
    "$desktop_version_to"
  program_reset_desktop_config "$desktop_config_backup_dir"
  admin_password_bcrypt="$(program_read_env_literal_value "$desktop_config_backup_dir/.env" "AUTH_ADMIN_PASSWORD_BCRYPT" || true)"
fi
program_initialize_config
if [[ "$desktop_config_reset" == "1" && -n "$admin_password_bcrypt" ]]; then
  program_set_env_value "AUTH_ADMIN_PASSWORD_BCRYPT" "$admin_password_bcrypt"
fi
if [[ -n "$auth_issuer" ]]; then
  program_set_env_value "AUTH_ISSUER" "$auth_issuer"
fi
if [[ "$desktop_config_reset" == "1" ]]; then
  program_secure_config_tree "$CONFIG_DIR"
fi

echo "[program-deploy] config initialized: $ENV_FILE"
if [[ -n "$auth_issuer" ]]; then
  echo "[program-deploy] AUTH_ISSUER=$auth_issuer"
fi
if [[ "$desktop_config_reset" == "1" ]]; then
  echo "[program-deploy] Desktop config rebuilt: $desktop_version_from -> $desktop_version_to"
fi
