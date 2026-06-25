#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/release-common.sh"

PROGRAM_ASSETS_DIR="$RELEASE_ASSETS_DIR/program"

prepare_release_context
ensure_release_requirements
require_dir "$PROGRAM_ASSETS_DIR"
require_dir "$PROGRAM_ASSETS_DIR/scripts"

PROGRAM_TARGET_OUTPUT="$(program_target_matrix_lines)"
PROGRAM_TARGET_PAIRS=()
while IFS= read -r pair; do
  [[ -n "$pair" ]] || continue
  PROGRAM_TARGET_PAIRS+=("$pair")
done <<EOF
$PROGRAM_TARGET_OUTPUT
EOF
[[ "${#PROGRAM_TARGET_PAIRS[@]}" -gt 0 ]] || die "no program targets resolved"

require_program_assets_for_os() {
  local target_os="$1"

  case "$target_os" in
    windows)
      require_file "$PROGRAM_ASSETS_DIR/deploy.ps1"
      require_file "$PROGRAM_ASSETS_DIR/start.ps1"
      require_file "$PROGRAM_ASSETS_DIR/stop.ps1"
      require_file "$PROGRAM_ASSETS_DIR/scripts/program-common.ps1"
      require_file "$PROGRAM_ASSETS_DIR/scripts/setup-public-key.ps1"
      require_file "$PROGRAM_ASSETS_DIR/scripts/issue-bridge-access-token.ps1"
      require_file "$PROGRAM_ASSETS_DIR/scripts/issue-bridge-runner-token.ps1"
      ;;
    *)
      require_file "$PROGRAM_ASSETS_DIR/deploy.sh"
      require_file "$PROGRAM_ASSETS_DIR/start.sh"
      require_file "$PROGRAM_ASSETS_DIR/stop.sh"
      require_file "$PROGRAM_ASSETS_DIR/scripts/program-common.sh"
      require_file "$PROGRAM_ASSETS_DIR/scripts/setup-public-key.sh"
      require_file "$PROGRAM_ASSETS_DIR/scripts/issue-bridge-access-token.sh"
      require_file "$PROGRAM_ASSETS_DIR/scripts/issue-bridge-runner-token.sh"
      ;;
  esac
}

for pair in "${PROGRAM_TARGET_PAIRS[@]}"; do
  require_archive_tool_for_os "${pair%%/*}"
  require_program_assets_for_os "${pair%%/*}"
done

log "VERSION=$VERSION"
log "PROGRAM_TARGETS=${PROGRAM_TARGET_PAIRS[*]}"
log "VITE_BASE_PATH=$VITE_BASE_PATH"
log "GOPROXY=$GOPROXY"
log "NPM_REGISTRY=$NPM_REGISTRY"
log "host build tools: go=$(go version | awk '{print $3}') npm=$(npm --version)"

if [[ "$RELEASE_DRY_RUN" == "1" ]]; then
  log "dry-run enabled; skipping host build and bundle assembly"
  exit 0
fi

ensure_release_dist
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/identity-center-program-release.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

FRONTEND_DIST_DIR="$TMP_DIR/frontend-dist"
build_frontend_dist "$FRONTEND_DIST_DIR"

for pair in "${PROGRAM_TARGET_PAIRS[@]}"; do
  target_os="${pair%%/*}"
  target_arch="${pair##*/}"
  archive_format="$(archive_format_for_os "$target_os")"
  stage_root="$TMP_DIR/${APP_NAME}-${target_os}-${target_arch}"
  bundle_root="$stage_root/$APP_NAME"
  backend_dir="$bundle_root/backend"
  frontend_dir="$bundle_root/frontend"
  scripts_dir="$bundle_root/scripts"
  backend_binary="$backend_dir/$APP_NAME"
  backend_entry="backend/$APP_NAME"
  if [[ "$target_os" == "windows" ]]; then
    backend_binary="$backend_dir/$APP_NAME.exe"
    backend_entry="backend/$APP_NAME.exe"
  fi

  mkdir -p "$backend_dir" "$frontend_dir/dist" "$scripts_dir"

  build_backend_binary "$target_os" "$target_arch" "$backend_binary"

  cp -R "$FRONTEND_DIST_DIR/." "$frontend_dir/dist/"
  cp "$REPO_ROOT/.env.example" "$bundle_root/.env.example"
  write_program_manifest "$bundle_root/manifest.json" "$target_os" "$target_arch" "$backend_entry" "$(program_bundle_filename "$VERSION" "$target_os" "$target_arch" "$archive_format")"
  if [[ "$target_os" == "windows" ]]; then
    cp "$PROGRAM_ASSETS_DIR/deploy.ps1" "$bundle_root/deploy.ps1"
    cp "$PROGRAM_ASSETS_DIR/start.ps1" "$bundle_root/start.ps1"
    cp "$PROGRAM_ASSETS_DIR/stop.ps1" "$bundle_root/stop.ps1"
    cp "$PROGRAM_ASSETS_DIR/scripts/program-common.ps1" "$scripts_dir/program-common.ps1"
    cp "$PROGRAM_ASSETS_DIR/scripts/setup-public-key.ps1" "$scripts_dir/setup-public-key.ps1"
    cp "$PROGRAM_ASSETS_DIR/scripts/issue-bridge-access-token.ps1" "$scripts_dir/issue-bridge-access-token.ps1"
    cp "$PROGRAM_ASSETS_DIR/scripts/issue-bridge-runner-token.ps1" "$scripts_dir/issue-bridge-runner-token.ps1"
  else
    cp "$PROGRAM_ASSETS_DIR/deploy.sh" "$bundle_root/deploy.sh"
    cp "$PROGRAM_ASSETS_DIR/start.sh" "$bundle_root/start.sh"
    cp "$PROGRAM_ASSETS_DIR/stop.sh" "$bundle_root/stop.sh"
    cp "$PROGRAM_ASSETS_DIR/scripts/program-common.sh" "$scripts_dir/program-common.sh"
    cp "$PROGRAM_ASSETS_DIR/scripts/setup-public-key.sh" "$scripts_dir/setup-public-key.sh"
    cp "$PROGRAM_ASSETS_DIR/scripts/issue-bridge-access-token.sh" "$scripts_dir/issue-bridge-access-token.sh"
    cp "$PROGRAM_ASSETS_DIR/scripts/issue-bridge-runner-token.sh" "$scripts_dir/issue-bridge-runner-token.sh"

    chmod +x \
      "$bundle_root/deploy.sh" \
      "$bundle_root/start.sh" \
      "$bundle_root/stop.sh" \
      "$scripts_dir/program-common.sh" \
      "$scripts_dir/setup-public-key.sh" \
      "$scripts_dir/issue-bridge-access-token.sh" \
      "$scripts_dir/issue-bridge-runner-token.sh"
  fi

  bundle_archive="$RELEASE_DIST_DIR/$(program_bundle_filename "$VERSION" "$target_os" "$target_arch" "$archive_format")"
  archive_bundle_dir "$stage_root" "$APP_NAME" "$bundle_archive" "$archive_format"
  log "done: $bundle_archive"
done
