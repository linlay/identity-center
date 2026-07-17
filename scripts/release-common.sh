#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
RELEASE_ASSETS_DIR="$SCRIPT_DIR/release-assets"
RELEASE_DIST_DIR="$REPO_ROOT/dist/release"
APP_NAME="identity-center"

die() { echo "[release] $*" >&2; exit 1; }
log() { echo "[release] $*"; }
require_file() { [[ -f "$1" ]] || die "missing required file: $1"; }
require_dir() { [[ -d "$1" ]] || die "missing required directory: $1"; }
require_cmd() { command -v "$1" >/dev/null 2>&1 || die "$1 is required"; }

normalize_arch() {
  local raw="${1:-}"
  case "$raw" in
    x86_64|amd64) printf 'amd64\n' ;;
    arm64|aarch64) printf 'arm64\n' ;;
    *)
      die "unsupported ARCH: $raw (allowed: amd64|arm64)"
      ;;
  esac
}

validate_os() {
  case "${1:-}" in
    darwin|windows|linux) ;;
    *)
      die "unsupported OS: ${1:-} (allowed: darwin|windows|linux)"
      ;;
  esac
}

validate_target_pair() {
  local os="$1"
  local arch="$2"
  validate_os "$os"
  case "$arch" in
    amd64|arm64) ;;
    *)
      die "unsupported ARCH: $arch (allowed: amd64|arm64)"
      ;;
  esac
}

resolve_version() {
  local version_value="${VERSION:-}"
  if [[ -z "$version_value" ]]; then
    require_file "$REPO_ROOT/VERSION"
    version_value="$(tr -d '[:space:]' < "$REPO_ROOT/VERSION")"
  fi
  [[ -n "$version_value" ]] || die "VERSION must not be empty"
  [[ "$version_value" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "VERSION must match vX.Y.Z (got: $version_value)"
  printf '%s\n' "$version_value"
}

detect_host_arch() {
  normalize_arch "$(uname -m)"
}

detect_host_os() {
  case "$(uname -s)" in
    Darwin) printf 'darwin\n' ;;
    Linux) printf 'linux\n' ;;
    MINGW*|MSYS*|CYGWIN*) printf 'windows\n' ;;
    *) die "unsupported host OS: $(uname -s)" ;;
  esac
}

load_bundle_env() {
  local root_env_source="$REPO_ROOT/.env.example"
  if [[ -f "$REPO_ROOT/.env" ]]; then
    root_env_source="$REPO_ROOT/.env"
  fi
  set -a
  . "$root_env_source"
  set +a
}

prepare_release_context() {
  VERSION="$(resolve_version)"
  ARCH="$(normalize_arch "${ARCH:-$(detect_host_arch)}")"
  load_bundle_env
  VITE_BASE_PATH="${VITE_BASE_PATH:-/admin/}"
  GOPROXY="${GOPROXY:-https://goproxy.cn,direct}"
  NPM_REGISTRY="${NPM_REGISTRY:-https://registry.npmmirror.com}"
  RELEASE_DRY_RUN="${RELEASE_DRY_RUN:-0}"
}

ensure_release_requirements() {
  require_file "$REPO_ROOT/.env.example"
  require_file "$REPO_ROOT/backend/go.mod"
  require_file "$REPO_ROOT/backend/schema.sql"
  require_file "$REPO_ROOT/frontend/package.json"
  require_file "$REPO_ROOT/backend/Dockerfile.release"
  require_file "$REPO_ROOT/frontend/Dockerfile.release"
  require_cmd go
  require_cmd npm
}

ensure_image_requirements() {
  ensure_release_requirements
  require_cmd docker
  docker buildx version >/dev/null 2>&1 || die "docker buildx is required"
}

ensure_release_dist() {
  mkdir -p "$RELEASE_DIST_DIR"
}

program_bundle_filename() {
  local version="$1"
  local os="$2"
  local arch="$3"
  local ext="${4:-tar.gz}"
  printf '%s-%s-%s-%s.%s\n' "$APP_NAME" "$version" "$os" "$arch" "$ext"
}

image_bundle_filename() {
  local version="$1"
  local os="$2"
  local arch="$3"
  local ext="${4:-tar.gz}"
  printf '%s-image-%s-%s-%s.%s\n' "$APP_NAME" "$version" "$os" "$arch" "$ext"
}

archive_format_for_os() {
  case "$1" in
    windows) printf 'zip\n' ;;
    *) printf 'tar.gz\n' ;;
  esac
}

require_archive_tool_for_os() {
  case "$(archive_format_for_os "$1")" in
    zip) require_cmd zip ;;
    tar.gz) require_cmd tar ;;
    *) die "unsupported archive format for OS: $1" ;;
  esac
}

archive_bundle_dir() {
  local stage_root="$1"
  local bundle_dir_name="$2"
  local output_path="$3"
  local format="$4"

  rm -f "$output_path"

  case "$format" in
    tar.gz)
      tar -czf "$output_path" -C "$stage_root" "$bundle_dir_name"
      ;;
    zip)
      (
        cd "$stage_root"
        zip -qr "$output_path" "$bundle_dir_name"
      )
      ;;
    *)
      die "unsupported archive format: $format"
      ;;
  esac
}

copy_env_example() {
  local dest="$1"
  cp "$REPO_ROOT/.env.example" "$dest"
}

build_frontend_dist() {
  local output_dir="$1"
  mkdir -p "$output_dir"
  log "building frontend assets on host..."
  (
    cd "$REPO_ROOT/frontend"
    npm_config_registry="$NPM_REGISTRY" npm install
    npm_config_registry="$NPM_REGISTRY" VITE_BASE_PATH="$VITE_BASE_PATH" npm run build
  )
  cp -R "$REPO_ROOT/frontend/dist/." "$output_dir/"
}

build_backend_binary() {
  local target_os="$1"
  local target_arch="$2"
  local output_path="$3"
  mkdir -p "$(dirname "$output_path")"
  log "building backend binary for $target_os/$target_arch..."
  (
    cd "$REPO_ROOT/backend"
    GOPROXY="$GOPROXY" \
    GOOS="$target_os" \
    GOARCH="$target_arch" \
    CGO_ENABLED=0 \
    go build -trimpath -ldflags='-s -w -buildid=' -o "$output_path" ./cmd/server
  )
}

write_program_manifest() {
  local dest="$1"
  local target_os="$2"
  local target_arch="$3"
  local backend_entry="$4"
  local asset_file_name="$5"

  (
    cd "$REPO_ROOT/backend"
    go run ./cmd/render-program-manifest \
      --template "$PROGRAM_ASSETS_DIR/manifest.template.json" \
      --output "$dest" \
      --version "$VERSION" \
      --os "$target_os" \
      --arch "$target_arch" \
      --backend "$backend_entry" \
      --asset "$asset_file_name"
  )
}
program_target_matrix_lines() {
  local matrix="${PROGRAM_TARGET_MATRIX:-}"
  local targets="${PROGRAM_TARGETS:-}"
  local arch_value="${ARCH:-}"
  local item os_value arch_part

  if [[ -n "$matrix" ]]; then
    IFS=',' read -r -a __release_pairs <<< "$matrix"
    for item in "${__release_pairs[@]}"; do
      item="$(printf '%s' "$item" | xargs)"
      [[ -n "$item" ]] || continue
      if [[ "$item" != */* ]]; then
        die "PROGRAM_TARGET_MATRIX entries must be os/arch (got: $item)"
      fi
      os_value="${item%%/*}"
      arch_part="${item##*/}"
      validate_target_pair "$os_value" "$arch_part"
      printf '%s/%s\n' "$os_value" "$arch_part"
    done
    return
  fi

  if [[ -n "$targets" ]]; then
    arch_value="$(normalize_arch "$arch_value")"
    IFS=',' read -r -a __release_targets <<< "$targets"
    for item in "${__release_targets[@]}"; do
      os_value="$(printf '%s' "$item" | xargs)"
      [[ -n "$os_value" ]] || continue
      validate_target_pair "$os_value" "$arch_value"
      printf '%s/%s\n' "$os_value" "$arch_value"
    done
    return
  fi

  printf '%s/%s\n' "$(detect_host_os)" "$ARCH"
}
