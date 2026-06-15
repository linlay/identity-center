#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
RELEASE_ASSETS_DIR="$SCRIPT_DIR/release-assets"
RELEASE_DIST_DIR="$REPO_ROOT/dist/release"
APP_NAME="zenmind-app-server"
DEFAULT_PROGRAM_TARGET_MATRIX="darwin/arm64,windows/amd64"

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

copy_env_example_with_version() {
  local dest="$1"
  cp "$REPO_ROOT/.env.example" "$dest"
  perl -0pi -e 's/^APP_SERVER_VERSION=.*/APP_SERVER_VERSION='"$VERSION"'/m' "$dest"
  grep -q "^APP_SERVER_VERSION=$VERSION$" "$dest" || die "failed to set APP_SERVER_VERSION in $dest"
}

build_frontend_dist() {
  local output_dir="$1"
  mkdir -p "$output_dir"
  log "building frontend assets on host..."
  (
    cd "$REPO_ROOT/frontend"
    npm_config_registry="$NPM_REGISTRY" npm install
    # Git Bash/MSYS converts /admin/ into C:/Program Files/Git/admin/ for native npm unless disabled.
    MSYS_NO_PATHCONV=1 MSYS2_ENV_CONV_EXCL="${MSYS2_ENV_CONV_EXCL:+$MSYS2_ENV_CONV_EXCL;}VITE_BASE_PATH" npm_config_registry="$NPM_REGISTRY" VITE_BASE_PATH="$VITE_BASE_PATH" npm run build
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
  local start_script="start.sh"
  local stop_script="stop.sh"
  local deploy_script="deploy.sh"
  local program_common_script="scripts/program-common.sh"

  if [[ "$target_os" == "windows" ]]; then
    start_script="start.ps1"
    stop_script="stop.ps1"
    deploy_script="deploy.ps1"
    program_common_script="scripts/program-common.ps1"
  fi

  cat > "$dest" <<EOF
{
  "kind": "builtin",
  "id": "$APP_NAME",
  "name": "认证服务",
  "version": "$VERSION",
  "description": "认证与管理服务，提供 OAuth2/OIDC、管理后台、App 访问令牌和设备管理。",
  "platform": {
    "os": "$target_os",
    "arch": "$target_arch"
  },
  "frontend": {
    "dist": "frontend/dist",
    "index": "index.html",
    "spa": true,
    "mode": "standalone",
    "entry": "/admin/"
  },
  "api": {
    "enabled": true,
    "adminBaseUrl": "/admin/api/",
    "openidBaseUrl": "/api/openid/",
    "oauth2BaseUrl": "/api/oauth2/"
  },
  "backend": {
    "entry": "$backend_entry"
  },
  "scripts": {
    "start": ["$start_script", "--daemon"],
    "stop": "$stop_script",
    "deploy": "$deploy_script"
  },
  "configFiles": [
    {
      "key": "env",
      "label": ".env",
      "relativePath": ".env",
      "templateRelativePath": ".env.example",
      "required": true
    }
  ],
  "runtime": {
    "pidRelativePath": "run/zenmind-app-server.pid",
    "logRelativePath": "run/zenmind-app-server.log",
    "errorLogRelativePath": "run/zenmind-app-server.stderr.log",
    "requiredPaths": [
      "$backend_entry",
      "$start_script",
      "$stop_script",
      "$deploy_script",
      "$program_common_script",
      ".env.example",
      "manifest.json",
      "frontend/dist/index.html"
    ]
  },
  "web": {
    "routePath": "/admin/",
    "portEnvKey": "SERVER_PORT",
    "defaultPort": 11950
  },
  "desktop": {
    "displayOrder": 4,
    "autoStart": true,
    "assetFileName": "$asset_file_name",
    "bundleTopLevelDir": "$APP_NAME",
    "capabilities": {
      "provides": [
        {
          "id": "auth.publicKey",
          "darwinCommand": [
            "scripts/setup-public-key.sh",
            "--mode",
            "bootstrap",
            "--db",
            "{{auth.dbPath}}",
            "--out",
            "{{provider.dataDir}}/keys",
            "--public-out",
            "{{output.path}}"
          ],
          "linuxCommand": [
            "scripts/setup-public-key.sh",
            "--mode",
            "bootstrap",
            "--db",
            "{{auth.dbPath}}",
            "--out",
            "{{provider.dataDir}}/keys",
            "--public-out",
            "{{output.path}}"
          ],
          "windowsCommand": [
            "scripts/setup-public-key.ps1",
            "-Mode",
            "bootstrap",
            "-Db",
            "{{auth.dbPath}}",
            "-Out",
            "{{provider.dataDir}}/keys",
            "-PublicOut",
            "{{output.path}}"
          ],
          "env": {
            "AUTH_DB_PATH": "{{auth.dbPath}}"
          },
          "output": "file",
          "outputPath": "{{provider.dataDir}}/keys/publicKey.pem",
          "retryOnSqliteBusy": true
        },
        {
          "id": "auth.accessToken",
          "darwinCommand": [
            "scripts/issue-bridge-access-token.sh",
            "--db",
            "{{auth.dbPath}}",
            "--issuer",
            "{{auth.issuer}}",
            "--username",
            "{{auth.username}}",
            "--device-name",
            "{{desktop.deviceName}}",
            "--device-id",
            "{{desktop.deviceId}}"
          ],
          "linuxCommand": [
            "scripts/issue-bridge-access-token.sh",
            "--db",
            "{{auth.dbPath}}",
            "--issuer",
            "{{auth.issuer}}",
            "--username",
            "{{auth.username}}",
            "--device-name",
            "{{desktop.deviceName}}",
            "--device-id",
            "{{desktop.deviceId}}"
          ],
          "windowsCommand": [
            "scripts/issue-bridge-access-token.ps1",
            "-Db",
            "{{auth.dbPath}}",
            "-Issuer",
            "{{auth.issuer}}",
            "-Username",
            "{{auth.username}}",
            "-DeviceName",
            "{{desktop.deviceName}}",
            "-DeviceId",
            "{{desktop.deviceId}}"
          ],
          "env": {
            "AUTH_DB_PATH": "{{auth.dbPath}}",
            "AUTH_ISSUER": "{{auth.issuer}}",
            "AUTH_APP_USERNAME": "{{auth.username}}",
            "DESKTOP_DEVICE_ID": "{{desktop.deviceId}}"
          },
          "output": "stdoutLastLine",
          "dependsOn": ["auth.publicKey"],
          "retryOnSqliteBusy": true,
          "validateJwtDeviceId": true,
          "allowDeviceIdFallback": true
        }
      ],
      "requires": []
    },
    "envBindings": [
      {
        "key": "SERVER_PORT",
        "value": "{{serviceDefaultPort}}",
        "onlyIfDefault": true
      }
    ],
    "capabilities": {
      "provides": [
        {
          "id": "auth.publicKey",
          "darwinCommand": [
            "scripts/setup-public-key.sh",
            "--mode",
            "bootstrap",
            "--db",
            "{{auth.dbPath}}",
            "--out",
            "{{provider.dataDir}}/keys",
            "--public-out",
            "{{output.path}}"
          ],
          "linuxCommand": [
            "scripts/setup-public-key.sh",
            "--mode",
            "bootstrap",
            "--db",
            "{{auth.dbPath}}",
            "--out",
            "{{provider.dataDir}}/keys",
            "--public-out",
            "{{output.path}}"
          ],
          "windowsCommand": [
            "scripts/setup-public-key.ps1",
            "-Mode",
            "bootstrap",
            "-Db",
            "{{auth.dbPath}}",
            "-Out",
            "{{provider.dataDir}}/keys",
            "-PublicOut",
            "{{output.path}}"
          ],
          "env": {
            "AUTH_DB_PATH": "{{auth.dbPath}}"
          },
          "output": "file",
          "outputPath": "{{provider.dataDir}}/keys/publicKey.pem",
          "retryOnSqliteBusy": true
        },
        {
          "id": "auth.accessToken",
          "darwinCommand": [
            "scripts/issue-bridge-access-token.sh",
            "--db",
            "{{auth.dbPath}}",
            "--issuer",
            "{{auth.issuer}}",
            "--username",
            "{{auth.username}}",
            "--device-name",
            "{{desktop.deviceName}}",
            "--device-id",
            "{{desktop.deviceId}}"
          ],
          "linuxCommand": [
            "scripts/issue-bridge-access-token.sh",
            "--db",
            "{{auth.dbPath}}",
            "--issuer",
            "{{auth.issuer}}",
            "--username",
            "{{auth.username}}",
            "--device-name",
            "{{desktop.deviceName}}",
            "--device-id",
            "{{desktop.deviceId}}"
          ],
          "windowsCommand": [
            "scripts/issue-bridge-access-token.ps1",
            "-Db",
            "{{auth.dbPath}}",
            "-Issuer",
            "{{auth.issuer}}",
            "-Username",
            "{{auth.username}}",
            "-DeviceName",
            "{{desktop.deviceName}}",
            "-DeviceId",
            "{{desktop.deviceId}}"
          ],
          "env": {
            "AUTH_DB_PATH": "{{auth.dbPath}}",
            "AUTH_ISSUER": "{{auth.issuer}}",
            "AUTH_APP_USERNAME": "{{auth.username}}",
            "DESKTOP_DEVICE_ID": "{{desktop.deviceId}}"
          },
          "output": "stdoutLastLine",
          "dependsOn": ["auth.publicKey"],
          "retryOnSqliteBusy": true,
          "validateJwtDeviceId": true,
          "allowDeviceIdFallback": true
        }
      ],
      "requires": []
    }
  }
}
EOF
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

  PROGRAM_TARGET_MATRIX="$DEFAULT_PROGRAM_TARGET_MATRIX" program_target_matrix_lines
}
