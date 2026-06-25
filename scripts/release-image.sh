#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/release-common.sh"

IMAGE_ASSETS_DIR="$RELEASE_ASSETS_DIR/image-bundle"
PLATFORM_OS="linux"

prepare_release_context
ensure_image_requirements
require_dir "$IMAGE_ASSETS_DIR"
require_file "$IMAGE_ASSETS_DIR/README.txt"
require_file "$IMAGE_ASSETS_DIR/load-image.sh"
require_file "$IMAGE_ASSETS_DIR/start.sh"
require_file "$IMAGE_ASSETS_DIR/stop.sh"
require_file "$IMAGE_ASSETS_DIR/compose.release.yml"
require_file "$IMAGE_ASSETS_DIR/setup-public-key.sh"
require_file "$IMAGE_ASSETS_DIR/issue-bridge-access-token.sh"
require_file "$IMAGE_ASSETS_DIR/issue-bridge-runner-token.sh"

PLATFORM="linux/$ARCH"
BACKEND_IMAGE="identity-center-backend:bundle"
FRONTEND_IMAGE="identity-center-frontend:bundle"
IMAGE_ARCHIVE_NAME="${APP_NAME}-image-${VERSION}-linux-${ARCH}.tar.gz"
IMAGE_BUNDLE_NAME="$(image_bundle_filename "$VERSION" "linux" "$ARCH")"

log "VERSION=$VERSION"
log "ARCH=$ARCH PLATFORM=$PLATFORM"
log "VITE_BASE_PATH=$VITE_BASE_PATH"
log "GOPROXY=$GOPROXY"
log "NPM_REGISTRY=$NPM_REGISTRY"
log "host build tools: go=$(go version | awk '{print $3}') npm=$(npm --version)"

if [[ "$RELEASE_DRY_RUN" == "1" ]]; then
  log "dry-run enabled; skipping host build and bundle assembly"
  exit 0
fi

ensure_release_dist
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/identity-center-image-release.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

BUNDLE_STAGE="$TMP_DIR/$APP_NAME"
BACKEND_BUILD_DIR="$TMP_DIR/backend-build"
FRONTEND_BUILD_DIR="$TMP_DIR/frontend-build"
IMAGE_WORK_DIR="$TMP_DIR/images"
mkdir -p "$BUNDLE_STAGE/images" "$BUNDLE_STAGE/data" "$BACKEND_BUILD_DIR" "$FRONTEND_BUILD_DIR" "$IMAGE_WORK_DIR"

build_backend_binary "$PLATFORM_OS" "$ARCH" "$BACKEND_BUILD_DIR/app"
cp "$REPO_ROOT/backend/schema.sql" "$BACKEND_BUILD_DIR/schema.sql"

build_frontend_dist "$FRONTEND_BUILD_DIR/dist"
cp "$REPO_ROOT/frontend/nginx.conf" "$FRONTEND_BUILD_DIR/nginx.conf"

log "building backend image..."
docker buildx build \
  --platform "$PLATFORM" \
  --file "$REPO_ROOT/backend/Dockerfile.release" \
  --tag "$BACKEND_IMAGE" \
  --load \
  "$BACKEND_BUILD_DIR"

log "building frontend image..."
docker buildx build \
  --platform "$PLATFORM" \
  --file "$REPO_ROOT/frontend/Dockerfile.release" \
  --tag "$FRONTEND_IMAGE" \
  --load \
  "$FRONTEND_BUILD_DIR"

log "exporting images..."
docker save "$BACKEND_IMAGE" "$FRONTEND_IMAGE" | gzip -c > "$BUNDLE_STAGE/images/$IMAGE_ARCHIVE_NAME"

copy_env_example "$BUNDLE_STAGE/.env.example"
cp "$IMAGE_ASSETS_DIR/README.txt" "$BUNDLE_STAGE/README.txt"
cp "$IMAGE_ASSETS_DIR/load-image.sh" "$BUNDLE_STAGE/load-image.sh"
cp "$IMAGE_ASSETS_DIR/start.sh" "$BUNDLE_STAGE/start.sh"
cp "$IMAGE_ASSETS_DIR/stop.sh" "$BUNDLE_STAGE/stop.sh"
cp "$IMAGE_ASSETS_DIR/compose.release.yml" "$BUNDLE_STAGE/compose.release.yml"
cp "$IMAGE_ASSETS_DIR/setup-public-key.sh" "$BUNDLE_STAGE/setup-public-key.sh"
cp "$IMAGE_ASSETS_DIR/issue-bridge-access-token.sh" "$BUNDLE_STAGE/issue-bridge-access-token.sh"
cp "$IMAGE_ASSETS_DIR/issue-bridge-runner-token.sh" "$BUNDLE_STAGE/issue-bridge-runner-token.sh"

chmod +x \
  "$BUNDLE_STAGE/load-image.sh" \
  "$BUNDLE_STAGE/start.sh" \
  "$BUNDLE_STAGE/stop.sh" \
  "$BUNDLE_STAGE/setup-public-key.sh" \
  "$BUNDLE_STAGE/issue-bridge-access-token.sh" \
  "$BUNDLE_STAGE/issue-bridge-runner-token.sh"

bundle_tar="$RELEASE_DIST_DIR/$IMAGE_BUNDLE_NAME"
tar -czf "$bundle_tar" -C "$TMP_DIR" "$APP_NAME"
log "done: $bundle_tar"
