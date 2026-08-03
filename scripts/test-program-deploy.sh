#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

bundle_root="$tmp_dir/identity-center"
config_dir="$tmp_dir/config"
backup_dir="$tmp_dir/config-backups/v0.3.26-to-v0.3.27/identity-center"
mkdir -p "$bundle_root/scripts" "$config_dir"
cp "$REPO_ROOT/scripts/release-assets/program/deploy.sh" "$bundle_root/deploy.sh"
cp "$REPO_ROOT/scripts/release-assets/program/scripts/program-common.sh" "$bundle_root/scripts/program-common.sh"
cp "$REPO_ROOT/.env.example" "$bundle_root/.env.example"
chmod +x "$bundle_root/deploy.sh" "$bundle_root/scripts/program-common.sh"

printf 'AUTH_ADMIN_PASSWORD_BCRYPT=custom-admin-bcrypt\nAUTH_APP_MASTER_PASSWORD_BCRYPT=custom-other-secret\nOLD_FIELD=remove-me\n' >"$config_dir/.env"
"$bundle_root/deploy.sh" \
  --output-dir "$config_dir" \
  --auth-issuer https://issuer.current.test \
  --desktop-config-reset \
  --desktop-config-backup-dir "$backup_dir" \
  --desktop-version-from v0.3.26 \
  --desktop-version-to v0.3.27

grep -Fqx 'OLD_FIELD=remove-me' "$backup_dir/.env"
grep -Fqx 'AUTH_ADMIN_PASSWORD_BCRYPT=custom-admin-bcrypt' "$config_dir/.env"
grep -Fqx 'AUTH_ISSUER=https://issuer.current.test' "$config_dir/.env"
! grep -Fq 'custom-other-secret' "$config_dir/.env"
! grep -Fq 'OLD_FIELD=' "$config_dir/.env"

printf 'FAILED_ONLY=diagnostic\n' >>"$config_dir/.env"
"$bundle_root/deploy.sh" \
  --output-dir "$config_dir" \
  --auth-issuer https://issuer.current.test \
  --desktop-config-reset \
  --desktop-config-backup-dir "$backup_dir" \
  --desktop-version-from v0.3.26 \
  --desktop-version-to v0.3.27

grep -Fqx 'AUTH_APP_MASTER_PASSWORD_BCRYPT=custom-other-secret' "$backup_dir/.env"
grep -Fqx 'FAILED_ONLY=diagnostic' "${backup_dir}.failed/.env"
! grep -Fq 'FAILED_ONLY=' "$config_dir/.env"

echo "[program-deploy-test] passed"
