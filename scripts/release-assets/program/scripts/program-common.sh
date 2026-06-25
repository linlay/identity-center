#!/usr/bin/env bash
set -euo pipefail

PROGRAM_COMMON_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUNDLE_ROOT="$(cd "$PROGRAM_COMMON_DIR/.." && pwd)"
APP_NAME="identity-center"
MANIFEST_FILE="$BUNDLE_ROOT/manifest.json"
ENV_EXAMPLE_FILE="$BUNDLE_ROOT/.env.example"
BACKEND_BIN="$BUNDLE_ROOT/backend/$APP_NAME"
FRONTEND_DIR="$BUNDLE_ROOT/frontend"
DIST_DIR="$FRONTEND_DIR/dist"
CONFIG_DIR="$BUNDLE_ROOT"
DATA_DIR="$BUNDLE_ROOT/data"
RUN_DIR="$BUNDLE_ROOT/run"
LOG_DIR="$RUN_DIR"
PROGRAM_PORT=""
ENV_FILE=""
PID_FILE=""
LOG_FILE=""
ERROR_LOG_FILE=""

program_refresh_layout_paths() {
  ENV_FILE="$CONFIG_DIR/.env"
  PID_FILE="$BUNDLE_ROOT/run/$APP_NAME.pid"
  LOG_FILE="$LOG_DIR/$APP_NAME.log"
  ERROR_LOG_FILE="$LOG_DIR/$APP_NAME.stderr.log"
}

program_apply_layout_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --config-dir)
        [[ $# -ge 2 ]] || program_die "missing value for --config-dir"
        CONFIG_DIR="$2"
        shift 2
        ;;
      --data-dir)
        [[ $# -ge 2 ]] || program_die "missing value for --data-dir"
        DATA_DIR="$2"
        shift 2
        ;;
      --state-dir)
        [[ $# -ge 2 ]] || program_die "missing value for --state-dir"
        RUN_DIR="$2"
        if [[ "$LOG_DIR" == "$BUNDLE_ROOT/run" ]]; then
          LOG_DIR="$RUN_DIR"
        fi
        shift 2
        ;;
      --log-dir)
        [[ $# -ge 2 ]] || program_die "missing value for --log-dir"
        LOG_DIR="$2"
        shift 2
        ;;
      --port)
        [[ $# -ge 2 ]] || program_die "missing value for --port"
        PROGRAM_PORT="$2"
        shift 2
        ;;
      *)
        program_die "unsupported argument: $1"
        ;;
    esac
  done
  program_refresh_layout_paths
}

program_refresh_layout_paths

program_die() {
  echo "[program] $*" >&2
  exit 1
}

program_require_file() {
  local path="$1"
  [[ -f "$path" ]] || program_die "required file not found: $path"
}

program_require_dir() {
  local path="$1"
  [[ -d "$path" ]] || program_die "required directory not found: $path"
}

program_resolve_frontend_dist_dir() {
  local resolved_dist="${FRONTEND_DIST_DIR:-./frontend/dist}"
  if [[ "$resolved_dist" != /* ]]; then
    resolved_dist="$BUNDLE_ROOT/${resolved_dist#./}"
  fi
  DIST_DIR="$resolved_dist"
  export FRONTEND_DIST_DIR
}

program_validate_bundle() {
  program_require_file "$MANIFEST_FILE"
  program_require_file "$ENV_EXAMPLE_FILE"
  [[ -x "$BACKEND_BIN" ]] || program_die "backend binary is not executable: $BACKEND_BIN"
  program_resolve_frontend_dist_dir
  program_require_dir "$DIST_DIR"
  program_require_file "$DIST_DIR/index.html"
}

program_initialize_config() {
  mkdir -p "$(dirname "$ENV_FILE")"
  if [[ ! -f "$ENV_FILE" ]]; then
    cp "$ENV_EXAMPLE_FILE" "$ENV_FILE"
  fi
}

program_set_env_value() {
  local key="$1"
  local value="$2"
  local tmp_file="$ENV_FILE.tmp.$$"
  local found=0

  while IFS= read -r line || [[ -n "$line" ]]; do
    case "$line" in
      "$key="*)
        printf '%s=%s\n' "$key" "$value" >>"$tmp_file"
        found=1
        ;;
      *)
        printf '%s\n' "$line" >>"$tmp_file"
        ;;
    esac
  done <"$ENV_FILE"

  if [[ "$found" -eq 0 ]]; then
    printf '%s=%s\n' "$key" "$value" >>"$tmp_file"
  fi

  mv "$tmp_file" "$ENV_FILE"
}

program_load_env() {
  [[ -f "$ENV_FILE" ]] || program_die "missing .env (copy from .env.example first)"
  set -a
  # shellcheck disable=SC1091
  . "$ENV_FILE"
  set +a
  SERVER_PORT="${SERVER_PORT:-18080}"
  if [[ -n "$PROGRAM_PORT" ]]; then
    SERVER_PORT="$PROGRAM_PORT"
  fi
  AUTH_DB_PATH="${AUTH_DB_PATH:-$DATA_DIR/auth.db}"
  FRONTEND_DIST_DIR="${FRONTEND_DIST_DIR:-./frontend/dist}"
  program_resolve_frontend_dist_dir
  export SERVER_PORT AUTH_DB_PATH FRONTEND_DIST_DIR
}

program_load_env_optional() {
  if [[ -f "$ENV_FILE" ]]; then
    program_load_env
    return
  fi
  SERVER_PORT="${SERVER_PORT:-18080}"
  if [[ -n "$PROGRAM_PORT" ]]; then
    SERVER_PORT="$PROGRAM_PORT"
  fi
  AUTH_DB_PATH="${AUTH_DB_PATH:-$DATA_DIR/auth.db}"
  FRONTEND_DIST_DIR="${FRONTEND_DIST_DIR:-./frontend/dist}"
  program_resolve_frontend_dist_dir
  export SERVER_PORT AUTH_DB_PATH FRONTEND_DIST_DIR
}

program_prepare_runtime_dirs() {
  mkdir -p "$DATA_DIR" "$RUN_DIR" "$LOG_DIR" "$(dirname "$PID_FILE")"
}

program_read_pid() {
  [[ -f "$PID_FILE" ]] || return 1
  local pid
  pid="$(cat "$PID_FILE")"
  [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  printf '%s\n' "$pid"
}

program_backend_running() {
  local pid
  pid="$(program_read_pid)" || return 1
  kill -0 "$pid" >/dev/null 2>&1
}

program_clear_stale_pid() {
  if [[ ! -f "$PID_FILE" ]]; then
    return
  fi

  local pid
  pid="$(program_read_pid || true)"
  if [[ -n "$pid" ]] && kill -0 "$pid" >/dev/null 2>&1; then
    program_die "$APP_NAME is already running with pid $pid"
  fi

  rm -f "$PID_FILE"
}

program_start_backend_daemon() {
  local pid
  local backend_args=(--config-dir "$CONFIG_DIR" --data-dir "$DATA_DIR" --state-dir "$RUN_DIR" --log-dir "$LOG_DIR")
  if [[ -n "$PROGRAM_PORT" ]]; then
    backend_args+=(--port "$PROGRAM_PORT")
  elif [[ -n "${SERVER_PORT:-}" ]]; then
    backend_args+=(--port "$SERVER_PORT")
  fi

  program_clear_stale_pid
  : >"$LOG_FILE"
  : >"$ERROR_LOG_FILE"
  nohup "$BACKEND_BIN" "${backend_args[@]}" >"$LOG_FILE" 2>"$ERROR_LOG_FILE" &
  pid=$!
  printf '%s\n' "$pid" >"$PID_FILE"
  sleep 1
  if ! kill -0 "$pid" >/dev/null 2>&1; then
    rm -f "$PID_FILE"
    program_die "backend failed to start; see $LOG_FILE and $ERROR_LOG_FILE"
  fi

  echo "[program-start] started $APP_NAME in daemon mode (pid=$pid)"
  echo "[program-start] log file: $LOG_FILE"
  echo "[program-start] stderr file: $ERROR_LOG_FILE"
}

program_exec_backend() {
  local backend_args=(--config-dir "$CONFIG_DIR" --data-dir "$DATA_DIR" --state-dir "$RUN_DIR" --log-dir "$LOG_DIR")
  if [[ -n "$PROGRAM_PORT" ]]; then
    backend_args+=(--port "$PROGRAM_PORT")
  elif [[ -n "${SERVER_PORT:-}" ]]; then
    backend_args+=(--port "$SERVER_PORT")
  fi
  exec "$BACKEND_BIN" "${backend_args[@]}"
}

program_stop_backend() {
  if [[ ! -f "$PID_FILE" ]]; then
    echo "[program-stop] pid file not found: $PID_FILE"
    return
  fi

  local pid
  pid="$(program_read_pid || true)"
  [[ -n "$pid" ]] || program_die "pid file must contain a numeric pid: $PID_FILE"

  if ! kill -0 "$pid" >/dev/null 2>&1; then
    rm -f "$PID_FILE"
    echo "[program-stop] process $pid is not running; removed stale pid file"
    return
  fi

  kill "$pid"

  for _ in $(seq 1 30); do
    if ! kill -0 "$pid" >/dev/null 2>&1; then
      rm -f "$PID_FILE"
      echo "[program-stop] stopped $APP_NAME (pid=$pid)"
      return
    fi
    sleep 1
  done

  program_die "process $pid did not stop within 30s"
}
