#!/bin/sh
set -eu

PACKAGE_NAME=${PACKAGE_NAME:-DSMPASS}
PKGDEST=${SYNOPKG_PKGDEST:-"/var/packages/$PACKAGE_NAME/target"}
PKGVAR=${SYNOPKG_PKGVAR:-"/var/packages/$PACKAGE_NAME/var"}
ENVFILE="$PKGVAR/dsmpass.env"
RUN_DIR="${DSMPASS_RUN_DIR:-$PKGVAR/run}"
PIDFILE="$RUN_DIR/helper.pid"
LOGFILE="$PKGVAR/dsmpass.log"

load_env() {
  [ -f "$ENVFILE" ] && . "$ENVFILE"
  export DSMPASS_APP_DIR="${DSMPASS_APP_DIR:-$PKGDEST}"
  export DSMPASS_DATA_DIR="${DSMPASS_DATA_DIR:-$PKGVAR/data}"
  export DSMPASS_RUN_DIR="${DSMPASS_RUN_DIR:-$RUN_DIR}"
  export DSMPASS_DATABASE_URL="${DSMPASS_DATABASE_URL:-sqlite://$PKGVAR/data/dsmpass.db}"
  export DSMPASS_HELPER_SOCKET="${DSMPASS_HELPER_SOCKET:-$RUN_DIR/helper.sock}"
  export DSMPASS_HELPER_HMAC_SECRET="${DSMPASS_HELPER_HMAC_SECRET:-}"
  export DSMPASS_DSM_REDIRECT_URL="${DSMPASS_DSM_REDIRECT_URL:-}"
  export DSMPASS_DSM_LOGIN_API="${DSMPASS_DSM_LOGIN_API:-}"
}

is_running() {
  [ -f "$PIDFILE" ] || return 1
  pid=$(cat "$PIDFILE" 2>/dev/null || true)
  [ -n "$pid" ] || return 1
  kill -0 "$pid" 2>/dev/null
}

require_root() {
  if [ "$(id -u)" != "0" ]; then
    echo "helper-control requires root; run setup-helper-sudo.sh first" >&2
    exit 1
  fi
}

start_root() {
  require_root
  load_env
  helper="$DSMPASS_APP_DIR/bin/dsmpass-helper"
  if [ ! -x "$helper" ]; then
    echo "missing helper executable: $helper" >&2
    exit 1
  fi
  if [ -z "${DSMPASS_HELPER_HMAC_SECRET:-}" ]; then
    echo "DSMPASS_HELPER_HMAC_SECRET is missing in $ENVFILE" >&2
    exit 1
  fi
  if is_running; then
    exit 0
  fi
  mkdir -p "$PKGVAR" "$RUN_DIR" "$RUN_DIR/locks"
  chmod 770 "$RUN_DIR" "$RUN_DIR/locks" 2>/dev/null || true
  rm -f "$DSMPASS_HELPER_SOCKET"
  nohup "$helper" >>"$LOGFILE" 2>&1 &
  echo $! > "$PIDFILE"
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    [ -S "$DSMPASS_HELPER_SOCKET" ] && exit 0
    sleep 1
  done
  echo "helper socket was not created: $DSMPASS_HELPER_SOCKET" >&2
  exit 1
}

stop_root() {
  require_root
  load_env
  if is_running; then
    pid=$(cat "$PIDFILE")
    kill "$pid" 2>/dev/null || true
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      kill -0 "$pid" 2>/dev/null || break
      sleep 1
    done
    kill "$pid" 2>/dev/null || true
  fi
  rm -f "$PIDFILE" "${DSMPASS_HELPER_SOCKET:-}"
}

run_as_root() {
  if [ "$(id -u)" = "0" ]; then
    "$0" "$1-root"
    return
  fi
  if command -v sudo >/dev/null 2>&1; then
    sudo -n -E "$0" "$1-root"
    return
  fi
  echo "sudo is required to manage helper" >&2
  exit 1
}

case "${1:-}" in
  start)
    run_as_root start
    ;;
  stop)
    run_as_root stop
    ;;
  restart)
    run_as_root stop
    run_as_root start
    ;;
  start-root)
    start_root
    ;;
  stop-root)
    stop_root
    ;;
  status)
    if is_running; then
      exit 0
    fi
    exit 1
    ;;
  *)
    echo "usage: $0 {start|stop|restart|status}" >&2
    exit 1
    ;;
esac
