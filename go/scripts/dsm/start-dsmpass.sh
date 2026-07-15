#!/bin/sh
set -eu

APP_DIR=${DSMPASS_APP_DIR:-}
if [ -z "$APP_DIR" ]; then
  APP_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
fi

DATA_DIR=${DSMPASS_DATA_DIR:-"$APP_DIR/data"}
RUN_DIR=${DSMPASS_RUN_DIR:-/run/dsmpass}
LISTEN=${DSMPASS_GO_LISTEN:-0.0.0.0:25000}

default_idp_listen() {
  listen_port=${LISTEN##*:}
  idp_port=26000
  if [ "$listen_port" = "$idp_port" ]; then
    idp_port=26001
  fi
  printf '0.0.0.0:%s\n' "$idp_port"
}

IDP_LISTEN=${DSMPASS_IDP_LISTEN:-$(default_idp_listen)}
DATABASE_URL=${DSMPASS_DATABASE_URL:-"sqlite://$DATA_DIR/dsmpass.db"}
HELPER_SOCKET=${DSMPASS_HELPER_SOCKET:-"$RUN_DIR/helper.sock"}
HELPER_HMAC_SECRET=${DSMPASS_HELPER_HMAC_SECRET:-}
FRONTEND_DIST_DIR=${DSMPASS_FRONTEND_DIST_DIR:-"$APP_DIR/frontend/dist"}
TLS_ENABLED=${DSMPASS_TLS_ENABLED:-1}
TLS_CERT_FILE=${DSMPASS_TLS_CERT_FILE:-"$DATA_DIR/tls/server.crt"}
TLS_KEY_FILE=${DSMPASS_TLS_KEY_FILE:-"$DATA_DIR/tls/server.key"}
IDP_TLS_CERT_FILE=${DSMPASS_IDP_TLS_CERT_FILE:-"$DATA_DIR/tls/idp.crt"}
IDP_TLS_KEY_FILE=${DSMPASS_IDP_TLS_KEY_FILE:-"$DATA_DIR/tls/idp.key"}
ADMIN_ALLOWED_CIDRS=${DSMPASS_ADMIN_ALLOWED_CIDRS:-}
IDP_ALLOWED_CIDRS=${DSMPASS_IDP_ALLOWED_CIDRS:-}
BACKEND_RUN_USER=${DSMPASS_BACKEND_RUN_USER:-}

detect_dsm_host() {
  configured=${DSMPASS_DSM_HOST:-${DSMPASS_ACCESS_HOST:-}}
  case "$configured" in
    ""|127.*|localhost)
      ;;
    *)
      printf '%s\n' "$configured"
      return
      ;;
  esac
  if command -v ip >/dev/null 2>&1; then
    detected=$(ip route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.][0-9.]*\).*/\1/p' | sed -n '1p')
    if [ -n "$detected" ] && [ "$detected" != "127.0.0.1" ]; then
      printf '%s\n' "$detected"
      return
    fi
  fi
  if command -v hostname >/dev/null 2>&1; then
    detected=$(hostname -I 2>/dev/null | tr ' ' '\n' | sed -n '/^127\./!{/^[0-9][0-9.]*$/p;}' | sed -n '1p')
    if [ -n "$detected" ]; then
      printf '%s\n' "$detected"
      return
    fi
  fi
  if command -v ifconfig >/dev/null 2>&1; then
    detected=$(ifconfig 2>/dev/null | sed -n 's/.*inet addr:\([0-9.][0-9.]*\).*/\1/p; s/.*inet \([0-9.][0-9.]*\).*/\1/p' | sed '/^127\./d' | sed -n '1p')
    if [ -n "$detected" ]; then
      printf '%s\n' "$detected"
      return
    fi
  fi
  printf '%s\n' "127.0.0.1"
}

DSM_HOST=$(detect_dsm_host)
LISTEN_PORT=${LISTEN##*:}
IDP_LISTEN_PORT=${IDP_LISTEN##*:}
ADMIN_PORTAL_PORT=${DSMPASS_ADMIN_PORTAL_PORT:-25000}
if [ "$LISTEN_PORT" != "$ADMIN_PORTAL_PORT" ] && [ -z "${DSMPASS_ADMIN_REDIRECT_LISTEN:-}" ]; then
  DSMPASS_ADMIN_REDIRECT_LISTEN="0.0.0.0:$ADMIN_PORTAL_PORT"
fi
if [ "$TLS_ENABLED" = "0" ] || [ "$TLS_ENABLED" = "false" ] || [ "$TLS_ENABLED" = "no" ] || [ "$TLS_ENABLED" = "off" ]; then
  DEFAULT_PUBLIC_BASE_URL="http://$DSM_HOST:$IDP_LISTEN_PORT"
  DEFAULT_DSM_REDIRECT_URL="http://$DSM_HOST:5000/"
else
  DEFAULT_PUBLIC_BASE_URL="https://$DSM_HOST:$IDP_LISTEN_PORT"
  DEFAULT_DSM_REDIRECT_URL="https://$DSM_HOST:5001/"
fi
PUBLIC_BASE_URL=${DSMPASS_PUBLIC_BASE_URL:-"$DEFAULT_PUBLIC_BASE_URL"}
DSM_REDIRECT_URL=${DSMPASS_DSM_REDIRECT_URL:-"$DEFAULT_DSM_REDIRECT_URL"}
DSM_LOGIN_API=${DSMPASS_DSM_LOGIN_API:-"${DEFAULT_DSM_REDIRECT_URL%/}/webapi/entry.cgi"}

if [ -z "$HELPER_HMAC_SECRET" ]; then
  echo "DSMPASS_HELPER_HMAC_SECRET is required" >&2
  echo "generate one with: openssl rand -hex 32" >&2
  exit 1
fi

mkdir -p "$APP_DIR/bin" "$DATA_DIR" "$RUN_DIR" "$RUN_DIR/locks"

chmod +x "$APP_DIR/start-dsmpass.sh" 2>/dev/null || true
chmod +x "$APP_DIR/bin/dsmpass-backend" 2>/dev/null || true
chmod +x "$APP_DIR/bin/dsmpass-helper" 2>/dev/null || true

export DSMPASS_GO_LISTEN="$LISTEN"
export DSMPASS_IDP_LISTEN="$IDP_LISTEN"
export DSMPASS_DATABASE_URL="$DATABASE_URL"
export DSMPASS_DATA_DIR="$DATA_DIR"
export DSMPASS_FRONTEND_DIST_DIR="$FRONTEND_DIST_DIR"
export DSMPASS_HELPER_SOCKET="$HELPER_SOCKET"
export DSMPASS_HELPER_HMAC_SECRET="$HELPER_HMAC_SECRET"
export DSMPASS_ACCESS_HOST="$DSM_HOST"
export DSMPASS_ADMIN_REDIRECT_LISTEN="${DSMPASS_ADMIN_REDIRECT_LISTEN:-}"
export DSMPASS_TLS_ENABLED="$TLS_ENABLED"
export DSMPASS_TLS_CERT_FILE="$TLS_CERT_FILE"
export DSMPASS_TLS_KEY_FILE="$TLS_KEY_FILE"
export DSMPASS_IDP_TLS_CERT_FILE="$IDP_TLS_CERT_FILE"
export DSMPASS_IDP_TLS_KEY_FILE="$IDP_TLS_KEY_FILE"
[ -n "$ADMIN_ALLOWED_CIDRS" ] && export DSMPASS_ADMIN_ALLOWED_CIDRS="$ADMIN_ALLOWED_CIDRS"
[ -n "$IDP_ALLOWED_CIDRS" ] && export DSMPASS_IDP_ALLOWED_CIDRS="$IDP_ALLOWED_CIDRS"
if [ -n "${DSMPASS_PUBLIC_BASE_URL:-}" ]; then
  export DSMPASS_PUBLIC_BASE_URL="$PUBLIC_BASE_URL"
fi
export DSMPASS_DSM_REDIRECT_URL="$DSM_REDIRECT_URL"
export DSMPASS_DSM_LOGIN_API="$DSM_LOGIN_API"

if [ ! -x "$APP_DIR/bin/dsmpass-backend" ]; then
  echo "missing executable: $APP_DIR/bin/dsmpass-backend" >&2
  exit 1
fi

if [ ! -x "$APP_DIR/bin/dsmpass-helper" ]; then
  echo "missing executable: $APP_DIR/bin/dsmpass-helper" >&2
  exit 1
fi

if [ -x "$APP_DIR/helper-control.sh" ]; then
  chmod +x "$APP_DIR/helper-control.sh" 2>/dev/null || true
fi

run_backend() {
  if [ "$(id -u)" = "0" ] && [ -n "$BACKEND_RUN_USER" ] && [ "$BACKEND_RUN_USER" != "root" ] && id "$BACKEND_RUN_USER" >/dev/null 2>&1; then
    backend_env="$RUN_DIR/backend.env"
    cat > "$backend_env" <<EOF
export DSMPASS_GO_LISTEN='$DSMPASS_GO_LISTEN'
export DSMPASS_IDP_LISTEN='$DSMPASS_IDP_LISTEN'
export DSMPASS_DATABASE_URL='$DSMPASS_DATABASE_URL'
export DSMPASS_DATA_DIR='$DSMPASS_DATA_DIR'
export DSMPASS_FRONTEND_DIST_DIR='$DSMPASS_FRONTEND_DIST_DIR'
export DSMPASS_HELPER_SOCKET='$DSMPASS_HELPER_SOCKET'
export DSMPASS_HELPER_HMAC_SECRET='$DSMPASS_HELPER_HMAC_SECRET'
export DSMPASS_ACCESS_HOST='$DSMPASS_ACCESS_HOST'
export DSMPASS_ADMIN_REDIRECT_LISTEN='$DSMPASS_ADMIN_REDIRECT_LISTEN'
export DSMPASS_TLS_ENABLED='$DSMPASS_TLS_ENABLED'
export DSMPASS_TLS_CERT_FILE='$DSMPASS_TLS_CERT_FILE'
export DSMPASS_TLS_KEY_FILE='$DSMPASS_TLS_KEY_FILE'
export DSMPASS_IDP_TLS_CERT_FILE='$DSMPASS_IDP_TLS_CERT_FILE'
export DSMPASS_IDP_TLS_KEY_FILE='$DSMPASS_IDP_TLS_KEY_FILE'
export DSMPASS_ADMIN_ALLOWED_CIDRS='$ADMIN_ALLOWED_CIDRS'
export DSMPASS_IDP_ALLOWED_CIDRS='$IDP_ALLOWED_CIDRS'
export DSMPASS_PUBLIC_BASE_URL='$PUBLIC_BASE_URL'
export DSMPASS_DSM_REDIRECT_URL='$DSMPASS_DSM_REDIRECT_URL'
export DSMPASS_DSM_LOGIN_API='$DSMPASS_DSM_LOGIN_API'
EOF
    chown "$BACKEND_RUN_USER" "$backend_env" 2>/dev/null || true
    chmod 600 "$backend_env" 2>/dev/null || true
    su -s /bin/sh "$BACKEND_RUN_USER" -c ". '$backend_env'; exec '$APP_DIR/bin/dsmpass-backend'"
    return
  fi
  "$APP_DIR/bin/dsmpass-backend"
}

run_helper() {
  if [ "$(id -u)" = "0" ]; then
    "$APP_DIR/bin/dsmpass-helper"
    return
  fi
  if command -v sudo >/dev/null 2>&1; then
    sudo -n -E "$APP_DIR/bin/dsmpass-helper"
    return
  fi
  echo "sudo is required to start helper with DSM account privileges" >&2
  return 1
}

run_backend &
backend_pid=$!

sleep 2

helper_pid=""
if [ -x "$APP_DIR/helper-control.sh" ]; then
  "$APP_DIR/helper-control.sh" start || true
else
  run_helper &
  helper_pid=$!
fi

for _ in 1 2 3 4 5 6 7 8 9 10; do
  [ -S "$HELPER_SOCKET" ] && break
  sleep 1
done
if [ -S "$HELPER_SOCKET" ] && [ "$(id -u)" = "0" ] && [ -n "$BACKEND_RUN_USER" ] && [ "$BACKEND_RUN_USER" != "root" ]; then
  chown "$BACKEND_RUN_USER" "$HELPER_SOCKET" 2>/dev/null || true
  chmod 660 "$HELPER_SOCKET" 2>/dev/null || true
elif [ ! -S "$HELPER_SOCKET" ]; then
  echo "helper socket was not created; run setup-helper-sudo.sh as root and restart Helper from the admin UI" >&2
fi

cleanup() {
  kill "$backend_pid" 2>/dev/null || true
  if [ -x "$APP_DIR/helper-control.sh" ]; then
    "$APP_DIR/helper-control.sh" stop 2>/dev/null || true
  elif [ -n "$helper_pid" ]; then
    kill "$helper_pid" 2>/dev/null || true
  fi
}
trap cleanup INT TERM EXIT

echo "backend listen preference: $LISTEN"
echo "idp listen preference: $IDP_LISTEN"
echo "admin redirect listen: ${DSMPASS_ADMIN_REDIRECT_LISTEN:-disabled}"
echo "frontend: $FRONTEND_DIST_DIR"
echo "database: $DATABASE_URL"
echo "helper socket: $HELPER_SOCKET"
echo "tls enabled: $TLS_ENABLED"
echo "admin tls cert: $TLS_CERT_FILE"
echo "admin tls key: $TLS_KEY_FILE"
echo "idp tls cert: $IDP_TLS_CERT_FILE"
echo "idp tls key: $IDP_TLS_KEY_FILE"
if [ -n "${DSMPASS_PUBLIC_BASE_URL:-}" ]; then
  echo "public base url: $PUBLIC_BASE_URL"
else
  echo "public base url: auto"
fi
echo "dsm redirect url: $DSM_REDIRECT_URL"
echo "dsm login api: $DSM_LOGIN_API"

wait "$backend_pid"
