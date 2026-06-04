#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
GO_DIR="$ROOT_DIR/go"
DIST_DIR="$GO_DIR/dist/dsm"
export GOCACHE="${GOCACHE:-$GO_DIR/.gocache}"
export GOMODCACHE="${GOMODCACHE:-$GO_DIR/.gomodcache}"
VERSION=${DSMPASS_VERSION:-}
if [ -z "$VERSION" ]; then
  VERSION=$(sed -n 's/^[[:space:]]*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$ROOT_DIR/frontend/package.json" | sed -n '1p')
fi
if [ -z "$VERSION" ]; then
  VERSION="0.1.0"
fi
case "$VERSION" in
  *[!0-9.]*|''|.*|*.)
    echo "DSMPASS_VERSION must contain only digits and dots for DSM SPK compatibility, got: $VERSION" >&2
    exit 1
    ;;
esac
PACKAGE_NAME=${DSMPASS_SPK_PACKAGE:-DSMPASS}
DISPLAY_NAME=${DSMPASS_SPK_DISPLAYNAME:-"DSM PASS"}
MAINTAINER=${DSMPASS_SPK_MAINTAINER:-"dsm-pass"}
DESCRIPTION=${DSMPASS_SPK_DESCRIPTION:-"Enterprise identity login gateway for Synology DSM."}
SUPPORT_URL=${DSMPASS_SPK_SUPPORT_URL:-"https://github.com/dsm-pass/dsm-pass"}
DEFAULT_MANAGEMENT_PORT=${DSMPASS_DEFAULT_MANAGEMENT_PORT:-25000}
DESKTOP_APP_ID=${DSMPASS_DESKTOP_APP_ID:-"com.dsmpass.DSMPASS"}

case "$DEFAULT_MANAGEMENT_PORT" in
  ''|*[!0-9]*)
    echo "DSMPASS_DEFAULT_MANAGEMENT_PORT must be a number" >&2
    exit 1
    ;;
esac
if [ "$DEFAULT_MANAGEMENT_PORT" -le 1024 ] || [ "$DEFAULT_MANAGEMENT_PORT" -gt 65535 ]; then
  echo "DSMPASS_DEFAULT_MANAGEMENT_PORT must be between 1025 and 65535" >&2
  exit 1
fi

export DSMPASS_VERSION="$VERSION"
"$GO_DIR/scripts/dsm/package-dsm.sh"
cd "$GO_DIR"
GOCACHE="${DSMPASS_ICON_GOCACHE:-$GOCACHE}" go run scripts/dsm/icon-gen.go -out "$DIST_DIR/icons"

checksum_file() {
  if command -v md5sum >/dev/null 2>&1; then
    md5sum "$1" | awk '{print $1}'
  else
    md5 -q "$1"
  fi
}

build_spk() {
  src_dir=$1
  syno_arch=$2
  suffix=$3
  work_dir="$DIST_DIR/spk-$suffix"
  spk_file="$DIST_DIR/${PACKAGE_NAME}-${VERSION}-${suffix}.spk"

  rm -rf "$work_dir" "$spk_file"
  mkdir -p "$work_dir/scripts" "$work_dir/conf" "$work_dir/package/ui/images" "$work_dir/WIZARD_UIFILES"

  cp -R "$src_dir/." "$work_dir/package/"
  mkdir -p "$work_dir/package/ui/images"
  cp "$DIST_DIR/icons/PACKAGE_ICON.PNG" "$work_dir/PACKAGE_ICON.PNG"
  cp "$DIST_DIR/icons/PACKAGE_ICON_256.PNG" "$work_dir/PACKAGE_ICON_256.PNG"
  for icon_size in 16 24 32 48 64 72 256; do
    cp "$DIST_DIR/icons/dsmpass_${icon_size}.png" "$work_dir/package/ui/images/dsmpass_${icon_size}.png"
  done
  cp "$ROOT_DIR/LICENSE" "$work_dir/LICENSE"

  cat > "$work_dir/package/ui/config" <<EOF
{
  ".url": {
    "$DESKTOP_APP_ID": {
      "type": "url",
      "icon": "images/dsmpass_{0}.png",
      "title": "$DISPLAY_NAME",
      "desc": "$DESCRIPTION",
      "url": "/webman/3rdparty/$PACKAGE_NAME/index.html"
    }
  }
}
EOF

  cat > "$work_dir/package/ui/index.html" <<EOF
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>$DISPLAY_NAME</title>
</head>
<body>
  <script>
    (function () {
      var host = window.location.hostname || "127.0.0.1";
      if (host.indexOf(":") !== -1 && host.charAt(0) !== "[") {
        host = "[" + host + "]";
      }
      window.location.replace("https://" + host + ":$DEFAULT_MANAGEMENT_PORT/");
    })();
  </script>
</body>
</html>
EOF

  cat > "$work_dir/conf/privilege" <<'EOF'
{
  "defaults": {
    "run-as": "package"
  }
}
EOF

  cat > "$work_dir/scripts/start-stop-status" <<EOF
#!/bin/sh
set -eu

PACKAGE_NAME="$PACKAGE_NAME"
EOF
  cat >> "$work_dir/scripts/start-stop-status" <<'EOF'
PKGDEST=${SYNOPKG_PKGDEST:-"/var/packages/$PACKAGE_NAME/target"}
PKGVAR=${SYNOPKG_PKGVAR:-"/var/packages/$PACKAGE_NAME/var"}
PIDFILE="$PKGVAR/dsmpass.pid"
LOGFILE="$PKGVAR/dsmpass.log"
ENVFILE="$PKGVAR/dsmpass.env"
RUN_DIR="$PKGVAR/run"

is_running() {
  [ -f "$PIDFILE" ] || return 1
  pid=$(cat "$PIDFILE" 2>/dev/null || true)
  [ -n "$pid" ] || return 1
  kill -0 "$pid" 2>/dev/null
}

load_env() {
  [ -f "$ENVFILE" ] && . "$ENVFILE"
  export DSMPASS_APP_DIR="${DSMPASS_APP_DIR:-$PKGDEST}"
  export DSMPASS_DATA_DIR="${DSMPASS_DATA_DIR:-$PKGVAR/data}"
  export DSMPASS_RUN_DIR="${DSMPASS_RUN_DIR:-$RUN_DIR}"
  export DSMPASS_DATABASE_URL="${DSMPASS_DATABASE_URL:-sqlite://$PKGVAR/data/dsmpass.db}"
  export DSMPASS_FRONTEND_DIST_DIR="${DSMPASS_FRONTEND_DIST_DIR:-$PKGDEST/frontend/dist}"
  export DSMPASS_HELPER_SOCKET="${DSMPASS_HELPER_SOCKET:-$RUN_DIR/helper.sock}"
  export DSMPASS_HELPER_HMAC_SECRET="${DSMPASS_HELPER_HMAC_SECRET:-}"
  export DSMPASS_GO_LISTEN="${DSMPASS_GO_LISTEN:-0.0.0.0:25000}"
  export DSMPASS_ADMIN_PORTAL_PORT="${DSMPASS_ADMIN_PORTAL_PORT:-25000}"
  export DSMPASS_ACCESS_HOST="${DSMPASS_ACCESS_HOST:-}"
  export DSMPASS_TLS_ENABLED="${DSMPASS_TLS_ENABLED:-1}"
  export DSMPASS_TLS_CERT_FILE="${DSMPASS_TLS_CERT_FILE:-$PKGVAR/data/tls/server.crt}"
  export DSMPASS_TLS_KEY_FILE="${DSMPASS_TLS_KEY_FILE:-$PKGVAR/data/tls/server.key}"
  export DSMPASS_IDP_TLS_CERT_FILE="${DSMPASS_IDP_TLS_CERT_FILE:-$PKGVAR/data/tls/idp.crt}"
  export DSMPASS_IDP_TLS_KEY_FILE="${DSMPASS_IDP_TLS_KEY_FILE:-$PKGVAR/data/tls/idp.key}"
  export DSMPASS_ADMIN_ALLOWED_CIDRS="${DSMPASS_ADMIN_ALLOWED_CIDRS:-}"
  export DSMPASS_IDP_ALLOWED_CIDRS="${DSMPASS_IDP_ALLOWED_CIDRS:-}"
  export DSMPASS_DSM_REDIRECT_URL="${DSMPASS_DSM_REDIRECT_URL:-}"
  export DSMPASS_DSM_LOGIN_API="${DSMPASS_DSM_LOGIN_API:-}"
}

sync_installed_admin_port() {
  port=$(printf '%s\n' "${DSMPASS_GO_LISTEN##*:}" | tr -d '[]')
  case "$port" in
    ''|*[!0-9]*)
      return 0
      ;;
  esac
  for info_file in "/var/packages/$PACKAGE_NAME/INFO"; do
    [ -f "$info_file" ] || continue
    tmp="$info_file.tmp.$$"
    if grep -q '^adminport=' "$info_file"; then
      sed "s|^adminport=.*|adminport=\"$port\"|" "$info_file" > "$tmp" || {
        rm -f "$tmp"
        continue
      }
    else
      cat "$info_file" > "$tmp" || {
        rm -f "$tmp"
        continue
      }
      printf 'adminport="%s"\n' "$port" >> "$tmp" || {
        rm -f "$tmp"
        continue
      }
    fi
    cat "$tmp" > "$info_file" || {
      rm -f "$tmp"
      continue
    }
    rm -f "$tmp"
  done
}

schedule_installed_admin_port_sync() {
  port=$(printf '%s\n' "${DSMPASS_GO_LISTEN##*:}" | tr -d '[]')
  case "$port" in
    ''|*[!0-9]*)
      return 0
      ;;
  esac
  nohup sh -c '
package_name=$1
port=$2
for delay in 1 2 3 5 8 13; do
  sleep "$delay"
  info_file="/var/packages/$package_name/INFO"
  [ -f "$info_file" ] || continue
  tmp="$info_file.tmp.$$"
  if grep -q "^adminport=" "$info_file"; then
    sed "s|^adminport=.*|adminport=\"$port\"|" "$info_file" > "$tmp" || {
      rm -f "$tmp"
      continue
    }
  else
    cat "$info_file" > "$tmp" || {
      rm -f "$tmp"
      continue
    }
    printf "adminport=\"%s\"\n" "$port" >> "$tmp" || {
      rm -f "$tmp"
      continue
    }
  fi
  cat "$tmp" > "$info_file" || {
    rm -f "$tmp"
    continue
  }
  rm -f "$tmp"
done
' sh "$PACKAGE_NAME" "$port" >/dev/null 2>&1 &
}

validate_listen_port() {
  port=$(printf '%s\n' "${DSMPASS_GO_LISTEN##*:}" | tr -d '[]')
  case "$port" in
    ''|*[!0-9]*)
      echo "invalid management listen port: $DSMPASS_GO_LISTEN" >&2
      exit 1
      ;;
  esac
  if [ "$port" -le 1024 ] || [ "$port" -gt 65535 ]; then
    echo "management port must be between 1025 and 65535: $port" >&2
    exit 1
  fi
}

render_desktop_launcher() {
  ui_index="$PKGDEST/ui/index.html"
  [ -d "$PKGDEST/ui" ] || return 0
  port=$(printf '%s\n' "${DSMPASS_GO_LISTEN##*:}" | tr -d '[]')
  case "$port" in
    ''|*[!0-9]*)
      return 0
      ;;
  esac
  protocol=https
  case "${DSMPASS_TLS_ENABLED:-1}" in
    0|false|FALSE|no|NO)
      protocol=http
      ;;
  esac
  tmp="$ui_index.tmp.$$"
  if cat > "$tmp" <<EOF_LAUNCHER
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>DSM PASS</title>
</head>
<body>
  <script>
    (function () {
      var host = window.location.hostname || "127.0.0.1";
      if (host.indexOf(":") !== -1 && host.charAt(0) !== "[") {
        host = "[" + host + "]";
      }
      window.location.replace("$protocol://" + host + ":$port/");
    })();
  </script>
</body>
</html>
EOF_LAUNCHER
  then
    mv "$tmp" "$ui_index" 2>/dev/null || rm -f "$tmp"
  else
    rm -f "$tmp"
  fi
}

case "${1:-}" in
  start)
    mkdir -p "$PKGVAR/data" "$PKGVAR/data/tls" "$RUN_DIR/locks"
    chmod 700 "$PKGVAR" "$PKGVAR/data" "$PKGVAR/data/tls" 2>/dev/null || true
    chmod 770 "$RUN_DIR" "$RUN_DIR/locks" 2>/dev/null || true
    load_env
    validate_listen_port
    render_desktop_launcher
    sync_installed_admin_port
    schedule_installed_admin_port_sync
    if is_running; then
      exit 0
    fi
    if [ -z "${DSMPASS_HELPER_HMAC_SECRET:-}" ]; then
      echo "DSMPASS_HELPER_HMAC_SECRET is missing in $ENVFILE" >&2
      exit 1
    fi
    nohup "$PKGDEST/start-dsmpass.sh" >>"$LOGFILE" 2>&1 &
    echo $! > "$PIDFILE"
    sleep 2
    is_running
    ;;
  stop)
    if is_running; then
      pid=$(cat "$PIDFILE")
      kill "$pid" 2>/dev/null || true
      for _ in 1 2 3 4 5 6 7 8 9 10; do
        kill -0 "$pid" 2>/dev/null || break
        sleep 1
      done
      kill "$pid" 2>/dev/null || true
    fi
    rm -f "$PIDFILE"
    ;;
  restart)
    "$0" stop
    "$0" start
    ;;
  status)
    load_env
    render_desktop_launcher
    sync_installed_admin_port
    if is_running; then
      exit 0
    fi
    exit 1
    ;;
  prestart|prestop)
    exit 0
    ;;
  log)
    echo "$LOGFILE"
    ;;
  *)
    echo "Usage: $0 {start|stop|restart|status|log}" >&2
    exit 1
    ;;
esac
EOF

  cat > "$work_dir/scripts/preinst" <<'EOF'
#!/bin/sh
exit 0
EOF

  cat > "$work_dir/scripts/postinst" <<EOF
#!/bin/sh
set -eu

PACKAGE_NAME="$PACKAGE_NAME"
DEFAULT_MANAGEMENT_PORT="$DEFAULT_MANAGEMENT_PORT"
EOF
  cat >> "$work_dir/scripts/postinst" <<'EOF'
PKGDEST=${SYNOPKG_PKGDEST:-"/var/packages/$PACKAGE_NAME/target"}
PKGVAR=${SYNOPKG_PKGVAR:-"/var/packages/$PACKAGE_NAME/var"}
ENVFILE="$PKGVAR/dsmpass.env"
INSTALL_LOG="$PKGVAR/dsmpass-install.log"
management_port_was_provided=false
if [ "${management_port+x}" = "x" ] && [ -n "${management_port:-}" ]; then
  management_port_was_provided=true
fi
management_port=${management_port:-$DEFAULT_MANAGEMENT_PORT}

log_install_status() {
  mkdir -p "$PKGVAR" 2>/dev/null || true
  printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$1" >> "$INSTALL_LOG" 2>/dev/null || true
}

set_env_value() {
  key=$1
  value=$2
  if [ -f "$ENVFILE" ] && grep -q "^$key=" "$ENVFILE"; then
    tmp="$ENVFILE.tmp.$$"
    sed "s|^$key=.*|$key=$value|" "$ENVFILE" > "$tmp"
    cat "$tmp" > "$ENVFILE"
    rm -f "$tmp"
  else
    printf '%s=%s\n' "$key" "$value" >> "$ENVFILE"
  fi
}

current_management_port() {
  port=$(printf '%s\n' "${DSMPASS_GO_LISTEN:-}" | awk -F: '{print $NF}' | tr -d '[]')
  case "$port" in
    ''|*[!0-9]*)
      printf '%s\n' "$management_port"
      ;;
    *)
      printf '%s\n' "$port"
      ;;
  esac
}

sync_installed_admin_port() {
  port=$(current_management_port)
  for info_file in "${SYNOPKG_PKGINFO:-}" "/var/packages/$PACKAGE_NAME/INFO"; do
    [ -n "$info_file" ] || continue
    [ -f "$info_file" ] || continue
    tmp="$info_file.tmp.$$"
    if grep -q '^adminport=' "$info_file"; then
      sed "s|^adminport=.*|adminport=\"$port\"|" "$info_file" > "$tmp" || {
        rm -f "$tmp"
        continue
      }
    else
      cat "$info_file" > "$tmp" || {
        rm -f "$tmp"
        continue
      }
      printf 'adminport="%s"\n' "$port" >> "$tmp" || {
        rm -f "$tmp"
        continue
      }
    fi
    cat "$tmp" > "$info_file" || {
      rm -f "$tmp"
      log_install_status "warning failed_to_update_adminport info=$info_file management_port=$port"
      continue
    }
    rm -f "$tmp"
  done
}

sync_installed_admin_port_later() {
  port=$(current_management_port)
  nohup sh -c '
package_name=$1
port=$2
for delay in 1 2 3 5 8 13; do
  sleep "$delay"
  info_file="/var/packages/$package_name/INFO"
  [ -f "$info_file" ] || continue
  tmp="$info_file.tmp.$$"
  if grep -q "^adminport=" "$info_file"; then
    sed "s|^adminport=.*|adminport=\"$port\"|" "$info_file" > "$tmp" || {
      rm -f "$tmp"
      continue
    }
  else
    cat "$info_file" > "$tmp" || {
      rm -f "$tmp"
      continue
    }
    printf "adminport=\"%s\"\n" "$port" >> "$tmp" || {
      rm -f "$tmp"
      continue
    }
  fi
  cat "$tmp" > "$info_file" || {
    rm -f "$tmp"
    continue
  }
  rm -f "$tmp"
done
' sh "$PACKAGE_NAME" "$port" >/dev/null 2>&1 &
}

render_desktop_launcher() {
  ui_index="$PKGDEST/ui/index.html"
  [ -d "$PKGDEST/ui" ] || return 0
  port=$(current_management_port)
  case "$port" in
    ''|*[!0-9]*)
      return 0
      ;;
  esac
  protocol=https
  case "${DSMPASS_TLS_ENABLED:-1}" in
    0|false|FALSE|no|NO)
      protocol=http
      ;;
  esac
  tmp="$ui_index.tmp.$$"
  if cat > "$tmp" <<EOF_LAUNCHER
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>DSM PASS</title>
</head>
<body>
  <script>
    (function () {
      var host = window.location.hostname || "127.0.0.1";
      if (host.indexOf(":") !== -1 && host.charAt(0) !== "[") {
        host = "[" + host + "]";
      }
      window.location.replace("$protocol://" + host + ":$port/");
    })();
  </script>
</body>
</html>
EOF_LAUNCHER
  then
    mv "$tmp" "$ui_index" 2>/dev/null || rm -f "$tmp"
  else
    rm -f "$tmp"
  fi
}

case "$management_port" in
  ''|*[!0-9]*)
    echo "management_port must be a number" >&2
    exit 1
    ;;
esac
if [ "$management_port" -le 1024 ] || [ "$management_port" -gt 65535 ]; then
  echo "management_port must be between 1025 and 65535" >&2
  exit 1
fi

mkdir -p "$PKGVAR/data" "$PKGVAR/data/tls"
chmod 700 "$PKGVAR" "$PKGVAR/data" "$PKGVAR/data/tls" 2>/dev/null || true

if [ ! -f "$ENVFILE" ]; then
  if command -v openssl >/dev/null 2>&1; then
    secret=$(openssl rand -hex 32)
  else
    secret=$(dd if=/dev/urandom bs=32 count=1 2>/dev/null | od -An -tx1 | tr -d ' \n')
  fi
  cat > "$ENVFILE" <<EOF_ENV
DSMPASS_HELPER_HMAC_SECRET=$secret
DSMPASS_GO_LISTEN=0.0.0.0:$management_port
DSMPASS_ADMIN_PORTAL_PORT=$DEFAULT_MANAGEMENT_PORT
DSMPASS_TLS_ENABLED=1
DSMPASS_TLS_CERT_FILE=$PKGVAR/data/tls/server.crt
DSMPASS_TLS_KEY_FILE=$PKGVAR/data/tls/server.key
DSMPASS_IDP_TLS_CERT_FILE=$PKGVAR/data/tls/idp.crt
DSMPASS_IDP_TLS_KEY_FILE=$PKGVAR/data/tls/idp.key
DSMPASS_ADMIN_ALLOWED_CIDRS=all
DSMPASS_IDP_ALLOWED_CIDRS=all
EOF_ENV
  chmod 600 "$ENVFILE"
else
  if [ "$management_port_was_provided" = "true" ]; then
    set_env_value DSMPASS_GO_LISTEN "0.0.0.0:$management_port"
  fi
  if ! grep -q '^DSMPASS_ADMIN_PORTAL_PORT=' "$ENVFILE"; then
    set_env_value DSMPASS_ADMIN_PORTAL_PORT "$DEFAULT_MANAGEMENT_PORT"
  fi
  if ! grep -q '^DSMPASS_TLS_ENABLED=' "$ENVFILE"; then
    set_env_value DSMPASS_TLS_ENABLED 1
  fi
  if ! grep -q '^DSMPASS_TLS_CERT_FILE=' "$ENVFILE"; then
    set_env_value DSMPASS_TLS_CERT_FILE "$PKGVAR/data/tls/server.crt"
  fi
  if ! grep -q '^DSMPASS_TLS_KEY_FILE=' "$ENVFILE"; then
    set_env_value DSMPASS_TLS_KEY_FILE "$PKGVAR/data/tls/server.key"
  fi
  if ! grep -q '^DSMPASS_IDP_TLS_CERT_FILE=' "$ENVFILE"; then
    set_env_value DSMPASS_IDP_TLS_CERT_FILE "$PKGVAR/data/tls/idp.crt"
  fi
  if ! grep -q '^DSMPASS_IDP_TLS_KEY_FILE=' "$ENVFILE"; then
    set_env_value DSMPASS_IDP_TLS_KEY_FILE "$PKGVAR/data/tls/idp.key"
  fi
  if ! grep -q '^DSMPASS_ADMIN_ALLOWED_CIDRS=' "$ENVFILE"; then
    set_env_value DSMPASS_ADMIN_ALLOWED_CIDRS all
  fi
  if ! grep -q '^DSMPASS_IDP_ALLOWED_CIDRS=' "$ENVFILE"; then
    set_env_value DSMPASS_IDP_ALLOWED_CIDRS all
  fi
  chmod 600 "$ENVFILE"
fi

[ -f "$ENVFILE" ] && . "$ENVFILE"
render_desktop_launcher
sync_installed_admin_port
sync_installed_admin_port_later
log_install_status "install_or_upgrade_success management_port=$management_port provided=$management_port_was_provided"

exit 0
EOF

  cat > "$work_dir/scripts/preuninst" <<'EOF'
#!/bin/sh
exit 0
EOF

  cat > "$work_dir/scripts/postuninst" <<EOF
#!/bin/sh
PACKAGE_NAME="$PACKAGE_NAME"
PKGVAR=\${SYNOPKG_PKGVAR:-"/var/packages/\$PACKAGE_NAME/var"}
APPDATA_DIR="/volume1/@appdata/\$PACKAGE_NAME"
SUDOERS_FILE="/etc/sudoers.d/\$PACKAGE_NAME-helper"

delete_data_selected=false
for value in "\${delete_data:-}" "\${DSMPASS_DELETE_DATA:-}" "\${remove_data:-}"; do
  case "\$value" in
    true|TRUE|yes|YES|1)
      delete_data_selected=true
      ;;
  esac
done

rm -f "\$SUDOERS_FILE" 2>/dev/null || true
if [ -e "\$SUDOERS_FILE" ]; then
  echo "WARNING: failed to remove \$SUDOERS_FILE; remove it manually with: sudo rm -f \$SUDOERS_FILE" >&2
fi

if [ "\$delete_data_selected" = "true" ]; then
  rm -rf "\$PKGVAR" "\$APPDATA_DIR"
fi

exit 0
EOF

  cat > "$work_dir/WIZARD_UIFILES/uninstall_uifile" <<'EOF'
[{
  "step_title": "Remove DSM PASS",
  "items": [{
    "type": "singleselect",
    "desc": "Choose whether to keep configuration, synced identities, logs, and TLS files. After uninstall, SSH into DSM and confirm /etc/sudoers.d/DSMPASS-helper has been removed.",
    "subitems": [{
      "key": "keep_data",
      "desc": "Keep package data",
      "defaultValue": true
    }, {
      "key": "delete_data",
      "desc": "Delete package data",
      "defaultValue": false
    }]
  }]
}]
EOF

  cat > "$work_dir/WIZARD_UIFILES/install_uifile" <<'EOF'
[{
  "step_title": "DSM PASS settings",
  "items": [{
    "type": "textfield",
    "desc": "Management HTTPS port. Use a free port greater than 1024. IDP protocol and IDP port are configured later in the web wizard.",
    "subitems": [{
      "key": "management_port",
      "desc": "Management port",
      "defaultValue": "__DEFAULT_MANAGEMENT_PORT__"
    }]
  }]
}]
EOF
  sed "s|__DEFAULT_MANAGEMENT_PORT__|$DEFAULT_MANAGEMENT_PORT|g" "$work_dir/WIZARD_UIFILES/install_uifile" > "$work_dir/WIZARD_UIFILES/install_uifile.tmp"
  mv "$work_dir/WIZARD_UIFILES/install_uifile.tmp" "$work_dir/WIZARD_UIFILES/install_uifile"

  cat > "$work_dir/WIZARD_UIFILES/install_uifile_chs" <<'EOF'
[{
  "step_title": "DSM PASS 设置",
  "items": [{
    "type": "textfield",
    "desc": "管理后台 HTTPS 端口。请使用一个大于 1024 且未被占用的端口。IDP 协议和 IDP 入口端口会在网页初始化向导里配置。",
    "subitems": [{
      "key": "management_port",
      "desc": "管理端口",
      "defaultValue": "__DEFAULT_MANAGEMENT_PORT__"
    }]
  }]
}]
EOF
  sed "s|__DEFAULT_MANAGEMENT_PORT__|$DEFAULT_MANAGEMENT_PORT|g" "$work_dir/WIZARD_UIFILES/install_uifile_chs" > "$work_dir/WIZARD_UIFILES/install_uifile_chs.tmp"
  mv "$work_dir/WIZARD_UIFILES/install_uifile_chs.tmp" "$work_dir/WIZARD_UIFILES/install_uifile_chs"

  cat > "$work_dir/WIZARD_UIFILES/uninstall_uifile_chs" <<'EOF'
[{
  "step_title": "卸载 DSM PASS",
  "items": [{
    "type": "singleselect",
    "desc": "请选择是否保留配置、同步身份、日志和 TLS 文件。卸载后请通过 SSH 确认 /etc/sudoers.d/DSMPASS-helper 已删除。",
    "subitems": [{
      "key": "keep_data",
      "desc": "保留套件数据",
      "defaultValue": true
    }, {
      "key": "delete_data",
      "desc": "删除套件数据",
      "defaultValue": false
    }]
  }]
}]
EOF

  chmod +x "$work_dir/scripts/start-stop-status" "$work_dir/scripts/preinst" "$work_dir/scripts/postinst" "$work_dir/scripts/preuninst" "$work_dir/scripts/postuninst"
  cp "$work_dir/scripts/postinst" "$work_dir/scripts/postupgrade"
  cp "$work_dir/scripts/preinst" "$work_dir/scripts/preupgrade"
  chmod +x "$work_dir/scripts/preupgrade" "$work_dir/scripts/postupgrade"

  extract_size=$(du -sk "$work_dir/package" | awk '{print $1}')
  COPYFILE_DISABLE=1 tar --format ustar -czf "$work_dir/package.tgz" -C "$work_dir/package" .
  checksum=$(checksum_file "$work_dir/package.tgz")
  rm -rf "$work_dir/package"

  cat > "$work_dir/INFO" <<EOF
package="$PACKAGE_NAME"
version="$VERSION"
os_min_ver="7.0-40000"
arch="$syno_arch"
displayname="$DISPLAY_NAME"
maintainer="$MAINTAINER"
description="$DESCRIPTION"
thirdparty="yes"
startable="yes"
ctl_stop="yes"
ctl_uninstall="yes"
silent_install="yes"
silent_upgrade="yes"
silent_uninstall="no"
install_reboot="no"
support_url="$SUPPORT_URL"
adminprotocol="https"
adminport="$DEFAULT_MANAGEMENT_PORT"
adminurl=""
dsmuidir="ui"
dsmappname="$DESKTOP_APP_ID"
checkport="yes"
precheckstartstop="yes"
offline_install="yes"
extractsize="$extract_size"
checksum="$checksum"
EOF

  COPYFILE_DISABLE=1 tar --format ustar -cf "$spk_file" -C "$work_dir" INFO package.tgz scripts conf WIZARD_UIFILES LICENSE PACKAGE_ICON.PNG PACKAGE_ICON_256.PNG
  echo "$spk_file"
}

amd64_spk=$(build_spk "$DIST_DIR/package-linux-amd64" x86_64 linux-amd64)
arm64_spk=$(build_spk "$DIST_DIR/package-linux-arm64" aarch64 linux-arm64)
(
  cd "$DIST_DIR"
  sha256sum=$(command -v sha256sum || true)
  if [ -n "$sha256sum" ]; then
    sha256sum "$(basename "$amd64_spk")" "$(basename "$arm64_spk")" > SHA256SUMS
  else
    shasum -a 256 "$(basename "$amd64_spk")" "$(basename "$arm64_spk")" > SHA256SUMS
  fi
)

echo "version: $VERSION"
echo "amd64 spk: $amd64_spk"
echo "arm64 spk: $arm64_spk"
echo "sha256: $DIST_DIR/SHA256SUMS"
