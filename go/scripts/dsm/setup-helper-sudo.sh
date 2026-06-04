#!/bin/sh
set -eu

PACKAGE_NAME=${DSMPASS_PACKAGE_NAME:-DSMPASS}
PACKAGE_USER=${DSMPASS_PACKAGE_USER:-$PACKAGE_NAME}
PKGDEST=${SYNOPKG_PKGDEST:-"/var/packages/$PACKAGE_NAME/target"}
HELPER="$PKGDEST/bin/dsmpass-helper"
HELPER_CONTROL="$PKGDEST/helper-control.sh"
SUDOERS_DIR="/etc/sudoers.d"
SUDOERS_FILE="$SUDOERS_DIR/$PACKAGE_NAME-helper"

if [ "$(id -u)" != "0" ]; then
  echo "setup-helper-sudo.sh must be run as root" >&2
  exit 1
fi

if [ ! -x "$HELPER" ]; then
  echo "missing helper executable: $HELPER" >&2
  exit 1
fi

if [ ! -x "$HELPER_CONTROL" ]; then
  echo "missing helper control script: $HELPER_CONTROL" >&2
  exit 1
fi

if ! id "$PACKAGE_USER" >/dev/null 2>&1; then
  echo "missing package user: $PACKAGE_USER" >&2
  exit 1
fi

mkdir -p "$SUDOERS_DIR"
tmp_file="$SUDOERS_FILE.tmp"
cat > "$tmp_file" <<EOF
$PACKAGE_USER ALL=(root) NOPASSWD:SETENV: $HELPER, $HELPER_CONTROL
EOF
chmod 0440 "$tmp_file"
chown root:root "$tmp_file" 2>/dev/null || true
mv "$tmp_file" "$SUDOERS_FILE"

echo "installed sudo rule: $SUDOERS_FILE"
