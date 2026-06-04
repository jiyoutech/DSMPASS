#!/bin/sh
set -eu

USER_NAME="${1:-zay}"
DSM_BASE="${2:-http://192.0.2.10:5000}"
SHADOW_PATH="${SHADOW_PATH:-/etc/shadow}"

echo "user=${USER_NAME}"
echo "dsm=${DSM_BASE}"
echo "shadow=${SHADOW_PATH}"

ORIG_LINE="$(grep "^${USER_NAME}:" "$SHADOW_PATH" || true)"
if [ -z "$ORIG_LINE" ]; then
  echo "ERROR: DSM user not found in ${SHADOW_PATH}: ${USER_NAME}" >&2
  exit 1
fi

TMP_PASS="$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 20)"
RESTORED=0

restore_shadow() {
  if [ "$RESTORED" -eq 0 ]; then
    sed -i "s#^${USER_NAME}:.*#${ORIG_LINE}#" "$SHADOW_PATH"
    RESTORED=1
  fi
}

session_check() {
  label="$1"
  sid="$2"
  echo "--- SessionData ${label} ---"
  curl -sS "${DSM_BASE}/webapi/entry.cgi?api=SYNO.Core.Desktop.SessionData&version=1&method=getjs&SynoToken=" \
    -H "Cookie: id=${sid}" | grep "isLogined" || true
}

trap restore_shadow EXIT INT TERM

echo "temp_password_length=${#TMP_PASS}"
echo "--- set temp password ---"
synouser --setpw "$USER_NAME" "$TMP_PASS"

echo "--- login with temp password ---"
LOGIN_BODY="$(curl -sS "${DSM_BASE}/webapi/entry.cgi?api=SYNO.API.Auth&method=login&version=7&account=${USER_NAME}&passwd=${TMP_PASS}&session=webui")"
echo "$LOGIN_BODY"

SID="$(printf '%s' "$LOGIN_BODY" | sed -n 's/.*"sid":"\([^"]*\)".*/\1/p')"
if [ -z "$SID" ]; then
  echo "ERROR: DSM login did not return sid" >&2
  exit 1
fi
echo "sid=${SID}"

session_check "before restore" "$SID"

echo "--- restore shadow ---"
restore_shadow
trap - EXIT INT TERM

session_check "after restore" "$SID"

echo "--- shadow restored check ---"
CURRENT_LINE="$(grep "^${USER_NAME}:" "$SHADOW_PATH" || true)"
if [ "$CURRENT_LINE" = "$ORIG_LINE" ]; then
  echo "shadow_restored=true"
else
  echo "shadow_restored=false"
  exit 2
fi
