#!/bin/sh
set -eu

# Installed in a root-owned directory. Never source package data or inherit
# Helper launch settings from the caller.
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
case "${1:-}" in
  start|stop|restart|status) ;;
  *) echo "usage: $0 {start|stop|restart|status}" >&2; exit 1 ;;
esac
[ "$#" -eq 1 ] || exit 1

if [ "$(id -u)" != "0" ]; then
  exec /usr/bin/sudo -n -- /usr/local/libexec/dsmpass/helper-control.sh "$1"
fi

exec /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin \
  /usr/local/libexec/dsmpass/dsmpass-helper control "$1"
