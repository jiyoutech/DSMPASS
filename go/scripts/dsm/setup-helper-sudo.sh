#!/bin/sh
set -eu

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
if [ "$(id -u)" != "0" ]; then
  echo "setup-helper-sudo.sh must be run as root" >&2
  exit 1
fi

# Bootstrap only from a freshly installed, trusted SPK. The package account is
# never granted sudo access to this installer or to the Helper executable.
exec /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin \
  /var/packages/DSMPASS/target/bin/dsmpass-helper install-helper
