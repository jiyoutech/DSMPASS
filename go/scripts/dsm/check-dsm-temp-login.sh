#!/bin/sh
set -eu

# The old standalone setpw + sed workflow bypassed account locks and changed SMB
# passwords. Run the coordinated Go integration tests on disposable accounts.
if [ "$#" -ne 1 ] || [ ! -x "$1" ]; then
  echo "Usage: $0 /path/to/dsmpass-helper.test" >&2
  echo "Build the DSM integration binary as described in docs/testing.md." >&2
  echo "The previous username-based password mutation mode is no longer supported." >&2
  exit 2
fi

DSMPASS_DSM_INTEGRATION=1 exec "$1" \
  -test.run '^TestDSMReal(ShadowConcurrentRelayAndRecovery|AccountLockCoordination)$' \
  -test.v
