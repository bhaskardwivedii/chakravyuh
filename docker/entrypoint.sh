#!/bin/sh
# Lane entrypoint: plant this lane's unique canary secret, then exec the role.
#
# The canary is a per-run random token written to the lane's private secret
# mount (/secrets/<lane>.canary) and exported in-process. The canary probe suite
# (probes/canary.py) later tries to read these from OTHER lanes; any success is
# a proven leak. Because each lane's /secrets is a separate mount and lanes are
# on separate internal networks, a correctly isolated arena yields zero leaks.
set -eu

LANE="${LANE:-unknown}"

if [ -d /secrets ] && [ -w /secrets ]; then
  CANARY="canary-${LANE}-$(head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  echo "$CANARY" > "/secrets/${LANE}.canary" 2>/dev/null || true
  export "$(echo "${LANE}" | tr '[:lower:]' '[:upper:]')_CANARY=$CANARY"
fi

exec "$@"
