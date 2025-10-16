#!/bin/bash

set -euo pipefail

AGENT_USER=${NIMBUS_AGENT_USER:-nimbus}
AGENT_GROUP=${NIMBUS_AGENT_GROUP:-$AGENT_USER}
NET_SETUP_SCRIPT=${NIMBUS_AGENT_NETWORK_SETUP_SCRIPT:-}

if [[ $(id -u) -ne 0 ]]; then
  echo "nimbus-privileged-setup: must be run as root" >&2
  exit 1
fi

if [[ -n "${NET_SETUP_SCRIPT}" ]]; then
  if [[ ! -x "${NET_SETUP_SCRIPT}" ]]; then
    echo "nimbus-privileged-setup: network setup script '${NET_SETUP_SCRIPT}' must be executable" >&2
    exit 1
  fi
  "${NET_SETUP_SCRIPT}"
fi

if ! command -v setpriv >/dev/null 2>&1; then
  echo "nimbus-privileged-setup: setpriv is required to drop capabilities" >&2
  exit 1
fi

if ! id -u "${AGENT_USER}" >/dev/null 2>&1; then
  useradd --system --create-home "${AGENT_USER}" >/dev/null 2>&1 || {
    echo "nimbus-privileged-setup: failed to ensure user '${AGENT_USER}' exists" >&2
    exit 1
  }
fi

if [[ $# -eq 0 ]]; then
  set -- python3 -m nimbus.host_agent.main
fi

exec setpriv \
  --reuid="${AGENT_USER}" \
  --regid="${AGENT_GROUP}" \
  --init-groups \
  --no-new-privs \
  --inh-caps=cap_net_admin \
  --ambient-caps=cap_net_admin \
  --bounding-set=cap_net_admin \
  "$@"
