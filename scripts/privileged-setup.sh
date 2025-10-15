#!/bin/bash
# Privileged setup helper for Nimbus host agent
# Run once at agent startup as root, then drop to unprivileged user

set -e

NIMBUS_USER="${NIMBUS_USER:-nimbus}"
NIMBUS_GROUP="${NIMBUS_GROUP:-nimbus}"

echo "=== Nimbus Privileged Setup ==="

# Create nimbus user if it doesn't exist
if ! id "$NIMBUS_USER" &>/dev/null; then
    echo "Creating user $NIMBUS_USER..."
    useradd -r -s /bin/false -d /var/lib/nimbus "$NIMBUS_USER"
fi

# Create required directories
mkdir -p /var/lib/nimbus
mkdir -p /var/run/nimbus
mkdir -p /srv/jailer
chown -R "$NIMBUS_USER:$NIMBUS_GROUP" /var/lib/nimbus /var/run/nimbus /srv/jailer

# Ensure iproute2 is installed
if ! command -v ip &>/dev/null; then
    echo "ERROR: 'ip' command not found. Install iproute2:" >&2
    echo "  Debian/Ubuntu: apt-get install iproute2" >&2
    echo "  RHEL/CentOS: yum install iproute" >&2
    exit 1
fi

echo "✓ Privileged setup complete"
echo ""
echo "Starting Nimbus host agent with minimal capabilities..."

# Drop privileges and exec into agent with only CAP_NET_ADMIN
exec setpriv \
  --reuid="$NIMBUS_USER" \
  --regid="$NIMBUS_GROUP" \
  --init-groups \
  --inh-caps=-all \
  --ambient-caps=cap_net_admin \
  "$@"
