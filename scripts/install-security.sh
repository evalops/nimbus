#!/bin/bash
# Install Firecracker security components for Nimbus
set -e

INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
CONFIG_DIR="${CONFIG_DIR:-/etc/nimbus}"
FIRECRACKER_VERSION="${FIRECRACKER_VERSION:-v1.7.0}"

echo "=== Installing Nimbus Security Components ==="
echo "Install directory: $INSTALL_DIR"
echo "Config directory: $CONFIG_DIR"
echo "Firecracker version: $FIRECRACKER_VERSION"
echo ""

# Detect architecture
ARCH=$(uname -m)
if [[ "$ARCH" != "x86_64" && "$ARCH" != "aarch64" ]]; then
    echo "ERROR: Unsupported architecture: $ARCH" >&2
    exit 1
fi

echo "Detected architecture: $ARCH"

# Create directories
sudo mkdir -p "$CONFIG_DIR"
sudo mkdir -p "$INSTALL_DIR"
sudo mkdir -p /srv/jailer
sudo mkdir -p /var/lib/nimbus
sudo mkdir -p /var/run/nimbus

# Download seccomp profile
echo ""
echo "Downloading seccomp profile for $ARCH..."
SECCOMP_FILE="$CONFIG_DIR/seccomp-${ARCH}.json"
SECCOMP_URL="https://raw.githubusercontent.com/firecracker-microvm/firecracker/${FIRECRACKER_VERSION}/resources/seccomp/${ARCH}-unknown-linux-musl.json"

sudo curl -fsSL -o "$SECCOMP_FILE" "$SECCOMP_URL"
echo "✓ Seccomp profile: $SECCOMP_FILE"

# Install privileged setup script
echo ""
echo "Installing privileged setup script..."
sudo cp scripts/privileged-setup.sh "$INSTALL_DIR/nimbus-privileged-setup.sh"
sudo chmod 755 "$INSTALL_DIR/nimbus-privileged-setup.sh"
echo "✓ Setup script: $INSTALL_DIR/nimbus-privileged-setup.sh"

# Create nimbus user
if ! id nimbus &>/dev/null; then
    echo ""
    echo "Creating nimbus user..."
    sudo useradd -r -s /bin/false -d /var/lib/nimbus nimbus
    echo "✓ User created: nimbus"
else
    echo "✓ User already exists: nimbus"
fi

# Set ownership
sudo chown -R nimbus:nimbus /var/lib/nimbus /var/run/nimbus /srv/jailer

# Install systemd service (if systemd is available)
if command -v systemctl &>/dev/null; then
    echo ""
    echo "Installing systemd service..."
    sudo cp deployment/nimbus-agent.service /etc/systemd/system/
    sudo systemctl daemon-reload
    echo "✓ Systemd service installed: nimbus-agent.service"
    echo ""
    echo "To start the service:"
    echo "  sudo systemctl start nimbus-agent"
    echo "  sudo systemctl enable nimbus-agent"
fi

echo ""
echo "=== Installation Complete ==="
echo ""
echo "Add to your .env or /etc/nimbus/agent.env:"
echo "  NIMBUS_JAILER_BIN=/usr/local/bin/jailer"
echo "  NIMBUS_SECCOMP_FILTER=$SECCOMP_FILE"
echo "  NIMBUS_JAILER_UID=$(id -u nimbus)"
echo "  NIMBUS_JAILER_GID=$(id -g nimbus)"
echo "  NIMBUS_JAILER_CHROOT_BASE=/srv/jailer"
echo ""
echo "Security checklist:"
echo "  [ ] Firecracker binary installed"
echo "  [ ] Jailer binary installed"
echo "  [ ] Kernel and rootfs images prepared"
echo "  [ ] Environment variables configured"
echo "  [ ] Agent credentials minted"
