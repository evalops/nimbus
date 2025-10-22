#!/usr/bin/env bash
set -euo pipefail

LOG="/var/log/bootstrap-nimbus-agent.log"
exec > >(tee -a "$LOG") 2>&1

echo "[Nimbus agent bootstrap] Installing dependencies..."

sudo yum update -y
sudo yum install -y docker git
sudo systemctl enable docker
sudo systemctl start docker

if ! command -v uv >/dev/null 2>&1; then
  curl -LsSf https://astral.sh/uv/install.sh | sh
  export PATH="$HOME/.local/bin:$PATH"
fi

echo "[Nimbus agent bootstrap] Fetching Nimbus..."
cd /opt
if [ ! -d "nimbus" ]; then
  sudo git clone https://github.com/evalops/nimbus.git
fi
cd nimbus

sudo chown -R ec2-user:ec2-user /opt/nimbus

cat <<'ENV' > /opt/nimbus/agent.env
NIMBUS_AGENT_ID=
NIMBUS_CONTROL_PLANE_URL=https://nimbus.example.com
NIMBUS_CONTROL_PLANE_TOKEN=
NIMBUS_KERNEL_IMAGE=/opt/nimbus/artifacts/kernel
NIMBUS_ROOTFS_IMAGE=/opt/nimbus/artifacts/rootfs.ext4
ENV

sudo su - ec2-user <<'EOS'
set -euo pipefail
cd /opt/nimbus
uv venv .venv
source .venv/bin/activate
uv pip install -e .
mkdir -p artifacts
python scripts/setup_firecracker_assets.py artifacts

cat agent.env | xargs -0

cat <<'SERVICE' > nimbus-agent.service
[Unit]
Description=Nimbus Host Agent
After=network-online.target docker.service
Requires=docker.service

[Service]
Type=simple
EnvironmentFile=/opt/nimbus/agent.env
WorkingDirectory=/opt/nimbus
ExecStart=/opt/nimbus/.venv/bin/python -m nimbus.host_agent
Restart=on-failure

[Install]
WantedBy=multi-user.target
SERVICE

sudo mv nimbus-agent.service /etc/systemd/system/nimbus-agent.service
sudo systemctl daemon-reload
sudo systemctl enable nimbus-agent.service
sudo systemctl start nimbus-agent.service
EOS

echo "[Nimbus agent bootstrap] Completed"
