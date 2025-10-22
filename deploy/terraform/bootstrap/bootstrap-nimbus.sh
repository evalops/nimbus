#!/usr/bin/env bash
set -euo pipefail

# Performs first-boot configuration of Nimbus services on an EC2 instance.

LOG="/var/log/bootstrap-nimbus.log"
exec > >(tee -a "$LOG") 2>&1

echo "[Nimbus bootstrap] Installing dependencies..."

sudo yum update -y
sudo yum install -y docker git
sudo systemctl enable docker
sudo systemctl start docker

if ! command -v docker-compose >/dev/null 2>&1; then
  sudo curl -L "https://github.com/docker/compose/releases/download/v2.24.7/docker-compose-linux-x86_64" \
    -o /usr/local/bin/docker-compose
  sudo chmod +x /usr/local/bin/docker-compose
fi

echo "[Nimbus bootstrap] Cloning Nimbus repo..."
cd /opt
if [ ! -d "nimbus" ]; then
  sudo git clone https://github.com/evalops/nimbus.git
fi
cd nimbus

sudo cp compose.env.sample .env
sudo chown ec2-user:ec2-user .env

cat <<ENV | sudo tee -a .env
NIMBUS_PUBLIC_BASE_URL=https://$(curl -s http://169.254.169.254/latest/meta-data/public-hostname)
ENV

echo "[Nimbus bootstrap] Starting services..."
sudo docker-compose pull
sudo docker-compose up -d control-plane cache-proxy docker-cache logging-pipeline web

echo "Bootstrap complete. Check the dashboard at https://$(curl -s http://169.254.169.254/latest/meta-data/public-hostname)"
