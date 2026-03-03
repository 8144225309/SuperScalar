#!/bin/bash
# Install Docker Engine directly in WSL Ubuntu 24.04 (lightweight, no Docker Desktop)
# Run this script inside WSL: bash /mnt/c/pirq/superscalar-dev-1/Superscalar/tools/docker-install-wsl.sh

set -e

echo "=== Installing Docker Engine in WSL ==="

# Remove old versions if present
sudo apt-get remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true

# Install prerequisites
sudo apt-get update -qq
sudo apt-get install -y ca-certificates curl gnupg

# Add Docker's GPG key
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

# Add Docker repo
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker Engine (CE only — lightweight)
sudo apt-get update -qq
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin

# Add current user to docker group (avoids sudo for docker commands)
sudo usermod -aG docker $USER

# Start Docker daemon (WSL doesn't use systemd by default)
sudo dockerd &
sleep 3

# Verify
docker run --rm hello-world

echo ""
echo "=== Docker Engine installed successfully ==="
echo "NOTE: After first install, log out and back in (or run 'newgrp docker')"
echo "      to use docker without sudo."
echo ""
echo "To start Docker in future sessions:"
echo "  sudo dockerd &"
echo ""
echo "Or add to ~/.bashrc:"
echo '  if ! pgrep -x dockerd > /dev/null; then sudo dockerd > /dev/null 2>&1 & fi'
