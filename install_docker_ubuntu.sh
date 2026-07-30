#!/bin/bash

# ==============================================================================
# Docker Installation Script for Ubuntu
# ==============================================================================
# Instructions for your friend:
# 1. Save this file on your Ubuntu machine as `install_docker.sh`
# 2. Make the script executable by running: chmod +x install_docker.sh
# 3. Run the script with sudo privileges: sudo ./install_docker.sh
# ==============================================================================

echo "Starting Docker installation for Ubuntu..."

echo "[1/8] Updating package manager..."
apt-get update

echo "[2/8] Installing prerequisites..."
apt-get install -y ca-certificates curl

echo "[3/8] Creating directory for security keys..."
install -m 0755 -d /etc/apt/keyrings

echo "[4/8] Fetching Docker's official GPG key..."
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc

echo "[5/8] Making the GPG key readable..."
chmod a+r /etc/apt/keyrings/docker.asc

echo "[6/8] Adding the official Docker repository to APT sources..."
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  tee /etc/apt/sources.list.d/docker.list > /dev/null

echo "[7/8] Updating package index with new repository..."
apt-get update

echo "[8/8] Installing Docker Engine and Docker Compose..."
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

echo "=============================================================================="
echo "Docker installation is complete!"
echo "To run Docker commands without 'sudo', please run the following command:"
echo "    sudo usermod -aG docker \$USER"
echo "Then, LOG OUT and LOG BACK IN for the changes to take effect."
echo "=============================================================================="
