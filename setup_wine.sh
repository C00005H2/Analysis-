#!/usr/bin/env bash
set -euo pipefail

echo "==> Enabling 32-bit architecture..."
sudo dpkg --add-architecture i386

echo "==> Updating package lists..."
sudo apt-get update -qq

echo "==> Installing Wine, Xvfb, and Xauth..."
sudo apt-get install -y --no-install-recommends \
    wine \
    wine64 \
    wine32 \
    xvfb \
    xauth

echo "==> Wine and Xvfb successfully installed."
wine --version
