#!/bin/bash

# Setup script for ngrok on Kali Linux
# This script installs ngrok for remote access tunneling

set -euo pipefail

echo "🌐 DARK MATER MCP Server - Ngrok Setup"
echo "======================================"

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    echo "⚠️  Please run this script as a regular user (not root)"
    exit 1
fi

# Function to log messages
log_info() {
    echo "ℹ️  $1"
}

log_success() {
    echo "✅ $1"
}

log_error() {
    echo "❌ $1"
}

# Check if ngrok is already installed
if command -v ngrok &> /dev/null; then
    log_success "Ngrok is already installed"
    ngrok version
    exit 0
fi

log_info "Installing ngrok..."

# Create temporary directory
TEMP_DIR=$(mktemp -d)
cd "$TEMP_DIR"

# Download ngrok
log_info "Downloading ngrok..."
if ! curl -sSL "https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-linux-amd64.zip" -o ngrok.zip; then
    log_error "Failed to download ngrok"
    exit 1
fi

# Extract ngrok
log_info "Extracting ngrok..."
if ! unzip -q ngrok.zip; then
    log_error "Failed to extract ngrok"
    exit 1
fi

# Install ngrok to /usr/local/bin
log_info "Installing ngrok to /usr/local/bin..."
if ! sudo mv ngrok /usr/local/bin/; then
    log_error "Failed to install ngrok"
    exit 1
fi

# Set permissions
sudo chmod +x /usr/local/bin/ngrok

# Clean up
cd /
rm -rf "$TEMP_DIR"

log_success "Ngrok installed successfully!"
ngrok version

echo ""
echo "🔑 Next steps:"
echo "1. Get your auth token from: https://dashboard.ngrok.com/get-started/your-authtoken"
echo "2. Run: sudo dark-mater_kali-mcp start-server"
echo "3. Enter your auth token when prompted"