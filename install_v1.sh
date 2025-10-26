#!/bin/bash
# Deep Reconnaissance Tool - Installation Script
# This script installs all required tools and dependencies

set -e

echo "=========================================="
echo "Deep Recon Tool - Dependency Installer"
echo "=========================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (use sudo)"
    exit 1
fi

# Update system
echo "[+] Updating system packages..."
apt-get update -qq

# Install basic dependencies
echo "[+] Installing basic dependencies..."
apt-get install -y -qq \
    python3 \
    python3-pip \
    git \
    curl \
    wget \
    whois \
    dnsutils \
    nmap \
    nikto \
    xmlstarlet \
    golang-go

# Install Python packages
echo "[+] Installing Python packages..."
pip3 install --quiet --break-system-packages \
    requests \
    urllib3 \
    asyncio

# Install Go-based tools
export GOPATH=/root/go
export PATH=$PATH:$GOPATH/bin

echo "[+] Installing subfinder (subdomain enumeration)..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null || true

echo "[+] Installing httpx (HTTP toolkit)..."
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null || true

echo "[+] Installing nuclei (vulnerability scanner)..."
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null || true

echo "[+] Installing katana (web crawler)..."
go install github.com/projectdiscovery/katana/cmd/katana@latest 2>/dev/null || true

echo "[+] Installing ffuf (web fuzzer)..."
go install github.com/ffuf/ffuf/v2@latest 2>/dev/null || true

# Update nuclei templates
echo "[+] Updating nuclei vulnerability templates..."
nuclei -update-templates -silent 2>/dev/null || true

# Install whatweb (technology detection)
echo "[+] Installing whatweb..."
if [ ! -d "/opt/whatweb" ]; then
    git clone --quiet https://github.com/urbanadventurer/WhatWeb.git /opt/whatweb
fi
ln -sf /opt/whatweb/whatweb /usr/local/bin/whatweb 2>/dev/null || true

# Install sslyze (SSL/TLS scanner)
echo "[+] Installing sslyze..."
pip3 install --quiet --break-system-packages sslyze 2>/dev/null || true

# Download common wordlists
echo "[+] Setting up wordlists..."
mkdir -p /usr/share/wordlists/dirb
if [ ! -f "/usr/share/wordlists/dirb/common.txt" ]; then
    wget -q https://raw.githubusercontent.com/daviddias/node-dirbuster/master/lists/directory-list-2.3-small.txt \
        -O /usr/share/wordlists/dirb/common.txt 2>/dev/null || true
fi

# Create symlinks for Go tools
echo "[+] Creating symlinks for Go tools..."
for tool in subfinder httpx nuclei katana ffuf; do
    if [ -f "$GOPATH/bin/$tool" ]; then
        ln -sf $GOPATH/bin/$tool /usr/local/bin/$tool 2>/dev/null || true
    fi
done

# Verify installations
echo ""
echo "=========================================="
echo "Verifying installations..."
echo "=========================================="

check_tool() {
    if command -v $1 &> /dev/null; then
        echo "✓ $1 installed"
    else
        echo "✗ $1 NOT installed"
    fi
}

check_tool whois
check_tool dig
check_tool nmap
check_tool subfinder
check_tool httpx
check_tool nuclei
check_tool katana
check_tool ffuf
check_tool whatweb
check_tool nikto
check_tool sslyze

echo ""
echo "=========================================="
echo "Installation Complete!"
echo "=========================================="
echo ""
echo "Run the tool with:"
echo "  python3 deep_recon.py -t example.com"
echo ""
echo "For help:"
echo "  python3 deep_recon.py -h"
echo ""
