#!/bin/bash
# Deep Reconnaissance Tool v2.0 - Enhanced Installation Script
# Installs all required tools (40+ security tools)

set -e

echo "=========================================="
echo "Deep Recon Tool v2.0 - Installer"
echo "=========================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (use sudo)"
    exit 1
fi

# Detect if Kali or Ubuntu
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    OS="unknown"
fi

echo "[+] Detected OS: $OS"

# Update system
echo "[+] Updating system packages..."
apt-get update -qq

# Install basic dependencies
echo "[+] Installing basic dependencies..."
apt-get install -y -qq \
    python3 \
    python3-pip \
    python3-dev \
    python3-venv \
    git \
    curl \
    wget \
    whois \
    dnsutils \
    nmap \
    nikto \
    xmlstarlet \
    golang-go \
    build-essential \
    libssl-dev \
    libffi-dev \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev

# Python packages
echo "[+] Installing Python packages..."
pip3 install --quiet --break-system-packages \
    requests \
    urllib3 \
    flask \
    sslyze \
    dirsearch 2>/dev/null || true

# Setup Go environment
export GOPATH=/root/go
export PATH=$PATH:$GOPATH/bin
mkdir -p $GOPATH/bin

echo "[+] Go environment: $GOPATH"

# Install DNS reconnaissance tools
echo ""
echo "=== Installing DNS Reconnaissance Tools ==="
echo "[+] Installing subfinder..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null || true

echo "[+] Installing amass..."
go install -v github.com/owasp-amass/amass/v4/...@master 2>/dev/null || true

echo "[+] Installing assetfinder..."
go install github.com/tomnomnom/assetfinder@latest 2>/dev/null || true

if [ "$OS" != "kali" ]; then
    echo "[+] Installing dnsenum..."
    apt-get install -y -qq dnsenum 2>/dev/null || true
    
    echo "[+] Installing dnsrecon..."
    apt-get install -y -qq dnsrecon 2>/dev/null || true
fi

# Install directory brute-forcing tools
echo ""
echo "=== Installing Directory Brute-forcing Tools ==="
echo "[+] Installing ffuf..."
go install github.com/ffuf/ffuf/v2@latest 2>/dev/null || true

echo "[+] Installing feroxbuster..."
curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash -s /usr/local/bin 2>/dev/null || true

echo "[+] Installing gobuster..."
go install github.com/OJ/gobuster/v3@latest 2>/dev/null || true

if [ "$OS" != "kali" ]; then
    echo "[+] Installing dirb..."
    apt-get install -y -qq dirb 2>/dev/null || true
fi

# Install port scanning tools
echo ""
echo "=== Installing Port Scanning Tools ==="
echo "[+] Nmap already installed"

echo "[+] Installing rustscan..."
wget -q https://github.com/RustScan/RustScan/releases/download/2.0.1/rustscan_2.0.1_amd64.deb -O /tmp/rustscan.deb 2>/dev/null || true
dpkg -i /tmp/rustscan.deb 2>/dev/null || true
apt-get install -f -y -qq 2>/dev/null || true
rm -f /tmp/rustscan.deb

echo "[+] Installing masscan..."
apt-get install -y -qq masscan 2>/dev/null || true

echo "[+] Installing naabu..."
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest 2>/dev/null || true

if [ "$OS" != "kali" ]; then
    echo "[+] Installing unicornscan..."
    apt-get install -y -qq unicornscan 2>/dev/null || true
fi

# Install vulnerability scanning tools
echo ""
echo "=== Installing Vulnerability Scanning Tools ==="
echo "[+] Installing nuclei..."
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null || true

echo "[+] Updating nuclei templates..."
nuclei -update-templates -silent 2>/dev/null || true

echo "[+] Nikto already installed"

if [ "$OS" = "kali" ]; then
    echo "[+] Installing wpscan..."
    gem install wpscan 2>/dev/null || true
    
    echo "[+] Installing sqlmap..."
    apt-get install -y -qq sqlmap 2>/dev/null || true
fi

echo "[+] Installing dalfox..."
go install github.com/hahwul/dalfox/v2@latest 2>/dev/null || true

# Install SSL/TLS testing tools
echo ""
echo "=== Installing SSL/TLS Testing Tools ==="
echo "[+] Installing testssl.sh..."
if [ ! -d "/opt/testssl" ]; then
    git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl 2>/dev/null || true
    ln -sf /opt/testssl/testssl.sh /usr/local/bin/testssl.sh 2>/dev/null || true
    chmod +x /usr/local/bin/testssl.sh 2>/dev/null || true
fi

echo "[+] Installing sslscan..."
apt-get install -y -qq sslscan 2>/dev/null || true

echo "[+] SSLyze already installed via pip"

# Install web crawling tools
echo ""
echo "=== Installing Web Crawling Tools ==="
echo "[+] Installing katana..."
go install github.com/projectdiscovery/katana/cmd/katana@latest 2>/dev/null || true

echo "[+] Installing gospider..."
go install github.com/jaeles-project/gospider@latest 2>/dev/null || true

echo "[+] Installing hakrawler..."
go install github.com/hakluke/hakrawler@latest 2>/dev/null || true

echo "[+] Installing gau..."
go install github.com/lc/gau/v2/cmd/gau@latest 2>/dev/null || true

echo "[+] Installing waybackurls..."
go install github.com/tomnomnom/waybackurls@latest 2>/dev/null || true

# Install additional tools
echo ""
echo "=== Installing Additional Tools ==="
echo "[+] Installing httpx..."
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null || true

echo "[+] Installing whatweb..."
if [ ! -d "/opt/whatweb" ]; then
    git clone --quiet https://github.com/urbanadventurer/WhatWeb.git /opt/whatweb 2>/dev/null || true
    ln -sf /opt/whatweb/whatweb /usr/local/bin/whatweb 2>/dev/null || true
    chmod +x /usr/local/bin/whatweb 2>/dev/null || true
fi

echo "[+] Installing paramspider..."
if [ ! -d "/opt/paramspider" ]; then
    git clone --quiet https://github.com/devanshbatham/ParamSpider /opt/paramspider 2>/dev/null || true
    pip3 install -r /opt/paramspider/requirements.txt --break-system-packages 2>/dev/null || true
fi

echo "[+] Installing unfurl..."
go install github.com/tomnomnom/unfurl@latest 2>/dev/null || true

echo "[+] Installing anew..."
go install -v github.com/tomnomnom/anew@latest 2>/dev/null || true

echo "[+] Installing gf (patterns)..."
go install github.com/tomnomnom/gf@latest 2>/dev/null || true

echo "[+] Installing arjun..."
pip3 install arjun --break-system-packages 2>/dev/null || true

echo "[+] Installing kxss..."
go install github.com/Emoe/kxss@latest 2>/dev/null || true

echo "[+] Installing shuffledns..."
go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest 2>/dev/null || true

echo "[+] Installing puredns..."
go install github.com/d3mondev/puredns/v2@latest 2>/dev/null || true

echo "[+] Installing httprobe..."
go install github.com/tomnomnom/httprobe@latest 2>/dev/null || true

echo "[+] Installing meg..."
go install github.com/tomnomnom/meg@latest 2>/dev/null || true

echo "[+] Installing subzy..."
go install -v github.com/LukaSikic/subzy@latest 2>/dev/null || true

echo "[+] Installing subjack..."
go install github.com/haccer/subjack@latest 2>/dev/null || true

# Setup wordlists
echo ""
echo "[+] Setting up wordlists..."
mkdir -p /usr/share/wordlists/dirb

if [ ! -f "/usr/share/wordlists/dirb/common.txt" ]; then
    wget -q https://raw.githubusercontent.com/daviddias/node-dirbuster/master/lists/directory-list-2.3-small.txt \
        -O /usr/share/wordlists/dirb/common.txt 2>/dev/null || true
fi

# Install SecLists if not present
if [ ! -d "/usr/share/seclists" ] && [ "$OS" != "kali" ]; then
    echo "[+] Installing SecLists..."
    git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists 2>/dev/null || true
fi

# Create symlinks for Go tools
echo ""
echo "[+] Creating symlinks for Go tools..."
for tool in subfinder amass assetfinder ffuf feroxbuster gobuster naabu nuclei dalfox \
            katana gospider hakrawler gau waybackurls httpx unfurl anew gf arjun kxss \
            shuffledns puredns httprobe meg subzy subjack rustscan; do
    if [ -f "$GOPATH/bin/$tool" ]; then
        ln -sf $GOPATH/bin/$tool /usr/local/bin/$tool 2>/dev/null || true
    fi
done

# Add Go bin to PATH permanently
if ! grep -q "GOPATH" /etc/profile; then
    echo "export GOPATH=/root/go" >> /etc/profile
    echo "export PATH=\$PATH:\$GOPATH/bin" >> /etc/profile
fi

if ! grep -q "GOPATH" ~/.bashrc; then
    echo "export GOPATH=/root/go" >> ~/.bashrc
    echo "export PATH=\$PATH:\$GOPATH/bin" >> ~/.bashrc
fi

# Verify installations
echo ""
echo "=========================================="
echo "Verifying installations..."
echo "=========================================="

check_tool() {
    if command -v $1 &> /dev/null; then
        echo "✓ $1 installed"
        return 0
    else
        echo "✗ $1 NOT installed"
        return 1
    fi
}

# Core tools
check_tool python3
check_tool whois
check_tool dig
check_tool nmap

# DNS recon tools
echo ""
echo "DNS Reconnaissance:"
check_tool subfinder
check_tool amass
check_tool assetfinder
[ "$OS" != "kali" ] && check_tool dnsenum
[ "$OS" != "kali" ] && check_tool dnsrecon

# Directory tools
echo ""
echo "Directory Brute-forcing:"
check_tool ffuf
check_tool feroxbuster
check_tool gobuster

# Port scan tools
echo ""
echo "Port Scanning:"
check_tool rustscan
check_tool masscan
check_tool naabu

# Vuln scan tools
echo ""
echo "Vulnerability Scanning:"
check_tool nuclei
check_tool nikto
check_tool dalfox

# SSL tools
echo ""
echo "SSL/TLS Testing:"
check_tool testssl.sh
check_tool sslscan
check_tool sslyze

# Web crawl tools
echo ""
echo "Web Crawling:"
check_tool katana
check_tool gospider
check_tool hakrawler
check_tool gau
check_tool waybackurls

# Additional tools
echo ""
echo "Additional Tools:"
check_tool httpx
check_tool whatweb
check_tool unfurl
check_tool anew

echo ""
echo "=========================================="
echo "Installation Complete!"
echo "=========================================="
echo ""
echo "Run the tool with:"
echo "  python3 deep_recon_v2.py -t example.com"
echo ""
echo "Start Web GUI:"
echo "  python3 recon_gui.py"
echo "  Then open: http://localhost:5000"
echo ""
echo "Modes:"
echo "  --mode default  : Use best tools (recommended)"
echo "  --mode random   : Random tool selection"
echo "  --mode custom   : Use GUI to select specific tools"
echo ""
