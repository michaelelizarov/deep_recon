# Installation Guide

## System Requirements

- **Operating System:** Linux (Kali Linux or Ubuntu 20.04+)
- **Python:** 3.8 or higher
- **Go:** 1.19 or higher (installed by script)
- **Privileges:** Root/sudo access
- **Disk Space:** ~1GB for tools
- **RAM:** 2GB minimum, 4GB recommended

## Automated Installation (Recommended)

The easiest way to install is using the provided script:

```bash
# Clone the repository
git clone https://github.com/yourusername/deep-recon-tool.git
cd deep-recon-tool

# Make the installer executable
chmod +x install_v2.sh

# Run the installer
sudo ./install_v2.sh
```

The installer will:
1. Update system packages
2. Install Python dependencies
3. Install 40+ security tools
4. Configure environment paths
5. Verify installations

## Verification

After installation, verify everything is working:

```bash
python3 verify_install.py
```

This will show which tools are installed and which are missing.

## Manual Installation

If the automated installer doesn't work, follow these steps:

### 1. Update System
```bash
sudo apt-get update
sudo apt-get upgrade -y
```

### 2. Install Base Dependencies
```bash
sudo apt-get install -y python3 python3-pip git curl wget \
    whois dnsutils nmap nikto golang-go build-essential \
    libssl-dev libffi-dev libxml2-dev libxslt1-dev zlib1g-dev
```

### 3. Install Python Packages
```bash
pip3 install --break-system-packages \
    requests urllib3 flask sslyze dirsearch
```

### 4. Install Go Tools
```bash
export GOPATH=/root/go
export PATH=$PATH:$GOPATH/bin

# DNS Tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/owasp-amass/amass/v4/...@master
go install github.com/tomnomnom/assetfinder@latest

# Directory Tools
go install github.com/ffuf/ffuf/v2@latest
go install github.com/OJ/gobuster/v3@latest

# Port Scan Tools
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# Vulnerability Tools
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/hahwul/dalfox/v2@latest

# Web Crawl Tools
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/jaeles-project/gospider@latest
go install github.com/hakluke/hakrawler@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest

# Additional Tools
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/tomnomnom/unfurl@latest
go install github.com/tomnomnom/anew@latest
```

### 5. Install Additional Tools

**testssl.sh:**
```bash
git clone https://github.com/drwetter/testssl.sh.git /opt/testssl
ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl.sh
chmod +x /usr/local/bin/testssl.sh
```

**WhatWeb:**
```bash
git clone https://github.com/urbanadventurer/WhatWeb.git /opt/whatweb
ln -s /opt/whatweb/whatweb /usr/local/bin/whatweb
```

**Feroxbuster:**
```bash
curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash -s /usr/local/bin
```

**Rustscan:**
```bash
wget https://github.com/RustScan/RustScan/releases/download/2.0.1/rustscan_2.0.1_amd64.deb
sudo dpkg -i rustscan_2.0.1_amd64.deb
```

**Masscan:**
```bash
sudo apt-get install -y masscan
```

**SSLScan:**
```bash
sudo apt-get install -y sslscan
```

### 6. Update Nuclei Templates
```bash
nuclei -update-templates
```

### 7. Configure PATH
```bash
echo 'export GOPATH=/root/go' >> ~/.bashrc
echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.bashrc
source ~/.bashrc
```

## Kali Linux Notes

If you're on Kali Linux, many tools are pre-installed:
- nmap, nikto, sqlmap
- whois, dnsutils
- Most command-line utilities

You mainly need to install the Go-based tools.

## Ubuntu Notes

On Ubuntu, you'll need to install more tools manually as they're not pre-installed like on Kali.

## Common Issues

### Go tools not found
```bash
export PATH=$PATH:/root/go/bin
# Add to ~/.bashrc to make permanent
```

### Permission denied
```bash
sudo chown -R $USER:$USER /root/go
```

### Network timeouts
- Check your internet connection
- Some tools require high bandwidth
- Consider using fewer workers initially

## Docker Installation (Coming Soon)

Docker support is planned for future releases.

## Verification Checklist

After installation, you should have:
- [ ] Python 3.8+
- [ ] All Go tools in PATH
- [ ] Nuclei templates updated
- [ ] Web GUI starts successfully
- [ ] Test scan completes

Run `python3 verify_install.py` to check everything.

## Next Steps

1. Read [QUICKSTART.md](QUICKSTART.md)
2. Try your first scan
3. Explore the Web GUI
4. Read the full documentation

## Support

If you encounter issues:
1. Check [TROUBLESHOOTING.md](TROUBLESHOOTING.md)
2. Verify all prerequisites
3. Try manual installation
4. Open an issue on GitHub
