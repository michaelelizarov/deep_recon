# 🔍 Deep Reconnaissance Automation Tool

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-linux-lightgrey.svg)](https://www.kali.org/)

A production-ready, high-performance Python security reconnaissance framework that automates comprehensive security assessments using 40+ industry-standard tools.

![Deep Recon Tool](https://img.shields.io/badge/Version-2.0-brightgreen)

## ⚠️ Legal Disclaimer

**FOR AUTHORIZED TESTING ONLY**

This tool is designed for security professionals, penetration testers, and bug bounty hunters. You MUST have explicit written permission before scanning any systems you do not own.

✅ **Authorized Use:**
- Your own systems and infrastructure
- Bug bounty programs (within scope)
- Penetration tests with signed contracts
- Security assessments with authorization

❌ **Prohibited:**
- Unauthorized scanning of any systems
- Any illegal activity
- Testing without permission

**You are responsible for complying with all applicable laws.**

---

## 🚀 Features

### Version 2.0 Highlights

- ✅ **40+ Integrated Security Tools** - Comprehensive toolkit
- ✅ **Web-Based GUI** - Beautiful Flask interface at `http://localhost:5000`
- ✅ **3 Scanning Modes** - Default (best tools), Random (variety), Custom (your choice)
- ✅ **Parallel Processing** - 10-20x faster with multi-threading
- ✅ **Professional Reports** - JSON and HTML outputs
- ✅ **Real-time Monitoring** - Watch scans in progress
- ✅ **Flexible Configuration** - Customize everything

### Core Capabilities

| Category | Tools Available |
|----------|----------------|
| 🌐 **DNS Reconnaissance** | Subfinder, Amass, dnsenum, dnsrecon, Assetfinder |
| 📂 **Directory Enumeration** | FFUF, Feroxbuster, Gobuster, Dirsearch, Dirb |
| 🔌 **Port Scanning** | Nmap, Rustscan, Masscan, Naabu, Unicornscan |
| 🚨 **Vulnerability Scanning** | Nuclei, Nikto, WPScan, SQLMap, Dalfox |
| 🔒 **SSL/TLS Testing** | testssl.sh, SSLScan, SSLyze, TLS-Sled |
| 🕷️ **Web Crawling** | Katana, Gospider, Hakrawler, GAU, Waybackurls |

---

## 📋 Prerequisites

- **OS:** Linux (Kali Linux or Ubuntu 20.04+)
- **Python:** 3.8 or higher
- **Privileges:** sudo access for installation
- **Network:** Internet connection
- **Disk Space:** ~1GB for tools

---

## 🛠️ Installation

### Quick Install (Recommended)

```bash
# Clone the repository
git clone https://github.com/yourusername/deep-recon-tool.git
cd deep-recon-tool

# Run the automated installer
sudo ./install_v2.sh

# Verify installation
python3 verify_install.py
```

### Manual Installation

See [INSTALLATION.md](docs/INSTALLATION.md) for detailed manual installation instructions.

---

## 🎯 Quick Start

### Method 1: Web GUI (Easiest)

```bash
# Start the web interface
python3 recon_gui.py

# Open your browser to:
# http://localhost:5000
```

### Method 2: Command Line

```bash
# Basic scan with default tools
python3 deep_recon_v2.py -t example.com

# Fast scan with random tools
python3 deep_recon_v2.py -t example.com --mode random

# Custom scan (configure tools in GUI first)
python3 deep_recon_v2.py -t example.com --mode custom
```

---

## 📊 Usage Examples

### Bug Bounty Hunting
```bash
python3 deep_recon_v2.py -t target.com -w 20 -o bounty_scan
```

### Quick Assessment
```bash
python3 deep_recon_v2.py -t target.com --mode random
```

### Comprehensive Audit
```bash
# Use GUI to select ALL tools, then:
python3 deep_recon_v2.py -t target.com --mode custom -w 15
```

### Batch Scanning
```bash
# Scan multiple targets
python3 batch_scan.py -f targets.txt -w 10 -d 30
```

---

## 📁 Project Structure

```
deep-recon-tool/
├── deep_recon_v2.py          # Main v2.0 scanner (40+ tools)
├── recon_gui.py              # Web-based GUI interface
├── batch_scan.py             # Batch scanning utility
├── verify_install.py         # Installation verification
├── install_v2.sh             # Automated installer
├── requirements.txt          # Python dependencies
├── config_example.json       # Configuration template
├── targets.txt               # Example target list
├── LICENSE                   # MIT License
├── README.md                 # This file
└── docs/                     # Documentation
    ├── QUICKSTART.md         # Quick start guide
    ├── USAGE_GUIDE.md        # Detailed usage examples
    ├── V2_COMPLETE_GUIDE.md  # v2.0 complete guide
    └── INSTALLATION.md       # Installation instructions
```

---

## 🎮 Scanning Modes

### 1. Default Mode (Recommended)
Uses 2-3 best tools per category for reliable results.

```bash
python3 deep_recon_v2.py -t example.com
```

### 2. Random Mode (Experimental)
Randomly selects tools for variety and speed.

```bash
python3 deep_recon_v2.py -t example.com --mode random
```

### 3. Custom Mode (Advanced)
Manually select specific tools via GUI.

```bash
# Configure in GUI, then:
python3 deep_recon_v2.py -t example.com --mode custom
```

---

## 📄 Output Structure

```
recon_results/
└── target_com/
    ├── report.json           # Complete JSON report
    ├── report.html           # Visual HTML dashboard
    ├── dns/                  # DNS results
    ├── ports/                # Port scan results
    ├── web/                  # Web enumeration
    ├── vulns/                # Vulnerabilities found
    ├── ssl/                  # SSL/TLS analysis
    └── raw/                  # Raw tool outputs
```

---

## ⚙️ Configuration

Edit `recon_config.json` or use the Web GUI:

```json
{
  "mode": "default",
  "parallel_workers": 10,
  "selected_tools": {
    "dns_recon": ["subfinder", "amass"],
    "port_scan": ["nmap", "rustscan"],
    "vuln_scan": ["nuclei", "nikto"]
  }
}
```

---

## 🔧 Troubleshooting

### Tools Not Found
```bash
export PATH=$PATH:/root/go/bin
echo 'export PATH=$PATH:/root/go/bin' >> ~/.bashrc
source ~/.bashrc
```

### Permission Errors
```bash
sudo python3 deep_recon_v2.py -t example.com
```

### Update Tools
```bash
nuclei -update-templates
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

See [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) for more help.

---

## 🎓 Documentation

- [📚 Quick Start Guide](docs/QUICKSTART.md)
- [📖 Complete Usage Guide](docs/USAGE_GUIDE.md)
- [🔧 Installation Guide](docs/INSTALLATION.md)
- [❓ Troubleshooting](docs/TROUBLESHOOTING.md)
- [📊 v2.0 Complete Guide](docs/V2_COMPLETE_GUIDE.md)

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📊 Performance

| System | Workers | Scan Time |
|--------|---------|-----------|
| Low-end | 5 | ~10 min |
| Medium | 10 | ~5 min |
| High-end | 20 | ~3 min |

---

## 🌟 Acknowledgments

Built using these excellent open-source tools:
- [ProjectDiscovery](https://projectdiscovery.io) - Nuclei, Subfinder, Katana, HTTPx, Naabu
- [OWASP Amass](https://github.com/OWASP/Amass)
- [Nmap Project](https://nmap.org)
- [FFUF](https://github.com/ffuf/ffuf)
- And many more amazing projects!

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

**Important:** This license does NOT grant permission to scan systems you don't own. Always obtain proper authorization.

---

## 📞 Support

- 🐛 **Issues:** [GitHub Issues](https://github.com/yourusername/deep-recon-tool/issues)
- 📖 **Documentation:** See `docs/` folder
- 💬 **Discussions:** [GitHub Discussions](https://github.com/yourusername/deep-recon-tool/discussions)

---

## 🎯 For Job Seekers

This project demonstrates:
- ✅ Production-quality Python code
- ✅ Full-stack development (CLI + Web GUI)
- ✅ Security tool integration
- ✅ Parallel processing optimization
- ✅ Professional documentation
- ✅ Real-world cybersecurity application

Perfect for showcasing your skills in security engineering, Python development, and software architecture!

---

**Version:** 2.0.0  
**Last Updated:** October 2025  
**Maintained by:** [Your Name]

---

⭐ If you find this tool useful, please give it a star on GitHub!

🔐 Remember: Always hack ethically and legally!
