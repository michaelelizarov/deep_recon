# 🚀 Quick Reference Guide - v2.0

## Installation (60 seconds)
```bash
sudo ./install_v2.sh
```

## Start Web GUI
```bash
python3 recon_gui.py
# Open: http://localhost:5000
```

## Command Line Usage

### Default Mode (Best Tools)
```bash
python3 deep_recon_v2.py -t example.com
```

### Random Mode
```bash
python3 deep_recon_v2.py -t example.com --mode random
```

### Custom Mode
```bash
# First configure in GUI, then:
python3 deep_recon_v2.py -t example.com --mode custom
```

## Tool Categories

| Category | Tools Available |
|----------|----------------|
| DNS | Subfinder⭐, Amass⭐, dnsenum, dnsrecon, Assetfinder |
| Directories | FFUF⭐, Feroxbuster⭐, Gobuster⭐, Dirsearch, Dirb |
| Ports | Nmap⭐, Rustscan⭐, Masscan, Naabu⭐, Unicornscan |
| Vulnerabilities | Nuclei⭐, Nikto⭐, WPScan, SQLMap, Dalfox |
| SSL/TLS | testssl.sh⭐, SSLScan⭐, SSLyze⭐, TLS-Sled, SSL Labs |
| Web Crawl | Katana⭐, Gospider⭐, Hakrawler⭐, GAU, Waybackurls |

⭐ = Used in Default Mode

## Web GUI Tabs

1. **🚀 Quick Scan**
   - Select mode (Default/Random/Custom)
   - Enter target
   - Start scan
   - Monitor progress

2. **🛠️ Tool Configuration**
   - View all 40+ tools
   - Select specific tools
   - See speed/accuracy ratings
   - Save custom config

3. **⚙️ Settings**
   - Parallel workers (1-50)
   - Timeout configuration
   - Performance tuning

4. **ℹ️ About**
   - Tool information
   - Features
   - Legal notices

## Configuration File
`recon_config.json`:
```json
{
  "mode": "default",
  "selected_tools": {
    "dns_recon": ["subfinder", "amass"],
    "port_scan": ["nmap", "rustscan"]
  },
  "parallel_workers": 10
}
```

## Quick Scans

### Fast Scan
```bash
python3 deep_recon_v2.py -t target.com --mode random
```

### Thorough Scan
Use GUI → Select ALL tools → Start Scan

### Specific Category Only
Use GUI → Select only tools from one category

## Output Location
```
recon_results/
└── target_com/
    ├── report.json
    ├── report.html
    ├── dns/
    ├── ports/
    ├── web/
    ├── vulns/
    └── ssl/
```

## Common Commands

### View Results
```bash
firefox recon_results/target_com/report.html
cat recon_results/target_com/report.json | jq
```

### Check Tool Versions
```bash
subfinder -version
nuclei -version
nmap --version
```

### Update Tools
```bash
# Update nuclei templates
nuclei -update-templates

# Reinstall Go tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

## Troubleshooting

### Tools Not Found
```bash
export PATH=$PATH:/root/go/bin
echo 'export PATH=$PATH:/root/go/bin' >> ~/.bashrc
```

### Permission Errors
```bash
sudo python3 deep_recon_v2.py -t target.com
```

### GUI Won't Start
```bash
pip3 install flask --break-system-packages
python3 recon_gui.py
```

## Speed vs Accuracy

### Fastest Tools
- DNS: subfinder, assetfinder
- Dirs: ffuf, feroxbuster  
- Ports: rustscan, masscan
- Vulns: nuclei, dalfox
- SSL: sslyze
- Crawl: katana, gau

### Most Accurate
- DNS: amass, subfinder
- Dirs: ffuf, gobuster
- Ports: nmap, naabu
- Vulns: nuclei, nikto
- SSL: testssl.sh, sslyze
- Crawl: katana, gospider

## Performance Settings

### System Resources
- **Low**: 5 workers
- **Medium**: 10 workers (default)
- **High**: 20 workers
- **Very High**: 50 workers

### Timeouts
- General: 300s
- Port Scan: 600s
- Vuln Scan: 900s

## Quick Tips

1. **First Time**: Use Default Mode
2. **Experimenting**: Use Random Mode
3. **Specific Needs**: Use Custom Mode + GUI
4. **Best Results**: Select ALL tools
5. **Fastest**: Use Random Mode
6. **Monitor Progress**: Use Web GUI

## Help Commands
```bash
python3 deep_recon_v2.py -h
python3 recon_gui.py -h
```

## Web GUI URL
```
http://localhost:5000
http://127.0.0.1:5000
http://YOUR-IP:5000  (accessible from network)
```

## Legal Notice
⚠️ **Always get authorization before scanning!**

## Support
- README_V2.md - Full documentation
- This file - Quick reference
- Tool help: `tool-name -h`

---

**Ready? Start scanning:**
```bash
python3 recon_gui.py
```

🎯 **Happy Hunting!**
