# 📖 Deep Recon Tool - Complete Usage Guide

## Table of Contents
1. [Installation](#installation)
2. [Basic Usage](#basic-usage)
3. [Advanced Usage](#advanced-usage)
4. [Batch Scanning](#batch-scanning)
5. [Understanding Results](#understanding-results)
6. [Real-World Examples](#real-world-examples)
7. [Tips & Best Practices](#tips--best-practices)
8. [Troubleshooting](#troubleshooting)

---

## Installation

### Method 1: Automated (Recommended)
```bash
# Make installation script executable
chmod +x install.sh

# Run installer (requires sudo)
sudo ./install.sh

# Verify installation
python3 verify_install.py
```

### Method 2: Manual
```bash
# Install system dependencies
sudo apt-get update
sudo apt-get install -y python3 python3-pip whois dnsutils nmap nikto golang-go

# Install Go tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/ffuf/ffuf/v2@latest

# Update nuclei templates
nuclei -update-templates

# Install Python dependencies
pip3 install sslyze --break-system-packages
```

---

## Basic Usage

### Your First Scan
```bash
# Scan a domain
python3 deep_recon.py -t example.com

# Scan an IP address
python3 deep_recon.py -t 192.168.1.1

# View results
firefox recon_results/example_com/report.html
```

### Command-Line Options
```bash
python3 deep_recon.py -h

Options:
  -t, --target TARGET    Target domain or IP (required)
  -o, --output OUTPUT    Output directory (default: recon_results)
  -w, --workers WORKERS  Max parallel workers (default: 10)
  -h, --help            Show help message
```

---

## Advanced Usage

### Performance Optimization

#### Fast Scan (Low Resource)
```bash
# Use fewer workers for slower systems
python3 deep_recon.py -t example.com -w 5
```

#### High-Speed Scan (Recommended)
```bash
# Use more workers for fast results
python3 deep_recon.py -t example.com -w 15
```

#### Maximum Speed (Powerful Systems)
```bash
# Maximum parallel processing
python3 deep_recon.py -t example.com -w 20
```

### Custom Output Locations

```bash
# Custom output directory
python3 deep_recon.py -t example.com -o /tmp/security_scan

# Organized by date
python3 deep_recon.py -t example.com -o scans/$(date +%Y-%m-%d)

# Per-client organization
python3 deep_recon.py -t client-domain.com -o clients/client-name/recon
```

### Redirecting Output

```bash
# Save terminal output to log file
python3 deep_recon.py -t example.com 2>&1 | tee scan.log

# Silent mode (only errors)
python3 deep_recon.py -t example.com 2>/dev/null

# Verbose logging
python3 deep_recon.py -t example.com -w 10 > detailed.log 2>&1
```

---

## Batch Scanning

### Basic Batch Scan
```bash
# Create target list
cat > targets.txt << EOF
example.com
test.com
demo.com
EOF

# Scan all targets
python3 batch_scan.py -f targets.txt
```

### Advanced Batch Options

```bash
# With custom workers
python3 batch_scan.py -f targets.txt -w 15

# With delay between scans (30 seconds)
python3 batch_scan.py -f targets.txt -d 30

# Continue on errors
python3 batch_scan.py -f targets.txt --continue-on-error

# Custom output location
python3 batch_scan.py -f targets.txt -o batch_results
```

### Creating Target Lists

```bash
# From subdomain enumeration
subfinder -d example.com -silent > targets.txt

# From file with additional domains
cat existing_targets.txt additional.txt > all_targets.txt

# From IP range (using nmap)
nmap -sL 192.168.1.0/24 | grep "Nmap scan" | awk '{print $5}' > ips.txt
```

---

## Understanding Results

### Directory Structure
```
recon_results/
└── example_com/
    ├── report.json          # Machine-readable results
    ├── report.html          # Visual dashboard
    ├── whois/
    │   └── whois.txt       # WHOIS information
    ├── dns/
    │   ├── dns_records.json
    │   └── subdomains.txt
    ├── ports/
    │   └── nmap_*.xml      # Port scan results
    ├── web/
    │   ├── dirs_*.json     # Directory findings
    │   └── crawl_*.txt     # Crawled URLs
    ├── vulns/
    │   ├── nuclei_results.json
    │   └── nikto_*.txt
    ├── ssl/
    │   └── ssl_*.json      # SSL/TLS findings
    └── raw/
        └── *.txt           # Raw tool outputs
```

### JSON Report Structure
```json
{
  "target": "example.com",
  "scan_time": "2025-10-23T14:30:00",
  "whois": { ... },
  "dns": { ... },
  "subdomains": [ ... ],
  "ip_addresses": [ ... ],
  "ports": { ... },
  "directories": [ ... ],
  "technologies": { ... },
  "vulnerabilities": [ ... ],
  "ssl_issues": [ ... ],
  "summary": {
    "total_subdomains": 23,
    "total_ips": 3,
    "open_ports": 8,
    "critical_vulns": 2,
    "high_vulns": 5,
    "medium_vulns": 5,
    "low_vulns": 3
  }
}
```

### Extracting Specific Data

```bash
# Get all subdomains
cat recon_results/example_com/report.json | jq '.subdomains[]'

# Get critical vulnerabilities
cat recon_results/example_com/report.json | jq '.vulnerabilities[] | select(.severity=="critical")'

# Get open ports
cat recon_results/example_com/report.json | jq '.ports'

# Get technologies detected
cat recon_results/example_com/report.json | jq '.technologies'

# Export to CSV (vulnerabilities)
cat recon_results/example_com/report.json | jq -r '.vulnerabilities[] | [.severity, .name, .host] | @csv' > vulns.csv
```

---

## Real-World Examples

### Example 1: Bug Bounty Reconnaissance
```bash
# Initial recon
python3 deep_recon.py -t bugcrowd-target.com -w 20 -o bounty/initial

# Review subdomains
cat bounty/initial/bugcrowd-target_com/dns/subdomains.txt

# Deep scan on interesting subdomains
for subdomain in api admin dev staging; do
    python3 deep_recon.py -t $subdomain.bugcrowd-target.com -o bounty/$subdomain
done

# Check for critical findings
cat bounty/*/report.json | jq '.vulnerabilities[] | select(.severity=="critical")'
```

### Example 2: Corporate Security Audit
```bash
# Scan corporate infrastructure
python3 deep_recon.py -t company.local -w 15 -o audit/company

# Generate executive summary
cat audit/company/company_local/report.json | jq '.summary'

# Export findings for report
cat audit/company/company_local/report.json | jq '.vulnerabilities' > findings.json

# Check SSL/TLS issues
cat audit/company/company_local/report.json | jq '.ssl_issues'
```

### Example 3: Penetration Test Prep
```bash
# Phase 1: Reconnaissance
python3 deep_recon.py -t target-client.com -w 20 -o pentest/recon

# Phase 2: Identify attack vectors
cat pentest/recon/target-client_com/report.json | jq '.ports, .vulnerabilities'

# Phase 3: Enumerate web apps
cat pentest/recon/target-client_com/web/crawl_*.txt

# Phase 4: Technology stack
cat pentest/recon/target-client_com/report.json | jq '.technologies'
```

### Example 4: Continuous Monitoring
```bash
# Daily scan script
cat > daily_scan.sh << 'EOF'
#!/bin/bash
DATE=$(date +%Y-%m-%d)
python3 deep_recon.py -t mycompany.com -o monitoring/$DATE -w 10
# Compare with yesterday
diff monitoring/$(date -d "yesterday" +%Y-%m-%d)/report.json monitoring/$DATE/report.json
EOF

chmod +x daily_scan.sh

# Add to cron (daily at 2 AM)
echo "0 2 * * * /path/to/daily_scan.sh" | crontab -
```

### Example 5: Multi-Target Campaign
```bash
# Create target list
cat > campaign_targets.txt << EOF
target1.com
target2.com
target3.com
target4.com
target5.com
EOF

# Batch scan with delays
python3 batch_scan.py -f campaign_targets.txt -w 15 -d 60 -o campaign_results

# Generate summary report
for dir in campaign_results/*/; do
    echo "=== $(basename $dir) ==="
    cat "$dir/report.json" | jq '.summary'
done > campaign_summary.txt
```

---

## Tips & Best Practices

### Performance Tips

1. **Start with Lower Workers**
   ```bash
   # Test with low workers first
   python3 deep_recon.py -t example.com -w 5
   # Increase if system handles it well
   python3 deep_recon.py -t example.com -w 20
   ```

2. **Monitor System Resources**
   ```bash
   # Run scan and monitor resources
   python3 deep_recon.py -t example.com -w 15 &
   watch -n 1 'top -b -n 1 | head -20'
   ```

3. **Use Screen/Tmux for Long Scans**
   ```bash
   # Start screen session
   screen -S recon_scan
   python3 deep_recon.py -t large-target.com -w 20
   # Detach: Ctrl+A, D
   # Reattach: screen -r recon_scan
   ```

### Security Tips

1. **Always Get Permission**
   ```bash
   # Document authorization
   echo "Authorized scan by: [Your Name]" > scan_authorization.txt
   echo "Date: $(date)" >> scan_authorization.txt
   echo "Target: example.com" >> scan_authorization.txt
   echo "Authority: Bug Bounty Program / Written Contract" >> scan_authorization.txt
   ```

2. **Rate Limiting for Sensitive Targets**
   ```bash
   # Use fewer workers for production systems
   python3 deep_recon.py -t production-site.com -w 5
   ```

3. **Keep Logs for Accountability**
   ```bash
   # Always log scans
   python3 deep_recon.py -t example.com 2>&1 | tee scans/$(date +%Y%m%d_%H%M%S).log
   ```

### Organization Tips

1. **Structured Output**
   ```bash
   # Organize by date and target
   mkdir -p scans/$(date +%Y-%m)
   python3 deep_recon.py -t example.com -o scans/$(date +%Y-%m)/example_com
   ```

2. **Archive Old Scans**
   ```bash
   # Compress old scans
   tar -czf archive/scans_$(date +%Y-%m).tar.gz scans/$(date +%Y-%m)/*
   ```

3. **Compare Scans Over Time**
   ```bash
   # Diff JSON reports
   diff <(jq -S . scan1/report.json) <(jq -S . scan2/report.json)
   ```

---

## Troubleshooting

### Common Issues

#### Issue 1: Tools Not Found
```bash
# Check PATH
echo $PATH

# Add Go binaries
export PATH=$PATH:$HOME/go/bin
export PATH=$PATH:/root/go/bin

# Make permanent
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc

# Or create symlinks
sudo ln -s $HOME/go/bin/* /usr/local/bin/
```

#### Issue 2: Permission Denied
```bash
# Nmap needs root for SYN scans
sudo python3 deep_recon.py -t example.com

# Or fix file permissions
sudo chown -R $USER:$USER recon_results/
chmod -R 755 recon_results/
```

#### Issue 3: Network Timeouts
```bash
# Check connectivity
ping -c 3 example.com

# Test DNS resolution
dig example.com

# Use fewer workers
python3 deep_recon.py -t example.com -w 3
```

#### Issue 4: Nuclei Templates Missing
```bash
# Update templates
nuclei -update-templates

# Check template location
ls -la ~/.nuclei-templates/

# Reinstall if needed
nuclei -update-templates -force
```

#### Issue 5: Out of Memory
```bash
# Check memory
free -h

# Reduce workers
python3 deep_recon.py -t example.com -w 5

# Close other applications
# Or upgrade system RAM
```

### Debug Mode

```bash
# Verbose output
python3 deep_recon.py -t example.com -w 10 2>&1 | tee debug.log

# Check specific tool
subfinder -d example.com -v
nuclei -u https://example.com -v
nmap -v example.com

# Python debugging
python3 -u deep_recon.py -t example.com
```

---

## Automation Examples

### Scheduled Scans

```bash
# Weekly scan (cron)
0 2 * * 1 /usr/bin/python3 /path/to/deep_recon.py -t example.com -o /scans/$(date +\%Y-\%m-\%d)

# Monthly comprehensive scan
0 3 1 * * /usr/bin/python3 /path/to/batch_scan.py -f /path/to/all_targets.txt -w 20 -o /monthly_scans/$(date +\%Y-\%m)
```

### Integration with Other Tools

```bash
# Export to Burp Suite
cat recon_results/example_com/web/crawl_*.txt | sort -u > burp_targets.txt

# Feed to custom exploitation script
cat recon_results/example_com/report.json | jq '.vulnerabilities' | python3 exploit_validator.py

# Send to SIEM
cat recon_results/example_com/report.json | jq -c '.vulnerabilities[]' | kafka-console-producer --topic security-findings
```

---

## Quick Reference

### Most Common Commands
```bash
# Basic scan
python3 deep_recon.py -t example.com

# Fast scan
python3 deep_recon.py -t example.com -w 20

# Custom output
python3 deep_recon.py -t example.com -o /tmp/scan

# Batch scan
python3 batch_scan.py -f targets.txt

# Verify installation
python3 verify_install.py

# Update tools
sudo ./install.sh
nuclei -update-templates
```

### File Locations
```
Tool:              /usr/local/bin/ or $HOME/go/bin/
Results:           recon_results/TARGET/
Logs:              recon_results/TARGET/raw/
Reports:           recon_results/TARGET/report.{json,html}
Wordlists:         /usr/share/wordlists/
```

---

## Getting Help

1. **Check Documentation**
   - README.md - Full documentation
   - QUICKSTART.md - Quick guide
   - This file - Usage examples

2. **Verify Installation**
   ```bash
   python3 verify_install.py
   ```

3. **Test Individual Tools**
   ```bash
   subfinder -version
   nuclei -version
   nmap --version
   ```

4. **Check Logs**
   ```bash
   cat recon_results/example_com/raw/*.log
   ```

5. **Common Solutions**
   - Update tools: `nuclei -update-templates`
   - Fix PATH: `export PATH=$PATH:$HOME/go/bin`
   - Run as root: `sudo python3 deep_recon.py ...`
   - Reduce workers: `-w 5`

---

## Next Steps

1. ✅ Complete installation
2. ✅ Run first scan
3. ✅ Review HTML report
4. ✅ Understand JSON structure
5. ✅ Try batch scanning
6. ✅ Customize for your needs
7. ✅ Integrate into workflow
8. ✅ Automate recurring scans

---

**Happy Hunting! 🎯**

Remember: Always scan responsibly and legally! 🔒
