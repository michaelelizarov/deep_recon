# 🚀 Quick Start Guide

## Installation (5 minutes)

### Option 1: Automated (Recommended)
```bash
sudo ./install.sh
```

### Option 2: Docker (Coming Soon)
```bash
docker pull deep-recon-tool
docker run -v $(pwd)/results:/results deep-recon-tool -t example.com
```

### Option 3: Kali Linux (Pre-installed Tools)
```bash
# Most tools are pre-installed in Kali
# Just install Go-based tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/ffuf/ffuf/v2@latest
nuclei -update-templates
```

## First Scan (1 minute)

```bash
# Run your first scan
python3 deep_recon.py -t example.com

# View results
firefox recon_results/example_com/report.html
```

## Understanding Results

### Report Sections

1. **Summary Dashboard** - High-level overview
   - Total subdomains discovered
   - IP addresses identified  
   - Open ports found
   - Vulnerability counts by severity

2. **Vulnerabilities** - Security issues found
   - Critical: Immediate action required
   - High: Address soon
   - Medium: Review and patch
   - Low: Minor issues

3. **Subdomains** - All discovered subdomains
   - Useful for expanding attack surface analysis

4. **Open Ports** - Network services
   - Port number
   - Service type
   - Version information

5. **Technologies** - Software stack
   - Web servers
   - Frameworks
   - CMS systems
   - Programming languages

6. **SSL/TLS** - Certificate analysis
   - Valid certificates
   - Expired certificates
   - Weak cipher suites
   - Protocol issues

7. **Directories** - Web paths discovered
   - Admin panels
   - API endpoints
   - Backup files
   - Configuration files

## Performance Tuning

### Fast Scan (3-5 minutes)
```bash
python3 deep_recon.py -t example.com -w 15
```

### Comprehensive Scan (10-15 minutes)
```bash
python3 deep_recon.py -t example.com -w 20
```

### Network Considerations
- **Good Network**: 10-20 workers
- **Slow Network**: 5-10 workers
- **VPN/Tor**: 3-5 workers

## Common Workflows

### Bug Bounty Program
```bash
# 1. Scan main domain
python3 deep_recon.py -t target.com -o target_recon

# 2. Review subdomains in report
cat target_recon/target_com/dns/subdomains.txt

# 3. Check vulnerabilities
cat target_recon/target_com/report.json | jq '.vulnerabilities'

# 4. Follow up on high/critical findings
```

### Internal Security Audit
```bash
# Scan corporate infrastructure
python3 deep_recon.py -t company.local -w 10

# Review ports and services
# Check for outdated software
# Identify misconfigured SSL/TLS
```

### Penetration Test
```bash
# Initial reconnaissance
python3 deep_recon.py -t target.com -o pentest_recon

# Use results for:
# - Attack surface mapping
# - Vulnerability prioritization
# - Exploitation planning
```

## Tips & Tricks

### 1. Subdomain Expansion
After initial scan, you can manually scan discovered subdomains:
```bash
# Get subdomains from first scan
cat recon_results/example_com/dns/subdomains.txt

# Scan interesting subdomains
python3 deep_recon.py -t admin.example.com
python3 deep_recon.py -t api.example.com
```

### 2. Compare Scans
```bash
# Initial scan
python3 deep_recon.py -t example.com -o scan_day1

# Follow-up scan
python3 deep_recon.py -t example.com -o scan_day7

# Compare results
diff scan_day1/example_com/report.json scan_day7/example_com/report.json
```

### 3. Export Specific Data
```bash
# Export just vulnerabilities
cat recon_results/example_com/report.json | jq '.vulnerabilities' > vulns.json

# Export just subdomains
cat recon_results/example_com/report.json | jq '.subdomains[]' > subdomains.txt

# Export high severity issues
cat recon_results/example_com/report.json | jq '.vulnerabilities[] | select(.severity=="high")' > high_vulns.json
```

### 4. Automate Regular Scans
```bash
# Create cron job for weekly scans
crontab -e

# Add line (runs every Monday at 2 AM):
0 2 * * 1 /usr/bin/python3 /path/to/deep_recon.py -t example.com -o /path/to/weekly_scans/$(date +\%Y-\%m-\%d)
```

## Next Steps

After your first scan:

1. ✅ Review the HTML report thoroughly
2. ✅ Investigate critical and high severity findings
3. ✅ Validate discovered subdomains and services
4. ✅ Document findings professionally
5. ✅ Follow responsible disclosure practices
6. ✅ Expand scope based on initial results

## Getting Help

### Check Installation
```bash
# Verify all tools are installed
which subfinder nuclei katana ffuf whatweb nmap nikto sslyze

# Test individual tools
subfinder -version
nuclei -version
```

### Debug Mode
```bash
# Run with verbose output
python3 deep_recon.py -t example.com 2>&1 | tee scan.log
```

### Common Errors

**"Command not found"**
- Tool not installed or not in PATH
- Run install.sh again or add tools to PATH

**"Permission denied"**
- Need root for raw sockets (nmap)
- Use `sudo python3 deep_recon.py ...`

**"Connection timeout"**
- Network issues or target blocking
- Try with fewer workers: `-w 5`

## Best Practices

✅ **DO**:
- Get written authorization before scanning
- Start with low worker count and increase
- Document your findings professionally
- Report vulnerabilities responsibly
- Keep tools updated regularly

❌ **DON'T**:
- Scan without permission
- Use maximum workers on slow networks
- Ignore timeout warnings
- Share sensitive findings publicly
- Exploit discovered vulnerabilities

---

## Sample Commands Reference

```bash
# Basic scan
python3 deep_recon.py -t example.com

# Fast scan with more workers
python3 deep_recon.py -t example.com -w 20

# Custom output location
python3 deep_recon.py -t example.com -o /tmp/scan_results

# Scan IP directly
python3 deep_recon.py -t 192.168.1.1

# Multiple targets (run separately)
for domain in example.com test.com demo.com; do
    python3 deep_recon.py -t $domain -o scans/$domain
done
```

---

**Ready to start?** Run your first scan now:
```bash
python3 deep_recon.py -t example.com
```

Open the HTML report and explore the findings! 🚀
