# Troubleshooting Guide

## Common Issues and Solutions

### 1. Tools Not Found in PATH

**Problem:** Commands like `subfinder`, `nuclei`, etc. are not recognized.

**Solution:**
```bash
# Check if Go bin directory exists
ls -la /root/go/bin

# Add to PATH temporarily
export PATH=$PATH:/root/go/bin

# Add to PATH permanently
echo 'export PATH=$PATH:/root/go/bin' >> ~/.bashrc
source ~/.bashrc

# Alternative: Create symlinks
sudo ln -s /root/go/bin/* /usr/local/bin/
```

### 2. Permission Denied Errors

**Problem:** Cannot write to output directory or execute tools.

**Solution:**
```bash
# Run with sudo for tools requiring raw sockets (nmap)
sudo python3 deep_recon_v2.py -t example.com

# Fix output directory permissions
sudo chown -R $USER:$USER recon_results/

# Change output location to user-writable directory
python3 deep_recon_v2.py -t example.com -o ~/scans
```

### 3. Nuclei Templates Missing/Outdated

**Problem:** Nuclei not finding vulnerabilities or showing template errors.

**Solution:**
```bash
# Update templates
nuclei -update-templates

# If that fails, reinstall nuclei
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates

# Check template location
ls -la ~/.nuclei-templates/
```

### 4. Web GUI Won't Start

**Problem:** `python3 recon_gui.py` fails or shows errors.

**Solution:**
```bash
# Install Flask
pip3 install flask --break-system-packages

# Check if port 5000 is in use
sudo netstat -tulpn | grep 5000
sudo lsof -i :5000

# Kill process using port 5000
sudo kill -9 <PID>

# Use a different port (edit recon_gui.py)
# Change: app.run(port=5000) to app.run(port=8080)
```

### 5. Network Timeouts

**Problem:** Scans timing out or tools not connecting.

**Solution:**
```bash
# Test connectivity
ping -c 3 8.8.8.8
curl -I https://google.com

# Reduce workers to avoid overwhelming network
python3 deep_recon_v2.py -t example.com -w 5

# Increase timeouts in config
# Edit recon_config.json:
{
  "timeouts": {
    "general": 600,
    "port_scan": 1200
  }
}
```

### 6. Out of Memory Errors

**Problem:** System runs out of memory during scans.

**Solution:**
```bash
# Check available memory
free -h

# Reduce parallel workers
python3 deep_recon_v2.py -t example.com -w 3

# Close other applications
# Scan in smaller batches
# Consider upgrading RAM
```

### 7. Tool Installation Failures

**Problem:** Specific tools fail to install.

**Solution:**
```bash
# For Go tools:
go clean -cache
go clean -modcache
go install -v <tool-url>@latest

# For Python tools:
pip3 install --upgrade <tool-name> --break-system-packages

# For system tools:
sudo apt-get update
sudo apt-get install --reinstall <tool-name>
```

### 8. Naabu Not Installing

**Problem:** Naabu installation fails (as seen in your output).

**Solution:**
```bash
# Try manual installation
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# Check Go version
go version  # Should be 1.19+

# Update Go if needed
sudo add-apt-repository ppa:longsleep/golang-backports
sudo apt-get update
sudo apt-get install golang-go

# Retry installation
```

### 9. SSL/TLS Verification Errors

**Problem:** Tools fail with SSL certificate errors.

**Solution:**
```bash
# Update CA certificates
sudo apt-get install ca-certificates
sudo update-ca-certificates

# For Python SSL issues
pip3 install --upgrade certifi

# Temporary: Disable SSL verification (not recommended)
# Edit deep_recon_v2.py and add verify=False to requests
```

### 10. Configuration File Issues

**Problem:** Config file not loading or causing errors.

**Solution:**
```bash
# Delete corrupted config
rm recon_config.json

# Tool will create new default config on next run
python3 deep_recon_v2.py -t example.com

# Validate JSON syntax
python3 -m json.tool recon_config.json
```

## Platform-Specific Issues

### Kali Linux

**Issue:** Tools already installed but wrong version
```bash
# Update Kali tools
sudo apt-get update
sudo apt-get upgrade
```

**Issue:** Go path not set
```bash
export GOPATH=/root/go
export PATH=$PATH:$GOPATH/bin
```

### Ubuntu

**Issue:** Missing dependencies
```bash
# Install build essentials
sudo apt-get install build-essential

# Install all dependencies
sudo apt-get install -y python3-dev libssl-dev libffi-dev
```

## Error Messages

### "Command not found"
- Tool not installed or not in PATH
- Solution: Check installation and PATH

### "Permission denied"
- Need sudo or file permissions issue
- Solution: Use sudo or fix permissions

### "Connection timed out"
- Network issue or firewall
- Solution: Check connectivity, reduce workers

### "ModuleNotFoundError"
- Python package not installed
- Solution: pip3 install <package>

### "Tool returned non-zero exit code"
- Tool crashed or error in execution
- Solution: Run tool manually to see error

## Debug Mode

Run tools in verbose mode to see detailed output:

```bash
# Python scripts
python3 -u deep_recon_v2.py -t example.com 2>&1 | tee debug.log

# Individual tools
subfinder -d example.com -v
nuclei -u https://example.com -v
nmap -v example.com
```

## Getting Help

1. **Check Documentation**
   - Read relevant docs in `docs/` folder
   - Check tool-specific documentation

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
   tail -f recon_results/*/raw/*.log
   ```

5. **Search Issues**
   - Check GitHub issues for similar problems
   - Search tool-specific forums

6. **Create Issue**
   - If problem persists, create GitHub issue
   - Include: OS, Python version, error messages, steps to reproduce

## Performance Optimization

### Slow Scans
```bash
# Increase workers (if system can handle it)
python3 deep_recon_v2.py -t example.com -w 20

# Use faster tools (Random mode often faster)
python3 deep_recon_v2.py -t example.com --mode random

# Skip slow scans
# Use GUI to deselect slow tools
```

### High CPU Usage
```bash
# Reduce workers
python3 deep_recon_v2.py -t example.com -w 5

# Nice the process
nice -n 10 python3 deep_recon_v2.py -t example.com
```

### High Memory Usage
```bash
# Reduce workers
# Clear cache
sync; echo 3 > /proc/sys/vm/drop_caches
```

## Clean Reinstall

If all else fails, try a clean reinstall:

```bash
# Remove Go tools
rm -rf /root/go

# Remove Python packages
pip3 uninstall -y requests urllib3 flask sslyze

# Reinstall
cd deep-recon-tool
sudo ./install_v2.sh
```

## Still Having Issues?

1. Join our discussions on GitHub
2. Create a detailed issue
3. Check the tool's official documentation
4. Ask in cybersecurity forums

Remember to always include:
- Your OS and version
- Python version
- Complete error message
- Steps you've already tried
