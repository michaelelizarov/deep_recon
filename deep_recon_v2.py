#!/usr/bin/env python3
"""
Deep Reconnaissance Automation Tool v2.0
Multi-tool support with web GUI configuration
Author: Security Research Team
"""

import subprocess
import json
import os
import sys
import asyncio
import argparse
import re
import socket
import random
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# Tool Configuration Database
TOOL_DATABASE = {
    "dns_recon": {
        "name": "DNS Reconnaissance",
        "tools": {
            "subfinder": {
                "name": "Subfinder",
                "cmd": ["subfinder", "-d", "{target}", "-silent", "-o", "{output}"],
                "install": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
                "speed": 5, "accuracy": 5, "recommended": True
            },
            "amass": {
                "name": "Amass",
                "cmd": ["amass", "enum", "-passive", "-d", "{target}", "-o", "{output}"],
                "install": "go install -v github.com/owasp-amass/amass/v4/...@master",
                "speed": 3, "accuracy": 5, "recommended": True
            },
            "dnsenum": {
                "name": "dnsenum",
                "cmd": ["dnsenum", "--noreverse", "-o", "{output}", "{target}"],
                "install": "sudo apt-get install -y dnsenum",
                "speed": 4, "accuracy": 4, "recommended": False
            },
            "dnsrecon": {
                "name": "dnsrecon",
                "cmd": ["dnsrecon", "-d", "{target}", "-t", "std", "-j", "{output}"],
                "install": "sudo apt-get install -y dnsrecon",
                "speed": 4, "accuracy": 4, "recommended": False
            },
            "assetfinder": {
                "name": "Assetfinder",
                "cmd": ["assetfinder", "--subs-only", "{target}"],
                "install": "go install github.com/tomnomnom/assetfinder@latest",
                "speed": 5, "accuracy": 3, "recommended": False
            }
        },
        "default": ["subfinder", "amass"]
    },
    
    "directory_bruteforce": {
        "name": "Directory Brute-forcing",
        "tools": {
            "ffuf": {
                "name": "FFUF",
                "cmd": ["ffuf", "-w", "{wordlist}", "-u", "{target}/FUZZ", "-mc", "200,204,301,302,307,401,403", 
                       "-t", "50", "-timeout", "10", "-o", "{output}", "-of", "json", "-s"],
                "install": "go install github.com/ffuf/ffuf/v2@latest",
                "speed": 5, "accuracy": 5, "recommended": True
            },
            "feroxbuster": {
                "name": "Feroxbuster",
                "cmd": ["feroxbuster", "-u", "{target}", "-w", "{wordlist}", "-t", "50", "-o", "{output}", 
                       "--quiet", "--json"],
                "install": "curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash",
                "speed": 5, "accuracy": 5, "recommended": True
            },
            "gobuster": {
                "name": "Gobuster",
                "cmd": ["gobuster", "dir", "-u", "{target}", "-w", "{wordlist}", "-t", "50", "-o", "{output}", 
                       "-q", "-k"],
                "install": "go install github.com/OJ/gobuster/v3@latest",
                "speed": 4, "accuracy": 4, "recommended": True
            },
            "dirsearch": {
                "name": "Dirsearch",
                "cmd": ["dirsearch", "-u", "{target}", "-w", "{wordlist}", "-t", "50", "-o", "{output}", 
                       "--format=json", "-q"],
                "install": "pip3 install dirsearch --break-system-packages",
                "speed": 4, "accuracy": 4, "recommended": False
            },
            "dirb": {
                "name": "Dirb",
                "cmd": ["dirb", "{target}", "{wordlist}", "-o", "{output}", "-S"],
                "install": "sudo apt-get install -y dirb",
                "speed": 3, "accuracy": 3, "recommended": False
            }
        },
        "default": ["ffuf", "feroxbuster"]
    },
    
    "port_scan": {
        "name": "Port Scanning",
        "tools": {
            "nmap": {
                "name": "Nmap",
                "cmd": ["nmap", "-sS", "-T4", "--top-ports", "1000", "-oX", "{output}", "--open", "{target}"],
                "install": "sudo apt-get install -y nmap",
                "speed": 3, "accuracy": 5, "recommended": True
            },
            "rustscan": {
                "name": "Rustscan",
                "cmd": ["rustscan", "-a", "{target}", "--ulimit", "5000", "-g"],
                "install": "wget https://github.com/RustScan/RustScan/releases/download/2.0.1/rustscan_2.0.1_amd64.deb && sudo dpkg -i rustscan_2.0.1_amd64.deb",
                "speed": 5, "accuracy": 4, "recommended": True
            },
            "masscan": {
                "name": "Masscan",
                "cmd": ["masscan", "{target}", "-p1-65535", "--rate=1000", "-oJ", "{output}"],
                "install": "sudo apt-get install -y masscan",
                "speed": 5, "accuracy": 3, "recommended": False
            },
            "naabu": {
                "name": "Naabu",
                "cmd": ["naabu", "-host", "{target}", "-top-ports", "1000", "-o", "{output}", "-silent"],
                "install": "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
                "speed": 5, "accuracy": 4, "recommended": True
            },
            "unicornscan": {
                "name": "Unicornscan",
                "cmd": ["unicornscan", "-mT", "{target}:a"],
                "install": "sudo apt-get install -y unicornscan",
                "speed": 4, "accuracy": 3, "recommended": False
            }
        },
        "default": ["nmap", "rustscan"]
    },
    
    "vuln_scan": {
        "name": "Vulnerability Scanning",
        "tools": {
            "nuclei": {
                "name": "Nuclei",
                "cmd": ["nuclei", "-l", "{target}", "-severity", "critical,high,medium,low", "-c", "50", 
                       "-json", "-o", "{output}", "-silent"],
                "install": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
                "speed": 4, "accuracy": 5, "recommended": True
            },
            "nikto": {
                "name": "Nikto",
                "cmd": ["nikto", "-h", "{target}", "-o", "{output}", "-Format", "json"],
                "install": "sudo apt-get install -y nikto",
                "speed": 2, "accuracy": 4, "recommended": True
            },
            "wpscan": {
                "name": "WPScan",
                "cmd": ["wpscan", "--url", "{target}", "--format", "json", "-o", "{output}", "--random-user-agent"],
                "install": "gem install wpscan",
                "speed": 3, "accuracy": 5, "recommended": False
            },
            "sqlmap": {
                "name": "SQLMap",
                "cmd": ["sqlmap", "-u", "{target}", "--batch", "--random-agent", "--output-dir={output}"],
                "install": "sudo apt-get install -y sqlmap",
                "speed": 2, "accuracy": 5, "recommended": False
            },
            "dalfox": {
                "name": "Dalfox (XSS)",
                "cmd": ["dalfox", "url", "{target}", "-o", "{output}", "--silence"],
                "install": "go install github.com/hahwul/dalfox/v2@latest",
                "speed": 4, "accuracy": 4, "recommended": False
            }
        },
        "default": ["nuclei", "nikto"]
    },
    
    "ssl_test": {
        "name": "SSL/TLS Testing",
        "tools": {
            "testssl": {
                "name": "testssl.sh",
                "cmd": ["testssl.sh", "--jsonfile", "{output}", "{target}"],
                "install": "git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl && ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl.sh",
                "speed": 2, "accuracy": 5, "recommended": True
            },
            "sslscan": {
                "name": "SSLScan",
                "cmd": ["sslscan", "--show-certificate", "--no-colour", "{target}"],
                "install": "sudo apt-get install -y sslscan",
                "speed": 4, "accuracy": 4, "recommended": True
            },
            "sslyze": {
                "name": "SSLyze",
                "cmd": ["sslyze", "--json_out", "{output}", "{target}"],
                "install": "pip3 install sslyze --break-system-packages",
                "speed": 3, "accuracy": 5, "recommended": True
            },
            "tlssled": {
                "name": "TLS-Sled",
                "cmd": ["tlssled", "{target}", "443"],
                "install": "git clone https://github.com/trimstray/tlssled /opt/tlssled && chmod +x /opt/tlssled/tlssled && ln -s /opt/tlssled/tlssled /usr/local/bin/",
                "speed": 3, "accuracy": 4, "recommended": False
            },
            "ssllabs": {
                "name": "SSL Labs API",
                "cmd": ["ssllabs-scan", "-quiet", "-jsonfile", "{output}", "{target}"],
                "install": "go install github.com/ssllabs/ssllabs-scan@latest",
                "speed": 1, "accuracy": 5, "recommended": False
            }
        },
        "default": ["sslyze", "sslscan"]
    },
    
    "web_crawl": {
        "name": "Web Crawling",
        "tools": {
            "gospider": {
                "name": "Gospider",
                "cmd": ["gospider", "-s", "{target}", "-d", "3", "-c", "10", "-o", "{output}"],
                "install": "go install github.com/jaeles-project/gospider@latest",
                "speed": 5, "accuracy": 4, "recommended": True
            },
            "katana": {
                "name": "Katana",
                "cmd": ["katana", "-u", "{target}", "-d", "3", "-jc", "-kf", "all", "-o", "{output}", "-silent"],
                "install": "go install github.com/projectdiscovery/katana/cmd/katana@latest",
                "speed": 5, "accuracy": 5, "recommended": True
            },
            "hakrawler": {
                "name": "Hakrawler",
                "cmd": ["echo", "{target}", "|", "hakrawler", "-d", "3"],
                "install": "go install github.com/hakluke/hakrawler@latest",
                "speed": 4, "accuracy": 4, "recommended": True
            },
            "gau": {
                "name": "GAU (Get All URLs)",
                "cmd": ["gau", "{target}", "--o", "{output}"],
                "install": "go install github.com/lc/gau/v2/cmd/gau@latest",
                "speed": 5, "accuracy": 3, "recommended": False
            },
            "waybackurls": {
                "name": "Waybackurls",
                "cmd": ["waybackurls", "{target}"],
                "install": "go install github.com/tomnomnom/waybackurls@latest",
                "speed": 4, "accuracy": 3, "recommended": False
            }
        },
        "default": ["katana", "gospider"]
    }
}

class Colors:
    """ANSI color codes"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'

class ConfigManager:
    """Manages tool configuration and selection"""
    
    def __init__(self, config_file: str = "recon_config.json"):
        self.config_file = Path(config_file)
        self.config = self.load_config()
    
    def load_config(self) -> Dict:
        """Load configuration from file"""
        if self.config_file.exists():
            try:
                return json.loads(self.config_file.read_text())
            except:
                pass
        return self.get_default_config()
    
    def save_config(self):
        """Save configuration to file"""
        self.config_file.write_text(json.dumps(self.config, indent=2))
    
    def get_default_config(self) -> Dict:
        """Get default configuration with best tools"""
        config = {
            "mode": "default",  # default, custom, random
            "selected_tools": {},
            "parallel_workers": 10,
            "timeouts": {
                "general": 300,
                "port_scan": 600,
                "vuln_scan": 900
            }
        }
        
        # Set default tools for each category
        for category, data in TOOL_DATABASE.items():
            config["selected_tools"][category] = data["default"].copy()
        
        return config
    
    def set_random_tools(self):
        """Select random tools for each category"""
        self.config["mode"] = "random"
        for category, data in TOOL_DATABASE.items():
            available = list(data["tools"].keys())
            # Select 1-2 random tools per category
            num_tools = random.randint(1, min(2, len(available)))
            self.config["selected_tools"][category] = random.sample(available, num_tools)
        self.save_config()
    
    def set_default_tools(self):
        """Set best/recommended tools"""
        self.config["mode"] = "default"
        for category, data in TOOL_DATABASE.items():
            self.config["selected_tools"][category] = data["default"].copy()
        self.save_config()
    
    def set_custom_tools(self, selections: Dict[str, List[str]]):
        """Set custom tool selection"""
        self.config["mode"] = "custom"
        self.config["selected_tools"] = selections
        self.save_config()
    
    def get_selected_tools(self, category: str) -> List[str]:
        """Get selected tools for a category"""
        return self.config["selected_tools"].get(category, [])
    
    def get_tool_info(self, category: str, tool: str) -> Dict:
        """Get tool information"""
        return TOOL_DATABASE.get(category, {}).get("tools", {}).get(tool, {})

class ReconScannerV2:
    """Enhanced reconnaissance scanner with multi-tool support"""
    
    def __init__(self, target: str, output_dir: str = "recon_results", 
                 config_manager: ConfigManager = None):
        self.target = target
        self.output_dir = Path(output_dir) / self.sanitize_target(target)
        self.config = config_manager or ConfigManager()
        self.max_workers = self.config.config.get("parallel_workers", 10)
        
        self.results = {
            "target": target,
            "scan_time": datetime.now().isoformat(),
            "config_mode": self.config.config.get("mode", "default"),
            "tools_used": {},
            "whois": {},
            "dns": {},
            "subdomains": [],
            "ip_addresses": [],
            "ports": {},
            "directories": [],
            "technologies": {},
            "vulnerabilities": [],
            "ssl_issues": [],
            "web_content": {},
            "summary": {
                "total_subdomains": 0,
                "total_ips": 0,
                "open_ports": 0,
                "total_urls_found": 0,
                "critical_vulns": 0,
                "high_vulns": 0,
                "medium_vulns": 0,
                "low_vulns": 0
            }
        }
        self.lock = threading.Lock()
    
    def sanitize_target(self, target: str) -> str:
        """Sanitize target name"""
        return re.sub(r'[^\w\-_\.]', '_', target)
    
    def setup_directories(self):
        """Create directory structure"""
        dirs = ['whois', 'dns', 'ports', 'web', 'vulns', 'ssl', 'raw', 'crawl']
        for d in dirs:
            (self.output_dir / d).mkdir(parents=True, exist_ok=True)
        self.log(f"Created output directory: {self.output_dir}", "green")
    
    def log(self, message: str, color: str = "blue"):
        """Thread-safe logging"""
        color_map = {
            "red": Colors.RED, "green": Colors.GREEN, "yellow": Colors.YELLOW,
            "blue": Colors.BLUE, "cyan": Colors.CYAN
        }
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"{color_map.get(color, Colors.BLUE)}[{timestamp}] {message}{Colors.END}")
    
    def run_command(self, cmd: List[str], timeout: int = 300) -> Optional[str]:
        """Execute command"""
        try:
            # Handle commands with pipes
            if "|" in cmd:
                # Complex shell command
                result = subprocess.run(
                    " ".join(cmd),
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=timeout
                )
            else:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    check=False
                )
            return result.stdout if result.returncode == 0 else None
        except subprocess.TimeoutExpired:
            self.log(f"Command timed out: {' '.join(cmd)}", "red")
            return None
        except FileNotFoundError:
            self.log(f"Tool not found: {cmd[0]}", "yellow")
            return None
        except Exception as e:
            self.log(f"Command failed: {e}", "red")
            return None
    
    def execute_tool(self, category: str, tool_name: str, **params) -> Optional[str]:
        """Execute a specific tool with parameters"""
        tool_info = self.config.get_tool_info(category, tool_name)
        if not tool_info:
            self.log(f"Tool {tool_name} not found in {category}", "red")
            return None
        
        # Build command from template
        cmd_template = tool_info.get("cmd", [])
        cmd = []
        
        for part in cmd_template:
            # Replace parameters
            for key, value in params.items():
                part = part.replace(f"{{{key}}}", str(value))
            cmd.append(part)
        
        self.log(f"Running {tool_info['name']}...", "cyan")
        
        # Track tool usage
        with self.lock:
            if category not in self.results["tools_used"]:
                self.results["tools_used"][category] = []
            self.results["tools_used"][category].append(tool_name)
        
        return self.run_command(cmd, timeout=params.get("timeout", 300))
    
    # ==================== DNS RECON ====================
    def dns_reconnaissance(self):
        """DNS enumeration with multiple tools"""
        self.log("Starting DNS reconnaissance...", "cyan")
        
        selected_tools = self.config.get_selected_tools("dns_recon")
        all_subdomains: Set[str] = set()
        
        for tool in selected_tools:
            output_file = self.output_dir / 'dns' / f'{tool}_subdomains.txt'
            
            result = self.execute_tool(
                "dns_recon",
                tool,
                target=self.target,
                output=str(output_file),
                timeout=180
            )
            
            # Parse results
            if output_file.exists():
                subs = [line.strip() for line in output_file.read_text().split('\n') 
                       if line.strip() and not line.startswith('#')]
                all_subdomains.update(subs)
                self.log(f"{tool} found {len(subs)} subdomains", "green")
        
        # Combine results
        self.results['subdomains'] = sorted(list(all_subdomains))
        self.results['summary']['total_subdomains'] = len(all_subdomains)
        
        # Save combined results
        combined_file = self.output_dir / 'dns' / 'all_subdomains.txt'
        combined_file.write_text('\n'.join(self.results['subdomains']))
        
        self.log(f"Total unique subdomains: {len(all_subdomains)}", "green")
    
    # ==================== PORT SCANNING ====================
    def port_scanning(self, targets: List[str]):
        """Port scanning with multiple tools"""
        self.log("Starting port scanning...", "cyan")
        
        if not targets:
            targets = self.results['ip_addresses'][:5]
        
        selected_tools = self.config.get_selected_tools("port_scan")
        all_ports = {}
        
        for target in targets:
            self.log(f"Scanning {target}...", "cyan")
            target_ports = {}
            
            for tool in selected_tools:
                output_file = self.output_dir / 'ports' / f'{tool}_{self.sanitize_target(target)}'
                
                self.execute_tool(
                    "port_scan",
                    tool,
                    target=target,
                    output=str(output_file),
                    timeout=600
                )
                
                # Parse results based on tool
                ports = self._parse_port_results(tool, output_file)
                if ports:
                    target_ports.update({p['port']: p for p in ports})
                    self.log(f"{tool} found {len(ports)} open ports", "green")
            
            if target_ports:
                all_ports[target] = list(target_ports.values())
        
        self.results['ports'] = all_ports
        self.results['summary']['open_ports'] = sum(len(p) for p in all_ports.values())
    
    def _parse_port_results(self, tool: str, output_file: Path) -> List[Dict]:
        """Parse port scan results"""
        ports = []
        
        if tool == "nmap" and output_file.with_suffix('.xml').exists():
            try:
                import xml.etree.ElementTree as ET
                tree = ET.parse(output_file.with_suffix('.xml'))
                for port in tree.findall('.//port'):
                    state = port.find('state')
                    service = port.find('service')
                    if state is not None and state.get('state') == 'open':
                        ports.append({
                            'port': port.get('portid'),
                            'protocol': port.get('protocol'),
                            'service': service.get('name', 'unknown') if service is not None else 'unknown'
                        })
            except:
                pass
        
        elif tool == "rustscan":
            # Parse rustscan output
            if output_file.exists():
                content = output_file.read_text()
                # Rustscan format: host:port
                for line in content.split('\n'):
                    if ':' in line:
                        try:
                            port = line.split(':')[-1].strip()
                            if port.isdigit():
                                ports.append({'port': port, 'protocol': 'tcp', 'service': 'unknown'})
                        except:
                            pass
        
        return ports
    
    # ==================== DIRECTORY BRUTE-FORCE ====================
    def directory_enumeration(self, urls: List[str]):
        """Directory enumeration with multiple tools"""
        self.log("Starting directory enumeration...", "cyan")
        
        selected_tools = self.config.get_selected_tools("directory_bruteforce")
        all_directories: Set[str] = set()
        
        # Get wordlist
        wordlist = self._get_wordlist()
        
        for url in urls[:5]:
            self.log(f"Enumerating directories on {url}...", "cyan")
            
            for tool in selected_tools:
                output_file = self.output_dir / 'web' / f'{tool}_{self.sanitize_target(url)}.json'
                
                self.execute_tool(
                    "directory_bruteforce",
                    tool,
                    target=url,
                    wordlist=wordlist,
                    output=str(output_file),
                    timeout=180
                )
                
                # Parse results
                dirs = self._parse_directory_results(tool, output_file, url)
                all_directories.update(dirs)
                if dirs:
                    self.log(f"{tool} found {len(dirs)} directories", "green")
        
        self.results['directories'] = sorted(list(all_directories))
    
    def _get_wordlist(self) -> str:
        """Get appropriate wordlist"""
        wordlists = [
            '/usr/share/wordlists/dirb/common.txt',
            '/usr/share/seclists/Discovery/Web-Content/common.txt',
            '/usr/share/dirbuster/wordlists/directory-list-2.3-small.txt'
        ]
        
        for wl in wordlists:
            if os.path.exists(wl):
                return wl
        
        # Create minimal wordlist
        wl_file = self.output_dir / 'raw' / 'wordlist.txt'
        common_dirs = [
            'admin', 'api', 'backup', 'config', 'dev', 'old', 'test', 'tmp',
            'login', 'dashboard', 'wp-admin', 'upload', 'assets', 'static'
        ]
        wl_file.write_text('\n'.join(common_dirs))
        return str(wl_file)
    
    def _parse_directory_results(self, tool: str, output_file: Path, base_url: str) -> Set[str]:
        """Parse directory enumeration results"""
        directories = set()
        
        if not output_file.exists():
            return directories
        
        try:
            if tool in ["ffuf", "feroxbuster", "dirsearch"]:
                data = json.loads(output_file.read_text())
                if tool == "ffuf" and 'results' in data:
                    directories = {r['url'] for r in data['results']}
                elif tool == "feroxbuster":
                    directories = {r['url'] for r in data if 'url' in r}
            elif tool in ["gobuster", "dirb"]:
                content = output_file.read_text()
                for line in content.split('\n'):
                    if line.strip() and not line.startswith('#'):
                        directories.add(line.strip())
        except:
            pass
        
        return directories
    
    # ==================== WEB CRAWLING ====================
    def web_crawling(self, urls: List[str]):
        """Web crawling with multiple tools"""
        self.log("Starting web crawling...", "cyan")
        
        selected_tools = self.config.get_selected_tools("web_crawl")
        all_urls: Set[str] = set()
        
        for url in urls[:5]:
            self.log(f"Crawling {url}...", "cyan")
            
            for tool in selected_tools:
                output_file = self.output_dir / 'crawl' / f'{tool}_{self.sanitize_target(url)}.txt'
                
                self.execute_tool(
                    "web_crawl",
                    tool,
                    target=url,
                    output=str(output_file),
                    timeout=120
                )
                
                # Parse results
                if output_file.exists():
                    urls_found = [line.strip() for line in output_file.read_text().split('\n') 
                                 if line.strip() and line.startswith('http')]
                    all_urls.update(urls_found)
                    self.log(f"{tool} found {len(urls_found)} URLs", "green")
        
        self.results['web_content']['crawled_urls'] = sorted(list(all_urls))
        self.results['summary']['total_urls_found'] = len(all_urls)
    
    # ==================== VULNERABILITY SCANNING ====================
    def vulnerability_scanning(self, targets: List[str]):
        """Vulnerability scanning with multiple tools"""
        self.log("Starting vulnerability scanning...", "cyan")
        
        selected_tools = self.config.get_selected_tools("vuln_scan")
        all_vulns = []
        
        # Prepare target file
        target_file = self.output_dir / 'raw' / 'vuln_targets.txt'
        target_file.write_text('\n'.join(targets[:10]))
        
        for tool in selected_tools:
            output_file = self.output_dir / 'vulns' / f'{tool}_results.json'
            
            # Special handling for different tools
            if tool == "nuclei":
                self.execute_tool(
                    "vuln_scan",
                    tool,
                    target=str(target_file),
                    output=str(output_file),
                    timeout=900
                )
            else:
                # Scan each target individually for other tools
                for target in targets[:5]:
                    self.execute_tool(
                        "vuln_scan",
                        tool,
                        target=target,
                        output=str(output_file),
                        timeout=300
                    )
            
            # Parse results
            vulns = self._parse_vuln_results(tool, output_file)
            all_vulns.extend(vulns)
            if vulns:
                self.log(f"{tool} found {len(vulns)} vulnerabilities", "yellow")
        
        self.results['vulnerabilities'] = all_vulns
        
        # Count by severity
        for vuln in all_vulns:
            sev = vuln.get('severity', 'info').lower()
            if sev == 'critical':
                self.results['summary']['critical_vulns'] += 1
            elif sev == 'high':
                self.results['summary']['high_vulns'] += 1
            elif sev == 'medium':
                self.results['summary']['medium_vulns'] += 1
            elif sev == 'low':
                self.results['summary']['low_vulns'] += 1
    
    def _parse_vuln_results(self, tool: str, output_file: Path) -> List[Dict]:
        """Parse vulnerability scan results"""
        vulns = []
        
        if not output_file.exists():
            return vulns
        
        try:
            if tool == "nuclei":
                for line in output_file.read_text().split('\n'):
                    if line.strip():
                        vuln = json.loads(line)
                        vulns.append({
                            'tool': tool,
                            'name': vuln.get('info', {}).get('name', 'Unknown'),
                            'severity': vuln.get('info', {}).get('severity', 'info'),
                            'host': vuln.get('host', ''),
                            'matched_at': vuln.get('matched-at', ''),
                            'cve': vuln.get('info', {}).get('classification', {}).get('cve-id', [])
                        })
            elif tool == "nikto":
                data = json.loads(output_file.read_text())
                for vuln in data.get('vulnerabilities', []):
                    vulns.append({
                        'tool': tool,
                        'name': vuln.get('msg', 'Unknown'),
                        'severity': 'medium',
                        'host': vuln.get('host', '')
                    })
        except:
            pass
        
        return vulns
    
    # ==================== SSL/TLS TESTING ====================
    def ssl_testing(self, domains: List[str]):
        """SSL/TLS testing with multiple tools"""
        self.log("Starting SSL/TLS testing...", "cyan")
        
        selected_tools = self.config.get_selected_tools("ssl_test")
        all_issues = []
        
        for domain in domains[:5]:
            self.log(f"Testing SSL on {domain}...", "cyan")
            
            for tool in selected_tools:
                output_file = self.output_dir / 'ssl' / f'{tool}_{self.sanitize_target(domain)}.json'
                
                self.execute_tool(
                    "ssl_test",
                    tool,
                    target=domain,
                    output=str(output_file),
                    timeout=120
                )
                
                # Parse results
                issues = self._parse_ssl_results(tool, output_file, domain)
                all_issues.extend(issues)
                if issues:
                    self.log(f"{tool} found {len(issues)} SSL issues", "yellow")
        
        self.results['ssl_issues'] = all_issues
    
    def _parse_ssl_results(self, tool: str, output_file: Path, domain: str) -> List[Dict]:
        """Parse SSL test results"""
        issues = []
        
        if not output_file.exists():
            return issues
        
        try:
            if tool == "sslyze":
                data = json.loads(output_file.read_text())
                # Simplified parsing - customize based on needs
                if 'server_scan_results' in data:
                    issues.append({
                        'tool': tool,
                        'severity': 'info',
                        'issue': 'SSL scan completed',
                        'domain': domain
                    })
        except:
            pass
        
        return issues
    
    # ==================== ORCHESTRATION ====================
    async def run_parallel_scans(self):
        """Run all scans in parallel"""
        self.log(f"Starting parallel reconnaissance on {self.target}...", "cyan")
        self.log(f"Mode: {self.config.config['mode']}", "blue")
        
        # Phase 1: DNS Reconnaissance
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [
                executor.submit(self.dns_reconnaissance),
            ]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    self.log(f"Error in DNS recon: {e}", "red")
        
        # Get targets for scanning
        all_targets = [self.target] + self.results['subdomains'][:20]
        web_targets = [f"https://{t}" for t in all_targets[:10]]
        
        # Resolve IPs
        ips = []
        for t in all_targets[:10]:
            try:
                ip = socket.gethostbyname(t)
                ips.append(ip)
            except:
                pass
        self.results['ip_addresses'] = list(set(ips))
        
        # Phase 2: Active Scanning
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [
                executor.submit(self.port_scanning, ips),
                executor.submit(self.directory_enumeration, web_targets),
                executor.submit(self.web_crawling, web_targets),
                executor.submit(self.ssl_testing, all_targets[:5]),
            ]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    self.log(f"Error in active scanning: {e}", "red")
        
        # Phase 3: Vulnerability Scanning
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [
                executor.submit(self.vulnerability_scanning, web_targets),
            ]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    self.log(f"Error in vuln scanning: {e}", "red")
    
    def generate_report(self):
        """Generate reports"""
        self.log("Generating reports...", "cyan")
        
        # Save JSON
        json_report = self.output_dir / 'report.json'
        json_report.write_text(json.dumps(self.results, indent=2))
        self.log(f"JSON report saved: {json_report}", "green")
        
        # Generate HTML
        html_report = self.output_dir / 'report.html'
        html_content = self._generate_html_report()
        html_report.write_text(html_content)
        self.log(f"HTML report saved: {html_report}", "green")
        
        return json_report, html_report
    
    def _generate_html_report(self) -> str:
        """Generate HTML report"""
        summary = self.results['summary']
        
        # Determine risk level
        if summary['critical_vulns'] > 0:
            risk_level, risk_color = "CRITICAL", "#dc3545"
        elif summary['high_vulns'] > 0:
            risk_level, risk_color = "HIGH", "#fd7e14"
        elif summary['medium_vulns'] > 0:
            risk_level, risk_color = "MEDIUM", "#ffc107"
        else:
            risk_level, risk_color = "LOW", "#28a745"
        
        # Tools used section
        tools_html = "<div class='section'><h2>🛠️ Tools Used</h2>"
        for category, tools in self.results.get('tools_used', {}).items():
            cat_name = TOOL_DATABASE.get(category, {}).get('name', category)
            tools_html += f"<h3>{cat_name}</h3><ul class='list-group'>"
            for tool in tools:
                tools_html += f"<li>{tool}</li>"
            tools_html += "</ul>"
        tools_html += "</div>"
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Recon Report - {self.target}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; }}
        .container {{ max-width: 1400px; margin: 0 auto; background: white; border-radius: 15px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); overflow: hidden; }}
        .header {{ background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%); color: white; padding: 40px; text-align: center; }}
        .header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .risk-badge {{ display: inline-block; padding: 10px 30px; background: {risk_color}; color: white; border-radius: 25px; font-size: 1.2em; font-weight: bold; margin-top: 15px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; padding: 30px; background: #f8f9fa; }}
        .summary-card {{ background: white; padding: 25px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; }}
        .summary-card .number {{ font-size: 2.5em; font-weight: bold; color: #667eea; }}
        .content {{ padding: 30px; }}
        .section {{ margin-bottom: 40px; background: #f8f9fa; border-radius: 10px; padding: 25px; }}
        .section h2 {{ color: #2a5298; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 3px solid #667eea; }}
        .list-group {{ list-style: none; background: white; border-radius: 8px; overflow: hidden; }}
        .list-group li {{ padding: 12px 15px; border-bottom: 1px solid #dee2e6; }}
        .badge {{ display: inline-block; padding: 4px 10px; border-radius: 12px; font-size: 0.85em; font-weight: bold; }}
        .badge-critical {{ background: #dc3545; color: white; }}
        .badge-high {{ background: #fd7e14; color: white; }}
        .badge-medium {{ background: #ffc107; color: black; }}
        .badge-low {{ background: #28a745; color: white; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Deep Reconnaissance Report v2.0</h1>
            <div>Target: {self.target}</div>
            <div>Scan Time: {self.results['scan_time']}</div>
            <div>Mode: {self.results['config_mode'].upper()}</div>
            <div class="risk-badge">Risk Level: {risk_level}</div>
        </div>
        
        <div class="summary">
            <div class="summary-card"><div class="number">{summary['total_subdomains']}</div><div>Subdomains</div></div>
            <div class="summary-card"><div class="number">{summary['total_ips']}</div><div>IP Addresses</div></div>
            <div class="summary-card"><div class="number">{summary['open_ports']}</div><div>Open Ports</div></div>
            <div class="summary-card"><div class="number">{summary['total_urls_found']}</div><div>URLs Found</div></div>
            <div class="summary-card"><div class="number">{summary['critical_vulns']}</div><div>Critical</div></div>
            <div class="summary-card"><div class="number">{summary['high_vulns']}</div><div>High</div></div>
            <div class="summary-card"><div class="number">{summary['medium_vulns']}</div><div>Medium</div></div>
        </div>
        
        <div class="content">
            {tools_html}
            
            {"<div class='section'><h2>🚨 Vulnerabilities</h2><ul class='list-group'>" + "".join(f"<li><span class='badge badge-{v.get('severity', 'low')}'>{v.get('severity', 'info').upper()}</span> {v.get('name', 'Unknown')} - {v.get('tool', 'unknown')}</li>" for v in self.results['vulnerabilities'][:50]) + "</ul></div>" if self.results['vulnerabilities'] else ""}
            
            {"<div class='section'><h2>🌐 Subdomains</h2><ul class='list-group'>" + "".join(f"<li>{s}</li>" for s in self.results['subdomains'][:100]) + "</ul></div>" if self.results['subdomains'] else ""}
        </div>
    </div>
</body>
</html>"""
        return html
    
    def run(self):
        """Main execution"""
        self.log(f"=== Deep Reconnaissance Tool v2.0 ===", "cyan")
        self.log(f"Target: {self.target}", "cyan")
        
        self.setup_directories()
        asyncio.run(self.run_parallel_scans())
        json_file, html_file = self.generate_report()
        
        self.log(f"\n=== Scan Complete ===", "green")
        self.log(f"JSON Report: {json_file}", "green")
        self.log(f"HTML Report: {html_file}", "green")
        
        # Print summary
        print(f"\n=== Summary ===")
        print(f"Subdomains: {self.results['summary']['total_subdomains']}")
        print(f"IPs: {self.results['summary']['total_ips']}")
        print(f"Open Ports: {self.results['summary']['open_ports']}")
        print(f"URLs Found: {self.results['summary']['total_urls_found']}")
        print(f"Critical Vulns: {self.results['summary']['critical_vulns']}")
        print(f"High Vulns: {self.results['summary']['high_vulns']}")

def main():
    parser = argparse.ArgumentParser(description='Deep Reconnaissance Tool v2.0')
    parser.add_argument('-t', '--target', required=True, help='Target domain/IP')
    parser.add_argument('-o', '--output', default='recon_results', help='Output directory')
    parser.add_argument('-m', '--mode', choices=['default', 'random', 'custom'], 
                       default='default', help='Tool selection mode')
    parser.add_argument('--gui', action='store_true', help='Start web GUI')
    
    args = parser.parse_args()
    
    # Load or create config
    config = ConfigManager()
    
    # Set mode
    if args.mode == 'random':
        config.set_random_tools()
        print(f"{Colors.YELLOW}Using RANDOM tool selection{Colors.END}")
    elif args.mode == 'default':
        config.set_default_tools()
        print(f"{Colors.GREEN}Using DEFAULT (best) tools{Colors.END}")
    
    # Create scanner and run
    scanner = ReconScannerV2(
        target=args.target,
        output_dir=args.output,
        config_manager=config
    )
    
    try:
        scanner.run()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Scan interrupted{Colors.END}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Colors.RED}Error: {e}{Colors.END}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
