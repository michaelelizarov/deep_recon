#!/usr/bin/env python3
"""
Deep Reconnaissance Automation Tool
Performs comprehensive security reconnaissance on target domains/IPs
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
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class ReconScanner:
    """Main reconnaissance scanner orchestrator"""
    
    def __init__(self, target: str, output_dir: str = "recon_results", max_workers: int = 10):
        self.target = target
        self.output_dir = Path(output_dir) / self.sanitize_target(target)
        self.max_workers = max_workers
        self.results = {
            "target": target,
            "scan_time": datetime.now().isoformat(),
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
                "critical_vulns": 0,
                "high_vulns": 0,
                "medium_vulns": 0,
                "low_vulns": 0
            }
        }
        self.lock = threading.Lock()
        
    def sanitize_target(self, target: str) -> str:
        """Sanitize target name for directory creation"""
        return re.sub(r'[^\w\-_\.]', '_', target)
    
    def setup_directories(self):
        """Create organized directory structure"""
        dirs = ['whois', 'dns', 'ports', 'web', 'vulns', 'ssl', 'raw']
        for d in dirs:
            (self.output_dir / d).mkdir(parents=True, exist_ok=True)
        self.log(f"Created output directory: {self.output_dir}", "green")
    
    def log(self, message: str, color: str = "blue"):
        """Thread-safe colored logging"""
        color_map = {
            "red": Colors.RED,
            "green": Colors.GREEN,
            "yellow": Colors.YELLOW,
            "blue": Colors.BLUE,
            "cyan": Colors.CYAN
        }
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"{color_map.get(color, Colors.BLUE)}[{timestamp}] {message}{Colors.END}")
    
    def run_command(self, cmd: List[str], timeout: int = 300) -> Optional[str]:
        """Execute shell command with timeout"""
        try:
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
        except Exception as e:
            self.log(f"Command failed: {e}", "red")
            return None
    
    def resolve_target(self) -> List[str]:
        """Resolve target to IP addresses"""
        self.log(f"Resolving target: {self.target}", "cyan")
        ips = []
        
        # Check if target is already an IP
        try:
            socket.inet_aton(self.target)
            ips.append(self.target)
            self.log(f"Target is IP: {self.target}", "green")
        except socket.error:
            # Try to resolve domain
            try:
                ip = socket.gethostbyname(self.target)
                ips.append(ip)
                self.log(f"Resolved {self.target} -> {ip}", "green")
            except socket.gaierror:
                self.log(f"Could not resolve {self.target}", "yellow")
        
        return ips
    
    # ==================== WHOIS ====================
    def whois_lookup(self):
        """Perform WHOIS lookup"""
        self.log("Starting WHOIS lookup...", "cyan")
        
        output = self.run_command(['whois', self.target])
        if output:
            whois_file = self.output_dir / 'whois' / 'whois.txt'
            whois_file.write_text(output)
            
            # Parse key information
            self.results['whois'] = {
                "registrar": self._extract_whois_field(output, r"Registrar:\s*(.+)"),
                "creation_date": self._extract_whois_field(output, r"Creation Date:\s*(.+)"),
                "expiration_date": self._extract_whois_field(output, r"Expir(?:y|ation) Date:\s*(.+)"),
                "name_servers": re.findall(r"Name Server:\s*(.+)", output, re.IGNORECASE),
                "organization": self._extract_whois_field(output, r"Organi[zs]ation:\s*(.+)"),
            }
            self.log(f"WHOIS lookup completed", "green")
        else:
            self.log("WHOIS lookup failed", "yellow")
    
    def _extract_whois_field(self, text: str, pattern: str) -> Optional[str]:
        """Extract field from WHOIS output"""
        match = re.search(pattern, text, re.IGNORECASE)
        return match.group(1).strip() if match else None
    
    # ==================== DNS RECON ====================
    def dns_enumeration(self):
        """Comprehensive DNS enumeration"""
        self.log("Starting DNS enumeration...", "cyan")
        
        dns_records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
        
        for rtype in record_types:
            output = self.run_command(['dig', '+short', self.target, rtype])
            if output:
                records = [line.strip() for line in output.split('\n') if line.strip()]
                if records:
                    dns_records[rtype] = records
                    self.log(f"Found {len(records)} {rtype} records", "green")
        
        self.results['dns'] = dns_records
        
        # Save raw DNS data
        dns_file = self.output_dir / 'dns' / 'dns_records.json'
        dns_file.write_text(json.dumps(dns_records, indent=2))
        
        # Extract IPs from DNS
        ips = set()
        if 'A' in dns_records:
            ips.update(dns_records['A'])
        if 'AAAA' in dns_records:
            ips.update(dns_records['AAAA'])
        
        self.results['ip_addresses'] = list(ips)
        self.results['summary']['total_ips'] = len(ips)
    
    def subdomain_enumeration(self):
        """Fast subdomain enumeration using subfinder"""
        self.log("Starting subdomain enumeration...", "cyan")
        
        # Use subfinder for fast passive enumeration
        subfinder_output = self.output_dir / 'dns' / 'subdomains.txt'
        cmd = ['subfinder', '-d', self.target, '-silent', '-o', str(subfinder_output)]
        
        self.run_command(cmd, timeout=180)
        
        subdomains = []
        if subfinder_output.exists():
            subdomains = [line.strip() for line in subfinder_output.read_text().split('\n') if line.strip()]
            self.results['subdomains'] = subdomains
            self.results['summary']['total_subdomains'] = len(subdomains)
            self.log(f"Found {len(subdomains)} subdomains", "green")
        else:
            self.log("No subdomains found", "yellow")
        
        return subdomains
    
    # ==================== PORT SCANNING ====================
    def port_scan(self, targets: List[str]):
        """Fast port scanning with nmap"""
        self.log("Starting port scanning...", "cyan")
        
        if not targets:
            targets = self.results['ip_addresses']
            if not targets:
                self.log("No targets for port scanning", "yellow")
                return
        
        all_ports = {}
        
        for target in targets[:5]:  # Limit to first 5 IPs for speed
            self.log(f"Scanning ports on {target}...", "cyan")
            
            # Fast SYN scan of top 1000 ports
            nmap_output = self.output_dir / 'ports' / f'nmap_{self.sanitize_target(target)}.xml'
            cmd = [
                'nmap', '-sS', '-T4', '--top-ports', '1000',
                '-oX', str(nmap_output),
                '--open',
                target
            ]
            
            self.run_command(cmd, timeout=300)
            
            # Parse nmap output
            if nmap_output.exists():
                ports = self._parse_nmap_output(nmap_output)
                if ports:
                    all_ports[target] = ports
                    self.log(f"Found {len(ports)} open ports on {target}", "green")
        
        self.results['ports'] = all_ports
        self.results['summary']['open_ports'] = sum(len(p) for p in all_ports.values())
    
    def _parse_nmap_output(self, xml_file: Path) -> List[Dict[str, Any]]:
        """Parse nmap XML output"""
        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            ports = []
            for port in root.findall('.//port'):
                state = port.find('state')
                service = port.find('service')
                
                if state is not None and state.get('state') == 'open':
                    port_info = {
                        'port': port.get('portid'),
                        'protocol': port.get('protocol'),
                        'service': service.get('name') if service is not None else 'unknown',
                        'product': service.get('product', '') if service is not None else '',
                        'version': service.get('version', '') if service is not None else ''
                    }
                    ports.append(port_info)
            
            return ports
        except Exception as e:
            self.log(f"Failed to parse nmap output: {e}", "red")
            return []
    
    # ==================== WEB RECON ====================
    def web_discovery(self, targets: List[str]):
        """Discover web servers and perform directory enumeration"""
        self.log("Starting web discovery...", "cyan")
        
        if not targets:
            targets = [self.target]
        
        # Find live web servers
        web_targets = []
        for target in targets[:10]:  # Limit for speed
            for proto in ['https', 'http']:
                url = f"{proto}://{target}"
                if self._check_http(url):
                    web_targets.append(url)
                    self.log(f"Found live web server: {url}", "green")
        
        # Parallel directory enumeration
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [executor.submit(self._directory_bruteforce, url) for url in web_targets[:5]]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    self.log(f"Directory enumeration error: {e}", "red")
    
    def _check_http(self, url: str, timeout: int = 5) -> bool:
        """Check if HTTP/HTTPS is accessible"""
        try:
            import urllib.request
            urllib.request.urlopen(url, timeout=timeout)
            return True
        except:
            return False
    
    def _directory_bruteforce(self, url: str):
        """Fast directory/file discovery using ffuf"""
        self.log(f"Directory bruteforce on {url}...", "cyan")
        
        # Use common wordlist
        wordlist = '/usr/share/wordlists/dirb/common.txt'
        if not os.path.exists(wordlist):
            # Create minimal wordlist if not available
            wordlist = self.output_dir / 'raw' / 'wordlist.txt'
            common_dirs = [
                'admin', 'api', 'backup', 'config', 'dev', 'old', 'test', 'tmp',
                'login', 'dashboard', 'wp-admin', 'phpmyadmin', 'upload', 'uploads',
                'images', 'js', 'css', 'assets', 'static', 'files', 'docs'
            ]
            wordlist.write_text('\n'.join(common_dirs))
        
        output_file = self.output_dir / 'web' / f'dirs_{self.sanitize_target(url)}.json'
        
        cmd = [
            'ffuf',
            '-w', str(wordlist),
            '-u', f"{url}/FUZZ",
            '-mc', '200,204,301,302,307,401,403',
            '-t', '50',  # 50 threads for speed
            '-timeout', '10',
            '-o', str(output_file),
            '-of', 'json',
            '-s'  # Silent mode
        ]
        
        self.run_command(cmd, timeout=180)
        
        if output_file.exists():
            try:
                data = json.loads(output_file.read_text())
                if 'results' in data:
                    dirs = [r['url'] for r in data['results']]
                    with self.lock:
                        self.results['directories'].extend(dirs)
                    self.log(f"Found {len(dirs)} directories on {url}", "green")
            except:
                pass
    
    def web_content_analysis(self, urls: List[str]):
        """Deep web content analysis and crawling"""
        self.log("Starting web content analysis...", "cyan")
        
        if not urls:
            return
        
        # Use katana for fast crawling
        for url in urls[:5]:
            self.log(f"Crawling {url}...", "cyan")
            
            crawl_output = self.output_dir / 'web' / f'crawl_{self.sanitize_target(url)}.txt'
            cmd = [
                'katana',
                '-u', url,
                '-d', '3',  # Depth 3
                '-jc',  # JavaScript crawling
                '-kf', 'all',
                '-o', str(crawl_output),
                '-silent'
            ]
            
            self.run_command(cmd, timeout=120)
            
            if crawl_output.exists():
                pages = [line.strip() for line in crawl_output.read_text().split('\n') if line.strip()]
                self.results['web_content'][url] = {
                    'crawled_pages': len(pages),
                    'pages': pages[:100]  # Limit for JSON size
                }
                self.log(f"Crawled {len(pages)} pages from {url}", "green")
    
    def technology_detection(self, urls: List[str]):
        """Detect web technologies using whatweb"""
        self.log("Detecting web technologies...", "cyan")
        
        if not urls:
            return
        
        for url in urls[:5]:
            output = self.run_command(['whatweb', '--color=never', '--log-json=-', url], timeout=30)
            if output:
                try:
                    tech_data = json.loads(output)
                    if tech_data:
                        technologies = {}
                        for plugin, details in tech_data[0].get('plugins', {}).items():
                            if isinstance(details, dict) and 'version' in details:
                                technologies[plugin] = details.get('version', [''])[0]
                            elif isinstance(details, dict) and 'string' in details:
                                technologies[plugin] = str(details.get('string', [''])[0])
                            else:
                                technologies[plugin] = 'detected'
                        
                        self.results['technologies'][url] = technologies
                        self.log(f"Detected {len(technologies)} technologies on {url}", "green")
                except:
                    pass
    
    # ==================== VULNERABILITY SCANNING ====================
    def vulnerability_scan(self, targets: List[str]):
        """Comprehensive vulnerability scanning using nuclei"""
        self.log("Starting vulnerability scanning...", "cyan")
        
        if not targets:
            return
        
        # Prepare target list
        target_file = self.output_dir / 'raw' / 'targets.txt'
        target_file.write_text('\n'.join(targets[:10]))
        
        # Run nuclei with multiple severity levels
        nuclei_output = self.output_dir / 'vulns' / 'nuclei_results.json'
        
        cmd = [
            'nuclei',
            '-l', str(target_file),
            '-severity', 'critical,high,medium,low',
            '-c', str(self.max_workers),
            '-stats',
            '-json',
            '-o', str(nuclei_output),
            '-silent'
        ]
        
        self.run_command(cmd, timeout=600)
        
        # Parse nuclei results
        if nuclei_output.exists():
            vulns = []
            try:
                for line in nuclei_output.read_text().split('\n'):
                    if line.strip():
                        vuln = json.loads(line)
                        vuln_info = {
                            'name': vuln.get('info', {}).get('name', 'Unknown'),
                            'severity': vuln.get('info', {}).get('severity', 'info'),
                            'host': vuln.get('host', ''),
                            'matched_at': vuln.get('matched-at', ''),
                            'description': vuln.get('info', {}).get('description', ''),
                            'cve': vuln.get('info', {}).get('classification', {}).get('cve-id', []),
                            'cvss_score': vuln.get('info', {}).get('classification', {}).get('cvss-score', 0)
                        }
                        vulns.append(vuln_info)
                
                self.results['vulnerabilities'] = vulns
                
                # Count by severity
                for vuln in vulns:
                    sev = vuln['severity'].lower()
                    if sev == 'critical':
                        self.results['summary']['critical_vulns'] += 1
                    elif sev == 'high':
                        self.results['summary']['high_vulns'] += 1
                    elif sev == 'medium':
                        self.results['summary']['medium_vulns'] += 1
                    elif sev == 'low':
                        self.results['summary']['low_vulns'] += 1
                
                self.log(f"Found {len(vulns)} vulnerabilities", "yellow")
            except Exception as e:
                self.log(f"Failed to parse nuclei output: {e}", "red")
    
    def nikto_scan(self, urls: List[str]):
        """Additional web vulnerability scanning with Nikto"""
        self.log("Running Nikto scans...", "cyan")
        
        for url in urls[:3]:  # Limit to 3 for speed
            self.log(f"Nikto scan on {url}...", "cyan")
            
            nikto_output = self.output_dir / 'vulns' / f'nikto_{self.sanitize_target(url)}.txt'
            cmd = ['nikto', '-h', url, '-o', str(nikto_output), '-Format', 'txt']
            
            self.run_command(cmd, timeout=300)
    
    # ==================== SSL/TLS TESTING ====================
    def ssl_analysis(self, domains: List[str]):
        """SSL/TLS security analysis using testssl.sh or sslyze"""
        self.log("Starting SSL/TLS analysis...", "cyan")
        
        ssl_domains = [d for d in domains if not d.startswith('http://')][:5]
        
        for domain in ssl_domains:
            self.log(f"SSL analysis on {domain}...", "cyan")
            
            # Try sslyze first (faster)
            ssl_output = self.output_dir / 'ssl' / f'ssl_{self.sanitize_target(domain)}.json'
            cmd = [
                'sslyze',
                '--json_out', str(ssl_output),
                domain
            ]
            
            output = self.run_command(cmd, timeout=60)
            
            if ssl_output.exists():
                try:
                    ssl_data = json.loads(ssl_output.read_text())
                    
                    # Parse SSL issues
                    issues = []
                    
                    # Check for various SSL/TLS issues
                    server_info = ssl_data.get('server_scan_results', [{}])[0]
                    
                    # Check certificate
                    cert_info = server_info.get('scan_commands_results', {}).get('certificate_info', {})
                    if cert_info:
                        cert_result = cert_info.get('result', {})
                        cert_deployments = cert_result.get('certificate_deployments', [])
                        
                        for deployment in cert_deployments:
                            verified = deployment.get('verified_certificate_chain')
                            if verified:
                                issues.append({
                                    'severity': 'info',
                                    'issue': 'Valid SSL certificate',
                                    'domain': domain
                                })
                            else:
                                issues.append({
                                    'severity': 'high',
                                    'issue': 'Invalid SSL certificate chain',
                                    'domain': domain
                                })
                    
                    # Check SSL/TLS versions
                    ssl_versions = server_info.get('scan_commands_results', {}).get('ssl_2_0_cipher_suites', {})
                    if ssl_versions and ssl_versions.get('result'):
                        issues.append({
                            'severity': 'critical',
                            'issue': 'SSLv2 enabled (insecure)',
                            'domain': domain
                        })
                    
                    tls_versions = server_info.get('scan_commands_results', {}).get('ssl_3_0_cipher_suites', {})
                    if tls_versions and tls_versions.get('result'):
                        issues.append({
                            'severity': 'high',
                            'issue': 'SSLv3 enabled (insecure)',
                            'domain': domain
                        })
                    
                    self.results['ssl_issues'].extend(issues)
                    self.log(f"SSL analysis completed for {domain}: {len(issues)} findings", "green")
                    
                except Exception as e:
                    self.log(f"Failed to parse SSL results: {e}", "red")
    
    # ==================== ORCHESTRATION ====================
    async def run_parallel_scans(self):
        """Run scans in parallel for maximum speed"""
        self.log(f"Starting parallel reconnaissance on {self.target}...", "cyan")
        
        # Phase 1: Basic enumeration (parallel where possible)
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [
                executor.submit(self.whois_lookup),
                executor.submit(self.dns_enumeration),
                executor.submit(self.subdomain_enumeration),
            ]
            
            # Wait for basic enumeration
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    self.log(f"Error in phase 1: {e}", "red")
        
        # Resolve IPs
        ips = self.resolve_target()
        if not self.results['ip_addresses']:
            self.results['ip_addresses'] = ips
        
        # Phase 2: Active scanning (parallel)
        all_targets = [self.target] + self.results['subdomains'][:20]  # Limit for speed
        web_targets = [f"https://{t}" for t in all_targets[:10]]
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [
                executor.submit(self.port_scan, self.results['ip_addresses']),
                executor.submit(self.web_discovery, all_targets),
                executor.submit(self.technology_detection, web_targets),
                executor.submit(self.ssl_analysis, all_targets),
            ]
            
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    self.log(f"Error in phase 2: {e}", "red")
        
        # Phase 3: Deep analysis (parallel)
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [
                executor.submit(self.web_content_analysis, web_targets),
                executor.submit(self.vulnerability_scan, web_targets),
            ]
            
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    self.log(f"Error in phase 3: {e}", "red")
    
    def generate_report(self):
        """Generate JSON report and HTML visualization"""
        self.log("Generating reports...", "cyan")
        
        # Save JSON report
        json_report = self.output_dir / 'report.json'
        json_report.write_text(json.dumps(self.results, indent=2))
        self.log(f"JSON report saved: {json_report}", "green")
        
        # Generate HTML report
        html_report = self.output_dir / 'report.html'
        html_content = self._generate_html_report()
        html_report.write_text(html_content)
        self.log(f"HTML report saved: {html_report}", "green")
        
        return json_report, html_report
    
    def _generate_html_report(self) -> str:
        """Generate comprehensive HTML report"""
        summary = self.results['summary']
        
        # Determine overall risk level
        if summary['critical_vulns'] > 0:
            risk_level = "CRITICAL"
            risk_color = "#dc3545"
        elif summary['high_vulns'] > 0:
            risk_level = "HIGH"
            risk_color = "#fd7e14"
        elif summary['medium_vulns'] > 0:
            risk_level = "MEDIUM"
            risk_color = "#ffc107"
        else:
            risk_level = "LOW"
            risk_color = "#28a745"
        
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Recon Report - {self.target}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        .header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .header .target {{ font-size: 1.3em; opacity: 0.9; }}
        .header .timestamp {{ font-size: 0.9em; opacity: 0.7; margin-top: 10px; }}
        
        .risk-badge {{
            display: inline-block;
            padding: 10px 30px;
            background: {risk_color};
            color: white;
            border-radius: 25px;
            font-size: 1.2em;
            font-weight: bold;
            margin-top: 15px;
        }}
        
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }}
        .summary-card {{
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
            transition: transform 0.3s;
        }}
        .summary-card:hover {{ transform: translateY(-5px); }}
        .summary-card .number {{
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
        }}
        .summary-card .label {{
            color: #666;
            font-size: 0.9em;
            margin-top: 5px;
        }}
        
        .content {{ padding: 30px; }}
        .section {{
            margin-bottom: 40px;
            background: #f8f9fa;
            border-radius: 10px;
            padding: 25px;
        }}
        .section h2 {{
            color: #2a5298;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 3px solid #667eea;
        }}
        
        .vuln-table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
            background: white;
            border-radius: 8px;
            overflow: hidden;
        }}
        .vuln-table th {{
            background: #2a5298;
            color: white;
            padding: 12px;
            text-align: left;
        }}
        .vuln-table td {{
            padding: 12px;
            border-bottom: 1px solid #dee2e6;
        }}
        .vuln-table tr:hover {{ background: #f1f3f5; }}
        
        .severity-critical {{ color: #dc3545; font-weight: bold; }}
        .severity-high {{ color: #fd7e14; font-weight: bold; }}
        .severity-medium {{ color: #ffc107; font-weight: bold; }}
        .severity-low {{ color: #28a745; font-weight: bold; }}
        
        .badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: bold;
        }}
        .badge-critical {{ background: #dc3545; color: white; }}
        .badge-high {{ background: #fd7e14; color: white; }}
        .badge-medium {{ background: #ffc107; color: black; }}
        .badge-low {{ background: #28a745; color: white; }}
        
        .list-group {{
            list-style: none;
            background: white;
            border-radius: 8px;
            overflow: hidden;
        }}
        .list-group li {{
            padding: 12px 15px;
            border-bottom: 1px solid #dee2e6;
        }}
        .list-group li:last-child {{ border-bottom: none; }}
        
        .port-info {{
            display: inline-block;
            background: #e7f3ff;
            padding: 5px 10px;
            border-radius: 5px;
            margin: 3px;
            font-size: 0.9em;
        }}
        
        .footer {{
            background: #2a5298;
            color: white;
            text-align: center;
            padding: 20px;
            margin-top: 40px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Deep Reconnaissance Report</h1>
            <div class="target">Target: {self.target}</div>
            <div class="timestamp">Scan Time: {self.results['scan_time']}</div>
            <div class="risk-badge">Risk Level: {risk_level}</div>
        </div>
        
        <div class="summary">
            <div class="summary-card">
                <div class="number">{summary['total_subdomains']}</div>
                <div class="label">Subdomains</div>
            </div>
            <div class="summary-card">
                <div class="number">{summary['total_ips']}</div>
                <div class="label">IP Addresses</div>
            </div>
            <div class="summary-card">
                <div class="number">{summary['open_ports']}</div>
                <div class="label">Open Ports</div>
            </div>
            <div class="summary-card">
                <div class="number">{summary['critical_vulns']}</div>
                <div class="label">Critical Vulns</div>
            </div>
            <div class="summary-card">
                <div class="number">{summary['high_vulns']}</div>
                <div class="label">High Vulns</div>
            </div>
            <div class="summary-card">
                <div class="number">{summary['medium_vulns']}</div>
                <div class="label">Medium Vulns</div>
            </div>
        </div>
        
        <div class="content">
"""
        
        # Vulnerabilities section
        if self.results['vulnerabilities']:
            html += """
            <div class="section">
                <h2>🚨 Vulnerabilities Detected</h2>
                <table class="vuln-table">
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Vulnerability</th>
                            <th>Host</th>
                            <th>CVE</th>
                        </tr>
                    </thead>
                    <tbody>
"""
            for vuln in self.results['vulnerabilities']:
                severity = vuln['severity'].lower()
                badge_class = f"badge-{severity}"
                cve = ', '.join(vuln.get('cve', [])) if vuln.get('cve') else 'N/A'
                
                html += f"""
                        <tr>
                            <td><span class="badge {badge_class}">{vuln['severity'].upper()}</span></td>
                            <td>{vuln['name']}</td>
                            <td>{vuln['host']}</td>
                            <td>{cve}</td>
                        </tr>
"""
            html += """
                    </tbody>
                </table>
            </div>
"""
        
        # Subdomains section
        if self.results['subdomains']:
            html += """
            <div class="section">
                <h2>🌐 Discovered Subdomains</h2>
                <ul class="list-group">
"""
            for subdomain in self.results['subdomains'][:50]:
                html += f"                    <li>{subdomain}</li>\n"
            
            if len(self.results['subdomains']) > 50:
                html += f"                    <li><em>... and {len(self.results['subdomains']) - 50} more</em></li>\n"
            
            html += """
                </ul>
            </div>
"""
        
        # Open ports section
        if self.results['ports']:
            html += """
            <div class="section">
                <h2>🔌 Open Ports</h2>
"""
            for ip, ports in self.results['ports'].items():
                html += f"                <h3>{ip}</h3>\n"
                html += "                <div>\n"
                for port in ports:
                    service_info = f"{port['port']}/{port['protocol']}"
                    if port['service'] != 'unknown':
                        service_info += f" - {port['service']}"
                    if port['version']:
                        service_info += f" {port['version']}"
                    
                    html += f'                    <span class="port-info">{service_info}</span>\n'
                html += "                </div>\n"
            
            html += """
            </div>
"""
        
        # Technologies section
        if self.results['technologies']:
            html += """
            <div class="section">
                <h2>🛠️ Detected Technologies</h2>
"""
            for url, techs in self.results['technologies'].items():
                html += f"                <h3>{url}</h3>\n"
                html += "                <ul class='list-group'>\n"
                for tech, version in list(techs.items())[:20]:
                    html += f"                    <li><strong>{tech}:</strong> {version}</li>\n"
                html += "                </ul>\n"
            
            html += """
            </div>
"""
        
        # SSL Issues section
        if self.results['ssl_issues']:
            html += """
            <div class="section">
                <h2>🔒 SSL/TLS Analysis</h2>
                <table class="vuln-table">
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Issue</th>
                            <th>Domain</th>
                        </tr>
                    </thead>
                    <tbody>
"""
            for issue in self.results['ssl_issues']:
                severity = issue['severity'].lower()
                badge_class = f"badge-{severity}"
                
                html += f"""
                        <tr>
                            <td><span class="badge {badge_class}">{issue['severity'].upper()}</span></td>
                            <td>{issue['issue']}</td>
                            <td>{issue['domain']}</td>
                        </tr>
"""
            html += """
                    </tbody>
                </table>
            </div>
"""
        
        # Directories section
        if self.results['directories']:
            html += """
            <div class="section">
                <h2>📁 Discovered Directories</h2>
                <ul class="list-group">
"""
            for directory in self.results['directories'][:100]:
                html += f"                    <li>{directory}</li>\n"
            
            if len(self.results['directories']) > 100:
                html += f"                    <li><em>... and {len(self.results['directories']) - 100} more</em></li>\n"
            
            html += """
                </ul>
            </div>
"""
        
        html += """
        </div>
        
        <div class="footer">
            <p>Generated by Deep Reconnaissance Tool</p>
            <p>Full JSON report available in report.json</p>
        </div>
    </div>
</body>
</html>
"""
        return html
    
    def run(self):
        """Main execution flow"""
        self.log(f"{Colors.BOLD}=== Deep Reconnaissance Tool ==={Colors.END}", "cyan")
        self.log(f"Target: {self.target}", "cyan")
        self.log(f"Max Workers: {self.max_workers}", "cyan")
        
        self.setup_directories()
        
        # Run all scans in parallel
        asyncio.run(self.run_parallel_scans())
        
        # Generate reports
        json_file, html_file = self.generate_report()
        
        self.log(f"\n{Colors.BOLD}=== Scan Complete ==={Colors.END}", "green")
        self.log(f"Results directory: {self.output_dir}", "green")
        self.log(f"JSON Report: {json_file}", "green")
        self.log(f"HTML Report: {html_file}", "green")
        
        # Print summary
        print(f"\n{Colors.BOLD}=== Summary ==={Colors.END}")
        print(f"{Colors.CYAN}Subdomains found:{Colors.END} {self.results['summary']['total_subdomains']}")
        print(f"{Colors.CYAN}IP addresses:{Colors.END} {self.results['summary']['total_ips']}")
        print(f"{Colors.CYAN}Open ports:{Colors.END} {self.results['summary']['open_ports']}")
        print(f"{Colors.RED}Critical vulnerabilities:{Colors.END} {self.results['summary']['critical_vulns']}")
        print(f"{Colors.YELLOW}High vulnerabilities:{Colors.END} {self.results['summary']['high_vulns']}")
        print(f"{Colors.YELLOW}Medium vulnerabilities:{Colors.END} {self.results['summary']['medium_vulns']}")
        print(f"{Colors.GREEN}Low vulnerabilities:{Colors.END} {self.results['summary']['low_vulns']}")

def main():
    parser = argparse.ArgumentParser(
        description='Deep Reconnaissance Automation Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t example.com
  %(prog)s -t 192.168.1.1 -w 20
  %(prog)s -t example.com -o custom_output
        """
    )
    
    parser.add_argument('-t', '--target', required=True, help='Target domain or IP address')
    parser.add_argument('-o', '--output', default='recon_results', help='Output directory (default: recon_results)')
    parser.add_argument('-w', '--workers', type=int, default=10, help='Max parallel workers (default: 10)')
    
    args = parser.parse_args()
    
    # Validate target
    if not args.target:
        print(f"{Colors.RED}Error: Target is required{Colors.END}")
        sys.exit(1)
    
    # Create scanner instance
    scanner = ReconScanner(
        target=args.target,
        output_dir=args.output,
        max_workers=args.workers
    )
    
    try:
        scanner.run()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Scan interrupted by user{Colors.END}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Colors.RED}Fatal error: {e}{Colors.END}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
