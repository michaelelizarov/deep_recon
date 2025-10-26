#!/usr/bin/env python3
"""
Installation Verification Script
Tests if all required tools are properly installed
"""

import subprocess
import sys
from typing import Tuple, List

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    END = '\033[0m'
    BOLD = '\033[1m'

def check_command(command: str) -> Tuple[bool, str]:
    """Check if a command exists and is executable"""
    try:
        result = subprocess.run(
            ['which', command],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            path = result.stdout.strip()
            return True, path
        return False, ""
    except:
        return False, ""

def check_version(command: str, version_flag: str = '--version') -> str:
    """Get version information for a command"""
    try:
        result = subprocess.run(
            [command, version_flag],
            capture_output=True,
            text=True,
            timeout=5
        )
        output = result.stdout + result.stderr
        # Get first line that looks like a version
        for line in output.split('\n'):
            if any(v in line.lower() for v in ['version', 'v1.', 'v2.', 'v3.']):
                return line.strip()[:50]
        return output.split('\n')[0][:50] if output else "Unknown"
    except:
        return "Unknown"

def main():
    print(f"\n{Colors.BOLD}{'='*60}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}Deep Reconnaissance Tool - Installation Verification{Colors.END}")
    print(f"{Colors.BOLD}{'='*60}{Colors.END}\n")
    
    # Required tools
    tools = [
        ('python3', 'Python 3', '--version'),
        ('whois', 'WHOIS Client', '--version'),
        ('dig', 'DNS Tools', '-v'),
        ('nmap', 'Nmap Port Scanner', '--version'),
        ('subfinder', 'Subfinder (ProjectDiscovery)', '-version'),
        ('httpx', 'HTTPx (ProjectDiscovery)', '-version'),
        ('nuclei', 'Nuclei (ProjectDiscovery)', '-version'),
        ('katana', 'Katana (ProjectDiscovery)', '-version'),
        ('ffuf', 'FFUF Web Fuzzer', '-V'),
        ('whatweb', 'WhatWeb Technology Detection', '--version'),
        ('nikto', 'Nikto Web Scanner', '-Version'),
        ('sslyze', 'SSLyze SSL/TLS Scanner', '--version'),
    ]
    
    results: List[Tuple[str, bool, str]] = []
    
    print(f"{Colors.BOLD}Checking required tools...{Colors.END}\n")
    
    for command, name, version_flag in tools:
        installed, path = check_command(command)
        
        if installed:
            version = check_version(command, version_flag)
            print(f"{Colors.GREEN}✓{Colors.END} {name:.<45} INSTALLED")
            print(f"  {Colors.BLUE}Location:{Colors.END} {path}")
            print(f"  {Colors.BLUE}Version:{Colors.END}  {version}\n")
            results.append((name, True, path))
        else:
            print(f"{Colors.RED}✗{Colors.END} {name:.<45} NOT FOUND")
            print(f"  {Colors.YELLOW}Please install this tool{Colors.END}\n")
            results.append((name, False, ""))
    
    # Summary
    print(f"{Colors.BOLD}{'='*60}{Colors.END}")
    print(f"{Colors.BOLD}Summary{Colors.END}\n")
    
    installed_count = sum(1 for _, installed, _ in results if installed)
    total_count = len(results)
    
    print(f"Installed: {Colors.GREEN}{installed_count}{Colors.END}/{total_count}")
    print(f"Missing:   {Colors.RED}{total_count - installed_count}{Colors.END}/{total_count}\n")
    
    if installed_count == total_count:
        print(f"{Colors.GREEN}{Colors.BOLD}✓ All tools are installed!{Colors.END}")
        print(f"\n{Colors.BLUE}You're ready to run:{Colors.END}")
        print(f"  python3 deep_recon.py -t example.com\n")
        return 0
    else:
        print(f"{Colors.YELLOW}{Colors.BOLD}⚠ Some tools are missing!{Colors.END}")
        print(f"\n{Colors.BLUE}Run the installation script:{Colors.END}")
        print(f"  sudo ./install.sh\n")
        
        missing = [name for name, installed, _ in results if not installed]
        print(f"{Colors.BOLD}Missing tools:{Colors.END}")
        for tool in missing:
            print(f"  - {tool}")
        print()
        return 1
    
    print(f"{Colors.BOLD}{'='*60}{Colors.END}\n")

if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Verification cancelled{Colors.END}")
        sys.exit(1)
