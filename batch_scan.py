#!/usr/bin/env python3
"""
Batch Scanner for Multiple Targets
Automates scanning of multiple domains/IPs from a file
"""

import subprocess
import sys
import argparse
import time
from pathlib import Path
from datetime import datetime

class Colors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'

def log(message: str, color: str = "blue"):
    """Colored logging"""
    color_map = {
        "red": Colors.RED,
        "green": Colors.GREEN,
        "yellow": Colors.YELLOW,
        "blue": Colors.BLUE
    }
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"{color_map.get(color, Colors.BLUE)}[{timestamp}] {message}{Colors.END}")

def read_targets(file_path: str) -> list:
    """Read targets from file, one per line"""
    try:
        with open(file_path, 'r') as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        return targets
    except FileNotFoundError:
        log(f"Target file not found: {file_path}", "red")
        sys.exit(1)
    except Exception as e:
        log(f"Error reading target file: {e}", "red")
        sys.exit(1)

def scan_target(target: str, output_dir: str, workers: int, delay: int) -> bool:
    """Scan a single target"""
    log(f"Starting scan for: {target}", "cyan")
    
    try:
        cmd = [
            'python3', 'deep_recon.py',
            '-t', target,
            '-o', output_dir,
            '-w', str(workers)
        ]
        
        result = subprocess.run(cmd, check=False)
        
        if result.returncode == 0:
            log(f"Completed scan for: {target}", "green")
            return True
        else:
            log(f"Scan failed for: {target}", "red")
            return False
            
    except Exception as e:
        log(f"Error scanning {target}: {e}", "red")
        return False
    finally:
        if delay > 0:
            log(f"Waiting {delay} seconds before next scan...", "yellow")
            time.sleep(delay)

def main():
    parser = argparse.ArgumentParser(
        description='Batch scanner for multiple targets',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -f targets.txt
  %(prog)s -f targets.txt -w 15 -d 30
  %(prog)s -f targets.txt -o batch_results
        """
    )
    
    parser.add_argument('-f', '--file', required=True, help='File containing targets (one per line)')
    parser.add_argument('-o', '--output', default='batch_results', help='Base output directory')
    parser.add_argument('-w', '--workers', type=int, default=10, help='Workers per scan')
    parser.add_argument('-d', '--delay', type=int, default=0, help='Delay between scans (seconds)')
    parser.add_argument('--continue-on-error', action='store_true', help='Continue if a scan fails')
    
    args = parser.parse_args()
    
    # Read targets
    targets = read_targets(args.file)
    
    if not targets:
        log("No targets found in file", "red")
        sys.exit(1)
    
    log(f"Loaded {len(targets)} targets from {args.file}", "green")
    
    # Create output directory
    output_base = Path(args.output)
    output_base.mkdir(parents=True, exist_ok=True)
    
    # Scan each target
    print(f"\n{Colors.BOLD}{'='*60}{Colors.END}")
    print(f"{Colors.BOLD}Starting Batch Scan{Colors.END}")
    print(f"{Colors.BOLD}{'='*60}{Colors.END}\n")
    
    results = []
    start_time = time.time()
    
    for i, target in enumerate(targets, 1):
        log(f"[{i}/{len(targets)}] Target: {target}", "blue")
        
        success = scan_target(target, str(output_base), args.workers, args.delay)
        results.append((target, success))
        
        if not success and not args.continue_on_error:
            log("Stopping due to error (use --continue-on-error to continue)", "red")
            break
    
    # Summary
    elapsed = time.time() - start_time
    successful = sum(1 for _, success in results if success)
    failed = len(results) - successful
    
    print(f"\n{Colors.BOLD}{'='*60}{Colors.END}")
    print(f"{Colors.BOLD}Batch Scan Complete{Colors.END}")
    print(f"{Colors.BOLD}{'='*60}{Colors.END}\n")
    
    print(f"Total targets:    {len(results)}")
    print(f"{Colors.GREEN}Successful scans: {successful}{Colors.END}")
    print(f"{Colors.RED}Failed scans:     {failed}{Colors.END}")
    print(f"Total time:       {elapsed/60:.1f} minutes")
    print(f"Average per scan: {elapsed/len(results):.1f} seconds\n")
    
    # List failed targets
    if failed > 0:
        print(f"{Colors.BOLD}Failed targets:{Colors.END}")
        for target, success in results:
            if not success:
                print(f"  - {target}")
        print()
    
    log(f"Results saved in: {output_base}", "green")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Batch scan interrupted{Colors.END}")
        sys.exit(1)
