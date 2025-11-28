#!/usr/bin/env python3
"""
MCP Security Tests - Kali Tool Orchestration via Docker

Execute comprehensive security assessments using Kali Linux tools
through the MCP server Docker container.

Features:
- Phase-based security testing (Recon, Network, Web, Enumeration)
- Integration with Kali MCP tools
- Result aggregation and reporting
- Parallel execution where possible
- Proper error handling and retry logic

Usage:
    python mcp_security_tests.py --target example.com
    python mcp_security_tests.py -t example.com --phases recon web
    python mcp_security_tests.py -t example.com --timeout 600 --workers 5

Author: Kali MCP Server Project
License: MIT
"""

import json
import os
import sys
import time
import subprocess
import argparse
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field, asdict
import socket


@dataclass
class ScanResult:
    """Container for scan results"""
    tool: str
    target: str
    category: str
    status: str  # 'success', 'error', 'timeout', 'skipped'
    output: str
    duration: float
    timestamp: str
    output_file: Optional[str] = None
    error: Optional[str] = None


@dataclass
class TestSummary:
    """Summary of all test results"""
    target: str
    start_time: str
    end_time: Optional[str] = None
    total_scans: int = 0
    successful: int = 0
    failed: int = 0
    skipped: int = 0
    results: List[ScanResult] = field(default_factory=list)


class MCPTestRunner:
    """Runner for MCP-based security testing"""
    
    def __init__(self, target: str, container_name: str = "kali-mcp-server",
                 max_workers: int = 3, timeout: int = 300, verbose: bool = True,
                 output_dir: Optional[str] = None):
        """
        Initialize the MCP test runner.
        
        Args:
            target: Target domain to test
            container_name: Name of the Docker container running MCP server
            max_workers: Maximum concurrent scans
            timeout: Default timeout for scans in seconds
            verbose: Enable verbose output
            output_dir: Directory for output files
        """
        # Remove protocol if provided
        self.target = target.replace('https://', '').replace('http://', '').rstrip('/')
        self.container_name = container_name
        self.max_workers = max_workers
        self.default_timeout = timeout
        self.verbose = verbose
        
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Set output directory - automatically create website-specific folder
        if output_dir:
            self.base_dir = Path(output_dir)
        else:
            # Create folder named after the website (e.g., example.com/)
            website_name = self.target.split('/')[0].split(':')[0]  # Get domain from target
            # Sanitize folder name (remove invalid characters)
            website_name = re.sub(r'[<>:"/\\|?*]', '_', website_name)
            self.base_dir = Path.cwd() / website_name
            
        self.scans_dir = self.base_dir / "scans"
        self.reports_dir = self.base_dir / "reports"
        
        # Create directories
        for subdir in ['network', 'web', 'enumeration', 'recon']:
            (self.scans_dir / subdir).mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        
        self.summary = TestSummary(
            target=target,
            start_time=datetime.now().isoformat()
        )
        
        # Colors for output
        self.colors = {
            'GREEN': '\033[92m',
            'RED': '\033[91m',
            'YELLOW': '\033[93m',
            'BLUE': '\033[94m',
            'CYAN': '\033[96m',
            'RESET': '\033[0m',
            'BOLD': '\033[1m'
        }
        
    def log(self, message: str, level: str = 'INFO') -> None:
        """Log messages with timestamp and color"""
        if not self.verbose and level == 'DEBUG':
            return
            
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        color_map = {
            'INFO': self.colors['BLUE'],
            'SUCCESS': self.colors['GREEN'],
            'WARNING': self.colors['YELLOW'],
            'ERROR': self.colors['RED'],
            'DEBUG': self.colors['CYAN']
        }
        color = color_map.get(level, self.colors['BLUE'])
        reset = self.colors['RESET']
        print(f"{color}[{timestamp}] [{level}]{reset} {message}")
        
    def check_container_running(self) -> Tuple[bool, str]:
        """Check if the MCP container is running"""
        try:
            # First, try to find container by image name (most reliable)
            # This works even if Docker assigned an auto-generated name
            result = subprocess.run(
                ["docker", "ps", "--filter", "ancestor=kali-mcp-server:latest",
                 "--format", "{{.Names}}"],
                capture_output=True, text=True, timeout=10
            )
            
            if result.returncode == 0 and result.stdout.strip():
                containers = [c.strip() for c in result.stdout.strip().split('\n') if c.strip()]
                if containers:
                    self.container_name = containers[0]
                    return True, f"Container '{self.container_name}' is running"
            
            # Also try without :latest tag
            result = subprocess.run(
                ["docker", "ps", "--filter", "ancestor=kali-mcp-server",
                 "--format", "{{.Names}}"],
                capture_output=True, text=True, timeout=10
            )
            
            if result.returncode == 0 and result.stdout.strip():
                containers = [c.strip() for c in result.stdout.strip().split('\n') if c.strip()]
                if containers:
                    self.container_name = containers[0]
                    return True, f"Container '{self.container_name}' is running"
            
            # Fall back to checking by name patterns
            result = subprocess.run(
                ["docker", "ps", "--filter", f"name={self.container_name}", 
                 "--format", "{{.Names}}"],
                capture_output=True, text=True, timeout=10
            )
            
            if result.returncode == 0 and self.container_name in result.stdout:
                return True, f"Container '{self.container_name}' is running"
                
            # Check for alternative container names
            alt_names = ["kali-mcp-server-detached", "kali-mcp", "mcp-server"]
            for alt_name in alt_names:
                result = subprocess.run(
                    ["docker", "ps", "--filter", f"name={alt_name}", 
                     "--format", "{{.Names}}"],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0 and alt_name in result.stdout:
                    self.container_name = alt_name
                    return True, f"Found container '{alt_name}'"
                    
            return False, "No MCP container found running"
            
        except subprocess.TimeoutExpired:
            return False, "Docker command timed out"
        except FileNotFoundError:
            return False, "Docker not found in PATH"
        except Exception as e:
            return False, f"Error checking container: {str(e)}"
            
    def execute_in_container(self, command: str, timeout: Optional[int] = None) -> Tuple[bool, str]:
        """Execute a command in the Docker container"""
        timeout = timeout or self.default_timeout
        
        try:
            result = subprocess.run(
                ["docker", "exec", self.container_name, "sh", "-c", command],
                capture_output=True, text=True, timeout=timeout
            )
            
            if result.returncode == 0:
                return True, result.stdout.strip()
            else:
                error_output = result.stderr.strip() or result.stdout.strip()
                return False, f"Command failed: {error_output}"
                
        except subprocess.TimeoutExpired:
            return False, f"Command timed out after {timeout} seconds"
        except Exception as e:
            return False, f"Execution error: {str(e)}"
            
    def run_mcp_tool(self, tool: str, target: str, category: str,
                     options: str = "", timeout: Optional[int] = None) -> ScanResult:
        """Run a specific MCP tool and capture results"""
        start_time = time.time()
        timestamp = datetime.now().isoformat()
        timeout = timeout or self.default_timeout
        
        self.log(f"Running {tool} on {target}...", level='INFO')
        
        # Build command based on tool
        command = self._build_tool_command(tool, target, options)
        
        if not command:
            return ScanResult(
                tool=tool,
                target=target,
                category=category,
                status='skipped',
                output='',
                duration=0,
                timestamp=timestamp,
                error=f'Unknown tool: {tool}'
            )
            
        success, output = self.execute_in_container(command, timeout=timeout)
        duration = time.time() - start_time
        
        # Save output to file
        output_file = self._save_output(tool, category, output)
        
        status = 'success' if success else 'error'
        if 'timed out' in output.lower():
            status = 'timeout'
            
        result = ScanResult(
            tool=tool,
            target=target,
            category=category,
            status=status,
            output=output[:10000],  # Truncate for summary
            duration=duration,
            timestamp=timestamp,
            output_file=str(output_file),
            error=None if success else output[:500]
        )
        
        self.summary.results.append(result)
        self.summary.total_scans += 1
        
        if status == 'success':
            self.summary.successful += 1
            self.log(f"✓ {tool} completed in {duration:.2f}s", level='SUCCESS')
        else:
            self.summary.failed += 1
            self.log(f"✗ {tool} failed: {output[:100]}", level='ERROR')
            
        return result
        
    def _build_tool_command(self, tool: str, target: str, options: str = "") -> Optional[str]:
        """Build the command for a specific tool"""
        tool_commands = {
            # Reconnaissance
            'whatweb': f'whatweb --no-errors https://{target} {options}',
            'theharvester': f'theHarvester -d {target} -b all -l 500 {options}',
            'dnsenum': f'dnsenum {target} {options}',
            'dnsrecon': f'dnsrecon -d {target} {options}',
            
            # Network
            'nmap': f'nmap -sV -O --top-ports 1000 {target} {options}',
            'nmap_quick': f'nmap -sV --top-ports 100 {target} {options}',
            'masscan': f'masscan -p1-65535 --rate=1000 {target} {options}',
            
            # Web Application
            'nikto': f'nikto -h https://{target} -maxtime 300 {options}',
            'wapiti': f'wapiti -u https://{target} --scope folder --max-scan-time 180 {options}',
            'sqlmap': f'sqlmap -u https://{target} --batch --crawl=1 --timeout=30 --threads=1 {options}',
            'xsser': f'xsser -u https://{target} -c 100 --Cl {options}',
            'xssstrike': f'python3 /usr/share/xssstrike/xssstrike.py -u https://{target} {options}',
            'commix': f'commix -u https://{target} --batch {options}',
            'zap_baseline': f'zap-baseline.py -t https://{target} -m 5 {options}',
            'skipfish': f'skipfish -o /tmp/skipfish_{self.timestamp} -l 3 -m 5 https://{target} {options}',
            'uniscan': f'uniscan -u https://{target} {options}',
            
            # Enumeration / Discovery
            'dirb': f'dirb https://{target} /usr/share/wordlists/dirb/common.txt -r {options}',
            'gobuster': f'gobuster dir -u https://{target} -w /usr/share/wordlists/dirb/common.txt -t 20 --timeout 10s {options}',
            'ffuf': f'ffuf -u https://{target}/FUZZ -w /usr/share/wordlists/dirb/common.txt -t 40 -timeout 10 -maxtime 120 {options}',
            'wfuzz': f'wfuzz -w /usr/share/wordlists/dirb/common.txt -c --conn-delay 10 https://{target}/FUZZ {options}',
            
            # WordPress specific
            'wpscan': f'wpscan --url https://{target} --enumerate u,p,t {options}',
        }
        
        return tool_commands.get(tool)
        
    def _save_output(self, tool: str, category: str, output: str) -> Path:
        """Save tool output to file"""
        category_dir = self.scans_dir / category
        category_dir.mkdir(parents=True, exist_ok=True)
        
        output_file = category_dir / f"{tool}_{self.timestamp}.txt"
        
        header = f"""{'='*60}
{tool.upper()} Scan Results
Target: {self.target}
Timestamp: {self.timestamp}
{'='*60}

"""
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(header + output)
            
        return output_file
        
    def run_recon_tests(self) -> List[ScanResult]:
        """Phase 1: Information Gathering & Reconnaissance"""
        self.log("\n" + "="*60, level='INFO')
        self.log("PHASE 1: Information Gathering & Reconnaissance", level='INFO')
        self.log("="*60, level='INFO')
        
        # Extract base domain for DNS tools
        domain_parts = self.target.split('.')
        if len(domain_parts) > 1:
            dns_target = '.'.join(domain_parts[-2:])  # Get base domain
        else:
            dns_target = self.target
        
        tests = [
            ('whatweb', self.target, 'recon', '', 60),
            ('theharvester', dns_target, 'recon', '', 180),
            ('dnsenum', dns_target, 'recon', '', 300),
            ('dnsrecon', dns_target, 'recon', '', 120),
            ('nmap_quick', self.target, 'recon', '', 120),
        ]
        
        results = []
        for tool, target, category, options, timeout in tests:
            result = self.run_mcp_tool(tool, target, category, options, timeout)
            results.append(result)
            
        return results
        
    def run_network_tests(self) -> List[ScanResult]:
        """Phase 2: Network Security Testing"""
        self.log("\n" + "="*60, level='INFO')
        self.log("PHASE 2: Network Security Testing", level='INFO')
        self.log("="*60, level='INFO')
        
        tests = [
            ('nmap', self.target, 'network', '', 300),
        ]
        
        results = []
        for tool, target, category, options, timeout in tests:
            result = self.run_mcp_tool(tool, target, category, options, timeout)
            results.append(result)
            
        return results
        
    def run_web_tests(self) -> List[ScanResult]:
        """Phase 3: Web Application Security Testing"""
        self.log("\n" + "="*60, level='INFO')
        self.log("PHASE 3: Web Application Security Testing", level='INFO')
        self.log("="*60, level='INFO')
        
        tests = [
            ('nikto', self.target, 'web', '', 360),
            ('wapiti', self.target, 'web', '', 300),
            ('sqlmap', self.target, 'web', '', 360),
            ('xsser', self.target, 'web', '', 180),
            ('commix', self.target, 'web', '', 180),
        ]
        
        results = []
        for tool, target, category, options, timeout in tests:
            result = self.run_mcp_tool(tool, target, category, options, timeout)
            results.append(result)
            
        return results
        
    def run_enumeration_tests(self) -> List[ScanResult]:
        """Phase 4: Directory & File Discovery"""
        self.log("\n" + "="*60, level='INFO')
        self.log("PHASE 4: Directory & File Discovery", level='INFO')
        self.log("="*60, level='INFO')
        
        tests = [
            ('dirb', self.target, 'enumeration', '', 300),
            ('gobuster', self.target, 'enumeration', '', 300),
            ('ffuf', self.target, 'enumeration', '', 180),
        ]
        
        results = []
        for tool, target, category, options, timeout in tests:
            result = self.run_mcp_tool(tool, target, category, options, timeout)
            results.append(result)
            
        return results
        
    def run_all_tests(self, phases: Optional[List[str]] = None) -> TestSummary:
        """Run all security test phases"""
        self.log("="*60, level='INFO')
        self.log(f"Starting comprehensive security assessment of {self.target}", level='INFO')
        self.log("="*60, level='INFO')
        
        # Check container first
        is_running, message = self.check_container_running()
        if not is_running:
            self.log(message, level='ERROR')
            self.log("Please start the MCP server container first:", level='ERROR')
            self.log("  ./run-docker.sh   (Linux/Mac)", level='ERROR')
            self.log("  .\\run-docker.ps1  (Windows)", level='ERROR')
            self.summary.end_time = datetime.now().isoformat()
            return self.summary
            
        self.log(message, level='SUCCESS')
        
        # Check if target is reachable
        if not self._check_target_reachable():
            self.log(f"Warning: Target {self.target} may not be reachable", level='WARNING')
        
        # Define phases
        phase_functions = {
            'recon': self.run_recon_tests,
            'network': self.run_network_tests,
            'web': self.run_web_tests,
            'enumeration': self.run_enumeration_tests,
        }
        
        # Run selected phases or all
        phases = phases or list(phase_functions.keys())
        
        for phase in phases:
            if phase in phase_functions:
                try:
                    phase_functions[phase]()
                except Exception as e:
                    self.log(f"Phase {phase} failed with error: {str(e)}", level='ERROR')
                    
        self.summary.end_time = datetime.now().isoformat()
        return self.summary
        
    def _check_target_reachable(self) -> bool:
        """Check if target is reachable"""
        try:
            socket.create_connection((self.target, 443), timeout=10)
            return True
        except (socket.timeout, socket.error, OSError):
            try:
                socket.create_connection((self.target, 80), timeout=10)
                return True
            except (socket.timeout, socket.error, OSError):
                return False
                
    def save_summary(self) -> str:
        """Save test summary to JSON file"""
        summary_file = self.reports_dir / f"mcp_test_summary_{self.timestamp}.json"
        
        # Convert dataclass to dict
        summary_dict = {
            'target': self.summary.target,
            'start_time': self.summary.start_time,
            'end_time': self.summary.end_time,
            'total_scans': self.summary.total_scans,
            'successful': self.summary.successful,
            'failed': self.summary.failed,
            'skipped': self.summary.skipped,
            'results': [asdict(r) for r in self.summary.results]
        }
        
        with open(summary_file, 'w', encoding='utf-8') as f:
            json.dump(summary_dict, f, indent=2, ensure_ascii=False)
            
        self.log(f"Summary saved to {summary_file}", level='INFO')
        return str(summary_file)
        
    def print_summary(self) -> None:
        """Print test summary to console"""
        c = self.colors
        print(f"\n{c['BOLD']}{'='*60}{c['RESET']}")
        print(f"{c['BOLD']}MCP SECURITY TEST SUMMARY{c['RESET']}")
        print(f"{c['BOLD']}{'='*60}{c['RESET']}")
        print(f"Target: {self.target}")
        print(f"Start:  {self.summary.start_time}")
        print(f"End:    {self.summary.end_time}")
        print(f"\n{c['BOLD']}Results:{c['RESET']}")
        print(f"  Total Scans:  {self.summary.total_scans}")
        print(f"  {c['GREEN']}✓ Successful: {self.summary.successful}{c['RESET']}")
        print(f"  {c['RED']}✗ Failed:     {self.summary.failed}{c['RESET']}")
        print(f"  {c['YELLOW']}○ Skipped:    {self.summary.skipped}{c['RESET']}")
        
        if self.summary.results:
            print(f"\n{c['BOLD']}Scan Details:{c['RESET']}")
            for result in self.summary.results:
                status_color = c['GREEN'] if result.status == 'success' else c['RED']
                status_symbol = '✓' if result.status == 'success' else '✗'
                print(f"  {status_color}{status_symbol}{c['RESET']} {result.tool}: "
                      f"{result.status} ({result.duration:.2f}s)")
                      
        print(f"\n{c['BOLD']}Output Locations:{c['RESET']}")
        print(f"  Scans:   {self.scans_dir}")
        print(f"  Reports: {self.reports_dir}")
        print(f"{'='*60}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Run Kali MCP security tests against a target',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python mcp_security_tests.py --target example.com
  python mcp_security_tests.py -t example.com --phases recon web
  python mcp_security_tests.py -t example.com --timeout 600 --workers 5
        """
    )
    
    parser.add_argument('--target', '-t', required=True,
                       help='Target domain to test')
    parser.add_argument('--container', '-c', default='kali-mcp-server',
                       help='Docker container name (default: kali-mcp-server)')
    parser.add_argument('--phases', '-p', nargs='+',
                       choices=['recon', 'network', 'web', 'enumeration'],
                       help='Phases to run (default: all)')
    parser.add_argument('--workers', '-w', type=int, default=3,
                       help='Max concurrent workers (default: 3)')
    parser.add_argument('--timeout', type=int, default=300,
                       help='Default scan timeout in seconds (default: 300)')
    parser.add_argument('--output-dir', '-o', help='Output directory for results')
    parser.add_argument('--quiet', '-q', action='store_true',
                       help='Suppress verbose output')
    
    args = parser.parse_args()
    
    runner = MCPTestRunner(
        target=args.target,
        container_name=args.container,
        max_workers=args.workers,
        timeout=args.timeout,
        verbose=not args.quiet,
        output_dir=args.output_dir
    )
    
    try:
        runner.run_all_tests(phases=args.phases)
        runner.save_summary()
        runner.print_summary()
        
        # Return non-zero if any tests failed
        if runner.summary.failed > 0:
            sys.exit(1)
        sys.exit(0)
        
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
        runner.summary.end_time = datetime.now().isoformat()
        runner.save_summary()
        runner.print_summary()
        sys.exit(130)
    except Exception as e:
        print(f"\nCritical error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()

