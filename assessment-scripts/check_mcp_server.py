#!/usr/bin/env python3
"""
MCP Server Health Checker

Comprehensive health checking for the Kali MCP Server Docker container.

Features:
- Container status verification
- Health endpoint checks
- Tool availability verification
- Resource usage monitoring
- Automatic container startup

Usage:
    python check_mcp_server.py
    python check_mcp_server.py --auto-start
    python check_mcp_server.py --container my-container --save

Author: Kali MCP Server Project
License: MIT
"""

import subprocess
import sys
import json
import time
from pathlib import Path
from typing import Tuple, Optional, Dict, Any, List
from datetime import datetime
import argparse


class Colors:
    """ANSI color codes for terminal output"""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


class MCPServerChecker:
    """Comprehensive MCP Server health checker"""
    
    def __init__(self, container_name: str = "kali-mcp-server", 
                 alt_names: Optional[List[str]] = None,
                 verbose: bool = True,
                 output_dir: Optional[str] = None):
        """
        Initialize the health checker.
        
        Args:
            container_name: Primary container name to check
            alt_names: Alternative container names to check
            verbose: Enable verbose output
            output_dir: Directory for output files
        """
        self.container_name = container_name
        self.alt_names = alt_names or ["kali-mcp-server-detached", "kali-mcp"]
        self.verbose = verbose
        
        if output_dir:
            self.output_dir = Path(output_dir)
        else:
            self.output_dir = Path.cwd() / 'output' / 'reports'
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.results: Dict[str, Any] = {
            'timestamp': datetime.now().isoformat(),
            'checks': {},
            'overall_status': 'unknown'
        }
        
    def log(self, message: str, level: str = 'INFO') -> None:
        """Log messages with color"""
        if not self.verbose and level == 'DEBUG':
            return
            
        color_map = {
            'INFO': Colors.BLUE,
            'SUCCESS': Colors.GREEN,
            'WARNING': Colors.YELLOW,
            'ERROR': Colors.RED,
            'DEBUG': Colors.CYAN
        }
        color = color_map.get(level, Colors.BLUE)
        print(f"{color}[{level}]{Colors.RESET} {message}")
        
    def run_docker_command(self, args: List[str], timeout: int = 10) -> Tuple[bool, str, int]:
        """Run a Docker command and return success, output, and return code"""
        try:
            result = subprocess.run(
                ["docker"] + args,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.returncode == 0, result.stdout.strip(), result.returncode
        except subprocess.TimeoutExpired:
            return False, "Command timed out", -1
        except FileNotFoundError:
            return False, "Docker not found in PATH", -1
        except Exception as e:
            return False, str(e), -1
            
    def check_docker_available(self) -> Tuple[bool, str]:
        """Check if Docker is available and running"""
        self.log("Checking Docker availability...", level='DEBUG')
        
        success, output, _ = self.run_docker_command(["--version"])
        if not success:
            self.results['checks']['docker'] = {'status': 'failed', 'error': output}
            return False, output
            
        # Check if Docker daemon is running
        success, output, _ = self.run_docker_command(["info"], timeout=15)
        if not success:
            self.results['checks']['docker'] = {'status': 'failed', 'error': 'Docker daemon not running'}
            return False, "Docker daemon is not running"
            
        self.results['checks']['docker'] = {'status': 'passed', 'version': output.split('\n')[0]}
        return True, "Docker is available and running"
        
    def find_container(self) -> Tuple[bool, Optional[str], str]:
        """Find a running MCP server container"""
        self.log("Looking for MCP server container...", level='DEBUG')
        
        all_names = [self.container_name] + self.alt_names
        
        for name in all_names:
            success, output, _ = self.run_docker_command([
                "ps", "--filter", f"name={name}", "--format", "{{.Names}}"
            ])
            
            if success and name in output:
                self.container_name = name
                return True, name, f"Found running container: {name}"
                
        # Check if container exists but is stopped
        for name in all_names:
            success, output, _ = self.run_docker_command([
                "ps", "-a", "--filter", f"name={name}", "--format", "{{.Names}} {{.Status}}"
            ])
            
            if success and name in output:
                return False, name, f"Container exists but is stopped: {output}"
                
        return False, None, "No MCP server container found"
        
    def check_container_health(self) -> Tuple[bool, Dict[str, Any]]:
        """Check container health and status"""
        self.log("Checking container health...", level='DEBUG')
        
        health_info: Dict[str, Any] = {}
        
        # Get container status
        success, output, _ = self.run_docker_command([
            "inspect", self.container_name, 
            "--format", "{{.State.Status}} {{.State.Running}} {{.State.Health.Status}}"
        ])
        
        if not success:
            return False, {'error': 'Failed to inspect container'}
            
        parts = output.split()
        health_info['status'] = parts[0] if parts else 'unknown'
        health_info['running'] = parts[1].lower() == 'true' if len(parts) > 1 else False
        health_info['health'] = parts[2] if len(parts) > 2 else 'none'
        
        # Get container resource usage
        success, output, _ = self.run_docker_command([
            "stats", self.container_name, "--no-stream", "--format",
            "{{.CPUPerc}} {{.MemUsage}} {{.MemPerc}}"
        ])
        
        if success and output:
            parts = output.split()
            health_info['cpu_percent'] = parts[0] if parts else 'unknown'
            health_info['memory'] = ' '.join(parts[1:3]) if len(parts) > 2 else 'unknown'
            health_info['memory_percent'] = parts[3] if len(parts) > 3 else 'unknown'
            
        # Get container uptime
        success, output, _ = self.run_docker_command([
            "inspect", self.container_name,
            "--format", "{{.State.StartedAt}}"
        ])
        
        if success:
            health_info['started_at'] = output
            
        is_healthy = health_info.get('running', False) and \
                     health_info.get('health', 'none') != 'unhealthy'
                     
        self.results['checks']['container_health'] = health_info
        return is_healthy, health_info
        
    def check_tools_available(self, tools: Optional[List[str]] = None) -> Tuple[bool, Dict[str, bool]]:
        """Check if security tools are available in the container"""
        self.log("Checking tool availability...", level='DEBUG')
        
        if tools is None:
            tools = [
                'nmap', 'nikto', 'sqlmap', 'whatweb', 'gobuster', 
                'ffuf', 'wfuzz', 'wapiti', 'dirb', 'xsser'
            ]
            
        tool_status: Dict[str, bool] = {}
        
        for tool in tools:
            success, output, _ = self.run_docker_command([
                "exec", self.container_name, "which", tool
            ])
            tool_status[tool] = success and tool in output
            
        all_available = all(tool_status.values())
        self.results['checks']['tools'] = tool_status
        
        return all_available, tool_status
        
    def check_mcp_server_responding(self) -> Tuple[bool, str]:
        """Check if MCP server process is responding"""
        self.log("Checking MCP server process...", level='DEBUG')
        
        # Check if Python/MCP process is running
        success, output, _ = self.run_docker_command([
            "exec", self.container_name, 
            "pgrep", "-f", "mcp_server"
        ], timeout=15)
        
        if success and output.strip():
            self.results['checks']['mcp_process'] = {'status': 'running', 'pid': output.strip()}
            return True, f"MCP server process is running (PID: {output.strip()})"
            
        # Try alternative check
        success, output, _ = self.run_docker_command([
            "exec", self.container_name,
            "python3", "-c", "print('OK')"
        ], timeout=15)
        
        if success and 'OK' in output:
            self.results['checks']['mcp_process'] = {'status': 'python_ok', 'note': 'Python available'}
            return True, "Python interpreter is available in container"
            
        self.results['checks']['mcp_process'] = {'status': 'not_found'}
        return False, "MCP server process not found"
        
    def execute_test_command(self) -> Tuple[bool, str]:
        """Execute a simple test command to verify functionality"""
        self.log("Executing test command...", level='DEBUG')
        
        test_commands = [
            ("echo 'MCP test'", "MCP test"),
            ("nmap --version", "Nmap"),
            ("python3 --version", "Python"),
        ]
        
        for cmd, expected in test_commands:
            success, output, _ = self.run_docker_command([
                "exec", self.container_name, "sh", "-c", cmd
            ], timeout=30)
            
            if success and expected in output:
                self.results['checks']['test_command'] = {
                    'status': 'passed',
                    'command': cmd,
                    'output': output[:200]
                }
                return True, f"Test command succeeded: {output[:100]}"
                
        self.results['checks']['test_command'] = {'status': 'failed'}
        return False, "All test commands failed"
        
    def start_container(self) -> Tuple[bool, str]:
        """Attempt to start the MCP server container"""
        self.log("Attempting to start container...", level='INFO')
        
        # Try starting existing container first
        success, output, _ = self.run_docker_command([
            "start", self.container_name
        ], timeout=30)
        
        if success:
            self.log("Started existing container", level='SUCCESS')
            time.sleep(3)
            return True, f"Started container: {self.container_name}"
            
        # Try docker-compose if available
        try:
            result = subprocess.run(
                ["docker-compose", "up", "-d"],
                capture_output=True,
                text=True,
                timeout=90
            )
            if result.returncode == 0:
                time.sleep(5)
                return True, "Started via docker-compose"
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
            
        return False, "Failed to start container"
        
    def run_all_checks(self, auto_start: bool = False) -> Tuple[bool, Dict[str, Any]]:
        """Run all health checks"""
        self.log(f"\n{Colors.BOLD}{'='*50}{Colors.RESET}")
        self.log(f"{Colors.BOLD}MCP Server Health Check{Colors.RESET}")
        self.log(f"{Colors.BOLD}{'='*50}{Colors.RESET}\n")
        
        all_passed = True
        
        # Check 1: Docker availability
        self.log("1. Checking Docker...", level='INFO')
        success, message = self.check_docker_available()
        if success:
            self.log(f"   ✓ {message}", level='SUCCESS')
        else:
            self.log(f"   ✗ {message}", level='ERROR')
            self.results['overall_status'] = 'failed'
            return False, self.results
            
        # Check 2: Find container
        self.log("2. Finding MCP container...", level='INFO')
        running, name, message = self.find_container()
        if running:
            self.log(f"   ✓ {message}", level='SUCCESS')
        else:
            self.log(f"   ⚠ {message}", level='WARNING')
            if auto_start and name:
                self.log("   Attempting auto-start...", level='INFO')
                success, start_msg = self.start_container()
                if success:
                    self.log(f"   ✓ {start_msg}", level='SUCCESS')
                    running = True
                else:
                    self.log(f"   ✗ {start_msg}", level='ERROR')
                    all_passed = False
            else:
                all_passed = False
                if auto_start:
                    success, start_msg = self.start_container()
                    if success:
                        self.log(f"   ✓ {start_msg}", level='SUCCESS')
                        running, name, _ = self.find_container()
                        
        if not running:
            self.results['overall_status'] = 'container_not_running'
            return False, self.results
            
        # Check 3: Container health
        self.log("3. Checking container health...", level='INFO')
        healthy, health_info = self.check_container_health()
        if healthy:
            status = health_info.get('status', 'unknown')
            self.log(f"   ✓ Container is healthy (Status: {status})", level='SUCCESS')
            if health_info.get('cpu_percent'):
                self.log(f"   ℹ Resources: CPU {health_info['cpu_percent']}, "
                        f"Memory {health_info.get('memory', 'N/A')}", level='DEBUG')
        else:
            self.log(f"   ⚠ Container health issues: {health_info}", level='WARNING')
            
        # Check 4: Tools availability
        self.log("4. Checking security tools...", level='INFO')
        tools_ok, tool_status = self.check_tools_available()
        available_count = sum(1 for v in tool_status.values() if v)
        total_count = len(tool_status)
        if tools_ok:
            self.log(f"   ✓ All {total_count} tools available", level='SUCCESS')
        else:
            missing = [k for k, v in tool_status.items() if not v]
            self.log(f"   ⚠ {available_count}/{total_count} tools available. "
                    f"Missing: {', '.join(missing)}", level='WARNING')
            
        # Check 5: MCP server process
        self.log("5. Checking MCP server process...", level='INFO')
        mcp_ok, mcp_msg = self.check_mcp_server_responding()
        if mcp_ok:
            self.log(f"   ✓ {mcp_msg}", level='SUCCESS')
        else:
            self.log(f"   ⚠ {mcp_msg}", level='WARNING')
            
        # Check 6: Test command execution
        self.log("6. Testing command execution...", level='INFO')
        test_ok, test_msg = self.execute_test_command()
        if test_ok:
            self.log(f"   ✓ {test_msg}", level='SUCCESS')
        else:
            self.log(f"   ✗ {test_msg}", level='ERROR')
            all_passed = False
            
        # Overall status
        self.results['overall_status'] = 'healthy' if all_passed else 'degraded'
        
        return all_passed, self.results
        
    def print_summary(self) -> None:
        """Print health check summary"""
        print(f"\n{Colors.BOLD}{'='*50}{Colors.RESET}")
        print(f"{Colors.BOLD}Health Check Summary{Colors.RESET}")
        print(f"{Colors.BOLD}{'='*50}{Colors.RESET}")
        
        status = self.results['overall_status']
        color = Colors.GREEN if status == 'healthy' else (Colors.YELLOW if status == 'degraded' else Colors.RED)
        print(f"Overall Status: {color}{status.upper()}{Colors.RESET}")
        print(f"Container: {self.container_name}")
        print(f"Timestamp: {self.results['timestamp']}")
        
        print(f"\n{Colors.BOLD}Check Results:{Colors.RESET}")
        for check, result in self.results['checks'].items():
            if isinstance(result, dict):
                status = result.get('status', 'unknown')
                symbol = '✓' if status in ['passed', 'running', 'python_ok'] else '✗'
                color = Colors.GREEN if symbol == '✓' else Colors.RED
            else:
                symbol = '✓' if result else '✗'
                color = Colors.GREEN if result else Colors.RED
            print(f"  {color}{symbol}{Colors.RESET} {check}")
            
        print(f"{'='*50}\n")
        
    def save_results(self, output_file: Optional[str] = None) -> str:
        """Save results to JSON file"""
        if output_file is None:
            output_file = str(self.output_dir / f"health_check_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
            
        Path(output_file).parent.mkdir(parents=True, exist_ok=True)
            
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2)
            
        self.log(f"Results saved to {output_file}", level='INFO')
        return output_file


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Check MCP Server health status',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python check_mcp_server.py                    # Basic health check
  python check_mcp_server.py --auto-start       # Start container if not running
  python check_mcp_server.py --container myname # Check specific container
  python check_mcp_server.py --quiet --save     # Minimal output, save results
        """
    )
    
    parser.add_argument('--container', '-c', default='kali-mcp-server',
                       help='Container name to check (default: kali-mcp-server)')
    parser.add_argument('--auto-start', '-a', action='store_true',
                       help='Automatically start container if not running')
    parser.add_argument('--quiet', '-q', action='store_true',
                       help='Minimal output')
    parser.add_argument('--save', '-s', action='store_true',
                       help='Save results to JSON file')
    parser.add_argument('--output', '-o', help='Output file path for results')
    parser.add_argument('--output-dir', help='Output directory for results')
    
    args = parser.parse_args()
    
    checker = MCPServerChecker(
        container_name=args.container,
        verbose=not args.quiet,
        output_dir=args.output_dir
    )
    
    try:
        success, results = checker.run_all_checks(auto_start=args.auto_start)
        
        if not args.quiet:
            checker.print_summary()
            
        if args.save or args.output:
            checker.save_results(args.output)
            
        sys.exit(0 if success else 1)
        
    except KeyboardInterrupt:
        print("\nCheck interrupted")
        sys.exit(130)
    except Exception as e:
        print(f"\nError: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

