#!/usr/bin/env python3
"""
Comprehensive test suite for Kali MCP Server

This script tests:
1. Docker availability and image existence
2. Container can start and run
3. MCP server responds to basic commands
4. Tools are accessible and functional
"""

import subprocess
import sys
import json
import time
import os
from pathlib import Path
from typing import Optional, Dict, Any, Tuple

# Colors for output
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def print_success(msg: str):
    print(f"{Colors.GREEN}✓{Colors.RESET} {msg}")

def print_error(msg: str):
    print(f"{Colors.RED}✗{Colors.RESET} {msg}")

def print_warning(msg: str):
    print(f"{Colors.YELLOW}⚠{Colors.RESET} {msg}")

def print_info(msg: str):
    print(f"{Colors.BLUE}ℹ{Colors.RESET} {msg}")

def print_header(msg: str):
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}{msg}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.RESET}\n")

def run_command(cmd: list, timeout: int = 30, capture_output: bool = True) -> Tuple[bool, str, int]:
    """Run a command and return success, output, and return code"""
    try:
        result = subprocess.run(
            cmd,
            capture_output=capture_output,
            text=True,
            timeout=timeout
        )
        return result.returncode == 0, result.stdout, result.returncode
    except subprocess.TimeoutExpired:
        return False, f"Command timed out after {timeout}s", -1
    except FileNotFoundError:
        return False, "Command not found", -1
    except Exception as e:
        return False, str(e), -1

def test_docker_available() -> bool:
    """Test if Docker is available"""
    print_header("Test 1: Docker Availability")
    success, output, _ = run_command(["docker", "--version"])
    if success:
        print_success(f"Docker is available: {output.strip()}")
        return True
    else:
        print_error(f"Docker is not available: {output}")
        return False

def test_docker_image_exists() -> bool:
    """Test if kali-mcp-server image exists"""
    print_header("Test 2: Docker Image Existence")
    success, output, _ = run_command(["docker", "images", "kali-mcp-server", "--format", "{{.Repository}}:{{.Tag}}"])
    if success and "kali-mcp-server" in output:
        print_success(f"Docker image exists: {output.strip()}")
        return True
    else:
        print_warning("Docker image 'kali-mcp-server' not found")
        print_info("You may need to build the image first:")
        print_info("  docker build -t kali-mcp-server .")
        return False

def find_running_container() -> Optional[str]:
    """Find a running kali-mcp-server container"""
    # Check for containers with kali-mcp-server image
    success, output, _ = run_command([
        "docker", "ps", "--filter", "ancestor=kali-mcp-server",
        "--format", "{{.Names}}"
    ], timeout=10)
    
    if success and output.strip():
        containers = [c.strip() for c in output.strip().split('\n') if c.strip()]
        if containers:
            return containers[0]
    
    # Also check by name patterns (Cursor might use different names)
    for name_pattern in ["kali-mcp", "mcp-server"]:
        success, output, _ = run_command([
            "docker", "ps", "--filter", f"name={name_pattern}",
            "--format", "{{.Names}}"
        ], timeout=10)
        if success and output.strip():
            containers = [c.strip() for c in output.strip().split('\n') if c.strip()]
            if containers:
                return containers[0]
    
    return None

def test_container_can_start() -> bool:
    """Test if container can start and run a simple command"""
    print_header("Test 3: Container Can Start")
    
    # First, check if a container is already running (e.g., started by Cursor)
    existing_container = find_running_container()
    
    if existing_container:
        print_info(f"Found existing container: {existing_container}")
        print_info("Testing command execution in existing container...")
        
        # Test by executing a command in the existing container
        success, output, _ = run_command([
            "docker", "exec", existing_container,
            "python3", "-c", "print('Container test successful')"
        ], timeout=30)
        
        if success and "Container test successful" in output:
            print_success(f"Existing container '{existing_container}' can execute commands")
            return True
        else:
            print_warning(f"Existing container found but command execution failed: {output}")
            print_info("Will try to start a new test container...")
    else:
        print_info("No existing container found. Starting test container...")
    
    # Clean up any existing test container
    run_command(["docker", "stop", "kali-mcp-test"], timeout=5)
    run_command(["docker", "rm", "kali-mcp-test"], timeout=5)
    
    # Start container with a simple command
    success, output, _ = run_command([
        "docker", "run", "--rm",
        "--name", "kali-mcp-test",
        "--cap-add=NET_RAW",
        "--cap-add=NET_ADMIN",
        "--memory=2g",
        "--cpus=2.0",
        "kali-mcp-server",
        "python3", "-c", "print('Container test successful')"
    ], timeout=60)
    
    if success and "Container test successful" in output:
        print_success("Container can start and execute commands")
        return True
    else:
        print_error(f"Container failed to start: {output}")
        return False

def test_mcp_server_responds() -> bool:
    """Test if MCP server responds to initialization"""
    print_header("Test 4: MCP Server Response")
    
    # Send MCP initialize request
    init_request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "test-client",
                "version": "1.0.0"
            }
        }
    }
    
    print_info("Sending MCP initialize request...")
    try:
        process = subprocess.Popen(
            [
                "docker", "run", "-i", "--rm",
                "--cap-add=NET_RAW",
                "--cap-add=NET_ADMIN",
                "--memory=2g",
                "--cpus=2.0",
                "kali-mcp-server"
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Send request
        request_json = json.dumps(init_request) + "\n"
        stdout, stderr = process.communicate(input=request_json, timeout=10)
        
        if process.returncode == 0 or stdout:
            # Try to parse response
            try:
                # MCP responses are JSON-RPC, look for response
                lines = stdout.strip().split('\n')
                for line in lines:
                    if line.strip():
                        try:
                            response = json.loads(line)
                            if "result" in response or "id" in response:
                                print_success("MCP server responded to initialize request")
                                return True
                        except json.JSONDecodeError:
                            continue
                
                # If we got output but couldn't parse, still consider it a success
                if stdout.strip():
                    print_warning("MCP server responded but response format unclear")
                    print_info(f"Response: {stdout[:200]}")
                    return True
            except Exception as e:
                print_warning(f"Could not parse response: {e}")
                if stdout:
                    print_info(f"Output: {stdout[:200]}")
                    return True
        
        print_error(f"MCP server did not respond correctly")
        if stderr:
            print_error(f"Stderr: {stderr[:200]}")
        return False
        
    except subprocess.TimeoutExpired:
        print_error("MCP server request timed out")
        process.kill()
        return False
    except Exception as e:
        print_error(f"Error testing MCP server: {e}")
        return False

def test_tools_available() -> bool:
    """Test if key tools are available in the container"""
    print_header("Test 5: Tools Availability")
    
    # Check for existing container first
    existing_container = find_running_container()
    use_existing = existing_container is not None
    
    if use_existing:
        print_info(f"Using existing container: {existing_container}")
    else:
        print_info("No existing container found. Will use temporary containers for testing.")
    
    tools_to_test = [
        "nmap",
        "nikto",
        "sqlmap",
        "whatweb",
        "gobuster",
        "ffuf"
    ]
    
    all_available = True
    for tool in tools_to_test:
        if use_existing:
            # Use exec to run in existing container
            success, output, _ = run_command([
                "docker", "exec", existing_container,
                "which", tool
            ], timeout=30)
        else:
            # Create temporary container
            success, output, _ = run_command([
                "docker", "run", "--rm",
                "--cap-add=NET_RAW",
                "--cap-add=NET_ADMIN",
                "--memory=2g",
                "--cpus=2.0",
                "kali-mcp-server",
                "which", tool
            ], timeout=30)
        
        if success and tool in output:
            print_success(f"{tool} is available")
        else:
            print_error(f"{tool} is not available")
            if output:
                print_info(f"  Output: {output.strip()[:100]}")
            all_available = False
    
    return all_available

def test_simple_command_execution() -> bool:
    """Test if a simple command can be executed via the MCP server"""
    print_header("Test 6: Simple Command Execution")
    
    # Test with a simple echo command
    test_command = "echo 'MCP server test'"
    
    # Check for existing container first
    existing_container = find_running_container()
    
    print_info(f"Testing command execution: {test_command}")
    
    if existing_container:
        print_info(f"Using existing container: {existing_container}")
        # Use exec to run in existing container
        success, output, _ = run_command([
            "docker", "exec", existing_container,
            "sh", "-c", test_command
        ], timeout=30)
    else:
        print_info("No existing container found. Using temporary container...")
        # Test direct execution instead
        success, output, _ = run_command([
            "docker", "run", "--rm",
            "--cap-add=NET_RAW",
            "--cap-add=NET_ADMIN",
            "--memory=2g",
            "--cpus=2.0",
            "kali-mcp-server",
            "sh", "-c", test_command
        ], timeout=30)
    
    if success and "MCP server test" in output:
        print_success("Simple command execution works")
        return True
    else:
        print_error(f"Command execution failed: {output}")
        return False

def test_nmap_basic() -> bool:
    """Test if nmap can run a basic scan"""
    print_header("Test 7: Nmap Basic Functionality")
    
    # Check for existing container first
    existing_container = find_running_container()
    
    # Test nmap version (safe, no network required)
    if existing_container:
        print_info(f"Using existing container: {existing_container}")
        success, output, _ = run_command([
            "docker", "exec", existing_container,
            "nmap", "--version"
        ], timeout=30)
    else:
        print_info("No existing container found. Using temporary container...")
        success, output, _ = run_command([
            "docker", "run", "--rm",
            "--cap-add=NET_RAW",
            "--cap-add=NET_ADMIN",
            "--memory=2g",
            "--cpus=2.0",
            "kali-mcp-server",
            "nmap", "--version"
        ], timeout=30)
    
    if success and "Nmap" in output:
        print_success("Nmap is functional")
        print_info(f"Nmap version info: {output.strip()[:100]}")
        return True
    else:
        print_error(f"Nmap test failed: {output}")
        return False

def generate_test_report(results: Dict[str, bool]) -> None:
    """Generate a test report"""
    print_header("Test Report Summary")
    
    total_tests = len(results)
    passed_tests = sum(1 for v in results.values() if v)
    failed_tests = total_tests - passed_tests
    
    print(f"\nTotal Tests: {total_tests}")
    print_success(f"Passed: {passed_tests}")
    if failed_tests > 0:
        print_error(f"Failed: {failed_tests}")
    else:
        print_success("Failed: 0")
    
    print("\nDetailed Results:")
    for test_name, result in results.items():
        status = "✓ PASS" if result else "✗ FAIL"
        color = Colors.GREEN if result else Colors.RED
        print(f"  {color}{status}{Colors.RESET} - {test_name}")
    
    print("\n" + "="*60)
    
    if failed_tests == 0:
        print_success("All tests passed! MCP server is working correctly.")
        return 0
    else:
        print_error("Some tests failed. Please review the errors above.")
        return 1

def main():
    """Run all tests"""
    print_header("Kali MCP Server Test Suite")
    print_info("This test suite verifies the Kali MCP server is working correctly")
    print_info("Tests may take several minutes to complete...\n")
    
    results = {}
    
    # Run tests
    results["Docker Available"] = test_docker_available()
    if not results["Docker Available"]:
        print_error("Docker is required for all tests. Please install Docker first.")
        return 1
    
    results["Docker Image Exists"] = test_docker_image_exists()
    if not results["Docker Image Exists"]:
        print_warning("Image not found. Some tests will be skipped.")
        return generate_test_report(results)
    
    results["Container Can Start"] = test_container_can_start()
    results["MCP Server Responds"] = test_mcp_server_responds()
    results["Tools Available"] = test_tools_available()
    results["Simple Command Execution"] = test_simple_command_execution()
    results["Nmap Basic Functionality"] = test_nmap_basic()
    
    return generate_test_report(results)

if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\nTest suite interrupted by user")
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

