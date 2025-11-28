from mcp.server.fastmcp import FastMCP
import subprocess
import os
import sys
import logging
import time
import re
from datetime import datetime
import shlex

# ============================================================================
# CONFIGURATION CONSTANTS
# ============================================================================

# Configuration
DEFAULT_TOOL_TIMEOUT = 120  # Reduced from 240
QUICK_TOOL_TIMEOUT = 45     # Reduced from 60
MAX_OUTPUT_SIZE = 500_000
DEBUG_MODE = os.getenv("DEBUG_MCP", "0") == "1"
DEBUG_LOG_FILE = "/tmp/mcp_debug.log"

# Configure logging - FILE ONLY, never stderr
log_level = logging.DEBUG if DEBUG_MODE else logging.WARNING
handlers = []

if DEBUG_MODE:
    try:
        file_handler = logging.FileHandler(DEBUG_LOG_FILE)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(
            logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        )
        handlers.append(file_handler)
    except Exception:
        pass

logging.basicConfig(level=log_level, handlers=handlers)
logger = logging.getLogger(__name__)

# Initialize MCP server
mcp = FastMCP("kali-mcp-server")

# ============================================================================
# CORE UTILITY
# ============================================================================

def strip_ansi_codes(text: str) -> str:
    """Remove ANSI color codes and control characters from text."""
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)


def truncate_output(output: str, max_size: int = MAX_OUTPUT_SIZE) -> str:
    """Truncate output to max_size with a note if truncated."""
    if len(output) <= max_size:
        return output
    
    truncated = output[:max_size]
    truncation_note = f"\n\n[... Output truncated at {max_size} bytes. Total size: {len(output)} bytes ...]"
    return truncated + truncation_note


@mcp.tool()
def run_command(command: str, timeout: int = DEFAULT_TOOL_TIMEOUT) -> str:
    """
    Execute an arbitrary Kali Linux command with improved error handling.
    
    Args:
        command: The shell command to execute
        timeout: Timeout in seconds (default: 120s)
    
    Returns:
        Command output as string, with errors prefixed by "Error:"
    """
    start_time = time.time()
    start_timestamp = datetime.now().isoformat()
    
    # Log command start
    if DEBUG_MODE:
        logger.debug(f"[START] Command: {command[:200]}")
        logger.debug(f"[START] Timeout: {timeout}s, Time: {start_timestamp}")
    
    try:
        # Set resource limits to prevent container crashes
        # Limit memory usage per process (2GB soft, 4GB hard)
        def set_limits():
            try:
                import resource
                # Set memory limit (soft: 2GB, hard: 4GB)
                # Note: Ruby/Java apps like WhatWeb, ZAP, Metasploit need generous memory
                resource.setrlimit(resource.RLIMIT_AS, (2 * 1024 * 1024 * 1024, 4 * 1024 * 1024 * 1024))
                # Set CPU time limit (cumulative CPU time, not wall-clock)
                # Use timeout * 2 as soft limit to allow I/O bound processes
                # Hard limit is timeout * 2 + 60 to allow graceful termination
                cpu_soft = timeout * 2
                cpu_hard = timeout * 2 + 60
                resource.setrlimit(resource.RLIMIT_CPU, (cpu_soft, cpu_hard))
            except (ImportError, ValueError) as e:
                if DEBUG_MODE:
                    logger.warning(f"Could not set resource limits: {e}")
        
        # Run command with timeout and resource limits
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            preexec_fn=set_limits if os.name != 'nt' else None,
            start_new_session=True,  # Create new process group
        )
        
        elapsed_time = time.time() - start_time
        output_raw = result.stdout if result.returncode == 0 else (result.stderr or result.stdout or "")
        output_size = len(output_raw)
        
        # Log completion
        if DEBUG_MODE:
            logger.debug(f"[END] Exit code: {result.returncode}, Elapsed: {elapsed_time:.2f}s, Output size: {output_size} bytes")
        
        # Clean and truncate output
        output_clean = strip_ansi_codes(output_raw)
        output_final = truncate_output(output_clean)
        
        if result.returncode == 0:
            # Flush immediately to ensure response is sent
            sys.stdout.flush()
            sys.stderr.flush()
            return output_final
        else:
            error_msg = output_final or "Command failed with no output"
            logger.warning(f"Command failed (exit code {result.returncode}, {elapsed_time:.2f}s): {command[:100]}")
            final_output = f"Error (exit code {result.returncode}): {error_msg}"
            sys.stdout.flush()
            sys.stderr.flush()
            return final_output
            
    except subprocess.TimeoutExpired as e:
        elapsed_time = time.time() - start_time
        logger.error(f"Command timed out after {elapsed_time:.2f}s (limit: {timeout}s): {command[:100]}")
        if DEBUG_MODE:
            logger.debug(f"[TIMEOUT] Full traceback:", exc_info=True)
        return f"Error: Command timed out after {timeout} seconds. The tool may need more time or different options."
    except subprocess.CalledProcessError as e:
        elapsed_time = time.time() - start_time
        logger.error(f"Command process error after {elapsed_time:.2f}s: {e}")
        if DEBUG_MODE:
            logger.debug(f"[ERROR] Full traceback:", exc_info=True)
        return f"Error: Process error - {str(e)}"
    except MemoryError:
        elapsed_time = time.time() - start_time
        logger.error(f"Out of memory after {elapsed_time:.2f}s running: {command[:100]}")
        if DEBUG_MODE:
            logger.debug(f"[MEMORY] Full traceback:", exc_info=True)
        return "Error: Out of memory. The tool may be too resource-intensive. Try with reduced scope or options."
    except OSError as e:
        elapsed_time = time.time() - start_time
        logger.error(f"OS error after {elapsed_time:.2f}s: {e}")
        if DEBUG_MODE:
            logger.debug(f"[OS_ERROR] Full traceback:", exc_info=True)
        return f"Error: System error - {str(e)}"
    except Exception as e:
        elapsed_time = time.time() - start_time
        logger.error(f"Unexpected error after {elapsed_time:.2f}s: {type(e).__name__}: {e}")
        if DEBUG_MODE:
            logger.debug(f"[EXCEPTION] Full traceback:", exc_info=True)
        return f"Error: {type(e).__name__} - {str(e)}"


# ============================================================================
# PORT SCANNING / SERVICE ENUM
# ============================================================================

@mcp.tool()
def run_nmap(target: str, options: str = "-sV") -> str:
    """
    Execute an nmap scan against a target.
    """
    # Try direct path first, then fallback to wrapper
    command = f"/usr/lib/nmap/nmap {options} {target} 2>&1 || nmap {options} {target} 2>&1"
    return run_command(command)


@mcp.tool()
def run_masscan(target: str, ports: str = "1-65535", rate: str = "1000") -> str:
    """
    Execute Masscan fast port scanner.
    Note: Masscan requires root privileges and may need --cap-add=NET_RAW.
    """
    # Limit rate and add timeout to prevent resource exhaustion
    try:
        safe_rate = min(int(rate), 1000)  # Cap at 1000 packets/sec
    except (ValueError, TypeError):
        safe_rate = 1000  # Default to max rate if invalid input
    command = f"timeout 300 masscan -p{ports} --rate={safe_rate} {target}"
    return run_command(command, timeout=360)  # 6 minute timeout


# ============================================================================
# WEB SCANNERS / DAST
# ============================================================================

@mcp.tool()
def run_nikto(target: str, quick: bool = True) -> str:
    """
    Execute Nikto web server scanner.
    
    Args:
        target: Target URL or IP to scan
        quick: Use quick mode with reduced scan time (default: True)
    
    Note: Quick mode scans for 2 minutes, full mode for 5 minutes.
    """
    # Quick mode: 2 minutes, Full mode: 5 minutes
    maxtime = "2m" if quick else "5m"
    timeout_seconds = 120 if quick else 300
    
    command = f"timeout {timeout_seconds} nikto -h {target} -maxtime {maxtime}"
    # Add buffer to timeout
    return run_command(command, timeout=timeout_seconds + 60)


@mcp.tool()
def run_sqlmap(target: str, options: str = "--batch", quick: bool = True) -> str:
    """
    Execute sqlmap SQL injection scanner against a target URL.
    
    Args:
        target: Target URL to scan
        options: Additional sqlmap options
        quick: Use quick mode with reduced crawling (default: True)
    
    Note: Quick mode uses --crawl=1 for faster scanning. Full mode uses --crawl=2.
    """
    # Add timeout and thread limits to prevent resource exhaustion
    crawl_depth = "--crawl=1" if quick else "--crawl=2"
    safe_options = f"{options} {crawl_depth} --timeout=30 --threads=1 --batch"
    command = f"sqlmap -u {target} {safe_options}"
    
    # Quick mode: 5 min timeout, Full mode: 10 min timeout
    timeout = 300 if quick else 600
    return run_command(command, timeout=timeout)


@mcp.tool()
def run_wpscan(target: str, options: str = "--enumerate u,p,t") -> str:
    """
    Execute WPScan WordPress vulnerability scanner.
    """
    command = f"wpscan --url {target} {options}"
    return run_command(command)


@mcp.tool()
def run_wapiti(target: str, options: str = "-u", quick: bool = True) -> str:
    """
    Execute Wapiti web application vulnerability scanner.
    
    Args:
        target: Target URL to scan
        options: Additional wapiti options
        quick: Use quick mode with reduced scan time (default: True)
    
    Note: Quick mode scans for 3 minutes, full mode for 5 minutes.
    """
    # Add scope limit to prevent excessive scanning
    max_time = 180 if quick else 300  # 3 min vs 5 min
    safe_options = f"{options} --scope folder --max-scan-time {max_time}"
    command = f"wapiti {safe_options} {target}"
    
    # Add buffer to timeout (scan time + 2 minutes)
    timeout = max_time + 120
    return run_command(command, timeout=timeout)


@mcp.tool()
def run_zap_baseline(target: str, options: str = "") -> str:
    """
    Execute OWASP ZAP baseline scan (zaproxy CLI).
    """
    # Add timeout and memory limits
    opt = options if options else "-m 5"  # 5 minute timeout
    command = f"zap-baseline.py -t {target} {opt}"
    return run_command(command, timeout=600)  # 10 minute timeout


@mcp.tool()
def run_skipfish(target: str, output_dir: str = "/tmp/skipfish") -> str:
    """
    Execute Skipfish active web application security scanner.
    Note: Skipfish is very resource-intensive. Use with caution.
    """
    # Add limits to prevent resource exhaustion
    command = f"skipfish -o {output_dir} -I 2 -X -W /tmp/skipfish.wordlist -S /usr/share/skipfish/dictionaries/complete.wl -l 3 -m 5 -f {target}"
    return run_command(command, timeout=600)  # 10 minute timeout for skipfish


@mcp.tool()
def run_uniscan(target: str, options: str = "-u") -> str:
    """
    Execute Uniscan web vulnerability scanner.
    """
    command = f"uniscan {options} {target}"
    return run_command(command)


# ============================================================================
# WEB DISCOVERY / FUZZING
# ============================================================================

@mcp.tool()
def run_dirb(
    target: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    recursive: bool = False,
) -> str:
    """
    Execute dirb directory brute forcer.
    
    Args:
        target: Target URL
        wordlist: Path to wordlist file
        recursive: Enable recursive scanning (default: False for speed)
    
    Note: Non-recursive mode is much faster and completes within timeout.
    """
    # Use -r flag for non-recursive (faster)
    recursive_flag = "" if recursive else "-r"
    command = f"dirb {target} {wordlist} {recursive_flag}"
    return run_command(command, timeout=180 if not recursive else DEFAULT_TOOL_TIMEOUT)


@mcp.tool()
def run_gobuster(
    target: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    mode: str = "dir",
    quick: bool = True,
) -> str:
    """
    Execute Gobuster directory/file brute forcer.
    
    Args:
        target: Target URL
        wordlist: Path to wordlist file
        mode: Scan mode (dir, dns, vhost)
        quick: Use quick mode with timeout and reduced threads (default: True)
    
    Note: Quick mode uses --timeout 10s and limits threads for faster completion.
    """
    # Add timeout and thread limits for reliability
    timeout_flag = "--timeout 10s" if quick else ""
    threads_flag = "-t 20" if quick else "-t 50"
    
    command = f"gobuster {mode} -u {target} -w {wordlist} {threads_flag} {timeout_flag}"
    return run_command(command, timeout=180 if quick else DEFAULT_TOOL_TIMEOUT)


@mcp.tool()
def run_ffuf(
    target: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    extensions: str = "",
    quick: bool = True,
) -> str:
    """
    Execute ffuf (Fuzz Faster U Fool) web fuzzer.
    
    Args:
        target: Target URL (use FUZZ as placeholder, e.g., http://example.com/FUZZ)
        wordlist: Path to wordlist file
        extensions: File extensions to try (comma-separated)
        quick: Use quick mode with timeout and limited threads (default: True)
    
    Note: Quick mode uses reduced threads and timeouts for faster, reliable scanning.
    """
    ext_flag = f"-e {extensions}" if extensions else ""
    
    # Add timeout and thread limits for reliability
    if quick:
        # Quick mode: 40 threads, 10s timeout per request, stop after 3 errors
        threads_flag = "-t 40"
        timeout_flag = "-timeout 10"
        maxtime_flag = "-maxtime 120"  # Overall 2-minute limit
        command = f"ffuf -u {target}/FUZZ -w {wordlist} {ext_flag} {threads_flag} {timeout_flag} {maxtime_flag} -se"
        return run_command(command, timeout=150)
    else:
        # Full mode: default ffuf behavior
        command = f"ffuf -u {target}/FUZZ -w {wordlist} {ext_flag}"
        return run_command(command)


@mcp.tool()
def run_wfuzz(
    target: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    parameter: str = "FUZZ",
    quick: bool = True,
) -> str:
    """
    Execute Wfuzz web application fuzzer.
    
    Args:
        target: Target URL (use FUZZ as placeholder)
        wordlist: Path to wordlist file
        parameter: Fuzz parameter name (default: "FUZZ")
        quick: Use quick mode with connection timeout (default: True)
    
    Note: The parameter name (default "FUZZ") is used as a placeholder in the target URL.
    Quick mode adds connection timeout and limits for faster completion.
    """
    # Check if parameter is already in the URL (user-provided placeholder)
    if parameter in target:
        fuzzed_target = target
    # Replace "FUZZ" placeholder with the specified parameter
    elif "FUZZ" in target:
        fuzzed_target = target.replace("FUZZ", parameter)
    else:
        # If no placeholder found, append parameter to path (common directory fuzzing use case)
        fuzzed_target = f"{target.rstrip('/')}/{parameter}"
    
    # Add timeout for quick mode
    timeout_flag = "--conn-delay 10 --req-delay 10" if quick else ""
    command = f"wfuzz -w {wordlist} -c {timeout_flag} {fuzzed_target}"
    return run_command(command, timeout=180 if quick else DEFAULT_TOOL_TIMEOUT)


# ============================================================================
# WEB / HOST FINGERPRINTING & RECON
# ============================================================================

@mcp.tool()
def run_whatweb(target: str, timeout_seconds: int = 45, verbosity: str = "normal") -> str:
    """
    Execute WhatWeb web technology identifier.
    
    Args:
        target: URL or IP address to scan
        timeout_seconds: Timeout for the scan (default: 45s)
        verbosity: Output verbosity - "minimal", "normal", or "verbose" (default: "normal")
    
    Returns:
        WhatWeb scan results
    
    Note: This tool is optimized for MCP usage with reasonable timeouts.
    Default mode completes in 5-10 seconds for most targets.
    """
    tool_start_time = time.time()
    
    if DEBUG_MODE:
        logger.debug(f"[run_whatweb] Starting scan of {target}, timeout={timeout_seconds}s, verbosity={verbosity}")
    
    # Build command based on verbosity
    verbosity_flag = ""
    if verbosity == "minimal":
        verbosity_flag = "-q"  # Quiet mode
    elif verbosity == "verbose":
        verbosity_flag = "-v"  # Verbose mode
    # "normal" uses default output
    
    # Use stdbuf to force line buffering and prevent hanging
    # Set environment to ensure non-interactive mode
    # Remove timeout wrapper - rely on subprocess timeout instead
    command = f"stdbuf -oL -eL whatweb --no-errors {verbosity_flag} {target} 2>&1".strip()
    
    # Use timeout_seconds + 5s buffer for subprocess timeout
    wrapper_timeout = timeout_seconds + 5
    result = run_command(command, timeout=wrapper_timeout)
    
    tool_elapsed = time.time() - tool_start_time
    if DEBUG_MODE:
        logger.debug(f"[run_whatweb] Completed in {tool_elapsed:.2f}s")
    
    # Ensure output is flushed immediately
    sys.stdout.flush()
    sys.stderr.flush()
    return result


@mcp.tool()
def run_theharvester(domain: str, source: str = "all", limit: int = 500) -> str:
    """
    Execute theHarvester to gather emails, subdomains, and hosts.
    """
    command = f"theHarvester -d {domain} -b {source} -l {limit}"
    return run_command(command)


@mcp.tool()
def run_reconng(module: str, target: str) -> str:
    """
    Execute recon-ng module against a target.
    """
    command = f"recon-ng -m {module} -o target={target}"
    return run_command(command)


@mcp.tool()
def run_dnsenum(domain: str) -> str:
    """
    Execute dnsenum DNS enumeration tool.
    """
    command = f"dnsenum {domain}"
    return run_command(command)


@mcp.tool()
def run_dnsrecon(domain: str, options: str = "-d") -> str:
    """
    Execute dnsrecon DNS enumeration tool.
    """
    command = f"dnsrecon {options} {domain}"
    return run_command(command)


# ============================================================================
# PASSWORD / AUTH ATTACKS
# ============================================================================

@mcp.tool()
def run_john(
    hash_file: str,
    wordlist: str = "/usr/share/wordlists/rockyou.txt",
    format: str = "",
) -> str:
    """
    Execute John the Ripper password cracker.
    """
    format_flag = f"--format={format}" if format else ""
    command = f"john {format_flag} --wordlist={wordlist} {hash_file}"
    return run_command(command)


@mcp.tool()
def run_hashcat(
    hash_file: str,
    hash_type: int = 0,
    attack_mode: int = 0,
    wordlist: str = "/usr/share/wordlists/rockyou.txt",
) -> str:
    """
    Execute hashcat advanced password recovery tool.
    """
    command = f"hashcat -m {hash_type} -a {attack_mode} {hash_file} {wordlist}"
    return run_command(command)


@mcp.tool()
def run_hydra(
    target: str,
    service: str,
    username: str = "",
    password_list: str = "/usr/share/wordlists/rockyou.txt",
) -> str:
    """
    Execute Hydra parallelized login cracker.
    """
    user_flag = f"-l {username}" if username else "-L /usr/share/wordlists/usernames.txt"
    command = f"hydra {user_flag} -P {password_list} {target} {service}"
    return run_command(command)


@mcp.tool()
def run_medusa(
    target: str,
    service: str,
    username: str = "",
    password_list: str = "/usr/share/wordlists/rockyou.txt",
) -> str:
    """
    Execute Medusa parallel network login cracker.
    """
    user_flag = f"-u {username}" if username else "-U /usr/share/wordlists/usernames.txt"
    command = f"medusa -h {target} {user_flag} -P {password_list} -M {service}"
    return run_command(command)


# ============================================================================
# EXPLOITATION
# ============================================================================

@mcp.tool()
def run_metasploit(module: str, target: str, options: str = "") -> str:
    """
    Execute a Metasploit Framework module in batch mode.
    """
    # Escape single quotes in inputs to prevent command injection
    # Pattern '\'' means: end quote, escaped quote, start quote
    module_escaped = module.replace("'", "'\\''")
    target_escaped = target.replace("'", "'\\''")
    options_escaped = options.replace("'", "'\\''") if options else ""
    command = (
        f"msfconsole -q -x 'use {module_escaped}; set RHOSTS {target_escaped}; {options_escaped}; exploit; exit'"
    )
    return run_command(command)


@mcp.tool()
def run_searchsploit(query: str) -> str:
    """
    Execute SearchSploit against Exploit-DB.
    """
    command = f"searchsploit {query}"
    return run_command(command)


# ============================================================================
# SNIFFING / SPOOFING / NETWORK MONITORING
# ============================================================================

@mcp.tool()
def run_tshark(
    interface: str = "eth0",
    capture_filter: str = "",
    output_file: str = "",
) -> str:
    """
    Execute tshark network protocol analyzer.
    """
    output_flag = f"-w {output_file}" if output_file else ""
    # Escape single quotes in filter to prevent command injection
    # Pattern '\'' means: end quote, escaped quote, start quote
    if capture_filter:
        filter_escaped = capture_filter.replace("'", "'\\''")
        filter_flag = f"-f '{filter_escaped}'"
    else:
        filter_flag = ""
    command = f"tshark -i {interface} {filter_flag} {output_flag}".strip()
    return run_command(command)


@mcp.tool()
def run_tcpdump(
    interface: str = "eth0",
    capture_filter: str = "",
    output_file: str = "",
) -> str:
    """
    Execute tcpdump packet analyzer.
    """
    output_flag = f"-w {output_file}" if output_file else ""
    # Escape single quotes in filter to prevent command injection
    # Pattern '\'' means: end quote, escaped quote, start quote
    if capture_filter:
        filter_escaped = capture_filter.replace("'", "'\\''")
        filter_flag = f"'{filter_escaped}'"
    else:
        filter_flag = ""
    command = f"tcpdump -i {interface} {output_flag} {filter_flag}".strip()
    return run_command(command)


# ============================================================================
# GENERAL NETWORK / HOST ENUM
# ============================================================================

@mcp.tool()
def run_netdiscover(network: str = "", interface: str = "eth0") -> str:
    """
    Execute netdiscover active/passive network discovery.
    """
    network_flag = f"-r {network}" if network else ""
    command = f"netdiscover -i {interface} {network_flag}"
    return run_command(command)


@mcp.tool()
def run_hping3(target: str, options: str = "-c 4 -S") -> str:
    """
    Execute hping3 network packet crafting tool.
    """
    command = f"hping3 {options} {target}"
    return run_command(command)


# ============================================================================
# XS(S) / INJECTION EXTRA TOOLS
# ============================================================================

@mcp.tool()
def run_xsser(target: str, options: str = "") -> str:
    """
    Execute XSSer XSS vulnerability scanner and exploiter.
    Uses crawler mode to automatically discover and test XSS vulnerabilities.
    """
    # XSSer requires either payload markers (XSS/X1S) or attack modes
    # Using crawler mode (-c 100 --Cl) to automatically discover and test
    command = f"xsser -u {target} -c 100 --Cl {options}"
    return run_command(command)


@mcp.tool()
def run_xssstrike(target: str, options: str = "") -> str:
    """
    Execute XSStrike advanced XSS detection suite.
    """
    command = f"python3 /usr/share/xssstrike/xssstrike.py -u {target} {options}"
    return run_command(command)


@mcp.tool()
def run_commix(target: str, options: str = "--batch") -> str:
    """
    Execute commix automated command injection exploitation tool.
    """
    command = f"commix -u {target} {options}"
    return run_command(command)


# ============================================================================
# MISC / INTERACTIVE (DOCUMENTATION-ONLY)
# ============================================================================

@mcp.tool()
def run_setoolkit() -> str:
    """
    Informational helper for launching the Social-Engineer Toolkit.
    """
    return "SET is interactive. Use run_command('setoolkit') from a terminal session if you need it."


if __name__ == "__main__":
    # Check if we should run in HTTP/SSE mode (for detached containers)
    if os.getenv("DETACHED_MODE") == "true" or os.getenv("MCP_SSE_MODE") == "true":
        # Run in SSE mode using the standard MCP Server SDK with FastMCP bridge
        try:
            import asyncio
            import inspect
            from mcp.server.sse import SseServerTransport
            from mcp.server import Server
            from mcp.types import Tool, TextContent
            from typing import Any, Sequence
            
            port = int(os.getenv("MCP_PORT", "8000"))
            host = os.getenv("MCP_HOST", "0.0.0.0")
            
            # Create standard MCP server for SSE
            sse_server = Server("kali-mcp-server")
            
            # Extract tools from FastMCP instance
            # FastMCP stores tools - try to access the internal registry
            tool_functions = {}
            
            # Method 1: Try FastMCP's internal tool storage
            if hasattr(mcp, '_tools'):
                for name, tool_info in mcp._tools.items():
                    if callable(tool_info):
                        tool_functions[name] = tool_info
                    elif hasattr(tool_info, 'func'):
                        tool_functions[name] = tool_info.func
                    elif isinstance(tool_info, dict):
                        tool_functions[name] = tool_info.get('handler') or tool_info.get('func')
            
            # Method 2: Use introspection to find all @mcp.tool decorated functions in this module
            if not tool_functions:
                import mcp_server as this_module
                for name, obj in inspect.getmembers(this_module):
                    if inspect.isfunction(obj):
                        # Check if function was decorated by FastMCP
                        # FastMCP decorator may set various attributes
                        if (hasattr(obj, '_mcp_tool') or 
                            hasattr(obj, '_fastmcp_tool') or
                            (hasattr(mcp, '_tools') and name in getattr(mcp, '_tools', {}))):
                            tool_functions[name] = obj
            
            # Method 3: Manual registration of known tools (fallback)
            if not tool_functions:
                # Manually register all known tool functions
                tool_functions = {
                    'run_command': run_command,
                    'run_nmap': run_nmap,
                    'run_masscan': run_masscan,
                    'run_nikto': run_nikto,
                    'run_sqlmap': run_sqlmap,
                    'run_wpscan': run_wpscan,
                    'run_wapiti': run_wapiti,
                    'run_zap_baseline': run_zap_baseline,
                    'run_skipfish': run_skipfish,
                    'run_uniscan': run_uniscan,
                    'run_dirb': run_dirb,
                    'run_gobuster': run_gobuster,
                    'run_ffuf': run_ffuf,
                    'run_wfuzz': run_wfuzz,
                    'run_whatweb': run_whatweb,
                    'run_theharvester': run_theharvester,
                    'run_reconng': run_reconng,
                    'run_dnsenum': run_dnsenum,
                    'run_dnsrecon': run_dnsrecon,
                    'run_john': run_john,
                    'run_hashcat': run_hashcat,
                    'run_hydra': run_hydra,
                    'run_medusa': run_medusa,
                    'run_metasploit': run_metasploit,
                    'run_searchsploit': run_searchsploit,
                    'run_tshark': run_tshark,
                    'run_tcpdump': run_tcpdump,
                    'run_netdiscover': run_netdiscover,
                    'run_hping3': run_hping3,
                    'run_xsser': run_xsser,
                    'run_xssstrike': run_xssstrike,
                    'run_commix': run_commix,
                    'run_setoolkit': run_setoolkit,
                }
            
            # Register tools with the standard server
            @sse_server.list_tools()
            async def list_tools() -> list[Tool]:
                """List all available tools from FastMCP"""
                tools_list = []
                for tool_name, tool_func in tool_functions.items():
                    # Get function signature and docstring
                    sig = inspect.signature(tool_func)
                    doc = inspect.getdoc(tool_func) or f"Tool: {tool_name}"
                    
                    # Build input schema from function signature
                    properties = {}
                    required = []
                    
                    for param_name, param in sig.parameters.items():
                        if param_name == 'self':
                            continue
                        param_type = "string"
                        if param.annotation != inspect.Parameter.empty:
                            if param.annotation is int:
                                param_type = "integer"
                            elif param.annotation is bool:
                                param_type = "boolean"
                        
                        param_schema = {"type": param_type}
                        if param.default != inspect.Parameter.empty:
                            param_schema["default"] = param.default
                        else:
                            required.append(param_name)
                        
                        properties[param_name] = param_schema
                    
                    tools_list.append(Tool(
                        name=tool_name,
                        description=doc.split('\n')[0] if doc else f"Tool: {tool_name}",
                        inputSchema={
                            "type": "object",
                            "properties": properties,
                            "required": required
                        }
                    ))
                return tools_list
            
            @sse_server.call_tool()
            async def call_tool(name: str, arguments: dict[str, Any] | None) -> Sequence[TextContent]:
                """Handle tool calls by delegating to FastMCP functions"""
                try:
                    if name not in tool_functions:
                        raise ValueError(f"Unknown tool: {name}")
                    
                    tool_func = tool_functions[name]
                    args = arguments or {}
                    
                    # Run sync function in executor
                    loop = asyncio.get_event_loop()
                    # Capture args in closure properly
                    result = await loop.run_in_executor(None, lambda a=args: tool_func(**a))
                    
                    return [TextContent(type="text", text=str(result))]
                except Exception as e:
                    error_msg = f"Error calling tool {name}: {e}"
                    logger.error(error_msg)
                    if DEBUG_MODE:
                        import traceback
                        logger.error(traceback.format_exc())
                    return [TextContent(type="text", text=f"Error: {str(e)}")]
            
            # Create SSE transport and ASGI app
            # SseServerTransport needs to be used with the server to create an ASGI app
            transport = SseServerTransport("/sse")
            
            # Try multiple methods to create the ASGI app
            app = None
            
            # Method 1: Try create_app() method (most common)
            if hasattr(transport, 'create_app'):
                try:
                    app = transport.create_app(sse_server)
                    logger.info("Using transport.create_app() for SSE")
                except Exception as e:
                    logger.warning(f"create_app() failed: {e}")
            
            # Method 2: Try if transport is callable
            if app is None and callable(transport):
                try:
                    app = transport(sse_server)
                    logger.info("Using transport as callable for SSE")
                except Exception as e:
                    logger.warning(f"Transport callable failed: {e}")
            
            # Method 3: Fallback to FastAPI implementation
            if app is None:
                logger.info("Using FastAPI fallback for SSE")
                from fastapi import FastAPI, Request
                from fastapi.responses import StreamingResponse
                import json
                
                fastapi_app = FastAPI()
                
                # Store active connections and message handlers
                active_connections = {}
                
                @fastapi_app.get("/sse")
                async def sse_endpoint(request: Request):
                    """SSE endpoint for MCP communication"""
                    import uuid
                    connection_id = str(uuid.uuid4())
                    active_connections[connection_id] = True
                    
                    async def event_stream():
                        """SSE event stream - simplified implementation"""
                        try:
                            # Send initial connection message
                            yield f"data: {json.dumps({'type': 'connection', 'id': connection_id})}\n\n"
                            
                            # Simple keepalive loop
                            # Actual MCP protocol handling will be done via POST endpoint
                            while True:
                                await asyncio.sleep(30.0)
                                yield ": keepalive\n\n"
                        except asyncio.CancelledError:
                            logger.debug(f"SSE stream cancelled for {connection_id}")
                        except Exception as e:
                            logger.error(f"SSE stream error: {e}")
                        finally:
                            active_connections.pop(connection_id, None)
                    
                    return StreamingResponse(event_stream(), media_type="text/event-stream")
                
                @fastapi_app.post("/sse")
                async def sse_post(request: Request):
                    """Handle MCP messages via POST - process tool calls directly"""
                    data = None
                    try:
                        data = await request.json()
                        
                        # Handle MCP protocol messages
                        if isinstance(data, dict):
                            method = data.get("method")
                            
                            # Handle initialize request
                            if method == "initialize":
                                return {
                                    "jsonrpc": "2.0",
                                    "id": data.get("id"),
                                    "result": {
                                        "protocolVersion": "2024-11-05",
                                        "capabilities": {
                                            "tools": {}
                                        },
                                        "serverInfo": {
                                            "name": "kali-mcp-server",
                                            "version": "1.0.0"
                                        }
                                    }
                                }
                            
                            # Handle tools/list request
                            elif method == "tools/list":
                                tools_list = []
                                for name, func in tool_functions.items():
                                    sig = inspect.signature(func)
                                    parameters = []
                                    for param_name, param in sig.parameters.items():
                                        if param_name in ['self', 'mcp']:
                                            continue
                                        param_type = 'string'
                                        if param.annotation is int:
                                            param_type = 'integer'
                                        elif param.annotation is bool:
                                            param_type = 'boolean'
                                        parameters.append({
                                            'name': param_name,
                                            'type': param_type,
                                            'description': f"Parameter for {param_name}",
                                            'required': param.default == inspect.Parameter.empty
                                        })
                                    tools_list.append({
                                        'name': name,
                                        'description': (func.__doc__ or f"Executes {name} command").split('\n')[0],
                                        'inputSchema': {
                                            'type': 'object',
                                            'properties': {p['name']: {'type': p['type']} for p in parameters},
                                            'required': [p['name'] for p in parameters if p['required']]
                                        }
                                    })
                                
                                return {
                                    "jsonrpc": "2.0",
                                    "id": data.get("id"),
                                    "result": {
                                        "tools": tools_list
                                    }
                                }
                            
                            # Handle tools/call request
                            elif method == "tools/call":
                                params = data.get("params", {})
                                tool_name = params.get("name")
                                # Handle null arguments from JSON - ensure it's always a dict
                                arguments = params.get("arguments") or {}
                                
                                if tool_name not in tool_functions:
                                    return {
                                        "jsonrpc": "2.0",
                                        "id": data.get("id"),
                                        "error": {
                                            "code": -32601,
                                            "message": f"Unknown tool: {tool_name}"
                                        }
                                    }
                                
                                # Execute tool
                                try:
                                    tool_func = tool_functions[tool_name]
                                    loop = asyncio.get_event_loop()
                                    
                                    # Run sync function in executor
                                    if inspect.iscoroutinefunction(tool_func):
                                        result = await tool_func(**arguments)
                                    else:
                                        # Capture arguments in closure properly
                                        result = await loop.run_in_executor(None, lambda a=arguments: tool_func(**a))
                                    
                                    return {
                                        "jsonrpc": "2.0",
                                        "id": data.get("id"),
                                        "result": {
                                            "content": [
                                                {
                                                    "type": "text",
                                                    "text": str(result)
                                                }
                                            ]
                                        }
                                    }
                                except Exception as e:
                                    logger.error(f"Tool execution error: {e}")
                                    if DEBUG_MODE:
                                        import traceback
                                        logger.error(traceback.format_exc())
                                    return {
                                        "jsonrpc": "2.0",
                                        "id": data.get("id"),
                                        "error": {
                                            "code": -32603,
                                            "message": f"Tool execution failed: {str(e)}"
                                        }
                                    }
                            
                            # Handle ping/keepalive
                            elif method == "ping" or method == "ping/keepalive":
                                return {
                                    "jsonrpc": "2.0",
                                    "id": data.get("id"),
                                    "result": {}
                                }
                            
                            # Unknown method
                            else:
                                return {
                                    "jsonrpc": "2.0",
                                    "id": data.get("id"),
                                    "error": {
                                        "code": -32601,
                                        "message": f"Unknown method: {method}"
                                    }
                                }
                        
                        # Default response
                        return {"status": "received", "message": "MCP message received"}
                        
                    except Exception as e:
                        logger.error(f"POST handler error: {e}")
                        if DEBUG_MODE:
                            import traceback
                            logger.error(traceback.format_exc())
                        return {
                            "jsonrpc": "2.0",
                            "id": data.get("id") if isinstance(data, dict) else None,
                            "error": {
                                "code": -32603,
                                "message": f"Internal error: {str(e)}"
                            }
                        }
                
                @fastapi_app.get("/health")
                async def health():
                    """Health check endpoint"""
                    return {
                        "status": "running",
                        "mode": "sse",
                        "tools_registered": len(tool_functions),
                        "active_connections": len(active_connections)
                    }
                
                app = fastapi_app
            
            # Run with uvicorn
            import uvicorn
            logger.info(f"Starting MCP SSE server on {host}:{port}/sse")
            logger.info(f"Registered {len(tool_functions)} tools for SSE transport")
            uvicorn.run(app, host=host, port=port, log_level="warning")
                
        except ImportError as e:
            logger.error(f"Required package not available: {e}")
            logger.error("Install: pip install uvicorn")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Failed to start SSE server: {e}")
            import traceback
            logger.error(traceback.format_exc())
            sys.exit(1)
    else:
        # Default stdio mode - use FastMCP
        try:
            mcp.run()
        except (EOFError, BrokenPipeError, KeyboardInterrupt):
            # Normal termination - client disconnected or user interrupted
            sys.exit(0)
        except Exception as e:
            # Log unexpected errors before exiting
            if DEBUG_MODE:
                logger.error(f"Unexpected error in stdio mode: {e}", exc_info=True)
            sys.exit(1)