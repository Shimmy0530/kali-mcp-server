# Security Assessment Scripts

A comprehensive collection of security testing scripts designed to work with the Kali MCP Server. These scripts provide automated security assessments using industry-standard tools.

## 📁 Contents

| Script | Description |
|--------|-------------|
| `custom_security_tests.py` | Python-based web application security testing |
| `mcp_security_tests.py` | MCP tool orchestration for Kali security tools |
| `check_mcp_server.py` | Health checker for MCP server container |
| `security_assessment.sh` | Shell-based security assessment using Docker |
| `run_assessment.sh` | Master orchestration script for full assessments |

## 🚀 Quick Start

### Prerequisites

- **Python 3.8+** with `requests` library
- **Docker** with the `kali-mcp-server` image built
- **Bash** (for shell scripts)

### Installation

1. Clone the repository:
```bash
git clone https://github.com/your-repo/kali-mcp-server.git
cd kali-mcp-server
```

2. Install Python dependencies:
```bash
pip install requests urllib3
```

3. Build the Docker image:
```bash
docker build -t kali-mcp-server .
```

4. Start the MCP server:
```bash
./run-docker.sh  # Linux/Mac
# or
.\run-docker.ps1  # Windows
```

## 📖 Usage

### Quick Assessment (Custom Python Tests Only)

Run lightweight security tests without Docker:

```bash
# Basic usage
python custom_security_tests.py --target https://example.com

# With options
python custom_security_tests.py \
    --target https://example.com \
    --timeout 15 \
    --rate-limit 1.0 \
    --output results.json
```

### Full Assessment (All Tools)

Run comprehensive assessment using all available tools:

```bash
# Full assessment
./run_assessment.sh --target example.com

# Quick mode (reduced timeouts)
./run_assessment.sh --target example.com --quick

# Specific phases only
./run_assessment.sh --target example.com --phases recon web
```

### MCP-Based Tests Only

Run Kali security tools via MCP server:

```bash
# All phases
python mcp_security_tests.py --target example.com

# Specific phases
python mcp_security_tests.py --target example.com --phases recon network

# With custom timeout
python mcp_security_tests.py --target example.com --timeout 600
```

### Check MCP Server Status

```bash
# Basic health check
python check_mcp_server.py

# Auto-start if not running
python check_mcp_server.py --auto-start

# Save results to file
python check_mcp_server.py --save --output health_report.json
```

## 🔧 Script Details

### `custom_security_tests.py`

A standalone Python security tester that doesn't require Docker. Tests include:

| Test | Description | Severity |
|------|-------------|----------|
| HTTP Methods | Checks for dangerous HTTP methods (TRACE, PUT, DELETE) | Medium |
| Security Headers | Validates presence of security headers (CSP, HSTS, etc.) | High-Low |
| SSL/TLS | Checks certificate validity and protocol versions | High |
| CORS | Tests for CORS misconfigurations | High-Medium |
| Cookie Security | Validates Secure, HttpOnly, SameSite flags | High-Medium |
| SQL Injection | Tests for SQL injection vulnerabilities | High |
| XSS | Tests for cross-site scripting | Medium |
| Directory Traversal | Tests for path traversal vulnerabilities | High |
| Sensitive Files | Checks for exposed sensitive files | High-Medium |
| Authentication | Tests login mechanisms for weaknesses | High-Medium |
| Rate Limiting | Checks for missing rate limits | Medium |

**Options:**
```
--target, -t      Target URL (required)
--timeout         Request timeout in seconds (default: 10)
--rate-limit      Delay between requests (default: 0.5)
--workers         Max concurrent workers (default: 5)
--output, -o      Output file for results
```

### `mcp_security_tests.py`

Orchestrates Kali security tools via the MCP Docker container.

**Phases:**
1. **Recon**: whatweb, theharvester, dnsenum, dnsrecon, nmap (quick)
2. **Network**: Full nmap scan, masscan
3. **Web**: nikto, wapiti, sqlmap, xsser, commix
4. **Enumeration**: dirb, gobuster, ffuf, wfuzz

**Options:**
```
--target, -t      Target domain (required)
--container, -c   Docker container name (default: kali-mcp-server)
--phases, -p      Phases to run: recon, network, web, enumeration
--workers, -w     Max concurrent workers (default: 3)
--timeout         Default scan timeout (default: 300)
--quiet, -q       Suppress verbose output
```

### `security_assessment.sh`

Shell script that runs Kali tools directly via Docker exec.

**Options:**
```
-t, --target      Target domain
-c, --container   Container name (default: kali-mcp-server)
-p, --phase       Specific phase: recon, network, web, enum, all
-q, --quick       Quick mode with reduced timeouts
-v, --verbose     Enable verbose output
```

### `run_assessment.sh`

Master orchestration script that runs all assessment types.

**Options:**
```
-t, --target      Target domain
-q, --quick       Quick mode
-s, --skip-mcp    Skip MCP-based tests
-v, --verbose     Verbose output
```

## 📊 Output

All scripts generate output in the following structure:

```
output/
├── scans/
│   ├── recon/           # Reconnaissance results
│   ├── network/         # Network scan results
│   ├── web/             # Web vulnerability results
│   └── enumeration/     # Directory/file discovery
├── reports/
│   ├── custom_tests_*.json
│   ├── mcp_test_summary_*.json
│   └── final_assessment_*.md
└── logs/
    └── assessment_*.log
```

## 🎯 Use Cases

### Penetration Testing Preparation
```bash
# Quick reconnaissance
python mcp_security_tests.py --target target.com --phases recon

# Full web application testing
./run_assessment.sh --target target.com --phases web
```

### Continuous Security Testing
```bash
# Lightweight daily checks
python custom_security_tests.py --target https://myapp.com --output daily_check.json

# Weekly full assessment
./run_assessment.sh --target myapp.com --quick
```

### Bug Bounty Hunting
```bash
# Comprehensive reconnaissance
python mcp_security_tests.py --target target.com --phases recon enumeration

# Vulnerability scanning
python custom_security_tests.py --target https://target.com --workers 10
```

## ⚠️ Legal Disclaimer

**IMPORTANT:** These tools are intended for authorized security testing only.

- Always obtain written permission before testing
- Only test systems you own or have explicit authorization to test
- Unauthorized testing may violate laws and regulations
- The authors are not responsible for misuse of these tools

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

