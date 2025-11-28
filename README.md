# kali-mcp-server

A Docker image providing a Model Context Protocol (MCP) server that exposes Kali Linux security testing tools for use with AI assistants and development environments.

## Overview

This image packages a comprehensive suite of Kali Linux penetration testing and security assessment tools, making them accessible through the Model Context Protocol. The MCP server allows AI assistants and other MCP-compatible clients to execute security testing tools programmatically.

**What is MCP?** The Model Context Protocol is a standardized protocol that enables AI assistants to interact with external tools and services. This server exposes Kali Linux security tools as MCP tools, allowing AI assistants to help with authorized security testing, vulnerability assessment, and penetration testing tasks.

**Open Source:** This project is open source and welcomes contributions! See the [Contributing](#contributing) section for how you can help improve this project.

## ⚠️ CRITICAL LEGAL AND ETHICAL WARNINGS

### AUTHORIZED USE ONLY

**THIS IMAGE CONTAINS SECURITY TESTING TOOLS THAT CAN BE USED TO COMPROMISE SYSTEMS AND NETWORKS. USE OF THIS IMAGE IS STRICTLY LIMITED TO AUTHORIZED SECURITY TESTING ONLY.**

**YOU MUST:**

- ✅ Only use these tools on systems and networks you own or have explicit written authorization to test
- ✅ Obtain proper authorization before conducting any security testing
- ✅ Comply with all applicable laws and regulations in your jurisdiction
- ✅ Respect terms of service and acceptable use policies
- ✅ Use these tools responsibly and ethically

**YOU MUST NOT:**

- ❌ Use these tools on systems or networks without explicit authorization
- ❌ Use these tools to access, damage, or disrupt unauthorized systems
- ❌ Use these tools for any illegal activities
- ❌ Use these tools to violate privacy or confidentiality
- ❌ Use these tools in violation of computer fraud and abuse laws

### Legal Disclaimer

**THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.**

**BY USING THIS IMAGE, YOU ACKNOWLEDGE THAT:**

- You understand the legal and ethical implications of using security testing tools
- You are solely responsible for ensuring your use complies with all applicable laws
- You will only use these tools on systems you own or have explicit authorization to test
- The authors and maintainers of this image are not responsible for any misuse or illegal activities
- Unauthorized access to computer systems is illegal in most jurisdictions and may result in criminal prosecution

**Jurisdiction Considerations:**

- Laws regarding security testing tools vary by country and jurisdiction
- Some tools in this image may be restricted or illegal in certain jurisdictions
- It is your responsibility to understand and comply with local laws
- When in doubt, consult with legal counsel before use

### Ethical Use Requirements

- **Responsible Disclosure:** If you discover vulnerabilities, follow responsible disclosure practices
- **Scope Limitation:** Only test within the explicitly authorized scope
- **Data Protection:** Do not access, copy, or exfiltrate unauthorized data
- **Minimal Impact:** Use the least intrusive methods necessary for testing
- **Documentation:** Maintain proper documentation of authorized testing activities

## Quick Start

### Pull the Image

```bash
docker pull kali-mcp-server
```

### Basic Usage (stdio mode for MCP clients)

**Minimal (for testing):**
```bash
docker run -i --rm \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  kali-mcp-server
```

**Recommended (with resource limits):**
```bash
docker run -i --rm \
  -e DEBUG_MCP=1 \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  --memory=4g \
  --memory-reservation=1g \
  --cpus=4.0 \
  kali-mcp-server
```

### Using Docker Compose

```yaml
version: '3.8'

services:
  kali-mcp-server:
    image: kali-mcp-server
    stdin_open: true
    cap_add:
      - NET_RAW
      - NET_ADMIN
    environment:
      - DEBUG_MCP=1
    deploy:
      resources:
        limits:
          memory: 4g
          cpus: '4.0'
        reservations:
          memory: 1g
    restart: unless-stopped
```

## What's Included

### Base Image

- **Kali Linux Rolling** - Latest rolling release of Kali Linux

### Security Tools

The image includes a comprehensive suite of security testing tools organized by category:

#### Network Scanning & Enumeration
- **nmap** - Network mapper and port scanner
- **masscan** - Fast port scanner
- **netdiscover** - Active/passive network discovery
- **hping3** - Network packet crafting tool

#### Web Application Security Testing
- **nikto** - Web server scanner
- **sqlmap** - SQL injection scanner
- **wpscan** - WordPress vulnerability scanner
- **wapiti** - Web application vulnerability scanner
- **zaproxy** - OWASP ZAP baseline scanner
- **skipfish** - Active web application security scanner
- **uniscan** - Web vulnerability scanner

#### Web Discovery & Fuzzing
- **dirb** - Directory brute forcer
- **gobuster** - Directory/file brute forcer
- **ffuf** - Fast web fuzzer
- **wfuzz** - Web application fuzzer

#### Information Gathering & Reconnaissance
- **whatweb** - Web technology identifier
- **theHarvester** - Email, subdomain, and host gatherer
- **recon-ng** - Reconnaissance framework
- **dnsenum** - DNS enumeration tool
- **dnsrecon** - DNS enumeration tool

#### Password Attacks
- **john** - John the Ripper password cracker
- **hashcat** - Advanced password recovery tool
- **hydra** - Parallelized login cracker
- **medusa** - Parallel network login cracker

#### Exploitation
- **metasploit** - Penetration testing framework
- **searchsploit** - Exploit-DB search tool

#### Network Monitoring & Analysis
- **tshark** - Network protocol analyzer
- **tcpdump** - Packet analyzer

#### Additional Tools
- **xsser** - XSS vulnerability scanner
- **xssstrike** - Advanced XSS detection suite
- **commix** - Command injection exploitation tool

### MCP Server Capabilities

The MCP server exposes all these tools as callable functions through the Model Context Protocol, allowing:

- Programmatic execution of security tools
- Integration with AI assistants for security testing workflows
- Automated security assessment pipelines
- Tool orchestration and result aggregation

## Usage Examples

### MCP Client Configuration

For use with MCP-compatible clients (like Cursor IDE), configure in your `mcp.json`:

```json
{
  "mcpServers": {
    "kali-mcp": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "-e",
        "DEBUG_MCP=1",
        "--cap-add=NET_RAW",
        "--cap-add=NET_ADMIN",
        "--memory=4g",
        "--memory-reservation=1g",
        "--cpus=4.0",
        "--cpu-shares=1024",
        "kali-mcp-server"
      ]
    }
  }
}
```

**Note:** Adjust `--memory` and `--cpus` based on your system resources. The above configuration is recommended for systems with 16GB+ RAM.

### Detached Mode (SSE Transport)

For running the MCP server in detached mode with HTTP/SSE transport:

```bash
docker run -d \
  -p 8001:8000 \
  --name kali-mcp-server-detached \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  -e DETACHED_MODE=true \
  kali-mcp-server
```

**Note:** Detached mode uses HTTP/SSE transport (accessible at `http://localhost:8001/sse`) instead of stdio transport. For MCP clients that support SSE transport, you can configure them to use this endpoint. For most MCP clients (like Cursor), stdio mode (via `mcp.json`) is recommended for best performance.

### Resource-Limited Execution

For production use, apply resource limits:

```bash
docker run -i --rm \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  --memory=4g \
  --memory-reservation=1g \
  --cpus=4.0 \
  --cpu-shares=1024 \
  kali-mcp-server
```

**Minimum recommended:** `--memory=2g --cpus=2.0` for basic tools.
**Recommended:** `--memory=4g --cpus=4.0` for resource-intensive tools (ZAP, Metasploit, etc.).

## Additional Tools and Scripts

### Security Assessment Scripts

This repository includes comprehensive security assessment scripts that work with the MCP server container:

- **Automated Security Testing**: Run full security assessments using multiple testing methodologies
- **Custom Python Tests**: Application-level security testing without Docker
- **MCP-Based Tests**: Orchestrate Kali tools via the MCP Docker container
- **Shell-Based Tests**: Direct Docker exec-based security assessments

For detailed documentation and usage examples, see [`assessment-scripts/README.md`](assessment-scripts/README.md).

**Quick Start:**
```bash
# Run full assessment
./assessment-scripts/run_assessment.sh --target example.com

# Quick mode
./assessment-scripts/run_assessment.sh --target example.com --quick
```

### Test Scripts

Test scripts are available to verify the MCP server is working correctly:

- **Cross-platform Python tests**: Comprehensive test suite
- **Windows PowerShell tests**: Optimized for Windows
- **Linux/macOS Bash tests**: Unix-optimized tests

For detailed documentation, see [`server-test-scripts/README.md`](server-test-scripts/README.md).

**Quick Start:**
```bash
# Python (cross-platform)
python3 server-test-scripts/test_mcp_server.py

# Bash (Linux/macOS)
bash server-test-scripts/test_mcp_server.sh

# PowerShell (Windows)
.\server-test-scripts\test_mcp_server.ps1
```

## Security Considerations

### Container Capabilities

This image requires elevated capabilities for network tools to function:

- **NET_RAW** - Required for raw socket access (nmap, masscan, etc.)
- **NET_ADMIN** - Required for network administration operations

**Warning:** These capabilities grant significant network access. Only run this container in trusted environments.

### Network Access

The container requires network access to:
- Perform network scans and reconnaissance
- Test web applications
- Conduct security assessments

**Isolation Recommendations:**
- Run in isolated Docker networks when possible
- Use firewall rules to limit outbound connections
- Monitor network traffic from the container
- Consider using read-only root filesystem: `--read-only`

### Resource Limits

The image includes built-in per-process resource limits (2GB soft, 4GB hard memory limit per tool). You should also set Docker container-level resource constraints:

```bash
--memory=4g              # Limit container memory (recommended)
--memory-reservation=1g  # Reserve minimum memory
--cpus=4.0               # Limit CPU cores (recommended)
--cpu-shares=1024        # CPU priority
```

**Why these values?** Security tools like WhatWeb (Ruby), ZAP (Java), and Metasploit (Ruby) require significant memory. The 4GB limit provides headroom for multiple concurrent tool executions.

### Per-Process Resource Limits

The MCP server enforces per-process resource limits to prevent any single tool from consuming all container resources:

| Limit | Value | Description |
|-------|-------|-------------|
| Memory (soft) | 2GB | Tool gets warning when exceeded |
| Memory (hard) | 4GB | Tool is killed if exceeded |
| CPU Time | timeout + 60s | Prevents runaway CPU usage |

These limits are enforced via Linux `rlimit` and apply to each tool execution independently.

### Security Best Practices

1. **Principle of Least Privilege:** Only grant necessary capabilities
2. **Network Isolation:** Use Docker networks to isolate containers
3. **Resource Constraints:** Always set memory and CPU limits
4. **Monitoring:** Monitor container activity and resource usage
5. **Regular Updates:** Keep the image updated to latest version
6. **Audit Logs:** Maintain logs of security testing activities

## Technical Details

### Image Specifications

- **Base Image:** `kalilinux/kali-rolling:latest`
- **Working Directory:** `/app`
- **Exposed Port:** `8000` (for SSE transport, if used)
- **Entrypoint:** `/app/entrypoint.sh`
- **Python Version:** Python 3 (system default)

### Python Dependencies

- `mcp` - Model Context Protocol server framework
- `python-dotenv` - Environment variable management
- `uvicorn` - ASGI server (for SSE transport)

### Image Size

**Warning:** This image is large (several GB) due to the comprehensive Kali Linux toolset. Consider:
- Using multi-stage builds for production
- Removing unused tools to reduce size
- Using volume mounts for tool data if needed

### Environment Variables

- `DEBUG_MCP` - Set to `1` to enable debug logging to `/tmp/mcp_debug.log` (default: `0`)
- `DETACHED_MODE` - Set to `true` for detached/monitoring mode (default: `false`)
- `PYTHONUNBUFFERED=1` - Ensures immediate output for MCP protocol (set in Dockerfile)
- `DEBIAN_FRONTEND=noninteractive` - Prevents interactive prompts during build (set in Dockerfile)

### File Structure

```
/app/
├── mcp_server.py    # MCP server implementation
└── entrypoint.sh    # Container entrypoint script
```

## Troubleshooting

### Container Won't Start

**Issue:** Container exits immediately

**Solutions:**
- Ensure you're using `-i` flag for stdio mode: `docker run -i ...`
- Check container logs: `docker logs <container-name>`
- Verify Docker has necessary permissions for capabilities

### Network Tools Not Working

**Issue:** nmap, masscan, or other network tools fail

**Solutions:**
- Ensure `--cap-add=NET_RAW` and `--cap-add=NET_ADMIN` are set
- Check if running in privileged mode is necessary (not recommended)
- Verify network connectivity from container

### MCP Protocol Errors

**Issue:** MCP client cannot communicate with server

**Solutions:**
- Ensure stdin/stdout are available (use `-i` flag, not `-d`)
- Check that MCP client configuration is correct
- Review MCP server logs for errors
- Verify Python dependencies are installed correctly

### Resource Exhaustion

**Issue:** Container crashes or becomes unresponsive

**Solutions:**
- Set appropriate memory limits: `--memory=4g` (recommended)
- Set CPU limits: `--cpus=4.0` (recommended)
- Reduce scope of security scans
- Use timeouts in tool execution
- For resource-constrained systems, use minimum: `--memory=2g --cpus=2.0`

### Permission Denied Errors

**Issue:** Tools report permission errors

**Solutions:**
- Verify required capabilities are granted
- Check file permissions in container
- Ensure tools have execute permissions (handled in Dockerfile)

## Support

### Reporting Issues

If you encounter bugs or have feature requests, please open an issue on GitHub with:
- A clear, descriptive title
- Detailed description of the issue or feature request
- Docker version and system information
- Relevant logs and error messages
- Steps to reproduce the issue (for bugs)
- Expected vs. actual behavior

### Getting Help

For questions or support:
- Review the troubleshooting section above
- Check the documentation for your specific use case
- Ensure you're using the latest version of the image

## Contributing

We welcome contributions from the community! This project is open source, and we appreciate any help you can provide to make it better.

### How to Contribute

There are many ways to contribute to this project:

- 🐛 **Report Bugs:** Open an issue describing the bug with steps to reproduce
- 💡 **Suggest Features:** Share your ideas for new features or improvements
- 📝 **Improve Documentation:** Help us make the documentation clearer and more comprehensive
- 🔧 **Fix Issues:** Submit pull requests to fix bugs or implement features
- 🧪 **Add Tests:** Help improve test coverage
- 🔍 **Code Review:** Review open pull requests and provide feedback
- 🌐 **Add Tools:** Propose new security tools to be integrated into the MCP server

### Getting Started

1. **Fork the Repository:** Click the "Fork" button on GitHub to create your own copy
2. **Clone Your Fork:** `git clone https://github.com/your-username/kali-mcp-server.git`
3. **Create a Branch:** `git checkout -b feature/your-feature-name` or `git checkout -b fix/your-bug-fix`
4. **Make Your Changes:** Implement your feature or fix
5. **Test Your Changes:** Ensure your changes work correctly and don't break existing functionality
6. **Commit Your Changes:** Write clear, descriptive commit messages
7. **Push to Your Fork:** `git push origin feature/your-feature-name`
8. **Open a Pull Request:** Submit your PR with a clear description of what you changed and why

### Development Setup

To set up a development environment:

```bash
# Clone the repository
git clone https://github.com/your-username/kali-mcp-server.git
cd kali-mcp-server

# Build the Docker image locally
docker build -t kali-mcp-server:dev .

# Test your changes
docker run -i --rm \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  -e DEBUG_MCP=1 \
  kali-mcp-server:dev
```

### Pull Request Guidelines

When submitting a pull request, please:

- ✅ **Keep PRs Focused:** One feature or fix per pull request
- ✅ **Write Clear Descriptions:** Explain what your PR does and why
- ✅ **Update Documentation:** If you add features, update the README or relevant docs
- ✅ **Follow Code Style:** Maintain consistency with existing code style
- ✅ **Test Thoroughly:** Ensure your changes work and don't introduce regressions
- ✅ **Reference Issues:** Link to related issues if applicable
- ✅ **Keep Commits Clean:** Use meaningful commit messages

### Code Style

- Follow Python PEP 8 style guidelines where applicable
- Use clear, descriptive variable and function names
- Add comments for complex logic
- Keep functions focused and maintainable
- Ensure error handling is appropriate

### What We're Looking For

We particularly welcome contributions that:

- Add new security tools to the MCP server
- Improve error handling and robustness
- Enhance documentation and examples
- Optimize performance and resource usage
- Add better timeout and resource limit handling
- Improve tool output parsing and formatting
- Add tests and improve test coverage
- Fix bugs and security issues

### Code of Conduct

By participating in this project, you agree to:

- Be respectful and inclusive
- Focus on constructive feedback
- Respect different viewpoints and experiences
- Accept responsibility for your words and actions
- Remember that this project is for authorized security testing only

### Questions?

If you have questions about contributing, feel free to:
- Open an issue with the `question` label
- Review existing issues and pull requests for examples
- Check the documentation for development guidelines

Thank you for contributing to kali-mcp-server! 🎉

## Additional Resources

- [Kali Linux Documentation](https://www.kali.org/docs/)
- [Model Context Protocol Specification](https://modelcontextprotocol.io/)
- [Docker Security Best Practices](https://docs.docker.com/engine/security/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

## License

MIT License

Copyright (c) 2024-2025

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Disclaimer (Repeated for Emphasis)

**THIS SOFTWARE IS PROVIDED FOR AUTHORIZED SECURITY TESTING ONLY. UNAUTHORIZED USE IS ILLEGAL AND MAY RESULT IN CRIMINAL PROSECUTION. USERS ARE SOLELY RESPONSIBLE FOR ENSURING COMPLIANCE WITH ALL APPLICABLE LAWS AND REGULATIONS.**

---

**Remember:** With great power comes great responsibility. Use these tools ethically, legally, and only with proper authorization.

