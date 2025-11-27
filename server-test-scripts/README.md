# Kali MCP Server Test Scripts

This directory contains test scripts to verify that the Kali MCP server is working correctly.

## Available Test Scripts

### Python Test Script (Cross-platform)
- **File**: `test_mcp_server.py`
- **Usage**: `python3 test_mcp_server.py`
- **Requirements**: Python 3.6+
- **Features**: 
  - Comprehensive test suite with colored output
  - Tests Docker availability, image existence, container startup, MCP server response, tool availability, and basic functionality
  - Generates detailed test reports

### PowerShell Test Script (Windows)
- **File**: `test_mcp_server.ps1`
- **Usage**: `.\test_mcp_server.ps1`
- **Requirements**: PowerShell 5.1+ and Docker
- **Features**: 
  - Same test coverage as Python script
  - Optimized for Windows environments
  - Colored output for better readability

### Bash Test Script (Linux/macOS)
- **File**: `test_mcp_server.sh`
- **Usage**: `bash test_mcp_server.sh` or `./test_mcp_server.sh` (after making executable)
- **Requirements**: Bash and Docker
- **Features**: 
  - Same test coverage as Python script
  - Optimized for Unix-like systems
  - Colored output for better readability

## Test Coverage

The test scripts verify:

1. **Docker Availability** - Checks if Docker is installed and accessible
2. **Docker Image Existence** - Verifies the `kali-mcp-server` image exists
3. **Container Can Start** - Tests that containers can be created and run (or uses existing container if already running)
4. **MCP Server Response** - Verifies the MCP server responds to initialization requests
5. **Tools Availability** - Checks that key security tools (nmap, nikto, sqlmap, whatweb, gobuster, ffuf) are available
6. **Simple Command Execution** - Tests basic command execution within the container
7. **Nmap Basic Functionality** - Verifies nmap can run (version check)

### Smart Container Detection

The test scripts automatically detect if a container is already running (e.g., started by Cursor IDE when using the MCP server). When an existing container is found:

- Tests will use `docker exec` to run commands in the existing container
- No new containers will be created unnecessarily
- This allows testing the actual MCP server instance that Cursor is using

If no existing container is found, the scripts will create temporary test containers as needed.

## Prerequisites

Before running the tests:

1. **Docker must be installed and running**
   - Verify with: `docker --version`
   - Ensure Docker daemon is running

2. **Docker image must be built**
   - Build the image: `docker build -t kali-mcp-server .`
   - Or pull from registry if available

3. **Required permissions**
   - Docker must have permissions to create containers
   - On Linux, you may need to be in the `docker` group or use `sudo`

## Running the Tests

### Quick Start

**Windows (PowerShell):**
```powershell
cd server-test-scripts
.\test_mcp_server.ps1
```

**Linux/macOS (Bash):**
```bash
cd server-test-scripts
chmod +x test_mcp_server.sh
./test_mcp_server.sh
```

**Cross-platform (Python):**
```bash
cd server-test-scripts
python3 test_mcp_server.py
```

### Expected Output

The tests will display:
- ✓ Green checkmarks for passing tests
- ✗ Red X marks for failing tests
- ⚠ Yellow warnings for non-critical issues
- ℹ Blue info messages for additional context

At the end, a summary report shows:
- Total number of tests
- Number of passed/failed tests
- Detailed results for each test

## Troubleshooting

### Docker Not Found
- **Error**: "Docker is not available"
- **Solution**: Install Docker Desktop or Docker Engine
- **Verify**: Run `docker --version`

### Image Not Found
- **Error**: "Docker image 'kali-mcp-server' not found"
- **Solution**: Build the image: `docker build -t kali-mcp-server .`
- **Location**: Run from the project root directory

### Container Startup Fails
- **Error**: "Container failed to start"
- **Possible Causes**:
  - Insufficient system resources (memory/CPU)
  - Docker daemon not running
  - Image corruption
- **Solution**: 
  - Check Docker daemon: `docker ps`
  - Rebuild image: `docker build -t kali-mcp-server .`
  - Check system resources

### Permission Denied
- **Error**: "Permission denied" (Linux)
- **Solution**: 
  - Add user to docker group: `sudo usermod -aG docker $USER`
  - Log out and back in
  - Or use `sudo` (not recommended)

### Tools Not Available
- **Error**: "Tool X is not available"
- **Possible Causes**:
  - Tool not installed in image
  - Image build incomplete
- **Solution**: 
  - Rebuild the Docker image
  - Check Dockerfile for tool installation

## Test Execution Time

- **Quick tests**: ~2-5 minutes
- **Full test suite**: ~5-10 minutes

Tests that require container startup may take longer on first run due to image pulling/initialization.

## Continuous Integration

These test scripts can be integrated into CI/CD pipelines:

```yaml
# Example GitHub Actions
- name: Test MCP Server
  run: |
    cd server-test-scripts
    python3 test_mcp_server.py
```

## Contributing

When adding new tests:
1. Follow the existing test structure
2. Use the provided helper functions for output
3. Add appropriate error handling
4. Update this README with new test descriptions

## Notes

- **Existing Container Detection**: Tests automatically detect and use containers already running (e.g., started by Cursor IDE)
- **Temporary Containers**: If no existing container is found, tests create temporary containers that are automatically cleaned up
- **Network Access**: Tests do not require network access (except for MCP protocol tests)
- **Resource Usage**: Some tests may take longer on resource-constrained systems
- **Safety**: All tests are designed to be safe and non-destructive
- **Cursor Integration**: When Cursor has started the MCP server container, tests will use that container instead of creating new ones

