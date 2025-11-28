#!/bin/bash
# Entrypoint script for MCP server container
# Supports both stdio mode (for mcp.json) and detached mode

set -e

# Check if we're in detached mode (only if DETACHED_MODE env var is explicitly set)
# Note: In stdio mode, stdin is available but not a TTY (Cursor uses -i without -t)
# So we only check the environment variable, not TTY status
if [ "${DETACHED_MODE:-false}" = "true" ]; then
    echo "Running in DETACHED mode (container: kali-mcp-server-detached)" >&2
    echo "Starting MCP server in HTTP/SSE mode on port 8000" >&2
    echo "Accessible at: http://localhost:8001/sse (mapped from container port 8000)" >&2
    echo "" >&2
    
    # Set environment for SSE mode
    export MCP_SSE_MODE=true
    export MCP_PORT=8000
    export MCP_HOST=0.0.0.0
    
    # Run MCP server - it will detect SSE mode from environment
    exec python3 /app/mcp_server.py
else
    # In stdio mode, stdout must be clean for MCP JSON protocol
    # Only log to stderr if needed for debugging
    # echo "Running in STDIO mode" >&2
    exec python3 /app/mcp_server.py
fi

