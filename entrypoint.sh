#!/bin/bash
# Entrypoint script for MCP server container
# Supports both stdio mode (for mcp.json) and detached mode

set -e

# Check if we're in detached mode (only if DETACHED_MODE env var is explicitly set)
# Note: In stdio mode, stdin is available but not a TTY (Cursor uses -i without -t)
# So we only check the environment variable, not TTY status
if [ "${DETACHED_MODE:-false}" = "true" ]; then
    echo "Running in DETACHED mode (container: kali-mcp-server-detached)" >&2
    echo "Note: MCP server stdio transport requires active stdin/stdout" >&2
    echo "This mode is for container management only, not for MCP communication" >&2
    echo "" >&2
    echo "Container is running but MCP server cannot function in this mode." >&2
    echo "Use mcp.json configuration for actual MCP server usage." >&2
    echo "" >&2
    echo "Container will stay running for health checks and monitoring." >&2
    
    # Keep container alive (for health checks, monitoring, etc.)
    # In a real scenario, you might run a health check endpoint here
    while true; do
        sleep 3600  # Sleep for 1 hour, then check again
        echo "$(date): Container still running (detached mode)" >&2
    done
else
    # In stdio mode, stdout must be clean for MCP JSON protocol
    # Only log to stderr if needed for debugging
    # echo "Running in STDIO mode" >&2
    exec python3 /app/mcp_server.py
fi

