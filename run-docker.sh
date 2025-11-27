#!/bin/bash
# Run Docker container in DETACHED mode
# 
# This creates a separate container named "kali-mcp-server-detached"
# to avoid conflicts with the stdio mode container "kali-mcp-server" (used by mcp.json)
#
# IMPORTANT: Detached mode does NOT support MCP server stdio transport.
# This container is for monitoring, health checks, or other purposes.
# For actual MCP server usage, use mcp.json configuration.

CONTAINER_NAME="kali-mcp-server-detached"

echo "Starting MCP server container in DETACHED mode"
echo "Container name: $CONTAINER_NAME"
echo "Note: This is separate from stdio mode container (kali-mcp-server)"
echo ""

# Stop and remove existing detached container if it exists
docker stop "$CONTAINER_NAME" 2>/dev/null || true
docker rm "$CONTAINER_NAME" 2>/dev/null || true

# Run container with resource limits and proper capabilities
# Set DETACHED_MODE environment variable to enable detached mode behavior
docker run -d \
    -p 8001:8000 \
    --name "$CONTAINER_NAME" \
    --cap-add=NET_RAW \
    --cap-add=NET_ADMIN \
    --memory=2g \
    --memory-reservation=512m \
    --cpus=2.0 \
    --cpu-shares=512 \
    --restart=unless-stopped \
    -e DETACHED_MODE=true \
    kali-mcp-server

echo ""
echo "Container '$CONTAINER_NAME' started successfully!"
echo ""
echo "Container Information:"
echo "  Name: $CONTAINER_NAME"
echo "  Mode: Detached (for monitoring/health checks)"
echo "  Port: 8001 (mapped from container port 8000)"
echo "  Stdio mode container: kali-mcp-server (managed by mcp.json)"
echo ""
echo "Useful commands:"
echo "  Check status: docker ps | grep $CONTAINER_NAME"
echo "  View logs: docker logs $CONTAINER_NAME"
echo "  Monitor resources: docker stats $CONTAINER_NAME"
echo "  Stop container: docker stop $CONTAINER_NAME"
echo ""
echo "Note: For MCP server usage, use mcp.json configuration (stdio mode)"

