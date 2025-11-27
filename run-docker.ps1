# PowerShell script to run Docker container in DETACHED mode
# 
# This creates a separate container named "kali-mcp-server-detached"
# to avoid conflicts with the stdio mode container "kali-mcp-server" (used by mcp.json)
#
# IMPORTANT: Detached mode does NOT support MCP server stdio transport.
# This container is for monitoring, health checks, or other purposes.
# For actual MCP server usage, use mcp.json configuration.

$CONTAINER_NAME = "kali-mcp-server-detached"

Write-Host "Starting MCP server container in DETACHED mode" -ForegroundColor Cyan
Write-Host "Container name: $CONTAINER_NAME" -ForegroundColor Cyan
Write-Host "Note: This is separate from stdio mode container (kali-mcp-server)" -ForegroundColor Yellow
Write-Host ""

# Stop and remove existing detached container if it exists
docker stop $CONTAINER_NAME 2>$null
docker rm $CONTAINER_NAME 2>$null

# Run container with resource limits and proper capabilities
# Set DETACHED_MODE environment variable to enable detached mode behavior
docker run -d `
    -p 8001:8000 `
    --name $CONTAINER_NAME `
    --cap-add=NET_RAW `
    --cap-add=NET_ADMIN `
    --memory=2g `
    --memory-reservation=512m `
    --cpus=2.0 `
    --cpu-shares=512 `
    --restart=unless-stopped `
    -e DETACHED_MODE=true `
    kali-mcp-server

Write-Host ""
Write-Host "Container '$CONTAINER_NAME' started successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "Container Information:" -ForegroundColor Cyan
Write-Host "  Name: $CONTAINER_NAME" -ForegroundColor White
Write-Host "  Mode: Detached (for monitoring/health checks)" -ForegroundColor White
Write-Host "  Port: 8001 (mapped from container port 8000)" -ForegroundColor White
Write-Host "  Stdio mode container: kali-mcp-server (managed by mcp.json)" -ForegroundColor White
Write-Host ""
Write-Host "Useful commands:" -ForegroundColor Cyan
Write-Host "  Check status: docker ps | Select-String $CONTAINER_NAME" -ForegroundColor White
Write-Host "  View logs: docker logs $CONTAINER_NAME" -ForegroundColor White
Write-Host "  Monitor resources: docker stats $CONTAINER_NAME" -ForegroundColor White
Write-Host "  Stop container: docker stop $CONTAINER_NAME" -ForegroundColor White
Write-Host ""
Write-Host "Note: For MCP server usage, use mcp.json configuration (stdio mode)" -ForegroundColor Yellow

