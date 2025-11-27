# PowerShell test script for Kali MCP Server
# Tests Docker availability, image existence, and basic functionality

param(
    [switch]$Quick,
    [switch]$Verbose
)

$ErrorActionPreference = "Continue"

# Colors for output
function Write-Success {
    param([string]$Message)
    Write-Host "✓ $Message" -ForegroundColor Green
}

function Write-Error {
    param([string]$Message)
    Write-Host "✗ $Message" -ForegroundColor Red
}

function Write-Warning {
    param([string]$Message)
    Write-Host "⚠ $Message" -ForegroundColor Yellow
}

function Write-Info {
    param([string]$Message)
    Write-Host "ℹ $Message" -ForegroundColor Cyan
}

function Write-Header {
    param([string]$Message)
    Write-Host ""
    Write-Host "=" * 60 -ForegroundColor Cyan
    Write-Host $Message -ForegroundColor Cyan
    Write-Host "=" * 60 -ForegroundColor Cyan
    Write-Host ""
}

function Find-RunningContainer {
    # Check for containers with kali-mcp-server image
    $containers = docker ps --filter "ancestor=kali-mcp-server" --format "{{.Names}}" 2>&1
    if ($LASTEXITCODE -eq 0 -and $containers) {
        $containerList = @($containers -split "`n" | Where-Object { $_.Trim() -ne "" })
        if ($containerList.Count -gt 0) {
            $firstContainer = $containerList[0].ToString().Trim()
            if ($firstContainer) {
                return $firstContainer
            }
        }
    }
    
    # Also check by name patterns (Cursor might use different names)
    $namePatterns = @("kali-mcp", "mcp-server")
    foreach ($pattern in $namePatterns) {
        $containers = docker ps --filter "name=$pattern" --format "{{.Names}}" 2>&1
        if ($LASTEXITCODE -eq 0 -and $containers) {
            $containerList = @($containers -split "`n" | Where-Object { $_.Trim() -ne "" })
            if ($containerList.Count -gt 0) {
                $firstContainer = $containerList[0].ToString().Trim()
                if ($firstContainer) {
                    return $firstContainer
                }
            }
        }
    }
    
    return $null
}

$TestResults = @{}

# Test 1: Docker Availability
Write-Header "Test 1: Docker Availability"
try {
    $dockerVersion = docker --version 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Docker is available: $dockerVersion"
        $TestResults["Docker Available"] = $true
    } else {
        Write-Error "Docker is not available"
        $TestResults["Docker Available"] = $false
        Write-Error "Docker is required for all tests. Please install Docker first."
        exit 1
    }
} catch {
    Write-Error "Docker is not available: $_"
    $TestResults["Docker Available"] = $false
    exit 1
}

# Test 2: Docker Image Existence
Write-Header "Test 2: Docker Image Existence"
try {
    $imageExists = docker images kali-mcp-server --format "{{.Repository}}:{{.Tag}}" 2>&1
    if ($LASTEXITCODE -eq 0 -and $imageExists -match "kali-mcp-server") {
        Write-Success "Docker image exists: $imageExists"
        $TestResults["Docker Image Exists"] = $true
    } else {
        Write-Warning "Docker image 'kali-mcp-server' not found"
        Write-Info "You may need to build the image first:"
        Write-Info "  docker build -t kali-mcp-server ."
        $TestResults["Docker Image Exists"] = $false
        Write-Warning "Image not found. Some tests will be skipped."
        exit 0
    }
} catch {
    Write-Error "Error checking image: $_"
    $TestResults["Docker Image Exists"] = $false
}

# Test 3: Container Can Start
Write-Header "Test 3: Container Can Start"
try {
    # First, check if a container is already running (e.g., started by Cursor)
    $existingContainer = Find-RunningContainer
    
    if ($existingContainer) {
        Write-Info "Found existing container: $existingContainer"
        Write-Info "Testing command execution in existing container..."
        
        $output = docker exec $existingContainer python3 -c "print('Container test successful')" 2>&1
        
        if ($LASTEXITCODE -eq 0 -and $output -match "Container test successful") {
            Write-Success "Existing container '$existingContainer' can execute commands"
            $TestResults["Container Can Start"] = $true
        } else {
            Write-Warning "Existing container found but command execution failed: $output"
            Write-Info "Will try to start a new test container..."
        }
    } else {
        Write-Info "No existing container found. Starting test container..."
    }
    
    # Only try to start new container if existing one didn't work
    if (-not $TestResults["Container Can Start"]) {
        # Clean up any existing test container
        docker stop kali-mcp-test 2>$null | Out-Null
        docker rm kali-mcp-test 2>$null | Out-Null
        
        $output = docker run --rm `
            --name kali-mcp-test `
            --cap-add=NET_RAW `
            --cap-add=NET_ADMIN `
            --memory=2g `
            --cpus=2.0 `
            kali-mcp-server `
            python3 -c "print('Container test successful')" 2>&1
        
        if ($LASTEXITCODE -eq 0 -and $output -match "Container test successful") {
            Write-Success "Container can start and execute commands"
            $TestResults["Container Can Start"] = $true
        } else {
            Write-Error "Container failed to start: $output"
            $TestResults["Container Can Start"] = $false
        }
    }
} catch {
    Write-Error "Error testing container: $_"
    $TestResults["Container Can Start"] = $false
}

# Test 4: Tools Availability
Write-Header "Test 4: Tools Availability"
$existingContainer = Find-RunningContainer
$useExisting = $null -ne $existingContainer

if ($useExisting) {
    Write-Info "Using existing container: $existingContainer"
} else {
    Write-Info "No existing container found. Will use temporary containers for testing."
}

$toolsToTest = @("nmap", "nikto", "sqlmap", "whatweb", "gobuster", "ffuf")
$allAvailable = $true

foreach ($tool in $toolsToTest) {
    try {
        if ($useExisting) {
            $output = docker exec $existingContainer which $tool 2>&1
        } else {
            $output = docker run --rm `
                --cap-add=NET_RAW `
                --cap-add=NET_ADMIN `
                --memory=2g `
                --cpus=2.0 `
                kali-mcp-server `
                which $tool 2>&1
        }
        
        if ($LASTEXITCODE -eq 0 -and $output -match $tool) {
            Write-Success "$tool is available"
        } else {
            Write-Error "$tool is not available"
            if ($output) {
                Write-Info "  Output: $($output.Substring(0, [Math]::Min(100, $output.Length)))"
            }
            $allAvailable = $false
        }
    } catch {
        Write-Error "Error checking $tool : $_"
        $allAvailable = $false
    }
}

$TestResults["Tools Available"] = $allAvailable

# Test 5: Simple Command Execution
Write-Header "Test 5: Simple Command Execution"
try {
    $testCommand = "echo 'MCP server test'"
    $existingContainer = Find-RunningContainer
    
    Write-Info "Testing command execution: $testCommand"
    
    if ($existingContainer) {
        Write-Info "Using existing container: $existingContainer"
        $output = docker exec $existingContainer sh -c $testCommand 2>&1
    } else {
        Write-Info "No existing container found. Using temporary container..."
        $output = docker run --rm `
            --cap-add=NET_RAW `
            --cap-add=NET_ADMIN `
            --memory=2g `
            --cpus=2.0 `
            kali-mcp-server `
            sh -c $testCommand 2>&1
    }
    
    if ($LASTEXITCODE -eq 0 -and $output -match "MCP server test") {
        Write-Success "Simple command execution works"
        $TestResults["Simple Command Execution"] = $true
    } else {
        Write-Error "Command execution failed: $output"
        $TestResults["Simple Command Execution"] = $false
    }
} catch {
    Write-Error "Error testing command execution: $_"
    $TestResults["Simple Command Execution"] = $false
}

# Test 6: Nmap Basic Functionality
Write-Header "Test 6: Nmap Basic Functionality"
try {
    $existingContainer = Find-RunningContainer
    
    if ($existingContainer) {
        Write-Info "Using existing container: $existingContainer"
        $output = docker exec $existingContainer nmap --version 2>&1
    } else {
        Write-Info "No existing container found. Using temporary container..."
        $output = docker run --rm `
            --cap-add=NET_RAW `
            --cap-add=NET_ADMIN `
            --memory=2g `
            --cpus=2.0 `
            kali-mcp-server `
            nmap --version 2>&1
    }
    
    if ($LASTEXITCODE -eq 0 -and $output -match "Nmap") {
        Write-Success "Nmap is functional"
        Write-Info "Nmap version info: $($output.Substring(0, [Math]::Min(100, $output.Length)))"
        $TestResults["Nmap Basic Functionality"] = $true
    } else {
        Write-Error "Nmap test failed: $output"
        $TestResults["Nmap Basic Functionality"] = $false
    }
} catch {
    Write-Error "Error testing nmap: $_"
    $TestResults["Nmap Basic Functionality"] = $false
}

# Generate Test Report
Write-Header "Test Report Summary"
$totalTests = $TestResults.Count
$passedTests = ($TestResults.Values | Where-Object { $_ -eq $true }).Count
$failedTests = $totalTests - $passedTests

Write-Host "`nTotal Tests: $totalTests"
Write-Success "Passed: $passedTests"
if ($failedTests -gt 0) {
    Write-Error "Failed: $failedTests"
} else {
    Write-Success "Failed: 0"
}

Write-Host "`nDetailed Results:"
foreach ($testName in $TestResults.Keys) {
    $result = $TestResults[$testName]
    $status = if ($result) { "✓ PASS" } else { "✗ FAIL" }
    $color = if ($result) { "Green" } else { "Red" }
    Write-Host "  $status - $testName" -ForegroundColor $color
}

Write-Host "`n" + ("=" * 60)

if ($failedTests -eq 0) {
    Write-Success "All tests passed! MCP server is working correctly."
    exit 0
} else {
    Write-Error "Some tests failed. Please review the errors above."
    exit 1
}

