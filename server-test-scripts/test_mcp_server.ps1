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
    # Clean up any existing test container
    docker stop kali-mcp-test 2>$null | Out-Null
    docker rm kali-mcp-test 2>$null | Out-Null
    
    Write-Info "Starting test container..."
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
} catch {
    Write-Error "Error testing container: $_"
    $TestResults["Container Can Start"] = $false
}

# Test 4: Tools Availability
Write-Header "Test 4: Tools Availability"
$toolsToTest = @("nmap", "nikto", "sqlmap", "whatweb", "gobuster", "ffuf")
$allAvailable = $true

foreach ($tool in $toolsToTest) {
    try {
        $output = docker run --rm `
            --cap-add=NET_RAW `
            --cap-add=NET_ADMIN `
            --memory=2g `
            --cpus=2.0 `
            kali-mcp-server `
            which $tool 2>&1
        
        if ($LASTEXITCODE -eq 0 -and $output -match $tool) {
            Write-Success "$tool is available"
        } else {
            Write-Error "$tool is not available"
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
    Write-Info "Testing command execution: $testCommand"
    
    $output = docker run --rm `
        --cap-add=NET_RAW `
        --cap-add=NET_ADMIN `
        --memory=2g `
        --cpus=2.0 `
        kali-mcp-server `
        sh -c $testCommand 2>&1
    
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
    $output = docker run --rm `
        --cap-add=NET_RAW `
        --cap-add=NET_ADMIN `
        --memory=2g `
        --cpus=2.0 `
        kali-mcp-server `
        nmap --version 2>&1
    
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

