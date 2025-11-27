#!/bin/bash
# Bash test script for Kali MCP Server
# Tests Docker availability, image existence, and basic functionality

set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

print_success() {
    echo -e "${GREEN}✓${RESET} $1"
}

print_error() {
    echo -e "${RED}✗${RESET} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${RESET} $1"
}

print_info() {
    echo -e "${CYAN}ℹ${RESET} $1"
}

print_header() {
    echo ""
    echo -e "${BOLD}${CYAN}============================================================${RESET}"
    echo -e "${BOLD}${CYAN}$1${RESET}"
    echo -e "${BOLD}${CYAN}============================================================${RESET}"
    echo ""
}

find_running_container() {
    # Check for containers with kali-mcp-server image
    CONTAINERS=$(docker ps --filter "ancestor=kali-mcp-server" --format "{{.Names}}" 2>&1)
    if [ $? -eq 0 ] && [ -n "$CONTAINERS" ]; then
        CONTAINER_LIST=$(echo "$CONTAINERS" | grep -v '^$' | head -n1)
        if [ -n "$CONTAINER_LIST" ]; then
            echo "$CONTAINER_LIST" | tr -d '[:space:]'
            return 0
        fi
    fi
    
    # Also check by name patterns (Cursor might use different names)
    for pattern in "kali-mcp" "mcp-server"; do
        CONTAINERS=$(docker ps --filter "name=$pattern" --format "{{.Names}}" 2>&1)
        if [ $? -eq 0 ] && [ -n "$CONTAINERS" ]; then
            CONTAINER_LIST=$(echo "$CONTAINERS" | grep -v '^$' | head -n1)
            if [ -n "$CONTAINER_LIST" ]; then
                echo "$CONTAINER_LIST" | tr -d '[:space:]'
                return 0
            fi
        fi
    done
    
    return 1
}

declare -A TEST_RESULTS

# Test 1: Docker Availability
print_header "Test 1: Docker Availability"
if command -v docker &> /dev/null; then
    DOCKER_VERSION=$(docker --version 2>&1)
    if [ $? -eq 0 ]; then
        print_success "Docker is available: $DOCKER_VERSION"
        TEST_RESULTS["Docker Available"]=1
    else
        print_error "Docker is not available"
        TEST_RESULTS["Docker Available"]=0
        print_error "Docker is required for all tests. Please install Docker first."
        exit 1
    fi
else
    print_error "Docker command not found"
    TEST_RESULTS["Docker Available"]=0
    exit 1
fi

# Test 2: Docker Image Existence
print_header "Test 2: Docker Image Existence"
IMAGE_EXISTS=$(docker images kali-mcp-server --format "{{.Repository}}:{{.Tag}}" 2>&1)
if [ $? -eq 0 ] && echo "$IMAGE_EXISTS" | grep -q "kali-mcp-server"; then
    print_success "Docker image exists: $IMAGE_EXISTS"
    TEST_RESULTS["Docker Image Exists"]=1
else
    print_warning "Docker image 'kali-mcp-server' not found"
    print_info "You may need to build the image first:"
    print_info "  docker build -t kali-mcp-server ."
    TEST_RESULTS["Docker Image Exists"]=0
    print_warning "Image not found. Some tests will be skipped."
    exit 0
fi

# Test 3: Container Can Start
print_header "Test 3: Container Can Start"
EXISTING_CONTAINER=$(find_running_container)

if [ -n "$EXISTING_CONTAINER" ]; then
    print_info "Found existing container: $EXISTING_CONTAINER"
    print_info "Testing command execution in existing container..."
    
    OUTPUT=$(docker exec "$EXISTING_CONTAINER" python3 -c "print('Container test successful')" 2>&1)
    
    if [ $? -eq 0 ] && echo "$OUTPUT" | grep -q "Container test successful"; then
        print_success "Existing container '$EXISTING_CONTAINER' can execute commands"
        TEST_RESULTS["Container Can Start"]=1
    else
        print_warning "Existing container found but command execution failed: $OUTPUT"
        print_info "Will try to start a new test container..."
        TEST_RESULTS["Container Can Start"]=0
    fi
else
    print_info "No existing container found. Starting test container..."
fi

# Only try to start new container if existing one didn't work
if [ "${TEST_RESULTS["Container Can Start"]:-0}" -eq 0 ]; then
    # Clean up any existing test container
    docker stop kali-mcp-test 2>/dev/null || true
    docker rm kali-mcp-test 2>/dev/null || true
    
    OUTPUT=$(docker run --rm \
        --name kali-mcp-test \
        --cap-add=NET_RAW \
        --cap-add=NET_ADMIN \
        --memory=2g \
        --cpus=2.0 \
        kali-mcp-server \
        python3 -c "print('Container test successful')" 2>&1)
    
    if [ $? -eq 0 ] && echo "$OUTPUT" | grep -q "Container test successful"; then
        print_success "Container can start and execute commands"
        TEST_RESULTS["Container Can Start"]=1
    else
        print_error "Container failed to start: $OUTPUT"
        TEST_RESULTS["Container Can Start"]=0
    fi
fi

# Test 4: Tools Availability
print_header "Test 4: Tools Availability"
EXISTING_CONTAINER=$(find_running_container)
USE_EXISTING=0

if [ -n "$EXISTING_CONTAINER" ]; then
    print_info "Using existing container: $EXISTING_CONTAINER"
    USE_EXISTING=1
else
    print_info "No existing container found. Will use temporary containers for testing."
fi

TOOLS_TO_TEST=("nmap" "nikto" "sqlmap" "whatweb" "gobuster" "ffuf")
ALL_AVAILABLE=1

for tool in "${TOOLS_TO_TEST[@]}"; do
    if [ $USE_EXISTING -eq 1 ]; then
        OUTPUT=$(docker exec "$EXISTING_CONTAINER" which "$tool" 2>&1)
    else
        OUTPUT=$(docker run --rm \
            --cap-add=NET_RAW \
            --cap-add=NET_ADMIN \
            --memory=2g \
            --cpus=2.0 \
            kali-mcp-server \
            which "$tool" 2>&1)
    fi
    
    if [ $? -eq 0 ] && echo "$OUTPUT" | grep -q "$tool"; then
        print_success "$tool is available"
    else
        print_error "$tool is not available"
        if [ -n "$OUTPUT" ]; then
            print_info "  Output: ${OUTPUT:0:100}"
        fi
        ALL_AVAILABLE=0
    fi
done

TEST_RESULTS["Tools Available"]=$ALL_AVAILABLE

# Test 5: Simple Command Execution
print_header "Test 5: Simple Command Execution"
TEST_COMMAND="echo 'MCP server test'"
EXISTING_CONTAINER=$(find_running_container)

print_info "Testing command execution: $TEST_COMMAND"

if [ -n "$EXISTING_CONTAINER" ]; then
    print_info "Using existing container: $EXISTING_CONTAINER"
    OUTPUT=$(docker exec "$EXISTING_CONTAINER" sh -c "$TEST_COMMAND" 2>&1)
else
    print_info "No existing container found. Using temporary container..."
    OUTPUT=$(docker run --rm \
        --cap-add=NET_RAW \
        --cap-add=NET_ADMIN \
        --memory=2g \
        --cpus=2.0 \
        kali-mcp-server \
        sh -c "$TEST_COMMAND" 2>&1)
fi

if [ $? -eq 0 ] && echo "$OUTPUT" | grep -q "MCP server test"; then
    print_success "Simple command execution works"
    TEST_RESULTS["Simple Command Execution"]=1
else
    print_error "Command execution failed: $OUTPUT"
    TEST_RESULTS["Simple Command Execution"]=0
fi

# Test 6: Nmap Basic Functionality
print_header "Test 6: Nmap Basic Functionality"
EXISTING_CONTAINER=$(find_running_container)

if [ -n "$EXISTING_CONTAINER" ]; then
    print_info "Using existing container: $EXISTING_CONTAINER"
    OUTPUT=$(docker exec "$EXISTING_CONTAINER" nmap --version 2>&1)
else
    print_info "No existing container found. Using temporary container..."
    OUTPUT=$(docker run --rm \
        --cap-add=NET_RAW \
        --cap-add=NET_ADMIN \
        --memory=2g \
        --cpus=2.0 \
        kali-mcp-server \
        nmap --version 2>&1)
fi

if [ $? -eq 0 ] && echo "$OUTPUT" | grep -q "Nmap"; then
    print_success "Nmap is functional"
    print_info "Nmap version info: ${OUTPUT:0:100}"
    TEST_RESULTS["Nmap Basic Functionality"]=1
else
    print_error "Nmap test failed: $OUTPUT"
    TEST_RESULTS["Nmap Basic Functionality"]=0
fi

# Generate Test Report
print_header "Test Report Summary"
TOTAL_TESTS=${#TEST_RESULTS[@]}
PASSED_TESTS=0
FAILED_TESTS=0

for result in "${TEST_RESULTS[@]}"; do
    if [ "$result" -eq 1 ]; then
        ((PASSED_TESTS++))
    else
        ((FAILED_TESTS++))
    fi
done

echo ""
echo "Total Tests: $TOTAL_TESTS"
print_success "Passed: $PASSED_TESTS"
if [ $FAILED_TESTS -gt 0 ]; then
    print_error "Failed: $FAILED_TESTS"
else
    print_success "Failed: 0"
fi

echo ""
echo "Detailed Results:"
for test_name in "${!TEST_RESULTS[@]}"; do
    result=${TEST_RESULTS[$test_name]}
    if [ "$result" -eq 1 ]; then
        echo -e "  ${GREEN}✓ PASS${RESET} - $test_name"
    else
        echo -e "  ${RED}✗ FAIL${RESET} - $test_name"
    fi
done

echo ""
echo "============================================================"

if [ $FAILED_TESTS -eq 0 ]; then
    print_success "All tests passed! MCP server is working correctly."
    exit 0
else
    print_error "Some tests failed. Please review the errors above."
    exit 1
fi

