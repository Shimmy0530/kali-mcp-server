#!/bin/bash

# ============================================================================
# Security Assessment Script
# Comprehensive security testing using Kali MCP tools via Docker
# ============================================================================
# Usage: ./security_assessment.sh --target example.com [OPTIONS]
#
# Options:
#   -t, --target TARGET    Target domain (required)
#   -c, --container NAME   Container name (default: kali-mcp-server)
#   -p, --phase PHASE      Run specific phase (recon|network|web|enum|all)
#   -q, --quick            Run quick scans with reduced timeout
#   -o, --output-dir DIR   Output directory (default: ./output)
#   -v, --verbose          Enable verbose output
#   -h, --help             Show this help message
# ============================================================================

set -o pipefail

# Configuration
TARGET=""
CONTAINER="${CONTAINER:-kali-mcp-server}"
OUTPUT_DIR="${OUTPUT_DIR:-./output}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
QUICK_MODE=false
VERBOSE=false
PHASE="all"

# Statistics
TOTAL_SCANS=0
SUCCESSFUL=0
FAILED=0
SKIPPED=0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ============================================================================
# Utility Functions
# ============================================================================

show_help() {
    head -n 17 "$0" | tail -n 14 | sed 's/^# //'
    exit 0
}

log() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo -e "${BLUE}$msg${NC}"
    [ -n "$LOG_FILE" ] && echo "$msg" >> "$LOG_FILE" 2>/dev/null
}

log_success() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] ✓ $1"
    echo -e "${GREEN}$msg${NC}"
    [ -n "$LOG_FILE" ] && echo "$msg" >> "$LOG_FILE" 2>/dev/null
}

log_error() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] ✗ ERROR: $1"
    echo -e "${RED}$msg${NC}"
    [ -n "$LOG_FILE" ] && echo "$msg" >> "$LOG_FILE" 2>/dev/null
}

log_warning() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] ⚠ WARNING: $1"
    echo -e "${YELLOW}$msg${NC}"
    [ -n "$LOG_FILE" ] && echo "$msg" >> "$LOG_FILE" 2>/dev/null
}

log_info() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] ℹ $1"
    echo -e "${CYAN}$msg${NC}"
    [ -n "$LOG_FILE" ] && echo "$msg" >> "$LOG_FILE" 2>/dev/null
}

log_debug() {
    if [ "$VERBOSE" = true ]; then
        local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [DEBUG] $1"
        echo -e "${NC}$msg${NC}"
        [ -n "$LOG_FILE" ] && echo "$msg" >> "$LOG_FILE" 2>/dev/null
    fi
}

# ============================================================================
# Docker/Container Functions
# ============================================================================

check_docker() {
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed or not in PATH"
        return 1
    fi
    
    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running"
        return 1
    fi
    
    log_success "Docker is available"
    return 0
}

check_container() {
    local container_running=$(docker ps --filter "name=$CONTAINER" --format "{{.Names}}" 2>/dev/null)
    
    if [ -n "$container_running" ] && [ "$container_running" = "$CONTAINER" ]; then
        log_success "Container '$CONTAINER' is running"
        return 0
    fi
    
    # Check alternative names
    for alt_name in "kali-mcp-server-detached" "kali-mcp"; do
        container_running=$(docker ps --filter "name=$alt_name" --format "{{.Names}}" 2>/dev/null)
        if [ -n "$container_running" ]; then
            CONTAINER="$alt_name"
            log_success "Found running container: $CONTAINER"
            return 0
        fi
    done
    
    log_error "Container '$CONTAINER' is not running"
    return 1
}

start_container() {
    log "Attempting to start container..."
    
    # Try to start existing container
    if docker start "$CONTAINER" &> /dev/null; then
        sleep 3
        if check_container; then
            return 0
        fi
    fi
    
    # Try docker-compose
    if command -v docker-compose &> /dev/null; then
        log "Running docker-compose..."
        docker-compose up -d &> /dev/null
        sleep 5
        if check_container; then
            return 0
        fi
    fi
    
    log_error "Failed to start container"
    return 1
}

# ============================================================================
# Tool Execution Functions
# ============================================================================

run_tool() {
    local tool_name="$1"
    local category="$2"
    local command="$3"
    local timeout="${4:-300}"
    
    local scans_dir="$OUTPUT_DIR/scans/$category"
    mkdir -p "$scans_dir"
    local output_file="$scans_dir/${tool_name}_${TIMESTAMP}.txt"
    local start_time=$(date +%s)
    
    log_info "Running $tool_name..."
    log_debug "Command: $command"
    
    TOTAL_SCANS=$((TOTAL_SCANS + 1))
    
    # Create output file with header
    cat > "$output_file" << EOF
================================================================================
$tool_name Scan Results
================================================================================
Target: $TARGET
Timestamp: $(date)
Command: $command
================================================================================

EOF

    # Run the tool in container with timeout
    local exit_code=0
    local output=""
    
    output=$(timeout "$timeout" docker exec "$CONTAINER" sh -c "$command" 2>&1) || exit_code=$?
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    # Append output to file
    echo "$output" >> "$output_file"
    
    # Append footer
    cat >> "$output_file" << EOF

================================================================================
Scan completed in ${duration}s
Exit code: $exit_code
================================================================================
EOF
    
    if [ $exit_code -eq 0 ]; then
        log_success "$tool_name completed in ${duration}s"
        SUCCESSFUL=$((SUCCESSFUL + 1))
        return 0
    elif [ $exit_code -eq 124 ]; then
        log_warning "$tool_name timed out after ${timeout}s"
        FAILED=$((FAILED + 1))
        return 124
    else
        log_error "$tool_name failed with exit code $exit_code"
        FAILED=$((FAILED + 1))
        return $exit_code
    fi
}

# ============================================================================
# Phase Functions
# ============================================================================

phase_recon() {
    log ""
    log "${BOLD}============================================================${NC}"
    log "${BOLD}PHASE 1: Information Gathering & Reconnaissance${NC}"
    log "${BOLD}============================================================${NC}"
    
    local timeout_short=60
    local timeout_med=180
    local timeout_long=300
    
    if [ "$QUICK_MODE" = true ]; then
        timeout_short=30
        timeout_med=60
        timeout_long=180
    fi
    
    # Extract base domain for DNS tools
    local dns_target=$(echo "$TARGET" | sed 's/.*\.\([^.]*\.[^.]*\)$/\1/')
    
    # WhatWeb
    run_tool "whatweb" "recon" \
        "whatweb --no-errors https://$TARGET" \
        "$timeout_short"
    
    # theHarvester
    run_tool "theharvester" "recon" \
        "theHarvester -d $dns_target -b all -l 500" \
        "$timeout_med"
    
    # DNS enumeration
    run_tool "dnsenum" "recon" \
        "dnsenum $dns_target" \
        "$timeout_long"
    
    run_tool "dnsrecon" "recon" \
        "dnsrecon -d $dns_target" \
        "$timeout_med"
    
    # Initial nmap scan
    run_tool "nmap_quick" "recon" \
        "nmap -sV --top-ports 100 $TARGET" \
        "$timeout_med"
    
    log_success "Phase 1 (Reconnaissance) completed"
}

phase_network() {
    log ""
    log "${BOLD}============================================================${NC}"
    log "${BOLD}PHASE 2: Network Security Testing${NC}"
    log "${BOLD}============================================================${NC}"
    
    local timeout=300
    if [ "$QUICK_MODE" = true ]; then
        timeout=120
    fi
    
    # Full nmap scan
    run_tool "nmap" "network" \
        "nmap -sV -O --top-ports 1000 $TARGET" \
        "$timeout"
    
    log_success "Phase 2 (Network) completed"
}

phase_web() {
    log ""
    log "${BOLD}============================================================${NC}"
    log "${BOLD}PHASE 3: Web Application Security Testing${NC}"
    log "${BOLD}============================================================${NC}"
    
    local timeout_short=180
    local timeout_med=300
    local timeout_long=360
    
    if [ "$QUICK_MODE" = true ]; then
        timeout_short=120
        timeout_med=180
        timeout_long=240
    fi
    
    # Nikto - tool max time should be slightly less than script timeout
    local nikto_maxtime=300
    if [ "$QUICK_MODE" = true ]; then
        nikto_maxtime=180
    fi
    
    # Nikto
    run_tool "nikto" "web" \
        "nikto -h https://$TARGET -maxtime $nikto_maxtime" \
        "$timeout_long"
    
    # Wapiti
    run_tool "wapiti" "web" \
        "wapiti -u https://$TARGET --scope folder --max-scan-time 180" \
        "$timeout_med"
    
    # SQLMap
    run_tool "sqlmap" "web" \
        "sqlmap -u https://$TARGET --batch --crawl=1 --timeout=30 --threads=1" \
        "$timeout_med"
    
    # XSS scanners
    run_tool "xsser" "web" \
        "xsser -u https://$TARGET -c 100 --Cl" \
        "$timeout_short"
    
    # Commix
    run_tool "commix" "web" \
        "commix -u https://$TARGET --batch" \
        "$timeout_short"
    
    log_success "Phase 3 (Web) completed"
}

phase_enumeration() {
    log ""
    log "${BOLD}============================================================${NC}"
    log "${BOLD}PHASE 4: Directory & File Discovery${NC}"
    log "${BOLD}============================================================${NC}"
    
    local timeout=300
    if [ "$QUICK_MODE" = true ]; then
        timeout=180
    fi
    
    # Dirb
    run_tool "dirb" "enumeration" \
        "dirb https://$TARGET /usr/share/wordlists/dirb/common.txt -r" \
        "$timeout"
    
    # Gobuster
    run_tool "gobuster" "enumeration" \
        "gobuster dir -u https://$TARGET -w /usr/share/wordlists/dirb/common.txt -t 20 --timeout 10s" \
        "$timeout"
    
    # FFUF
    run_tool "ffuf" "enumeration" \
        "ffuf -u https://$TARGET/FUZZ -w /usr/share/wordlists/dirb/common.txt -t 40 -timeout 10 -maxtime 120" \
        "$timeout"
    
    log_success "Phase 4 (Enumeration) completed"
}

# ============================================================================
# Report Generation
# ============================================================================

generate_report() {
    local reports_dir="$OUTPUT_DIR/reports"
    mkdir -p "$reports_dir"
    local report_file="$reports_dir/scan_report_${TIMESTAMP}.md"
    
    cat > "$report_file" << EOF
# Security Assessment Report

## Target: $TARGET
## Date: $(date)

---

## Summary

| Metric | Value |
|--------|-------|
| Total Scans | $TOTAL_SCANS |
| Successful | $SUCCESSFUL |
| Failed | $FAILED |
| Skipped | $SKIPPED |

---

## Scan Results

EOF

    for category in recon network web enumeration; do
        local scan_dir="$OUTPUT_DIR/scans/$category"
        if [ -d "$scan_dir" ]; then
            echo "### $category" >> "$report_file"
            echo "" >> "$report_file"
            for file in "$scan_dir"/*_${TIMESTAMP}.txt; do
                if [ -f "$file" ]; then
                    echo "- $(basename "$file")" >> "$report_file"
                fi
            done
            echo "" >> "$report_file"
        fi
    done

    cat >> "$report_file" << EOF

---

## Recommendations

1. Review all findings and prioritize based on severity
2. Verify any potential vulnerabilities manually
3. Implement fixes for confirmed issues
4. Re-test after remediation

---

*Report generated by Security Assessment Script*
EOF

    log_success "Report generated: $report_file"
}

print_summary() {
    echo ""
    echo -e "${BOLD}============================================================${NC}"
    echo -e "${BOLD}SECURITY ASSESSMENT SUMMARY${NC}"
    echo -e "${BOLD}============================================================${NC}"
    echo -e "Target:      $TARGET"
    echo -e "Container:   $CONTAINER"
    echo -e "Timestamp:   $TIMESTAMP"
    echo ""
    echo -e "Total Scans: $TOTAL_SCANS"
    echo -e "${GREEN}Successful:  $SUCCESSFUL${NC}"
    echo -e "${RED}Failed:      $FAILED${NC}"
    echo -e "${YELLOW}Skipped:     $SKIPPED${NC}"
    echo ""
    echo -e "Output:      $OUTPUT_DIR"
    echo -e "${BOLD}============================================================${NC}"
}

# ============================================================================
# Main Execution
# ============================================================================

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -t|--target)
                TARGET="$2"
                shift 2
                ;;
            -c|--container)
                CONTAINER="$2"
                shift 2
                ;;
            -p|--phase)
                PHASE="$2"
                shift 2
                ;;
            -o|--output-dir)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -q|--quick)
                QUICK_MODE=true
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                show_help
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                ;;
        esac
    done
    
    if [ -z "$TARGET" ]; then
        log_error "Target is required. Use -t or --target"
        show_help
    fi
}

main() {
    parse_args "$@"
    
    # Remove protocol from target if present
    TARGET=$(echo "$TARGET" | sed 's|https\?://||' | sed 's|/$||')
    
    # Setup directories
    mkdir -p "$OUTPUT_DIR/scans"/{network,web,enumeration,recon}
    mkdir -p "$OUTPUT_DIR/reports"
    mkdir -p "$OUTPUT_DIR/logs"
    
    LOG_FILE="$OUTPUT_DIR/logs/assessment_${TIMESTAMP}.log"
    
    log "${BOLD}============================================================${NC}"
    log "${BOLD}Starting Security Assessment${NC}"
    log "${BOLD}============================================================${NC}"
    log "Target: $TARGET"
    log "Container: $CONTAINER"
    log "Quick Mode: $QUICK_MODE"
    log "Phase: $PHASE"
    log "Output: $OUTPUT_DIR"
    
    # Check prerequisites
    if ! check_docker; then
        exit 1
    fi
    
    if ! check_container; then
        log_warning "Container not running, attempting to start..."
        if ! start_container; then
            exit 1
        fi
    fi
    
    # Run phases
    case $PHASE in
        recon)
            phase_recon
            ;;
        network)
            phase_network
            ;;
        web)
            phase_web
            ;;
        enum|enumeration)
            phase_enumeration
            ;;
        all|*)
            phase_recon
            phase_network
            phase_web
            phase_enumeration
            ;;
    esac
    
    # Generate report and summary
    generate_report
    print_summary
    
    log_success "Security assessment completed"
    
    if [ $FAILED -gt 0 ]; then
        exit 1
    fi
    exit 0
}

main "$@"

