#!/bin/bash

# ============================================================================
# Run Assessment - Master Orchestration Script
# ============================================================================
# Runs all security test phases and generates final report.
# Orchestrates both custom Python tests and MCP-based Kali tool scans.
#
# Usage: ./run_assessment.sh --target example.com [OPTIONS]
#
# Options:
#   -t, --target TARGET    Target domain (required)
#   -o, --output-dir DIR   Output directory (default: ./output)
#   -q, --quick            Run in quick mode (reduced timeouts)
#   -s, --skip-mcp         Skip MCP-based tests (run custom tests only)
#   -v, --verbose          Enable verbose output
#   -h, --help             Show this help message
# ============================================================================

set -o pipefail

# Configuration
TARGET=""
OUTPUT_DIR="${OUTPUT_DIR:-./output}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
QUICK_MODE=false
SKIP_MCP=false
VERBOSE=false

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Exit codes
EXIT_SUCCESS=0
EXIT_DOCKER_ERROR=1
EXIT_PYTHON_ERROR=2
EXIT_TEST_FAILED=3

# Colors
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

# ============================================================================
# Parse Arguments
# ============================================================================

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -t|--target)
                TARGET="$2"
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
            -s|--skip-mcp)
                SKIP_MCP=true
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

# ============================================================================
# Check Prerequisites
# ============================================================================

check_python() {
    if command -v python3 &> /dev/null; then
        local version=$(python3 --version 2>&1)
        log_success "Python available: $version"
        return 0
    elif command -v python &> /dev/null; then
        local version=$(python --version 2>&1)
        if [[ $version == *"3."* ]]; then
            log_success "Python available: $version"
            alias python3=python
            return 0
        fi
    fi
    log_error "Python 3 is required but not found"
    return 1
}

check_docker() {
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed"
        return 1
    fi
    
    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running"
        return 1
    fi
    
    log_success "Docker is available"
    return 0
}

# ============================================================================
# Test Phases
# ============================================================================

run_custom_tests() {
    log ""
    log "${BOLD}============================================================${NC}"
    log "${BOLD}PHASE 1: Custom Python Security Tests${NC}"
    log "${BOLD}============================================================${NC}"
    
    local target_url="https://${TARGET}"
    
    if python3 "$SCRIPT_DIR/custom_security_tests.py" \
        --target "$target_url" \
        --output-dir "$OUTPUT_DIR" 2>&1 | tee -a "$LOG_FILE"; then
        log_success "Custom Python tests completed successfully"
        return 0
    else
        log_warning "Custom Python tests completed with warnings or errors"
        return 1
    fi
}

check_mcp_server() {
    log ""
    log "${BOLD}============================================================${NC}"
    log "${BOLD}PHASE 2: MCP Server Health Check${NC}"
    log "${BOLD}============================================================${NC}"
    
    if python3 "$SCRIPT_DIR/check_mcp_server.py" \
        --auto-start \
        --output-dir "$OUTPUT_DIR" 2>&1 | tee -a "$LOG_FILE"; then
        log_success "MCP server is running and healthy"
        return 0
    else
        log_error "MCP server is not available"
        return 1
    fi
}

run_mcp_tests() {
    log ""
    log "${BOLD}============================================================${NC}"
    log "${BOLD}PHASE 3: MCP-Based Security Tests (Kali Tools)${NC}"
    log "${BOLD}============================================================${NC}"
    
    local args="--target $TARGET --output-dir $OUTPUT_DIR"
    if [ "$QUICK_MODE" = true ]; then
        args="$args --timeout 180"
    fi
    
    if python3 "$SCRIPT_DIR/mcp_security_tests.py" $args 2>&1 | tee -a "$LOG_FILE"; then
        log_success "MCP-based tests completed successfully"
        return 0
    else
        log_warning "MCP-based tests completed with some failures"
        return 1
    fi
}

run_shell_tests() {
    log ""
    log "${BOLD}============================================================${NC}"
    log "${BOLD}PHASE 4: Shell-Based Security Tests${NC}"
    log "${BOLD}============================================================${NC}"
    
    local args="--target $TARGET --output-dir $OUTPUT_DIR"
    if [ "$QUICK_MODE" = true ]; then
        args="$args --quick"
    fi
    if [ "$VERBOSE" = true ]; then
        args="$args --verbose"
    fi
    
    if bash "$SCRIPT_DIR/security_assessment.sh" $args 2>&1 | tee -a "$LOG_FILE"; then
        log_success "Shell-based tests completed successfully"
        return 0
    else
        log_warning "Shell-based tests completed with some failures"
        return 1
    fi
}

# ============================================================================
# Generate Final Report
# ============================================================================

generate_final_report() {
    local reports_dir="$OUTPUT_DIR/reports"
    mkdir -p "$reports_dir"
    local report_file="$reports_dir/final_assessment_${TIMESTAMP}.md"
    
    log ""
    log "${BOLD}Generating final assessment report...${NC}"
    
    cat > "$report_file" << EOF
# Comprehensive Security Assessment Report

## Target: $TARGET
## Assessment Date: $(date)
## Assessment ID: $TIMESTAMP

---

## Executive Summary

This report contains the results of a comprehensive security assessment 
performed against $TARGET using multiple testing methodologies:

1. **Custom Python Tests** - Application-level security testing
2. **Kali MCP Tools** - Industry-standard security scanning tools

---

## Test Phases Executed

EOF

    # List all generated reports
    echo "### Reports Generated" >> "$report_file"
    echo "" >> "$report_file"
    
    for report in "$reports_dir"/*.json "$reports_dir"/*.md; do
        if [ -f "$report" ] && [ "$report" != "$report_file" ]; then
            echo "- $(basename "$report")" >> "$report_file"
        fi
    done 2>/dev/null
    
    echo "" >> "$report_file"
    echo "### Scan Output Files" >> "$report_file"
    echo "" >> "$report_file"
    
    for category in recon network web enumeration; do
        local scan_dir="$OUTPUT_DIR/scans/$category"
        if [ -d "$scan_dir" ]; then
            local files=$(find "$scan_dir" -name "*.txt" -type f 2>/dev/null | wc -l)
            if [ "$files" -gt 0 ]; then
                echo "- **$category**: $files scan files" >> "$report_file"
            fi
        fi
    done

    cat >> "$report_file" << EOF

---

## Recommendations

1. **Review All Findings**: Carefully review each finding in the detailed reports
2. **Prioritize by Severity**: Address HIGH and CRITICAL findings first
3. **Verify Vulnerabilities**: Manually verify potential vulnerabilities before remediation
4. **Implement Fixes**: Apply security patches and configuration changes
5. **Re-test**: Perform follow-up testing after remediation

---

## Files and Directories

- **Scan Results**: \`$OUTPUT_DIR/scans/\`
- **Reports**: \`$reports_dir\`
- **Log File**: \`$LOG_FILE\`

---

*This report was automatically generated by the Security Assessment Suite*
*Assessment completed: $(date)*
EOF

    log_success "Final report generated: $report_file"
    echo "$report_file"
}

# ============================================================================
# Print Summary
# ============================================================================

print_summary() {
    local phase1_status=$1
    local phase2_status=$2
    local phase3_status=$3
    local phase4_status=$4
    
    echo ""
    echo -e "${BOLD}============================================================${NC}"
    echo -e "${BOLD}SECURITY ASSESSMENT COMPLETE${NC}"
    echo -e "${BOLD}============================================================${NC}"
    echo -e "Target:      $TARGET"
    echo -e "Timestamp:   $TIMESTAMP"
    echo ""
    echo -e "${BOLD}Phase Results:${NC}"
    
    local phases=("Custom Python Tests" "MCP Server Check" "MCP-Based Tests" "Shell-Based Tests")
    local statuses=($phase1_status $phase2_status $phase3_status $phase4_status)
    
    for i in "${!phases[@]}"; do
        local status="${statuses[$i]}"
        if [ "$status" = "0" ]; then
            echo -e "  ${GREEN}✓${NC} ${phases[$i]}: Passed"
        elif [ "$status" = "skipped" ]; then
            echo -e "  ${YELLOW}○${NC} ${phases[$i]}: Skipped"
        else
            echo -e "  ${RED}✗${NC} ${phases[$i]}: Failed/Warnings"
        fi
    done
    
    echo ""
    echo -e "${BOLD}Output Locations:${NC}"
    echo -e "  Reports:  $OUTPUT_DIR/reports"
    echo -e "  Scans:    $OUTPUT_DIR/scans"
    echo -e "  Logs:     $OUTPUT_DIR/logs"
    echo -e "${BOLD}============================================================${NC}"
}

# ============================================================================
# Main Execution
# ============================================================================

main() {
    parse_args "$@"
    
    # Remove protocol from target if present
    TARGET=$(echo "$TARGET" | sed 's|https\?://||' | sed 's|/$||')
    
    # Create directories
    mkdir -p "$OUTPUT_DIR/scans"/{network,web,enumeration,recon}
    mkdir -p "$OUTPUT_DIR/reports"
    mkdir -p "$OUTPUT_DIR/logs"
    
    LOG_FILE="$OUTPUT_DIR/logs/full_assessment_${TIMESTAMP}.log"
    
    # Initialize log file
    echo "============================================" > "$LOG_FILE"
    echo "Security Assessment Log" >> "$LOG_FILE"
    echo "Started: $(date)" >> "$LOG_FILE"
    echo "Target: $TARGET" >> "$LOG_FILE"
    echo "============================================" >> "$LOG_FILE"
    
    log "${BOLD}============================================================${NC}"
    log "${BOLD}Comprehensive Security Assessment${NC}"
    log "${BOLD}============================================================${NC}"
    log "Target: $TARGET"
    log "Mode: $([ "$QUICK_MODE" = true ] && echo "Quick" || echo "Full")"
    log "Output: $OUTPUT_DIR"
    log ""
    
    # Track phase results
    local phase1_status="skipped"
    local phase2_status="skipped"
    local phase3_status="skipped"
    local phase4_status="skipped"
    
    # Check Python availability
    if ! check_python; then
        log_error "Python 3 is required. Please install Python 3 and try again."
        exit $EXIT_PYTHON_ERROR
    fi
    
    # Phase 1: Custom Python Tests
    run_custom_tests
    phase1_status=$?
    
    # Check if MCP tests should be skipped
    if [ "$SKIP_MCP" = true ]; then
        log_info "Skipping MCP-based tests as requested"
        phase2_status="skipped"
        phase3_status="skipped"
        phase4_status="skipped"
    else
        # Check Docker availability
        if ! check_docker; then
            log_warning "Docker not available, skipping MCP-based tests"
            phase2_status="skipped"
            phase3_status="skipped"
            phase4_status="skipped"
        else
            # Phase 2: MCP Server Health Check
            check_mcp_server
            phase2_status=$?
            
            if [ "$phase2_status" = "0" ]; then
                # Phase 3: MCP-Based Tests
                run_mcp_tests
                phase3_status=$?
                
                # Phase 4: Shell-Based Tests
                run_shell_tests
                phase4_status=$?
            else
                log_warning "MCP server not available, skipping MCP-based tests"
                log_info "You can start the MCP server with: ./run-docker.sh"
                phase3_status="skipped"
                phase4_status="skipped"
            fi
        fi
    fi
    
    # Generate final report
    generate_final_report
    
    # Print summary
    print_summary "$phase1_status" "$phase2_status" "$phase3_status" "$phase4_status"
    
    log_success "Assessment completed! Review the reports in $OUTPUT_DIR/reports"
    
    # Exit with appropriate code
    if [ "$phase1_status" != "0" ] && [ "$phase1_status" != "skipped" ]; then
        exit $EXIT_TEST_FAILED
    fi
    
    exit $EXIT_SUCCESS
}

main "$@"

