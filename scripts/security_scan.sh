#!/bin/bash
set -euo pipefail

# NexusController Security Scanning Script
# Comprehensive security analysis and vulnerability assessment

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
REPORTS_DIR="$PROJECT_ROOT/security_reports"
DATE=$(date +%Y%m%d_%H%M%S)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PYTHON_VERSION="3.11"
SEVERITY_THRESHOLD="MEDIUM"
FAIL_ON_HIGH=true

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install tools if not present
install_security_tools() {
    print_status "Installing security scanning tools..."
    
    # Update pip
    python -m pip install --upgrade pip
    
    # Install security tools
    pip install safety bandit semgrep pip-audit cyclonedx-bom detect-secrets
    
    # Install Trivy if not present
    if ! command_exists trivy; then
        print_status "Installing Trivy..."
        curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v0.48.0
    fi
    
    # Install Syft for SBOM generation
    if ! command_exists syft; then
        print_status "Installing Syft..."
        curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
    fi
    
    print_success "Security tools installed successfully"
}

# Function to create reports directory
setup_reports_directory() {
    mkdir -p "$REPORTS_DIR"
    print_status "Reports will be saved to: $REPORTS_DIR"
}

# Function to run dependency vulnerability scan
scan_dependencies() {
    print_status "Running dependency vulnerability scans..."
    
    # Safety check
    print_status "Running Safety check for Python vulnerabilities..."
    if safety check --json --output "$REPORTS_DIR/safety_report_${DATE}.json" 2>/dev/null; then
        print_success "Safety scan completed - no vulnerabilities found"
    else
        print_warning "Safety scan found potential vulnerabilities - check report"
    fi
    
    # pip-audit check
    print_status "Running pip-audit for package vulnerabilities..."
    if pip-audit --format json --output "$REPORTS_DIR/pip_audit_report_${DATE}.json" 2>/dev/null; then
        print_success "pip-audit scan completed - no vulnerabilities found"
    else
        print_warning "pip-audit found potential vulnerabilities - check report"
    fi
    
    # Generate requirements with hashes for security
    print_status "Generating secure requirements file..."
    pip-compile --generate-hashes --output-file "$REPORTS_DIR/requirements_secure_${DATE}.txt" requirements.txt 2>/dev/null || true
}

# Function to run static code analysis
scan_code_security() {
    print_status "Running static code security analysis..."
    
    # Bandit security linter
    print_status "Running Bandit security linter..."
    bandit -r "$PROJECT_ROOT" -f json -o "$REPORTS_DIR/bandit_report_${DATE}.json" \
        -x "$PROJECT_ROOT/.venv,$PROJECT_ROOT/tests,$PROJECT_ROOT/build" \
        --severity-level low 2>/dev/null || print_warning "Bandit found potential security issues"
    
    # Semgrep security analysis
    print_status "Running Semgrep security analysis..."
    if command_exists semgrep; then
        cd "$PROJECT_ROOT"
        semgrep --config=auto --json --output="$REPORTS_DIR/semgrep_report_${DATE}.json" . 2>/dev/null || \
            print_warning "Semgrep found potential security issues"
    else
        print_warning "Semgrep not available, skipping analysis"
    fi
    
    # Detect secrets
    print_status "Scanning for secrets in code..."
    if command_exists detect-secrets; then
        cd "$PROJECT_ROOT"
        detect-secrets scan --all-files --baseline "$REPORTS_DIR/secrets_baseline_${DATE}.json" 2>/dev/null || \
            print_warning "Potential secrets detected"
    fi
}

# Function to run filesystem scan
scan_filesystem() {
    print_status "Running filesystem vulnerability scan..."
    
    if command_exists trivy; then
        trivy fs --security-checks vuln,secret,config \
            --severity "$SEVERITY_THRESHOLD,HIGH,CRITICAL" \
            --format json \
            --output "$REPORTS_DIR/trivy_fs_report_${DATE}.json" \
            "$PROJECT_ROOT" 2>/dev/null || print_warning "Trivy filesystem scan found issues"
        
        print_success "Trivy filesystem scan completed"
    else
        print_warning "Trivy not available, skipping filesystem scan"
    fi
}

# Function to scan Docker image if Dockerfile exists
scan_container() {
    if [[ -f "$PROJECT_ROOT/Dockerfile" ]]; then
        print_status "Docker configuration found, scanning container security..."
        
        # Build image for scanning
        DOCKER_IMAGE="nexuscontroller-security-scan:latest"
        docker build -t "$DOCKER_IMAGE" "$PROJECT_ROOT" > /dev/null 2>&1 || {
            print_error "Failed to build Docker image for scanning"
            return 1
        }
        
        # Trivy container scan
        if command_exists trivy; then
            trivy image --security-checks vuln,secret,config \
                --severity "$SEVERITY_THRESHOLD,HIGH,CRITICAL" \
                --format json \
                --output "$REPORTS_DIR/trivy_container_report_${DATE}.json" \
                "$DOCKER_IMAGE" 2>/dev/null || print_warning "Container vulnerabilities found"
        fi
        
        # Clean up image
        docker rmi "$DOCKER_IMAGE" > /dev/null 2>&1 || true
        
        print_success "Container security scan completed"
    else
        print_status "No Dockerfile found, skipping container scan"
    fi
}

# Function to generate SBOM
generate_sbom() {
    print_status "Generating Software Bill of Materials (SBOM)..."
    
    # Python SBOM using cyclonedx
    if command_exists cyclonedx-py; then
        cd "$PROJECT_ROOT"
        cyclonedx-py -o "$REPORTS_DIR/sbom_python_${DATE}.json" --format json 2>/dev/null || \
            print_warning "Failed to generate Python SBOM"
    fi
    
    # Comprehensive SBOM using Syft
    if command_exists syft; then
        syft packages dir:"$PROJECT_ROOT" -o json > "$REPORTS_DIR/sbom_comprehensive_${DATE}.json" 2>/dev/null || \
            print_warning "Failed to generate comprehensive SBOM"
    fi
    
    print_success "SBOM generation completed"
}

# Function to check compliance
check_compliance() {
    print_status "Running compliance checks..."
    
    # Check for required security files
    security_files=(
        "SECURITY.md"
        ".gitignore"
        "requirements.txt"
        "pyproject.toml"
    )
    
    missing_files=()
    for file in "${security_files[@]}"; do
        if [[ ! -f "$PROJECT_ROOT/$file" ]]; then
            missing_files+=("$file")
        fi
    done
    
    if [[ ${#missing_files[@]} -gt 0 ]]; then
        print_warning "Missing recommended security files: ${missing_files[*]}"
    else
        print_success "All recommended security files present"
    fi
    
    # Check for secure coding practices
    print_status "Checking secure coding practices..."
    
    # Check for hardcoded secrets patterns
    secret_patterns=(
        "password\s*=\s*['\"][^'\"]*['\"]"
        "api_key\s*=\s*['\"][^'\"]*['\"]"
        "secret\s*=\s*['\"][^'\"]*['\"]"
        "token\s*=\s*['\"][^'\"]*['\"]"
    )
    
    violations=0
    for pattern in "${secret_patterns[@]}"; do
        if grep -r -i -E "$pattern" "$PROJECT_ROOT" --include="*.py" --exclude-dir=".venv" --exclude-dir="tests" > /dev/null 2>&1; then
            ((violations++))
        fi
    done
    
    if [[ $violations -gt 0 ]]; then
        print_warning "Found $violations potential hardcoded credential patterns"
    else
        print_success "No hardcoded credential patterns detected"
    fi
}

# Function to run license compliance check
check_licenses() {
    print_status "Checking license compliance..."
    
    # Generate license report
    pip-licenses --format json --output-file "$REPORTS_DIR/licenses_${DATE}.json" 2>/dev/null || \
        print_warning "Failed to generate license report"
    
    # Check for potentially problematic licenses
    problematic_licenses=("GPL" "AGPL" "SSPL")
    
    if [[ -f "$REPORTS_DIR/licenses_${DATE}.json" ]]; then
        for license in "${problematic_licenses[@]}"; do
            if grep -q "$license" "$REPORTS_DIR/licenses_${DATE}.json"; then
                print_warning "Found potentially problematic license: $license"
            fi
        done
    fi
    
    print_success "License compliance check completed"
}

# Function to analyze results and generate summary
analyze_results() {
    print_status "Analyzing security scan results..."
    
    # Create summary report
    summary_file="$REPORTS_DIR/security_summary_${DATE}.md"
    
    cat > "$summary_file" << EOF
# NexusController Security Scan Summary

**Scan Date:** $(date)
**Scan ID:** ${DATE}

## Scan Coverage

- ✅ Dependency Vulnerabilities (Safety, pip-audit)
- ✅ Static Code Analysis (Bandit, Semgrep)
- ✅ Secret Detection
- ✅ Filesystem Vulnerabilities (Trivy)
- ✅ Container Security (if applicable)
- ✅ Software Bill of Materials (SBOM)
- ✅ Compliance Checks
- ✅ License Analysis

## Report Files Generated

EOF
    
    # List all generated reports
    for report in "$REPORTS_DIR"/*"${DATE}"*; do
        if [[ -f "$report" ]]; then
            echo "- $(basename "$report")" >> "$summary_file"
        fi
    done
    
    echo "" >> "$summary_file"
    echo "## Recommendations" >> "$summary_file"
    echo "" >> "$summary_file"
    echo "1. Review all HIGH and CRITICAL severity findings immediately" >> "$summary_file"
    echo "2. Update vulnerable dependencies to latest secure versions" >> "$summary_file"
    echo "3. Address any detected secrets or hardcoded credentials" >> "$summary_file"
    echo "4. Implement additional security controls as needed" >> "$summary_file"
    echo "5. Schedule regular security scans (recommended: weekly)" >> "$summary_file"
    
    print_success "Security summary generated: $summary_file"
}

# Function to cleanup old reports
cleanup_old_reports() {
    print_status "Cleaning up old reports (keeping last 10)..."
    
    # Keep only the 10 most recent reports of each type
    find "$REPORTS_DIR" -name "*_report_*.json" -type f | \
        sort -r | tail -n +11 | xargs -r rm -f
    
    find "$REPORTS_DIR" -name "*_summary_*.md" -type f | \
        sort -r | tail -n +6 | xargs -r rm -f
}

# Function to send notifications (placeholder)
send_notifications() {
    print_status "Security scan completed successfully"
    
    # In production, you could send notifications to:
    # - Slack channels
    # - Email lists
    # - SIEM systems
    # - Security dashboards
    
    # Example Slack notification (requires webhook URL)
    # if [[ -n "${SLACK_WEBHOOK_URL:-}" ]]; then
    #     curl -X POST -H 'Content-type: application/json' \
    #         --data '{"text":"NexusController security scan completed"}' \
    #         "$SLACK_WEBHOOK_URL"
    # fi
}

# Main execution function
main() {
    print_status "Starting NexusController Security Scan"
    print_status "Timestamp: $(date)"
    
    # Change to project root
    cd "$PROJECT_ROOT"
    
    # Setup
    setup_reports_directory
    
    # Install tools if needed
    if [[ "${INSTALL_TOOLS:-true}" == "true" ]]; then
        install_security_tools
    fi
    
    # Run security scans
    scan_dependencies || print_error "Dependency scan failed"
    scan_code_security || print_error "Code security scan failed"
    scan_filesystem || print_error "Filesystem scan failed"
    scan_container || print_warning "Container scan failed or skipped"
    generate_sbom || print_warning "SBOM generation failed"
    check_compliance || print_warning "Compliance check had issues"
    check_licenses || print_warning "License check failed"
    
    # Analyze and report
    analyze_results
    cleanup_old_reports
    send_notifications
    
    print_success "Security scan completed successfully!"
    print_status "Reports saved to: $REPORTS_DIR"
    
    # Exit with appropriate code based on findings
    if [[ "$FAIL_ON_HIGH" == "true" ]]; then
        # Check if any HIGH or CRITICAL issues were found
        if find "$REPORTS_DIR" -name "*${DATE}*" -exec grep -l "HIGH\|CRITICAL" {} \; | grep -q .; then
            print_error "HIGH or CRITICAL security issues found!"
            exit 1
        fi
    fi
    
    exit 0
}

# Script execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi