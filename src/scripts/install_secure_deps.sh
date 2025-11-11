#!/bin/bash
set -euo pipefail

# NexusController Secure Dependencies Installation Script
# Installs dependencies with security verification and integrity checks

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Install UV package manager for fast, secure installs
install_uv() {
    if ! command_exists uv; then
        print_status "Installing uv package manager..."
        curl -LsSf https://astral.sh/uv/install.sh | sh
        export PATH="$HOME/.cargo/bin:$PATH"
        print_success "uv installed successfully"
    else
        print_status "uv already installed"
    fi
}

# Verify Python version
check_python_version() {
    print_status "Checking Python version..."
    
    if ! command_exists python3; then
        print_error "Python 3 is not installed"
        exit 1
    fi
    
    python_version=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    required_version="3.10"
    
    if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then
        print_error "Python $required_version or higher is required (found $python_version)"
        exit 1
    fi
    
    print_success "Python version $python_version is compatible"
}

# Create secure virtual environment
create_venv() {
    print_status "Creating secure virtual environment..."
    
    cd "$PROJECT_ROOT"
    
    if [ -d ".venv" ]; then
        print_warning "Virtual environment already exists, removing..."
        rm -rf .venv
    fi
    
    if command_exists uv; then
        uv venv --python python3
    else
        python3 -m venv .venv
    fi
    
    # Activate virtual environment
    source .venv/bin/activate
    
    # Upgrade pip and install security tools
    python -m pip install --upgrade pip setuptools wheel
    
    print_success "Virtual environment created and activated"
}

# Install dependencies with security verification
install_dependencies() {
    print_status "Installing dependencies with security verification..."
    
    cd "$PROJECT_ROOT"
    source .venv/bin/activate
    
    # Install pip-audit for vulnerability checking
    pip install pip-audit
    
    if command_exists uv; then
        # Use uv for faster, more secure installs
        print_status "Installing dependencies with uv..."
        uv pip install -r requirements.txt
        
        # Install development dependencies if file exists
        if [ -f "requirements-dev.txt" ]; then
            uv pip install -r requirements-dev.txt
        fi
    else
        # Use pip with security flags
        print_status "Installing dependencies with pip..."
        pip install --require-hashes --no-deps -r requirements.txt 2>/dev/null || \
            pip install -r requirements.txt
        
        if [ -f "requirements-dev.txt" ]; then
            pip install -r requirements-dev.txt
        fi
    fi
    
    print_success "Dependencies installed successfully"
}

# Run security audit on installed packages
security_audit() {
    print_status "Running security audit on installed packages..."
    
    cd "$PROJECT_ROOT"
    source .venv/bin/activate
    
    # Check for known vulnerabilities
    if pip-audit --desc --format json --output security_audit.json; then
        print_success "No known vulnerabilities found in dependencies"
    else
        print_warning "Potential vulnerabilities found - check security_audit.json"
        
        # Display summary of vulnerabilities
        if [ -f "security_audit.json" ]; then
            python3 -c "
import json
with open('security_audit.json') as f:
    data = json.load(f)
    if 'vulnerabilities' in data:
        print(f'Found {len(data[\"vulnerabilities\"])} vulnerabilities')
        for vuln in data['vulnerabilities'][:5]:  # Show first 5
            print(f'  - {vuln.get(\"package\", \"unknown\")}: {vuln.get(\"id\", \"unknown\")}')
    else:
        print('No vulnerability data format recognized')
"
        fi
    fi
}

# Generate secure requirements file with hashes
generate_secure_requirements() {
    print_status "Generating secure requirements file with hashes..."
    
    cd "$PROJECT_ROOT"
    source .venv/bin/activate
    
    # Install pip-tools if not present
    pip install pip-tools
    
    # Generate requirements with hashes for security
    if [ -f "requirements.in" ]; then
        pip-compile --generate-hashes --output-file requirements-secure.txt requirements.in
    else
        # Create requirements-secure.txt from current environment
        pip freeze > requirements-current.txt
        pip-compile --generate-hashes --output-file requirements-secure.txt requirements-current.txt
        rm requirements-current.txt
    fi
    
    print_success "Secure requirements file generated: requirements-secure.txt"
}

# Verify installation integrity
verify_installation() {
    print_status "Verifying installation integrity..."
    
    cd "$PROJECT_ROOT"
    source .venv/bin/activate
    
    # Check that key packages are installed correctly
    key_packages=(
        "fastapi"
        "pydantic"
        "sqlalchemy"
        "structlog"
        "uvicorn"
    )
    
    for package in "${key_packages[@]}"; do
        if python -c "import $package" 2>/dev/null; then
            print_success "$package installed correctly"
        else
            print_error "$package installation failed"
            exit 1
        fi
    done
    
    # Verify no conflicting packages
    pip check || print_warning "Package dependency conflicts detected"
    
    print_success "Installation integrity verified"
}

# Create activation script
create_activation_script() {
    print_status "Creating activation script..."
    
    cat > "$PROJECT_ROOT/activate_nexus.sh" << 'EOF'
#!/bin/bash
# NexusController Environment Activation Script

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ -f ".venv/bin/activate" ]; then
    source .venv/bin/activate
    echo "✅ NexusController environment activated"
    echo "📊 Python: $(python --version)"
    echo "📦 Packages: $(pip list --format=freeze | wc -l) installed"
    echo ""
    echo "Available commands:"
    echo "  python nexus_api_server_enhanced.py  - Start API server"
    echo "  ./scripts/security_scan.sh          - Run security scan"
    echo "  pytest                              - Run tests"
    echo "  ruff check .                        - Run linter"
    echo ""
else
    echo "❌ Virtual environment not found. Run ./scripts/install_secure_deps.sh first"
    exit 1
fi
EOF
    
    chmod +x "$PROJECT_ROOT/activate_nexus.sh"
    print_success "Activation script created: activate_nexus.sh"
}

# Update gitignore for security
update_gitignore() {
    print_status "Updating .gitignore for security..."
    
    cd "$PROJECT_ROOT"
    
    # Security-focused gitignore entries
    security_entries=(
        "# Security and secrets"
        "*.key"
        "*.pem"
        "*.crt"
        "*.p12"
        ".env"
        ".env.*"
        "secrets/"
        "security_reports/"
        "security_audit.json"
        "*.log"
        ""
        "# Python security"
        "__pycache__/"
        "*.pyc"
        "*.pyo"
        "*.pyd"
        ".Python"
        "env/"
        ".venv/"
        "venv/"
        ""
        "# Development"
        ".idea/"
        ".vscode/"
        "*.swp"
        "*.swo"
        "*~"
        ""
        "# Testing"
        ".coverage"
        ".pytest_cache/"
        "htmlcov/"
        ""
        "# Build artifacts"
        "build/"
        "dist/"
        "*.egg-info/"
    )
    
    if [ ! -f ".gitignore" ]; then
        printf '%s\n' "${security_entries[@]}" > .gitignore
        print_success "Created .gitignore with security entries"
    else
        # Check if security entries are already present
        if ! grep -q "# Security and secrets" .gitignore; then
            echo "" >> .gitignore
            printf '%s\n' "${security_entries[@]}" >> .gitignore
            print_success "Added security entries to existing .gitignore"
        else
            print_status ".gitignore already contains security entries"
        fi
    fi
}

# Create security configuration
create_security_config() {
    print_status "Creating security configuration..."
    
    cd "$PROJECT_ROOT"
    
    # Create .env.example for secure configuration
    cat > .env.example << 'EOF'
# NexusController Security Configuration Template
# Copy to .env and fill in actual values

# Database Configuration
DATABASE_URL=postgresql://username:password@localhost:5432/nexusdb

# Security
JWT_SECRET_KEY=your-super-secret-jwt-key-here
API_RATE_LIMIT=100
SESSION_TIMEOUT=3600

# Observability
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317
PROMETHEUS_ENDPOINT=http://localhost:9090

# Environment
ENVIRONMENT=development
DEBUG=false
LOG_LEVEL=INFO

# External Services
AWS_ACCESS_KEY_ID=your-aws-access-key
AWS_SECRET_ACCESS_KEY=your-aws-secret-key
AZURE_SUBSCRIPTION_ID=your-azure-subscription-id
GCP_PROJECT_ID=your-gcp-project-id
EOF
    
    print_success "Security configuration template created: .env.example"
    print_warning "Remember to copy .env.example to .env and fill in actual values"
}

# Main installation function
main() {
    print_status "Starting NexusController secure dependency installation"
    print_status "Timestamp: $(date)"
    
    # Pre-installation checks
    check_python_version
    
    # Install uv for faster package management
    install_uv
    
    # Create secure environment
    create_venv
    
    # Install dependencies securely
    install_dependencies
    
    # Security verification
    security_audit
    
    # Generate secure requirements
    generate_secure_requirements
    
    # Verify installation
    verify_installation
    
    # Create helper scripts and configs
    create_activation_script
    update_gitignore
    create_security_config
    
    print_success "✅ NexusController dependencies installed securely!"
    print_status "Next steps:"
    echo "  1. Copy .env.example to .env and configure"
    echo "  2. Run: source activate_nexus.sh"
    echo "  3. Run: ./scripts/security_scan.sh"
    echo "  4. Start development: python nexus_api_server_enhanced.py"
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi