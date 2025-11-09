#!/bin/bash
################################################################################
# DeepEval Fuzzing Setup Script for macOS
################################################################################
#
# This script sets up the complete fuzzing environment for DeepEval on macOS.
#
# What it does:
# 1. Checks for required tools (Python, pip, git)
# 2. Creates a virtual environment
# 3. Installs DeepEval and dependencies
# 4. Installs fuzzing tools (Atheris, Hypothesis)
# 5. Sets up corpus directories with sample data
# 6. Verifies the installation
#
# Usage:
#   chmod +x deploy_macos.sh
#   ./deploy_macos.sh
#
################################################################################

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

################################################################################
# Helper Functions
################################################################################

print_header() {
    echo -e "\n${BOLD}${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${CYAN}  $1${NC}"
    echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════════${NC}\n"
}

print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

check_command() {
    if command -v $1 &> /dev/null; then
        print_success "$1 is installed"
        return 0
    else
        print_error "$1 is not installed"
        return 1
    fi
}

################################################################################
# Main Installation
################################################################################

print_header "🔍 DeepEval Fuzzing Setup for macOS"

# Check OS
if [[ "$OSTYPE" != "darwin"* ]]; then
    print_warning "This script is designed for macOS. Detected: $OSTYPE"
    print_info "The script will continue, but some steps might need adjustment."
fi

################################################################################
# Step 1: Check Prerequisites
################################################################################

print_header "Step 1: Checking Prerequisites"

ALL_GOOD=true

# Check Python
if check_command python3; then
    PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
    print_info "Python version: $PYTHON_VERSION"

    # Check Python version >= 3.9
    PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d'.' -f1)
    PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d'.' -f2)

    if [[ $PYTHON_MAJOR -lt 3 ]] || [[ $PYTHON_MAJOR -eq 3 && $PYTHON_MINOR -lt 9 ]]; then
        print_error "Python 3.9+ is required (found $PYTHON_VERSION)"
        ALL_GOOD=false
    fi
else
    print_error "Python 3 is required"
    print_info "Install via Homebrew: brew install python3"
    ALL_GOOD=false
fi

# Check pip
if check_command pip3; then
    PIP_VERSION=$(pip3 --version | cut -d' ' -f2)
    print_info "pip version: $PIP_VERSION"
else
    print_error "pip3 is required"
    ALL_GOOD=false
fi

# Check git
if ! check_command git; then
    print_warning "git is recommended but not required"
fi

# Check clang (needed for Atheris)
if check_command clang; then
    CLANG_VERSION=$(clang --version | head -n1)
    print_info "Clang: $CLANG_VERSION"
else
    print_warning "clang not found - Atheris might not compile"
    print_info "Install Xcode Command Line Tools: xcode-select --install"
fi

if [ "$ALL_GOOD" = false ]; then
    print_error "Prerequisites not met. Please install missing tools and try again."
    exit 1
fi

print_success "All prerequisites satisfied!"

################################################################################
# Step 2: Setup Virtual Environment
################################################################################

print_header "Step 2: Setting Up Virtual Environment"

VENV_DIR="$PROJECT_ROOT/.venv-fuzzing"

if [ -d "$VENV_DIR" ]; then
    print_warning "Virtual environment already exists at: $VENV_DIR"
    read -p "Do you want to recreate it? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        print_info "Removing old virtual environment..."
        rm -rf "$VENV_DIR"
    else
        print_info "Using existing virtual environment"
    fi
fi

if [ ! -d "$VENV_DIR" ]; then
    print_info "Creating virtual environment at: $VENV_DIR"
    python3 -m venv "$VENV_DIR"
    print_success "Virtual environment created"
fi

# Activate virtual environment
print_info "Activating virtual environment..."
source "$VENV_DIR/bin/activate"
print_success "Virtual environment activated"

# Upgrade pip
print_info "Upgrading pip..."
pip install --upgrade pip setuptools wheel --quiet
print_success "pip upgraded"

################################################################################
# Step 3: Install DeepEval
################################################################################

print_header "Step 3: Installing DeepEval"

cd "$PROJECT_ROOT"

# Check if we're in a DeepEval repo
if [ -f "pyproject.toml" ] && grep -q "deepeval" pyproject.toml; then
    print_info "Detected DeepEval repository - installing in development mode"

    # Install with dev dependencies
    if command -v poetry &> /dev/null; then
        print_info "Using Poetry for installation..."
        poetry install
    else
        print_info "Poetry not found, using pip..."
        pip install -e ".[dev]" --quiet
    fi
else
    print_info "Installing DeepEval from PyPI..."
    pip install deepeval --quiet
fi

print_success "DeepEval installed"

################################################################################
# Step 4: Install Fuzzing Tools
################################################################################

print_header "Step 4: Installing Fuzzing Tools"

print_info "Installing Atheris (Google's Python fuzzer)..."
pip install atheris --quiet
print_success "Atheris installed"

print_info "Installing Hypothesis (property-based testing)..."
pip install hypothesis --quiet
print_success "Hypothesis installed"

print_info "Installing pytest (test runner)..."
pip install pytest pytest-xdist pytest-timeout --quiet
print_success "pytest installed"

print_info "Installing pandas (for dataset parsing)..."
pip install pandas --quiet
print_success "pandas installed"

################################################################################
# Step 5: Setup Corpus Directories
################################################################################

print_header "Step 5: Setting Up Corpus Directories"

cd "$SCRIPT_DIR"

# Create corpus subdirectories
for dir in datasets test_cases metrics; do
    mkdir -p "corpus/$dir"
    print_info "Created corpus/$dir"
done

# Create sample CSV corpus
print_info "Creating sample CSV corpus..."
cat > corpus/datasets/sample_valid.csv << 'EOF'
input,output,expected,context
"What is Python?","Python is a programming language","Python is a high-level language","programming;software"
"Define AI","AI is artificial intelligence","AI mimics human intelligence","technology;machine learning"
"Hello","Hi there!","Hi!","greeting"
EOF
print_success "Created sample CSV file"

# Create sample JSON corpus
print_info "Creating sample JSON corpus..."
cat > corpus/datasets/sample_valid.json << 'EOF'
[
  {
    "input": "What is fuzzing?",
    "actual_output": "Fuzzing is a testing technique",
    "expected_output": "Fuzzing is automated testing with random inputs",
    "context": ["security", "testing"]
  },
  {
    "input": "Explain property-based testing",
    "actual_output": "Property-based testing verifies invariants",
    "expected_output": "It generates test cases from properties"
  }
]
EOF
print_success "Created sample JSON file"

# Create malformed samples for testing
print_info "Creating malformed test samples..."

# Malformed CSV (missing headers)
echo "data1,data2,data3" > corpus/datasets/malformed_no_header.csv

# Deeply nested JSON
cat > corpus/datasets/deeply_nested.json << 'EOF'
{"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":{"i":{"j":"deep"}}}}}}}}}}}
EOF

# Invalid UTF-8 (binary file)
echo -e '\xff\xfe\x00\x00' > corpus/datasets/invalid_utf8.bin

print_success "Created test corpus files"

################################################################################
# Step 6: Make Scripts Executable
################################################################################

print_header "Step 6: Making Scripts Executable"

chmod +x "$SCRIPT_DIR/run_fuzzing.py"
chmod +x "$SCRIPT_DIR/targets/"*.py
print_success "Scripts are now executable"

################################################################################
# Step 7: Verify Installation
################################################################################

print_header "Step 7: Verifying Installation"

print_info "Checking Python packages..."

PACKAGES=("atheris" "hypothesis" "pytest" "deepeval" "pandas")
ALL_INSTALLED=true

for pkg in "${PACKAGES[@]}"; do
    if python3 -c "import $pkg" 2>/dev/null; then
        VERSION=$(python3 -c "import $pkg; print(getattr($pkg, '__version__', 'unknown'))")
        print_success "$pkg ($VERSION)"
    else
        print_error "$pkg not found"
        ALL_INSTALLED=false
    fi
done

if [ "$ALL_INSTALLED" = false ]; then
    print_error "Some packages failed to install"
    exit 1
fi

################################################################################
# Success!
################################################################################

print_header "🎉 Installation Complete!"

echo -e "${GREEN}${BOLD}Fuzzing environment is ready!${NC}\n"

echo -e "${BOLD}Next Steps:${NC}\n"
echo -e "  1. Activate the virtual environment:"
echo -e "     ${CYAN}source $VENV_DIR/bin/activate${NC}\n"
echo -e "  2. Run a quick test:"
echo -e "     ${CYAN}cd $SCRIPT_DIR${NC}"
echo -e "     ${CYAN}python run_fuzzing.py --target property${NC}\n"
echo -e "  3. Start fuzzing (run for 1 hour):"
echo -e "     ${CYAN}python run_fuzzing.py --target all --duration 3600${NC}\n"
echo -e "  4. Read the documentation:"
echo -e "     ${CYAN}cat README.md${NC}\n"

echo -e "${BOLD}Quick Reference:${NC}\n"
echo -e "  List targets:        ${CYAN}python run_fuzzing.py --list${NC}"
echo -e "  Fuzz dataset parser: ${CYAN}python run_fuzzing.py --target dataset --duration 1800${NC}"
echo -e "  Property tests:      ${CYAN}python run_fuzzing.py --target property${NC}"
echo -e "  All targets:         ${CYAN}python run_fuzzing.py --target all --duration 3600${NC}\n"

echo -e "${BOLD}Learning Resources:${NC}\n"
echo -e "  • Fuzzing Book: ${CYAN}https://www.fuzzingbook.org/${NC}"
echo -e "  • Atheris Docs: ${CYAN}https://github.com/google/atheris${NC}"
echo -e "  • Hypothesis:   ${CYAN}https://hypothesis.readthedocs.io/${NC}\n"

print_success "Happy Fuzzing! 🚀"
