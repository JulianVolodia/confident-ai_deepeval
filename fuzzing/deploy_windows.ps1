################################################################################
# DeepEval Fuzzing Setup Script for Windows
################################################################################
#
# This script sets up the complete fuzzing environment for DeepEval on Windows.
#
# What it does:
# 1. Checks for required tools (Python, pip, git)
# 2. Creates a virtual environment
# 3. Installs DeepEval and dependencies
# 4. Installs fuzzing tools (Atheris, Hypothesis)
# 5. Sets up corpus directories with sample data
# 6. Verifies the installation
#
# Usage (PowerShell as Administrator):
#   Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
#   .\deploy_windows.ps1
#
################################################################################

# Enable strict mode
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Script location
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir

################################################################################
# Helper Functions
################################################################################

function Print-Header {
    param([string]$Message)
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "  $Message" -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Print-Info {
    param([string]$Message)
    Write-Host "i " -ForegroundColor Blue -NoNewline
    Write-Host $Message
}

function Print-Success {
    param([string]$Message)
    Write-Host "√ " -ForegroundColor Green -NoNewline
    Write-Host $Message
}

function Print-Warning {
    param([string]$Message)
    Write-Host "! " -ForegroundColor Yellow -NoNewline
    Write-Host $Message
}

function Print-Error {
    param([string]$Message)
    Write-Host "x " -ForegroundColor Red -NoNewline
    Write-Host $Message
}

function Test-Command {
    param([string]$Command)

    try {
        Get-Command $Command -ErrorAction Stop | Out-Null
        return $true
    }
    catch {
        return $false
    }
}

################################################################################
# Main Installation
################################################################################

Print-Header "🔍 DeepEval Fuzzing Setup for Windows"

# Check if running as Administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Print-Warning "Not running as Administrator. Some features might not work."
    Print-Info "For best results, run PowerShell as Administrator."
}

################################################################################
# Step 1: Check Prerequisites
################################################################################

Print-Header "Step 1: Checking Prerequisites"

$AllGood = $true

# Check Python
if (Test-Command python) {
    Print-Success "Python is installed"
    $PythonVersion = python --version 2>&1 | Out-String
    Print-Info "Version: $PythonVersion"

    # Check Python version >= 3.9
    $VersionMatch = $PythonVersion -match "Python (\d+)\.(\d+)"
    if ($VersionMatch) {
        $Major = [int]$Matches[1]
        $Minor = [int]$Matches[2]

        if ($Major -lt 3 -or ($Major -eq 3 -and $Minor -lt 9)) {
            Print-Error "Python 3.9+ is required (found $Major.$Minor)"
            $AllGood = $false
        }
    }
}
else {
    Print-Error "Python is not installed or not in PATH"
    Print-Info "Download from: https://www.python.org/downloads/"
    Print-Info "Make sure to check 'Add Python to PATH' during installation"
    $AllGood = $false
}

# Check pip
if (Test-Command pip) {
    Print-Success "pip is installed"
    $PipVersion = pip --version 2>&1 | Out-String
    Print-Info "Version: $PipVersion"
}
else {
    Print-Error "pip is not installed"
    $AllGood = $false
}

# Check git (optional)
if (Test-Command git) {
    Print-Success "git is installed"
}
else {
    Print-Warning "git is not installed (optional)"
    Print-Info "Download from: https://git-scm.com/download/win"
}

# Check Visual Studio Build Tools (needed for Atheris on Windows)
$VSWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (Test-Path $VSWhere) {
    $VSInstall = & $VSWhere -latest -property installationPath 2>$null
    if ($VSInstall) {
        Print-Success "Visual Studio Build Tools detected"
        Print-Info "Location: $VSInstall"
    }
    else {
        Print-Warning "Visual Studio Build Tools not found"
        Print-Info "Atheris might fail to install without C++ build tools"
        Print-Info "Download from: https://visualstudio.microsoft.com/downloads/"
    }
}
else {
    Print-Warning "Visual Studio Build Tools might be required for Atheris"
    Print-Info "If installation fails, install VS Build Tools with C++ support"
}

if (-not $AllGood) {
    Print-Error "Prerequisites not met. Please install missing tools and try again."
    exit 1
}

Print-Success "All prerequisites satisfied!"

################################################################################
# Step 2: Setup Virtual Environment
################################################################################

Print-Header "Step 2: Setting Up Virtual Environment"

$VenvDir = Join-Path $ProjectRoot ".venv-fuzzing"

if (Test-Path $VenvDir) {
    Print-Warning "Virtual environment already exists at: $VenvDir"
    $Response = Read-Host "Do you want to recreate it? (y/N)"
    if ($Response -eq 'y' -or $Response -eq 'Y') {
        Print-Info "Removing old virtual environment..."
        Remove-Item -Recurse -Force $VenvDir
    }
    else {
        Print-Info "Using existing virtual environment"
    }
}

if (-not (Test-Path $VenvDir)) {
    Print-Info "Creating virtual environment at: $VenvDir"
    python -m venv $VenvDir
    Print-Success "Virtual environment created"
}

# Activate virtual environment
Print-Info "Activating virtual environment..."
$ActivateScript = Join-Path $VenvDir "Scripts\Activate.ps1"

if (Test-Path $ActivateScript) {
    & $ActivateScript
    Print-Success "Virtual environment activated"
}
else {
    Print-Error "Failed to find activation script"
    exit 1
}

# Upgrade pip
Print-Info "Upgrading pip..."
python -m pip install --upgrade pip setuptools wheel --quiet
Print-Success "pip upgraded"

################################################################################
# Step 3: Install DeepEval
################################################################################

Print-Header "Step 3: Installing DeepEval"

Set-Location $ProjectRoot

# Check if we're in a DeepEval repo
if (Test-Path "pyproject.toml") {
    $Content = Get-Content "pyproject.toml" -Raw
    if ($Content -match "deepeval") {
        Print-Info "Detected DeepEval repository - installing in development mode"

        # Check for Poetry
        if (Test-Command poetry) {
            Print-Info "Using Poetry for installation..."
            poetry install
        }
        else {
            Print-Info "Poetry not found, using pip..."
            pip install -e ".[dev]"
        }
    }
}
else {
    Print-Info "Installing DeepEval from PyPI..."
    pip install deepeval --quiet
}

Print-Success "DeepEval installed"

################################################################################
# Step 4: Install Fuzzing Tools
################################################################################

Print-Header "Step 4: Installing Fuzzing Tools"

Print-Info "Installing Atheris (Google's Python fuzzer)..."
try {
    pip install atheris --quiet 2>&1 | Out-Null
    Print-Success "Atheris installed"
}
catch {
    Print-Warning "Atheris installation failed (might need Visual Studio Build Tools)"
    Print-Info "Continuing with other tools..."
}

Print-Info "Installing Hypothesis (property-based testing)..."
pip install hypothesis --quiet
Print-Success "Hypothesis installed"

Print-Info "Installing pytest (test runner)..."
pip install pytest pytest-xdist pytest-timeout --quiet
Print-Success "pytest installed"

Print-Info "Installing pandas (for dataset parsing)..."
pip install pandas --quiet
Print-Success "pandas installed"

################################################################################
# Step 5: Setup Corpus Directories
################################################################################

Print-Header "Step 5: Setting Up Corpus Directories"

Set-Location $ScriptDir

# Create corpus subdirectories
@("datasets", "test_cases", "metrics") | ForEach-Object {
    $CorpusPath = Join-Path "corpus" $_
    New-Item -ItemType Directory -Force -Path $CorpusPath | Out-Null
    Print-Info "Created corpus/$_"
}

# Create sample CSV corpus
Print-Info "Creating sample CSV corpus..."
@"
input,output,expected,context
"What is Python?","Python is a programming language","Python is a high-level language","programming;software"
"Define AI","AI is artificial intelligence","AI mimics human intelligence","technology;machine learning"
"Hello","Hi there!","Hi!","greeting"
"@ | Out-File -FilePath "corpus\datasets\sample_valid.csv" -Encoding UTF8
Print-Success "Created sample CSV file"

# Create sample JSON corpus
Print-Info "Creating sample JSON corpus..."
@"
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
"@ | Out-File -FilePath "corpus\datasets\sample_valid.json" -Encoding UTF8
Print-Success "Created sample JSON file"

# Create malformed samples for testing
Print-Info "Creating malformed test samples..."

# Malformed CSV (missing headers)
"data1,data2,data3" | Out-File -FilePath "corpus\datasets\malformed_no_header.csv" -Encoding UTF8

# Deeply nested JSON
@"
{"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":{"i":{"j":"deep"}}}}}}}}}}}
"@ | Out-File -FilePath "corpus\datasets\deeply_nested.json" -Encoding UTF8

# Invalid UTF-8 (binary file)
[byte[]](0xff, 0xfe, 0x00, 0x00) | Set-Content -Path "corpus\datasets\invalid_utf8.bin" -Encoding Byte

Print-Success "Created test corpus files"

################################################################################
# Step 6: Verify Installation
################################################################################

Print-Header "Step 6: Verifying Installation"

Print-Info "Checking Python packages..."

$Packages = @("hypothesis", "pytest", "deepeval", "pandas")
$AllInstalled = $true

foreach ($pkg in $Packages) {
    try {
        $Version = python -c "import $pkg; print(getattr($pkg, '__version__', 'unknown'))" 2>&1
        Print-Success "$pkg ($Version)"
    }
    catch {
        Print-Error "$pkg not found"
        $AllInstalled = $false
    }
}

# Check Atheris separately (might not be installed)
try {
    $AtherisVersion = python -c "import atheris; print(atheris.__version__)" 2>&1
    Print-Success "atheris ($AtherisVersion)"
}
catch {
    Print-Warning "atheris not installed (optional, but recommended)"
}

if (-not $AllInstalled) {
    Print-Error "Some packages failed to install"
    exit 1
}

################################################################################
# Success!
################################################################################

Print-Header "🎉 Installation Complete!"

Write-Host "Fuzzing environment is ready!`n" -ForegroundColor Green

Write-Host "Next Steps:`n" -ForegroundColor Yellow

Write-Host "  1. Activate the virtual environment:"
Write-Host "     $VenvDir\Scripts\Activate.ps1`n" -ForegroundColor Cyan

Write-Host "  2. Run a quick test:"
Write-Host "     cd $ScriptDir" -ForegroundColor Cyan
Write-Host "     python run_fuzzing.py --target property`n" -ForegroundColor Cyan

Write-Host "  3. Start fuzzing (run for 1 hour):"
Write-Host "     python run_fuzzing.py --target all --duration 3600`n" -ForegroundColor Cyan

Write-Host "  4. Read the documentation:"
Write-Host "     type README.md`n" -ForegroundColor Cyan

Write-Host "Quick Reference:`n" -ForegroundColor Yellow

Write-Host "  List targets:        " -NoNewline
Write-Host "python run_fuzzing.py --list" -ForegroundColor Cyan

Write-Host "  Fuzz dataset parser: " -NoNewline
Write-Host "python run_fuzzing.py --target dataset --duration 1800" -ForegroundColor Cyan

Write-Host "  Property tests:      " -NoNewline
Write-Host "python run_fuzzing.py --target property" -ForegroundColor Cyan

Write-Host "  All targets:         " -NoNewline
Write-Host "python run_fuzzing.py --target all --duration 3600`n" -ForegroundColor Cyan

Write-Host "Learning Resources:`n" -ForegroundColor Yellow
Write-Host "  • Fuzzing Book: " -NoNewline
Write-Host "https://www.fuzzingbook.org/" -ForegroundColor Cyan

Write-Host "  • Atheris Docs: " -NoNewline
Write-Host "https://github.com/google/atheris" -ForegroundColor Cyan

Write-Host "  • Hypothesis:   " -NoNewline
Write-Host "https://hypothesis.readthedocs.io/`n" -ForegroundColor Cyan

Print-Success "Happy Fuzzing! 🚀"
