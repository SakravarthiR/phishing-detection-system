#!/bin/bash

# Render.com Build Script for Phishing Detector
# Installs dependencies and validates build for the backend

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Header
echo "========================================="
echo "🔐 PHISHING DETECTOR BUILD SCRIPT"
echo "========================================="

# Check if requirements.txt exists
if [ ! -f "backend/requirements.txt" ]; then
    log_error "requirements.txt not found!"
    exit 1
fi

log_info "Python version: $(python --version)"

# Upgrade pip
log_info "Upgrading pip..."
python -m pip install --upgrade pip setuptools wheel

# Install dependencies
log_info "Installing Python dependencies from backend/requirements.txt..."
if pip install -r backend/requirements.txt; then
    log_info "Dependencies installed successfully"
else
    log_error "Failed to install dependencies"
    exit 1
fi

# Verify key packages
log_info "Verifying critical packages..."
python -c "import flask; print(f'Flask {flask.__version__}')" || (log_error "Flask not installed"; exit 1)
python -c "import gunicorn; print(f'Gunicorn installed')" || (log_error "Gunicorn not installed"; exit 1)
python -c "import sklearn; print(f'Scikit-learn {sklearn.__version__}')" || (log_error "Scikit-learn not installed"; exit 1)

# Check if backend files exist
log_info "Verifying backend files..."
[ -f "backend/secure_api.py" ] && log_info "✓ secure_api.py found" || (log_error "secure_api.py not found"; exit 1)
[ -f "backend/phish_detector.py" ] && log_info "✓ phish_detector.py found" || (log_error "phish_detector.py not found"; exit 1)
[ -f "backend/gunicorn_config.py" ] && log_info "✓ gunicorn_config.py found" || (log_error "gunicorn_config.py not found"; exit 1)

# Syntax check Python files
log_info "Checking Python syntax..."
python -m py_compile backend/secure_api.py || (log_error "Syntax error in secure_api.py"; exit 1)
python -m py_compile backend/phish_detector.py || (log_error "Syntax error in phish_detector.py"; exit 1)
log_info "✓ All Python files have valid syntax"

# Verify frontend files exist
log_info "Verifying frontend files..."
[ -f "frontend/index.html" ] && log_info "✓ index.html found" || (log_error "index.html not found"; exit 1)
[ -f "frontend/app.js" ] && log_info "✓ app.js found" || (log_error "app.js not found"; exit 1)
[ -f "frontend/professional.css" ] && log_info "✓ professional.css found" || (log_error "professional.css not found"; exit 1)

# Final validation
log_info "Running final validation..."
cd backend
python -c "
from phish_detector import load_model, extract_features
from security_utils import logger
print('[✓] Core modules import successfully')
" || (log_error "Failed to import core modules"; exit 1)
cd ..

echo ""
echo "========================================="
log_info "BUILD SUCCESSFUL! ✓"
echo "========================================="
echo "Backend is ready to start with:"
echo "  python backend/secure_api.py"
echo "  or"
echo "  gunicorn --config backend/gunicorn_config.py backend/secure_api:app"
echo "=========================================

