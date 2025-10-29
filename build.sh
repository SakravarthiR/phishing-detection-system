#!/bin/bash

# Render.com Build Script
# Installs dependencies for the phishing detector backend

set -e

echo "========================================="
echo "BUILDING PHISHING DETECTOR"
echo "========================================="

# Check if requirements.txt exists
if [ ! -f "backend/requirements.txt" ]; then
    echo "ERROR: backend/requirements.txt not found!"
    exit 1
fi

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip setuptools wheel

# Install Python dependencies
echo "Installing Python packages..."
pip install -r backend/requirements.txt

# Verify Python syntax
echo "Checking Python files..."
python -m py_compile backend/*.py

# Check if gunicorn is installed
if ! python -c "import gunicorn" 2>/dev/null; then
    echo "ERROR: gunicorn not installed!"
    exit 1
fi

# Check if Flask is installed
if ! python -c "import flask" 2>/dev/null; then
    echo "ERROR: Flask not installed!"
    exit 1
fi

echo "========================================="
echo "Build completed successfully!"
echo "========================================="
