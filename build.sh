#!/bin/bash

# Render.com Build Script
# Installs dependencies for the phishing detector backend

set -e

echo "========================================="
echo "BUILDING PHISHING DETECTOR"
echo "========================================="

# Install Python dependencies
echo "Installing Python packages..."
pip install -r backend/requirements.txt

echo "Build complete!"
