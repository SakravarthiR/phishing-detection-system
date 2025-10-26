#!/bin/bash

# Render.com Start Script
# Starts the backend API server

set -e

echo "========================================="
echo "STARTING PHISHING DETECTOR API"
echo "========================================="

# Set temp directory for Render (fix permission denied in /var/run)
export TMPDIR=/tmp
mkdir -p /tmp

# Navigate to backend directory
cd backend

# Start Gunicorn with config
# The config file handles PORT, pidfile=None, and temp directory
exec gunicorn --config gunicorn_config.py secure_api:app
