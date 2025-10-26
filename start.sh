#!/bin/bash

# Render.com Start Script
# Starts the backend API server

set -e

echo "========================================="
echo "STARTING PHISHING DETECTOR API"
echo "========================================="

# Navigate to backend directory
cd backend

# Start Gunicorn with config
exec gunicorn --config gunicorn_config.py secure_api:app
