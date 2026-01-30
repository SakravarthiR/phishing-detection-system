# =====================================================
# PRODUCTION SERVER CONFIGURATION (Gunicorn)
# =====================================================

import multiprocessing
import os

# Server socket
# Use PORT from environment (Render provides this) or default to 5000
port = os.environ.get("PORT", "5000")
bind = f"0.0.0.0:{port}"
backlog = 2048

# Worker processes - OPTIMIZED FOR 50 CONCURRENT USERS ON 512MB FREE TIER
# 2 workers with connection pooling supports ~50 concurrent users safely
workers = 2  # 2 workers for 512MB (each ~100MB) with 25 connections per worker = 50 total
worker_class = "sync"  # Synchronous worker (most memory efficient)
worker_connections = 25  # 25 connections per worker = 50 concurrent users total
timeout = 60  # Increased timeout for complex predictions
keepalive = 2  # Minimal keepalive to close idle connections
max_requests = 200  # Restart worker every 200 requests to prevent memory bloat
max_requests_jitter = 20  # Randomize restarts to avoid sync restarts

# Logging
# On Render, logs go to stdout/stderr (no need for log files)
accesslog = "-"  # stdout
errorlog = "-"   # stderr
loglevel = "info"
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'

# Process naming
proc_name = "phishing-detector-api"

# Server mechanics
daemon = False
pidfile = None  # Disable pidfile for Render (no permission to /var/run)
user = None  # Set to your user in production
group = None  # Set to your group in production
umask = 0

# Temporary directory configuration (fix for Render permission denied)
# Use /tmp instead of /var/run which may have restricted permissions
import tempfile
tempdir = "/tmp"
if not os.path.exists(tempdir):
    tempdir = os.environ.get("TMPDIR", "/tmp")
# Set Python's tempdir for gunicorn operations
os.environ["TMPDIR"] = tempdir

# Security
limit_request_line = 4096
limit_request_fields = 100
limit_request_field_size = 8190
