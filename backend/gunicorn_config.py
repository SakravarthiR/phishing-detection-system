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

# Worker processes - OPTIMIZED FOR 512MB RENDER FREE TIER
# Single worker to maximize available RAM per process
# With 512MB total, 1 worker gets ~400MB usable after OS overhead
workers = 1  # Single worker for 512MB (uses ~150-200MB)
worker_class = "sync"  # Synchronous worker (most memory efficient)
worker_connections = 50  # Handle 50 concurrent connections
timeout = 120  # Increased timeout for cold starts on Render
keepalive = 2  # Minimal keepalive to close idle connections
max_requests = 100  # Restart worker every 100 requests to prevent memory bloat
max_requests_jitter = 10  # Randomize restarts

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
