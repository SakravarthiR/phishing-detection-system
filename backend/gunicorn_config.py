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

# Worker processes
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = "sync"
worker_connections = 1000
timeout = 120
keepalive = 5

# Restart workers after this many requests (prevent memory leaks)
max_requests = 1000
max_requests_jitter = 50

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
pidfile = "/var/run/phishing-detector.pid"
user = None  # Set to your user in production
group = None  # Set to your group in production
umask = 0

# Security
limit_request_line = 4096
limit_request_fields = 100
limit_request_field_size = 8190
