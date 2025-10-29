# =====================================================
# production server config (gunicorn)
# =====================================================

import multiprocessing
import os

# server socket
# use PORT from environment (render gives us this) or default to 5000
port = os.environ.get("PORT", "5000")
bind = f"0.0.0.0:{port}"
backlog = 2048

# worker processes
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = "sync"
worker_connections = 1000
timeout = 120
keepalive = 5

# restart workers after this many requests (stops memory leaks)
max_requests = 1000
max_requests_jitter = 50

# logging
# on render, logs go to stdout/stderr (no files needed)
accesslog = "-"  # stdout
errorlog = "-"   # stderr
loglevel = "info"
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'

# process naming
proc_name = "phishing-detector-api"

# server mechanics
daemon = False
pidfile = None  # disable pidfile for render (no permission to /var/run)
user = None  # set to your user in production
group = None  # set to your group in production
umask = 0

# temp directory config (fix for render permission denied)
# use /tmp instead of /var/run which might have restricted permissions
import tempfile
tempdir = "/tmp"
if not os.path.exists(tempdir):
    tempdir = os.environ.get("TMPDIR", "/tmp")
# set pythons tempdir for gunicorn stuff
os.environ["TMPDIR"] = tempdir

# Security
limit_request_line = 4096
limit_request_fields = 100
limit_request_field_size = 8190
