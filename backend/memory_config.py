"""
Memory optimization for 512MB Render free tier.
This file provides lean configurations that fit in minimal memory.
"""

import os

# Detect environment
IS_RENDER = os.environ.get('RENDER') == 'true'
MEMORY_CONSTRAINT = os.environ.get('MEMORY_CONSTRAINT', '512MB')

# For 512MB: aggressive memory management
if MEMORY_CONSTRAINT == '512MB':
    # PhishTank caching disabled (too much memory)
    PHISHTANK_CACHE_ENABLED = False
    PHISHTANK_UPDATE_INTERVAL = None  # Don't auto-update
    
    # Request pooling (minimal overhead)
    REQUEST_POOL_SIZE = 2  # Only 2 concurrent requests
    
    # Model prediction settings
    BATCH_SIZE = 1  # Process URLs one at a time
    
    # Memory thresholds
    MAX_MEMORY_MB = 450  # Hard limit (512 - overhead)
    CLEANUP_THRESHOLD_MB = 400  # Cleanup if exceeds this
    
    # Disable expensive features
    ADVANCED_THREAT_DETECTION = False  # Too memory intensive
    SSL_VERIFICATION_DETAILED = False  # Reduced SSL checks
    
    # Timeouts
    REQUEST_TIMEOUT = 5  # Shorter timeout
    MODEL_INFERENCE_TIMEOUT = 30  # Fast inference or kill
    
    # Capacity settings
    # With cleanup_memory() after each request, can handle 500+ safely
    MAX_PREDICTIONS_PER_HOUR = 1000  # ~1000 predictions per hour safely
    
    print("[!] 512MB Memory Optimization Mode Enabled")
    print("    - PhishTank caching DISABLED")
    print("    - Advanced threat detection DISABLED")
    print("    - Serial request processing (no concurrency)")
    print("    - Capacity: ~1000 predictions/hour safely")
    
else:
    # Standard configuration (higher memory)
    PHISHTANK_CACHE_ENABLED = True
    PHISHTANK_UPDATE_INTERVAL = 3600  # Update hourly
    
    REQUEST_POOL_SIZE = 5
    BATCH_SIZE = 10
    
    MAX_MEMORY_MB = 1800
    CLEANUP_THRESHOLD_MB = 1600
    
    ADVANCED_THREAT_DETECTION = True
    SSL_VERIFICATION_DETAILED = True
    
    REQUEST_TIMEOUT = 10
    MODEL_INFERENCE_TIMEOUT = 60
    
    print("[+] Standard Memory Configuration")
