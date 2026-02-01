"""
Memory optimization for 512MB Render free tier.
This file provides lean configurations that fit in minimal memory.
"""

import os

# Detect environment
IS_RENDER = os.environ.get('RENDER') == 'true'
MEMORY_CONSTRAINT = os.environ.get('MEMORY_CONSTRAINT', '512MB')

# For 512MB: aggressive memory management (also auto-detect Render)
if MEMORY_CONSTRAINT == '512MB' or IS_RENDER:
    # PhishTank caching disabled (too much memory)
    PHISHTANK_CACHE_ENABLED = False
    PHISHTANK_UPDATE_INTERVAL = None  # Don't auto-update
    
    # Request pooling (minimal overhead)
    REQUEST_POOL_SIZE = 1  # Single request at a time
    
    # Model prediction settings
    BATCH_SIZE = 1  # Process URLs one at a time
    
    # Memory thresholds - AGGRESSIVE FOR 512MB
    MAX_MEMORY_MB = 350  # Hard limit (512 - OS - safety margin)
    CLEANUP_THRESHOLD_MB = 200  # Cleanup if exceeds this
    CRITICAL_MEMORY_MB = 250  # Reject new requests above this
    
    # Disable expensive features
    ADVANCED_THREAT_DETECTION = False  # Too memory intensive
    SSL_VERIFICATION_DETAILED = False  # Reduced SSL checks
    
    # Timeouts - shorter for faster cleanup
    REQUEST_TIMEOUT = 5  # Shorter timeout
    MODEL_INFERENCE_TIMEOUT = 20  # Fast inference or kill
    
    # Capacity settings
    MAX_PREDICTIONS_PER_HOUR = 500  # Conservative for stability
    MAX_CONCURRENT_REQUESTS = 1  # Serial processing only
    
    print("[!] 512MB RENDER OPTIMIZATION MODE")
    print("    - Single worker, serial processing")
    print("    - Memory limit: 350MB, cleanup at 200MB")
    print("    - PhishTank/advanced features DISABLED")
    
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
