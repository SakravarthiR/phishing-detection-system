"""
Memory optimization utilities for the phishing detector
Reduces RAM usage during model inference and request handling
Optimized for 512MB Render free tier
"""

import gc
import psutil
import os
import logging
from functools import wraps
from typing import Any, Callable

logger = logging.getLogger(__name__)

# OPTIMIZED THRESHOLDS FOR 512MB RENDER FREE TIER
# With 1 worker, we have ~400MB available after OS overhead
# Target: Keep worker under 200MB for safety margin
MEMORY_THRESHOLD_MB = 180  # Trigger cleanup above this
CRITICAL_MEMORY_MB = 150   # Aggressive cleanup at 150MB
EMERGENCY_MEMORY_MB = 100  # Log warning at 100MB


def get_memory_usage() -> float:
    """Get current process memory usage in MB"""
    try:
        process = psutil.Process(os.getpid())
        return process.memory_info().rss / 1024 / 1024
    except:
        return 0


def cleanup_memory(aggressive: bool = False):
    """Force garbage collection and clear caches"""
    try:
        gc.collect(0)  # Collect gen0 objects
        if aggressive:
            gc.collect(1)  # Collect gen1 objects
            gc.collect(2)  # Collect gen2 objects
        logger.debug(f"Memory after cleanup: {get_memory_usage():.2f} MB")
    except Exception as e:
        logger.warning(f"Memory cleanup error: {e}")


def memory_efficient(func: Callable) -> Callable:
    """Decorator to ensure aggressive memory cleanup after function execution"""
    @wraps(func)
    def wrapper(*args, **kwargs) -> Any:
        mem_start = get_memory_usage()
        try:
            result = func(*args, **kwargs)
            return result
        finally:
            # Always cleanup after function
            mem_end = get_memory_usage()
            if mem_end > CRITICAL_MEMORY_MB:
                cleanup_memory(aggressive=True)
            else:
                cleanup_memory(aggressive=False)
    return wrapper


def monitor_memory():
    """Monitor and log current memory usage"""
    mem_mb = get_memory_usage()
    logger.info(f"Current memory usage: {mem_mb:.2f} MB")
    
    if mem_mb > MEMORY_THRESHOLD_MB:
        logger.warning(f"Memory usage high ({mem_mb:.2f} MB), triggering cleanup...")
        cleanup_memory()


class MemoryPool:
    """Simple memory pool to reuse objects and reduce allocations"""
    def __init__(self, pool_size: int = 5):
        self.pool_size = pool_size
        self.pools = {}
    
    def get_buffer(self, size: int = 1024):
        """Get a reusable buffer"""
        if 'buffer' not in self.pools:
            self.pools['buffer'] = []
        
        if self.pools['buffer']:
            return self.pools['buffer'].pop()
        return bytearray(size)
    
    def release_buffer(self, buf):
        """Release buffer back to pool"""
        if 'buffer' not in self.pools:
            self.pools['buffer'] = []
        
        if len(self.pools['buffer']) < self.pool_size:
            self.pools['buffer'].append(buf)


# Global memory pool instance
memory_pool = MemoryPool()


def reduce_dataframe_memory(df):
    """
    Reduce pandas DataFrame memory usage by optimizing dtypes
    This can reduce DataFrame size by 50% or more
    """
    import pandas as pd
    
    for col in df.columns:
        col_type = df[col].dtype
        
        if col_type != 'object':
            c_min = df[col].min()
            c_max = df[col].max()
            
            if str(col_type)[:3] == 'int':
                if c_min > np.iinfo(np.int8).min and c_max < np.iinfo(np.int8).max:
                    df[col] = df[col].astype(np.int8)
                elif c_min > np.iinfo(np.int16).min and c_max < np.iinfo(np.int16).max:
                    df[col] = df[col].astype(np.int16)
                elif c_min > np.iinfo(np.int32).min and c_max < np.iinfo(np.int32).max:
                    df[col] = df[col].astype(np.int32)
            else:
                if c_min > np.finfo(np.float16).min and c_max < np.finfo(np.float16).max:
                    df[col] = df[col].astype(np.float16)
                elif c_min > np.finfo(np.float32).min and c_max < np.finfo(np.float32).max:
                    df[col] = df[col].astype(np.float32)
    
    return df


# Import numpy after function definition to avoid issues
try:
    import numpy as np
except ImportError:
    pass
