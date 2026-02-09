"""
security configs
handles security stuff and utilites
loads credentials from external secure location
"""

import os
import secrets
from datetime import timedelta
from dotenv import load_dotenv

# load environment variables
load_dotenv()

# import external credentials loader
try:
    from credentials_loader import (
        get_secret_key,
        get_jwt_secret_key,
        get_admin_username,
        get_admin_password_hash,
        get_allowed_origins,
        CredentialsLoader
    )
    EXTERNAL_CREDENTIALS_LOADED = True
except ImportError as e:
    print(f"WARNING: Could not load external credentials: {e}")
    print(f"   Using environment variables instead")
    EXTERNAL_CREDENTIALS_LOADED = False


class SecurityConfig:
    """Security configuration class"""
    
    # Flask Secret Key (from external credentials or .env)
    if EXTERNAL_CREDENTIALS_LOADED:
        SECRET_KEY = get_secret_key()
        JWT_SECRET_KEY = get_jwt_secret_key()
    else:
        SECRET_KEY = os.getenv('SECRET_KEY', secrets.token_hex(32))
        JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', secrets.token_hex(32))
    
    # Session Configuration
    SESSION_COOKIE_SECURE = os.getenv('SESSION_COOKIE_SECURE', 'True') == 'True'
    SESSION_COOKIE_HTTPONLY = os.getenv('SESSION_COOKIE_HTTPONLY', 'True') == 'True'
    SESSION_COOKIE_SAMESITE = os.getenv('SESSION_COOKIE_SAMESITE', 'Strict')
    PERMANENT_SESSION_LIFETIME = timedelta(
        seconds=int(os.getenv('MAX_SESSION_AGE', 86400))
    )
    
    # Rate Limiting - ADJUSTED FOR 50 CONCURRENT USERS
    RATE_LIMIT_ENABLED = os.getenv('RATE_LIMIT_ENABLED', 'True') == 'True'
    RATE_LIMIT_STORAGE_URL = os.getenv('RATE_LIMIT_STORAGE_URL', 'memory://')
    # Allow 200 requests/min for 50 users (4 req/user/min) + API calls
    RATE_LIMIT_PER_MINUTE = int(os.getenv('RATE_LIMIT_PER_MINUTE', 200))
    # Allow 2000 requests/hour for sustained usage
    RATE_LIMIT_PER_HOUR = int(os.getenv('RATE_LIMIT_PER_HOUR', 2000))
    # Login attempts: 10 per 15 minutes (allows retries for 50 users)
    LOGIN_RATE_LIMIT = int(os.getenv('LOGIN_RATE_LIMIT', 10))
    
    # CORS (from external credentials or .env)
    if EXTERNAL_CREDENTIALS_LOADED:
        origins = get_allowed_origins()
        ALLOWED_ORIGINS = origins if origins else ['http://localhost:3000', 'http://127.0.0.1:5500']
    else:
        ALLOWED_ORIGINS = os.getenv(
            'ALLOWED_ORIGINS',
            'http://localhost:3000,http://127.0.0.1:5500'
        ).split(',')
    
    # Security Headers
    FORCE_HTTPS = os.getenv('FORCE_HTTPS', 'False') == 'True'
    CONTENT_SECURITY_POLICY = {
        'default-src': "'self'",
        'script-src': ["'self'", "'unsafe-inline'"],
        'style-src': ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        'font-src': ["'self'", "https://fonts.gstatic.com"],
        'img-src': ["'self'", "data:", "https:"],
        'connect-src': ["'self'"]
    }
    X_FRAME_OPTIONS = os.getenv('X_FRAME_OPTIONS', 'DENY')
    X_CONTENT_TYPE_OPTIONS = os.getenv('X_CONTENT_TYPE_OPTIONS', 'nosniff')
    
    # Authentication (from external credentials or .env)
    PASSWORD_MIN_LENGTH = int(os.getenv('PASSWORD_MIN_LENGTH', 8))
    
    if EXTERNAL_CREDENTIALS_LOADED:
        security_config = CredentialsLoader.get_security_config()
        SESSION_TIMEOUT_MINUTES = security_config.get('session_timeout_minutes', 1440)
        MAX_LOGIN_ATTEMPTS = security_config.get('max_login_attempts', 5)
        LOCKOUT_DURATION_MINUTES = security_config.get('lockout_duration_minutes', 15)
    else:
        SESSION_TIMEOUT_MINUTES = int(os.getenv('SESSION_TIMEOUT_MINUTES', 1440))
        MAX_LOGIN_ATTEMPTS = int(os.getenv('MAX_LOGIN_ATTEMPTS', 5))
        LOCKOUT_DURATION_MINUTES = int(os.getenv('LOCKOUT_DURATION_MINUTES', 15))
    
    # Request Limits
    MAX_CONTENT_LENGTH = int(os.getenv('MAX_CONTENT_LENGTH', 1048576))  # 1MB
    MAX_URL_LENGTH = int(os.getenv('MAX_URL_LENGTH', 2048))
    REQUEST_TIMEOUT = int(os.getenv('REQUEST_TIMEOUT', 30))
    
    # Admin Credentials (from external credentials or .env)
    # NOTE: These are loaded as static values at startup
    # For dynamic password updates, use get_admin_username() and get_admin_password_hash() functions
    if EXTERNAL_CREDENTIALS_LOADED:
        ADMIN_USERNAME = get_admin_username()
        # Don't cache password hash - load dynamically for security
        _ADMIN_PASSWORD_HASH_STATIC = None  # Intentionally not set
    else:
        ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', 'admin')
        _ADMIN_PASSWORD_HASH_STATIC = os.getenv(
            'ADMIN_PASSWORD_HASH',
            '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYqgOCkT0Ci'
        )
    
    @classmethod
    def get_admin_password_hash_dynamic(cls):
        """Get admin password hash dynamically (always fresh from file)"""
        if EXTERNAL_CREDENTIALS_LOADED:
            return get_admin_password_hash()
        else:
            return cls._ADMIN_PASSWORD_HASH_STATIC
    
    # For backwards compatibility, create a property
    @property
    def ADMIN_PASSWORD_HASH(self):
        """Dynamic property to always get fresh password hash"""
        return SecurityConfig.get_admin_password_hash_dynamic()
    
    # Logging
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FILE = os.getenv('LOG_FILE', 'security.log')
    
    # Environment
    FLASK_ENV = os.getenv('FLASK_ENV', 'development')
    DEBUG = os.getenv('DEBUG', 'False') == 'True'


# Security Constants
SUSPICIOUS_PATTERNS = [
    # SQL Injection patterns
    r"(\bUNION\b|\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bDROP\b)",
    r"(--|\#|\/\*|\*\/)",
    r"(\bOR\b\s+\d+\s*=\s*\d+|\bAND\b\s+\d+\s*=\s*\d+)",
    
    # XSS patterns
    r"(<script|<iframe|<object|<embed|<img.*onerror|javascript:)",
    r"(onload=|onerror=|onclick=|onmouseover=)",
    
    # Command Injection
    r"(;|\||&&|\$\(|\`)",
    r"(\.\./|\.\.\\)",
    
    # Path Traversal
    r"(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e%5c)",
]


# Compile suspicious patterns for fast matching
import re
COMPILED_SUSPICIOUS_PATTERNS = [re.compile(p, re.IGNORECASE) for p in SUSPICIOUS_PATTERNS]

# Allowed content types
ALLOWED_CONTENT_TYPES = ['application/json']

# Security headers
SECURITY_HEADERS = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
}
