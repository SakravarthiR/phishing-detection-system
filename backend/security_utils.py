"""
Security utilities - auth, validation, rate limiting, all that good stuff.

Most of this is standard security practices but I added some extra validation
for URLs and user inputs. Better safe than sorry, especially with web APIs.
The JWT token stuff took me a while to get working properly.
"""

import re
import jwt
import bcrypt
import bleach
import validators
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify, g
from security_config import SecurityConfig, SUSPICIOUS_PATTERNS, COMPILED_SUSPICIOUS_PATTERNS
import logging
import sys

# Use pre-compiled patterns for O(n) time complexity
_COMPILED_SUSPICIOUS_PATTERNS = COMPILED_SUSPICIOUS_PATTERNS

# Configure logging with UTF-8 encoding for Windows
logging.basicConfig(
    level=getattr(logging, SecurityConfig.LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(SecurityConfig.LOG_FILE, encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# In-memory storage for failed login attempts (use Redis in production)
failed_login_attempts = {}
blocked_ips = {}

# Token blacklist for logout - invalidated tokens stored here
# In production, use Redis with TTL matching token expiration
# OPTIMIZED FOR 512MB RENDER - reduced size
token_blacklist = set()
MAX_BLACKLIST_SIZE = 2000  # Reduced from 10000 for 512MB RAM


# Input validation constants
MAX_USERNAME_LENGTH = 64
MAX_PASSWORD_LENGTH = 256
MIN_PASSWORD_LENGTH = 8
USERNAME_PATTERN = r'^[a-zA-Z0-9_\-\.@]+$'  # Alphanumeric, underscore, dash, dot, @
class SecurityValidator:
    """Security validation utilities"""
    
    @staticmethod
    def sanitize_input(input_string):
        """
        Sanitize user input to prevent XSS and injection attacks
        
        Args:
            input_string: Raw input string
            
        Returns:
            Sanitized string
        """
        if not isinstance(input_string, str):
            return input_string
        
        # Remove HTML tags and dangerous characters
        sanitized = bleach.clean(
            input_string,
            tags=[],
            attributes={},
            strip=True
        )
        
        # Additional cleanup
        sanitized = sanitized.strip()
        
        return sanitized
    
    @staticmethod
    def validate_url(url):
        """
        Validate and sanitize URL input
        
        Args:
            url: URL string to validate
            
        Returns:
            tuple: (is_valid, sanitized_url, error_message)
        """
        if not url or not isinstance(url, str):
            return False, None, "URL must be a non-empty string"
        
        # Sanitize input
        url = SecurityValidator.sanitize_input(url)
        
        # Check length
        if len(url) > SecurityConfig.MAX_URL_LENGTH:
            return False, None, f"URL exceeds maximum length of {SecurityConfig.MAX_URL_LENGTH}"
        
        # Add protocol if missing
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        # Validate URL format
        if not validators.url(url):
            return False, None, "Invalid URL format"
        
        # Check for suspicious patterns
        for pattern in SUSPICIOUS_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                logger.warning(f"Suspicious pattern detected in URL: {url}")
                return False, None, "URL contains suspicious patterns"
        
        return True, url, None
    
    @staticmethod
    def validate_domain(domain):
        """
        Validate domain name
        
        Args:
            domain: Domain string to validate
            
        Returns:
            tuple: (is_valid, sanitized_domain, error_message)
        """
        if not domain or not isinstance(domain, str):
            return False, None, "Domain must be a non-empty string"
        
        # Sanitize input
        domain = SecurityValidator.sanitize_input(domain)
        
        # Remove protocol if present
        domain = re.sub(r'^https?://', '', domain)
        domain = domain.split('/')[0]  # Remove path
        
        # Validate domain format
        if not validators.domain(domain):
            return False, None, "Invalid domain format"
        
        # Check length
        if len(domain) > 253:  # RFC 1035
            return False, None, "Domain name too long"
        
        return True, domain, None
    
    @staticmethod
    def check_suspicious_input(input_string):
        """
        Check for suspicious patterns in input
        
        Args:
            input_string: String to check
            
        Returns:
            bool: True if suspicious, False otherwise
        """
        if not isinstance(input_string, str):
            return False
        
        # Use pre-compiled patterns for O(n) instead of O(n*m)
        for pattern in _COMPILED_SUSPICIOUS_PATTERNS:
            if pattern.search(input_string):
                logger.warning(f"Suspicious pattern detected in input")
                return True
        
        return False
    
    @staticmethod
    def validate_username(username):
        """
        Validate username format and length
        
        Args:
            username: Username to validate
            
        Returns:
            tuple: (is_valid, error_message)
        """
        if not isinstance(username, str):
            return False, "Username must be a string"
        
        # Check length
        if len(username) < 2 or len(username) > MAX_USERNAME_LENGTH:
            return False, f"Username must be between 2 and {MAX_USERNAME_LENGTH} characters"
        
        # Check format
        if not re.match(USERNAME_PATTERN, username):
            return False, "Username contains invalid characters"
        
        return True, None
    
    @staticmethod
    def validate_password_strength(password):
        """
        Validate password meets security requirements
        
        Args:
            password: Password to validate
            
        Returns:
            tuple: (is_valid, error_message)
        """
        if not isinstance(password, str):
            return False, "Password must be a string"
        
        # Check length
        if len(password) < MIN_PASSWORD_LENGTH or len(password) > MAX_PASSWORD_LENGTH:
            return False, f"Password must be between {MIN_PASSWORD_LENGTH} and {MAX_PASSWORD_LENGTH} characters"
        
        # Check for uppercase
        if not re.search(r'[A-Z]', password):
            return False, "Password must contain at least one uppercase letter"
        
        # Check for lowercase
        if not re.search(r'[a-z]', password):
            return False, "Password must contain at least one lowercase letter"
        
        # Check for numbers
        if not re.search(r'[0-9]', password):
            return False, "Password must contain at least one number"
        
        # Check for special characters
        if not re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password):
            return False, "Password must contain at least one special character"
        
        return True, None


class AuthenticationManager:
    """Manages authentication and session handling"""
    
    @staticmethod
    def hash_password(password):
        """
        Hash password using bcrypt
        
        Args:
            password: Plain text password
            
        Returns:
            Hashed password string
        """
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    @staticmethod
    def verify_password(password, password_hash):
        """
        Verify password against hash
        
        Args:
            password: Plain text password
            password_hash: Hashed password (string or bytes)
            
        Returns:
            bool: True if password matches, False otherwise
        """
        try:
            # Ensure password is bytes
            if isinstance(password, str):
                password = password.encode('utf-8')
            
            # Ensure password_hash is bytes
            if isinstance(password_hash, str):
                password_hash = password_hash.encode('utf-8')
            
            # Verify password
            is_valid = bcrypt.checkpw(password, password_hash)
            
            if not is_valid:
                logger.warning("Password verification failed")
            
            return is_valid
        except Exception as e:
            logger.error(f"Password verification error: {str(e)}")
            logger.error(f"Password type: {type(password)}, Hash type: {type(password_hash)}")
            return False
    
    @staticmethod
    def generate_token(username, expires_in=None):
        """
        Generate JWT token
        
        Args:
            username: Username to encode in token
            expires_in: Token expiration in seconds
            
        Returns:
            JWT token string
        """
        if expires_in is None:
            expires_in = SecurityConfig.SESSION_TIMEOUT_MINUTES * 60
        
        payload = {
            'username': username,
            'exp': datetime.utcnow() + timedelta(seconds=expires_in),
            'iat': datetime.utcnow(),
            'jti': bcrypt.gensalt().decode('utf-8')  # Unique token ID
        }
        
        token = jwt.encode(
            payload,
            SecurityConfig.JWT_SECRET_KEY,
            algorithm='HS256'
        )
        
        logger.info(f"Token generated for user: {username}")
        return token
    
    @staticmethod
    def verify_token(token):
        """
        Verify and decode JWT token
        
        Args:
            token: JWT token string
            
        Returns:
            tuple: (is_valid, payload, error_message)
        """
        try:
            # Check if token is blacklisted (logged out)
            if token in token_blacklist:
                logger.warning("Attempted use of blacklisted token")
                return False, None, "Token has been invalidated"
            
            payload = jwt.decode(
                token,
                SecurityConfig.JWT_SECRET_KEY,
                algorithms=['HS256']
            )
            return True, payload, None
        
        except jwt.ExpiredSignatureError:
            logger.warning("Token expired")
            return False, None, "Token has expired"
        
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token: {str(e)}")
            return False, None, "Invalid token"
    
    @staticmethod
    def blacklist_token(token):
        """
        Add token to blacklist to invalidate it (for logout)
        
        Args:
            token: JWT token string to invalidate
            
        Returns:
            bool: True if blacklisted successfully
        """
        global token_blacklist
        try:
            # Prevent unbounded growth
            if len(token_blacklist) >= MAX_BLACKLIST_SIZE:
                # Remove oldest entries (convert to list, remove first half)
                token_blacklist = set(list(token_blacklist)[MAX_BLACKLIST_SIZE // 2:])
            
            token_blacklist.add(token)
            logger.info("Token added to blacklist")
            return True
        except Exception as e:
            logger.error(f"Failed to blacklist token: {e}")
            return False
    
    @staticmethod
    def authenticate_user(username, password):
        """
        Authenticate user credentials
        
        Args:
            username: Username
            password: Password
            
        Returns:
            tuple: (is_authenticated, token, error_message)
        """
        # Sanitize inputs
        username = SecurityValidator.sanitize_input(username)
        
        # Validate username
        if username != SecurityConfig.ADMIN_USERNAME:
            logger.warning(f"❌ Failed login attempt - Invalid username: {username}")
            logger.warning(f"   Expected username: {SecurityConfig.ADMIN_USERNAME}")
            return False, None, "Invalid credentials"
        
        # Get password hash dynamically (fresh from file for live updates)
        try:
            password_hash = SecurityConfig.get_admin_password_hash_dynamic()
            logger.info(f"✅ Password hash loaded successfully")
        except Exception as e:
            logger.error(f"❌ Error loading password hash: {e}")
            return False, None, "Authentication system error"
        
        # Verify password
        logger.info(f"🔐 Attempting password verification for user: {username}")
        logger.debug(f"   Password length: {len(password)}, Hash length: {len(password_hash)}")
        
        if not AuthenticationManager.verify_password(password, password_hash):
            logger.warning(f"❌ Failed password verification for user: {username}")
            return False, None, "Invalid credentials"
        
        # Password verified successfully
        logger.info(f"✅ User authenticated successfully: {username}")
        
        # Generate token
        token = AuthenticationManager.generate_token(username)
        
        logger.info(f"✅ Token generated for user: {username}")
        return True, token, None


class RateLimiter:
    """Rate limiting utilities"""
    
    @staticmethod
    def get_client_ip():
        """
        Get client IP address
        
        Returns:
            IP address string
        """
        # Check for proxy headers
        if request.headers.get('X-Forwarded-For'):
            return request.headers.get('X-Forwarded-For').split(',')[0].strip()
        elif request.headers.get('X-Real-IP'):
            return request.headers.get('X-Real-IP')
        else:
            return request.remote_addr
    
    @staticmethod
    def check_login_attempts(ip_address):
        """
        Check if IP has exceeded login attempts
        
        Args:
            ip_address: Client IP address
            
        Returns:
            tuple: (is_allowed, remaining_attempts, lockout_time)
        """
        current_time = datetime.utcnow()
        
        # Check if IP is blocked
        if ip_address in blocked_ips:
            blocked_until = blocked_ips[ip_address]
            if current_time < blocked_until:
                remaining_time = (blocked_until - current_time).seconds
                logger.warning(f"Blocked IP attempted access: {ip_address}")
                return False, 0, remaining_time
            else:
                # Unblock IP
                del blocked_ips[ip_address]
                if ip_address in failed_login_attempts:
                    del failed_login_attempts[ip_address]
        
        # Check failed attempts
        if ip_address in failed_login_attempts:
            attempts = failed_login_attempts[ip_address]
            
            # Clean old attempts (older than lockout duration)
            cutoff_time = current_time - timedelta(
                minutes=SecurityConfig.LOCKOUT_DURATION_MINUTES
            )
            attempts = [t for t in attempts if t > cutoff_time]
            failed_login_attempts[ip_address] = attempts
            
            if len(attempts) >= SecurityConfig.MAX_LOGIN_ATTEMPTS:
                # Block IP
                blocked_until = current_time + timedelta(
                    minutes=SecurityConfig.LOCKOUT_DURATION_MINUTES
                )
                blocked_ips[ip_address] = blocked_until
                logger.warning(f"IP blocked due to too many failed attempts: {ip_address}")
                return False, 0, SecurityConfig.LOCKOUT_DURATION_MINUTES * 60
            
            remaining = SecurityConfig.MAX_LOGIN_ATTEMPTS - len(attempts)
            return True, remaining, 0
        
        return True, SecurityConfig.MAX_LOGIN_ATTEMPTS, 0
    
    @staticmethod
    def record_failed_attempt(ip_address):
        """
        Record a failed login attempt
        
        Args:
            ip_address: Client IP address
        """
        current_time = datetime.utcnow()
        
        if ip_address not in failed_login_attempts:
            failed_login_attempts[ip_address] = []
        
        failed_login_attempts[ip_address].append(current_time)
        logger.warning(f"Failed login attempt recorded for IP: {ip_address}")
    
    @staticmethod
    def clear_failed_attempts(ip_address):
        """
        Clear failed login attempts for an IP
        
        Args:
            ip_address: Client IP address
        """
        if ip_address in failed_login_attempts:
            del failed_login_attempts[ip_address]
        if ip_address in blocked_ips:
            del blocked_ips[ip_address]


def require_auth(f):
    """
    Decorator to require JWT authentication
    
    Usage:
        @app.route('/protected')
        @require_auth
        def protected_route():
            return jsonify({'message': 'Access granted'})
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Get token from header
        auth_header = request.headers.get('Authorization')
        
        if not auth_header:
            logger.warning("Missing Authorization header")
            return jsonify({
                'error': 'Authentication required',
                'message': 'Missing authorization header'
            }), 401
        
        # Extract token
        try:
            token = auth_header.split(' ')[1]  # Format: "Bearer <token>"
        except IndexError:
            logger.warning("Invalid Authorization header format")
            return jsonify({
                'error': 'Authentication required',
                'message': 'Invalid authorization header format'
            }), 401
        
        # Verify token
        is_valid, payload, error = AuthenticationManager.verify_token(token)
        
        if not is_valid:
            logger.warning(f"Token verification failed: {error}")
            return jsonify({
                'error': 'Authentication failed',
                'message': error
            }), 401
        
        # Store user info in request context
        g.user = payload
        
        return f(*args, **kwargs)
    
    return decorated_function


def add_security_headers(response):
    """
    Add security headers to response
    
    Args:
        response: Flask response object
        
    Returns:
        Modified response with security headers
    """
    from security_config import SECURITY_HEADERS
    
    for header, value in SECURITY_HEADERS.items():
        response.headers[header] = value
    
    return response


def log_security_event(event_type, details, severity='INFO'):
    """
    Log security event
    
    Args:
        event_type: Type of security event
        details: Event details
        severity: Log severity level
    """
    ip_address = RateLimiter.get_client_ip()
    
    log_message = f"Security Event [{event_type}] - IP: {ip_address} - {details}"
    
    if severity == 'WARNING':
        logger.warning(log_message)
    elif severity == 'ERROR':
        logger.error(log_message)
    elif severity == 'CRITICAL':
        logger.critical(log_message)
    else:
        logger.info(log_message)
