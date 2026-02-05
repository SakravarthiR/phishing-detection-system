"""IP-based session security"""

import json
import os
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify, g
import logging
import ipaddress
import secrets

# Optional redis import (not available on Render free tier)
try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

logger = logging.getLogger(__name__)

# Initialize session storage
REDIS_CLIENT = None
USE_REDIS = False
SESSION_STORE = {}

if REDIS_AVAILABLE:
    try:
        REDIS_CLIENT = redis.Redis(
            host=os.getenv('REDIS_HOST', 'localhost'),
            port=int(os.getenv('REDIS_PORT', 6379)),
            db=int(os.getenv('REDIS_DB', 0)),
            decode_responses=True
        )
        REDIS_CLIENT.ping()
        USE_REDIS = True
        logger.info("Redis session store connected")
    except Exception as e:
        logger.warning(f"Redis connection failed: {e} - Using in-memory store")
        REDIS_CLIENT = None
        USE_REDIS = False
else:
    logger.info("Redis not installed - Using in-memory session store")

DEVICE_IP_WHITELIST = set()
WHITELISTED_DEVICES = {}
TRUSTED_PROXIES = set(os.getenv('TRUSTED_PROXIES', '127.0.0.1,localhost').split(','))


class IPSessionManager:
    """Manages sessions with strict IP validation"""
    
    CONFIG_FILE = 'device_whitelist.json'
    
    @staticmethod
    def _generate_session_id():
        """Generate a secure session ID"""
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def load_whitelisted_devices():
        """Load whitelisted device IPs from config file"""
        global DEVICE_IP_WHITELIST, WHITELISTED_DEVICES
        
        try:
            if os.path.exists(IPSessionManager.CONFIG_FILE):
                with open(IPSessionManager.CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                    WHITELISTED_DEVICES = config.get('devices', {})
                    DEVICE_IP_WHITELIST = set(WHITELISTED_DEVICES.keys())
                    logger.info(f"✅ Loaded {len(DEVICE_IP_WHITELIST)} whitelisted devices")
                    return True
            else:
                logger.warning(f"⚠️  Device whitelist file not found: {IPSessionManager.CONFIG_FILE}")
                return False
        except Exception as e:
            logger.error(f"❌ Error loading device whitelist: {e}")
            return False
    
    @staticmethod
    def get_device_name(ip_address):
        """Get friendly name of whitelisted device"""
        return WHITELISTED_DEVICES.get(ip_address, {}).get('name', 'Unknown Device')
    
    @staticmethod
    def is_device_whitelisted(ip_address):
        """Check if IP is whitelisted for privilege access"""
        return ip_address in DEVICE_IP_WHITELIST
    
    @staticmethod
    def add_whitelisted_device(ip_address, device_name, description=''):
        """Add a new whitelisted device"""
        global WHITELISTED_DEVICES, DEVICE_IP_WHITELIST
        
        # Validate inputs
        if not ip_address or not device_name:
            logger.error("Cannot add device: missing ip_address or device_name")
            return False
        
        try:
            # Validate IP address format
            try:
                ipaddress.ip_address(ip_address)
            except ValueError as e:
                logger.error(f"Invalid IP address format: {ip_address} - {e}")
                return False
            
            WHITELISTED_DEVICES[ip_address] = {
                'name': device_name,
                'description': description,
                'added_at': datetime.utcnow().isoformat(),
                'last_access': None
            }
            DEVICE_IP_WHITELIST.add(ip_address)
            
            # Save to file
            IPSessionManager._save_whitelist()
            logger.info(f"✅ Added whitelisted device: {device_name} ({ip_address})")
            return True
        except Exception as e:
            logger.error(f"❌ Error adding whitelisted device: {e}")
            return False
    
    @staticmethod
    def remove_whitelisted_device(ip_address):
        """Remove a whitelisted device"""
        global WHITELISTED_DEVICES, DEVICE_IP_WHITELIST
        
        try:
            if ip_address in WHITELISTED_DEVICES:
                device_name = WHITELISTED_DEVICES[ip_address].get('name')
                del WHITELISTED_DEVICES[ip_address]
                DEVICE_IP_WHITELIST.discard(ip_address)
                
                # Save to file
                IPSessionManager._save_whitelist()
                logger.info(f"✅ Removed whitelisted device: {device_name} ({ip_address})")
                return True
            return False
        except Exception as e:
            logger.error(f"❌ Error removing whitelisted device: {e}")
            return False
    
    @staticmethod
    def _save_whitelist():
        """Save whitelist to file"""
        try:
            config = {'devices': WHITELISTED_DEVICES}
            with open(IPSessionManager.CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=2)
            logger.debug("✅ Whitelist saved to file")
        except Exception as e:
            logger.error(f"❌ Error saving whitelist: {e}")
    
    @staticmethod
    def create_session(username, token, ip_address, user_agent, session_timeout_minutes=1440):
        """
        Create a new session tied to IP and user agent
        
        Args:
            username: Username
            token: JWT token
            ip_address: Client IP address (normalized)
            user_agent: User agent string
            session_timeout_minutes: Session timeout in minutes
            
        Returns:
            Session ID
        """
        session_id = IPSessionManager._generate_session_id()
        
        session_data = {
            'session_id': session_id,
            'username': username,
            'token': token,
            'ip_address': ip_address,
            'user_agent': user_agent,
            'created_at': datetime.utcnow().isoformat(),
            'expires_at': (datetime.utcnow() + timedelta(minutes=session_timeout_minutes)).isoformat(),
            'is_privileged': IPSessionManager.is_device_whitelisted(ip_address),
            'device_name': IPSessionManager.get_device_name(ip_address),
            'last_activity': datetime.utcnow().isoformat(),
            'request_count': 0,
            'csrf_token': secrets.token_urlsafe(32)  # CSRF protection
        }
        
        if USE_REDIS:
            # Store in Redis with TTL
            redis_key = f"session:{session_id}"
            REDIS_CLIENT.setex(
                redis_key,
                session_timeout_minutes * 60,
                json.dumps(session_data)
            )
            logger.info(f"✅ Redis session created: {username} from {ip_address}")
        else:
            # Fallback to in-memory store
            SESSION_STORE[session_id] = session_data
            logger.warning(f"⚠️  In-memory session (development only): {username} from {ip_address}")
        
        logger.info(f"✅ Session created: {username} from {ip_address} (Privileged: {session_data['is_privileged']})")
        return session_id
    
    @staticmethod
    def validate_session(session_id, ip_address, user_agent, csrf_token=None):
        """
        Validate session with strict IP and user agent matching.
        Prevents session fixation and hijacking attacks.
        
        Args:
            session_id: Session ID
            ip_address: Current client IP (normalized)
            user_agent: Current user agent
            csrf_token: CSRF token from request
            
        Returns:
            tuple: (is_valid, session_data, error_message)
        """
        if USE_REDIS:
            redis_key = f"session:{session_id}"
            session_json = REDIS_CLIENT.get(redis_key)
            if not session_json:
                return False, None, "Session not found or expired"
            session = json.loads(session_json)
        else:
            if session_id not in SESSION_STORE:
                return False, None, "Session not found"
            session = SESSION_STORE[session_id]
        
        # Check expiration
        expires_at = datetime.fromisoformat(session['expires_at'])
        if datetime.utcnow() > expires_at:
            if USE_REDIS:
                REDIS_CLIENT.delete(f"session:{session_id}")
            else:
                del SESSION_STORE[session_id]
            return False, None, "Session expired"
        
        # Strict IP validation - must match exactly (now handles IPv6)
        if not ips_equal(session['ip_address'], ip_address):
            logger.warning(f"❌ Session IP mismatch: {session['username']} - Expected: {session['ip_address']}, Got: {ip_address}")
            return False, None, "Session IP mismatch - Access denied"
        
        # CSRF token validation
        if csrf_token and session.get('csrf_token') != csrf_token:
            logger.warning(f"❌ CSRF token mismatch for {session['username']} - Possible CSRF attack")
            return False, None, "CSRF validation failed"
        
        # User agent validation (optional - can be bypassed in some cases)
        if session['user_agent'] and session['user_agent'] != user_agent:
            logger.warning(f"⚠️  User agent mismatch for {session['username']} - Possible session hijacking")
            # Log but don't deny - user agent changes are common
        
        # Update last activity and request count
        session['last_activity'] = datetime.utcnow().isoformat()
        session['request_count'] = session.get('request_count', 0) + 1
        
        # Save updated session
        if USE_REDIS:
            redis_key = f"session:{session_id}"
            # Get remaining TTL
            ttl = REDIS_CLIENT.ttl(redis_key)
            if ttl > 0:
                REDIS_CLIENT.setex(redis_key, ttl, json.dumps(session))
        else:
            SESSION_STORE[session_id] = session
        
        return True, session, None
    
    @staticmethod
    def get_session_info(session_id):
        """Get session information"""
        return SESSION_STORE.get(session_id)
    
    @staticmethod
    def destroy_session(session_id):
        """Destroy a session securely"""
        try:
            if USE_REDIS:
                REDIS_CLIENT.delete(f"session:{session_id}")
            else:
                if session_id in SESSION_STORE:
                    del SESSION_STORE[session_id]
            logger.info(f"✅ Session destroyed: {session_id}")
            return True
        except Exception as e:
            logger.error(f"Error destroying session: {e}")
            return False
    
    @staticmethod
    def cleanup_expired_sessions():
        """Remove expired sessions"""
        if USE_REDIS:
            # Redis auto-expires with TTL, no manual cleanup needed
            logger.debug("Redis auto-expires sessions via TTL")
            return 0
        else:
            # Manual cleanup for in-memory store
            current_time = datetime.utcnow()
            expired_sessions = [
                sid for sid, session in SESSION_STORE.items()
                if datetime.fromisoformat(session['expires_at']) < current_time
            ]
            
            for sid in expired_sessions:
                del SESSION_STORE[sid]
            
            if expired_sessions:
                logger.debug(f"🧹 Cleaned up {len(expired_sessions)} expired sessions")
            
            return len(expired_sessions)


def normalize_ip(ip_str):
    """
    Normalize IP address to support both IPv4 and IPv6.
    Validates IP format and returns standardized string.
    """
    try:
        # Parse and normalize IP address
        ip_obj = ipaddress.ip_address(ip_str)
        return str(ip_obj)
    except ValueError:
        logger.warning(f"Invalid IP address format: {ip_str}")
        return ip_str  # Return as-is if invalid


def ips_equal(ip1, ip2):
    """
    Compare two IP addresses for equality.
    Handles both IPv4 and IPv6, with normalization.
    """
    try:
        return ipaddress.ip_address(ip1) == ipaddress.ip_address(ip2)
    except ValueError:
        # Fallback to string comparison if parsing fails
        return ip1 == ip2


def get_user_agent():
    """Extract user agent from request"""
    return request.headers.get('User-Agent', '')[:500]  # Limit length for storage


def get_csrf_token_from_request():
    """Extract CSRF token from request header"""
    return request.headers.get('X-CSRF-Token', '')


def get_client_ip():
    """
    Extract client IP from request with security validation.
    Prevents IP spoofing by validating X-Forwarded-For header.
    """
    # Direct connection IP (most secure - always trust this)
    remote_addr = request.remote_addr
    
    # Only process X-Forwarded-For if from trusted proxy
    if request.headers.get('X-Forwarded-For'):
        # Check if direct connection is from trusted proxy
        if remote_addr in TRUSTED_PROXIES:
            # Safe to trust X-Forwarded-For
            forwarded_for = request.headers.get('X-Forwarded-For').split(',')[0].strip()
            logger.debug(f"Trusting X-Forwarded-For from proxy {remote_addr}: {forwarded_for}")
            return normalize_ip(forwarded_for)
        else:
            # Untrusted proxy trying to spoof header - log and ignore
            logger.warning(f"⚠️  Untrusted X-Forwarded-For header from {remote_addr}: {request.headers.get('X-Forwarded-For')}")
    
    # Use X-Real-IP if available and from trusted proxy
    if request.headers.get('X-Real-IP') and remote_addr in TRUSTED_PROXIES:
        return normalize_ip(request.headers.get('X-Real-IP'))
    
    # Fall back to direct connection IP
    return normalize_ip(remote_addr)


def require_session(f):
    """
    Decorator to require valid session with strict IP validation.
    Prevents session fixation and hijacking attacks.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Extract session ID from Authorization header (Bearer token)
        session_id = None
        auth_header = request.headers.get('Authorization', '')
        
        if not auth_header.startswith('Bearer '):
            logger.warning(f"❌ Missing or invalid Authorization header from {request.remote_addr}")
            return jsonify({
                'error': 'Unauthorized',
                'message': 'Missing Authorization header'
            }), 401
        
        session_id = auth_header[7:].strip()
        
        if not session_id or len(session_id) < 20:  # Basic validation
            return jsonify({
                'error': 'Unauthorized',
                'message': 'Invalid session token'
            }), 401
        
        # Validate session with strict IP checking
        ip_address = get_client_ip()
        user_agent = get_user_agent()
        csrf_token = get_csrf_token_from_request()
        
        is_valid, session_data, error = IPSessionManager.validate_session(
            session_id, ip_address, user_agent, csrf_token
        )
        
        if not is_valid:
            logger.warning(f"❌ Session validation failed: {error} from {ip_address}")
            return jsonify({
                'error': 'Session invalid',
                'message': error,
                'code': 'SESSION_INVALID'
            }), 401
        
        # Store session info in Flask g for route access
        g.session = session_data
        g.session_id = session_id
        g.ip_address = ip_address
        g.is_privileged = session_data.get('is_privileged', False)
        g.csrf_token = session_data.get('csrf_token')
        
        return f(*args, **kwargs)
    
    return decorated_function


def require_privilege(f):
    """
    Decorator to require privileged session (whitelisted IP).
    Must be used AFTER require_session decorator.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # First check if session decorator ran
        if not hasattr(g, 'is_privileged') or not hasattr(g, 'session'):
            return jsonify({
                'error': 'Unauthorized',
                'message': 'Session required for this operation'
            }), 401
        
        # Check if user has privilege
        if not g.is_privileged:
            logger.warning(f"❌ Privilege access denied for {g.session['username']} from {g.ip_address} - Not whitelisted")
            return jsonify({
                'error': 'Insufficient privileges',
                'message': 'This operation requires a whitelisted device',
                'required': 'Device must be in whitelist',
                'current_ip': g.ip_address
            }), 403
        
        logger.info(f"✅ Privileged access granted to {g.session['username']} from {g.ip_address}")
        return f(*args, **kwargs)
    
    return decorated_function
