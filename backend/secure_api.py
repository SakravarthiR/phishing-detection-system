"""Phishing Detection API Server"""

from flask import Flask, request, jsonify, g, send_from_directory
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os
import sys
from datetime import datetime
import gc
import requests
import logging


if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

logger = logging.getLogger(__name__)


def cleanup_memory():
    try:
        gc.collect()
        if hasattr(IPSessionManager, 'cleanup_expired_sessions'):
            IPSessionManager.cleanup_expired_sessions()
    except Exception as e:
        logger.debug(f"Memory cleanup error: {e}")


# Import security modules
from security_config import SecurityConfig, SECURITY_HEADERS
from security_utils import (
    SecurityValidator,
    AuthenticationManager,
    RateLimiter,
    require_auth,
    add_security_headers,
    log_security_event,
    logger
)
from advanced_security import (
    advanced_security_check,
    DDoSProtection,
    AdvancedSecurityConfig
)
from ip_session_security import (
    IPSessionManager,
    require_session,
    require_privilege,
    get_client_ip,
    get_user_agent,
    get_csrf_token_from_request,
    normalize_ip
)

# Enterprise-grade security system
from good_security import (
    good_security_check,
    record_login_result,
    DeviceFingerprint,
    DeviceTrustManager,
    AccountLockout,
    AnomalyDetector,
    LoginHistory,
    TOTPManager,
    PasswordSecurity,
    SecurityChallenge,
    enable_mfa,
    verify_mfa,
    is_mfa_enabled,
    get_user_security_status,
    AuthSecurityConfig
)

# Import ML modules
from phish_detector import (
    load_model,
    predict_url,
    get_top_feature,
    extract_subdomain_info,
    check_website_live,
    get_professional_risk_assessment
)

from phishtank_integration import check_phishtank, get_phishtank_db
from subdomain_scanner import SubdomainScanner

try:
    from memory_optimizer import cleanup_memory, get_memory_usage, memory_efficient
except ImportError:
    def cleanup_memory(): gc.collect()
    def get_memory_usage(): return 0
    def memory_efficient(f): return f

from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


def create_session_with_pool():
    session = requests.Session()
    adapter = HTTPAdapter(
        pool_connections=10,
        pool_maxsize=10,
        max_retries=Retry(total=2, backoff_factor=0.3)
    )
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session


REQUESTS_SESSION = create_session_with_pool()

import os
FRONTEND_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'frontend')

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path='')
app.config.from_object(SecurityConfig)

try:
    from flask_compress import Compress
    Compress(app)
except ImportError as e:
    logger.warning(f"Flask-Compress not available: {str(e)}")

ALLOWED_ORIGINS = [
    'http://localhost',
    'http://127.0.0.1',
    'http://localhost:80',
    'http://127.0.0.1:80',
    'http://localhost:5000',
    'http://127.0.0.1:5000',
    'https://phishing-detection-system-1.onrender.com',
    'https://phishingdetector.systems',
    'http://phishingdetector.systems',
    'null'
]


@app.after_request
def after_request_cors(response):
    origin = request.headers.get('Origin', '')
    response.headers['Access-Control-Allow-Origin'] = origin if origin else '*'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, Accept, X-Requested-With'
    response.headers['Access-Control-Max-Age'] = '3600'
    return response


limiter = Limiter(
    app=app,
    key_func=lambda: get_client_ip(),
    storage_uri=SecurityConfig.RATE_LIMIT_STORAGE_URL,
    default_limits=[
        f"{SecurityConfig.RATE_LIMIT_PER_MINUTE} per minute",
        f"{SecurityConfig.RATE_LIMIT_PER_HOUR} per hour"
    ],
    enabled=SecurityConfig.RATE_LIMIT_ENABLED,
    in_memory_fallback_enabled=True
)

model = None
model_loaded = False
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'phish_model.pkl')


def initialize_model():
    global model, model_loaded
    logger.info("Initializing phishing detector API...")
    model = load_model(MODEL_PATH)
    if model is not None:
        model_loaded = True
        logger.info("API ready with trained model")
    else:
        model_loaded = False
        logger.warning("API started but model not loaded")


IPSessionManager.load_whitelisted_devices()
logger.info("IP Session Security initialized")

initialize_model()

# Frontend served from same Render deployment
FRONTEND_URL = ''  # Empty for same-origin


@app.route('/')
def serve_index():
    """Serve the main index page"""
    from flask import send_from_directory
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/<path:filename>')
def serve_static(filename):
    """Serve static files from frontend folder"""
    from flask import send_from_directory
    if os.path.exists(os.path.join(app.static_folder, filename)):
        return send_from_directory(app.static_folder, filename)
    return jsonify({'error': 'Not found'}), 404

@app.before_request
def security_checks():
    """
    Perform advanced security checks before each request
    Includes DDoS/DoS protection, IP whitelisting, and memory monitoring
    """
    # Allow CORS preflight requests to pass through without security checks
    if request.method == 'OPTIONS':
        logger.debug(f"CORS preflight request: {request.path}")
        return None
    
    # Memory check for 512MB Render - prevent OOM
    try:
        mem_usage = get_memory_usage()
        if mem_usage > 180:  # Above 180MB, trigger cleanup
            logger.warning(f"High memory usage: {mem_usage:.1f}MB - triggering cleanup")
            cleanup_memory()
        if mem_usage > 250:  # Critical - refuse new requests temporarily
            logger.critical(f"CRITICAL memory: {mem_usage:.1f}MB - rejecting request")
            return jsonify({
                'error': 'Server busy',
                'message': 'Server is temporarily overloaded. Please retry in a few seconds.'
            }), 503
    except Exception as e:
        logger.debug(f"Memory check error: {e}")
    
    try:
        # Get client IP with null check
        ip_address = RateLimiter.get_client_ip()
        if not ip_address:
            logger.warning("Could not determine client IP address")
            ip_address = 'unknown'
        
        # Advanced security check (DDoS/DoS protection, IP whitelisting, pattern detection)
        is_allowed, error_response, http_code = advanced_security_check(request, ip_address)
        
        if not is_allowed:
            logger.critical(f"Security violation: {ip_address} - {error_response.get('code')}")
            return jsonify(error_response), http_code
        
        # Check content length
        if request.content_length and request.content_length > SecurityConfig.MAX_CONTENT_LENGTH:
            DDoSProtection.handle_violation(ip_address, 'Oversized request')
            log_security_event(
                'REQUEST_TOO_LARGE',
                f'Content length: {request.content_length}',
                'WARNING'
            )
            return jsonify({
                'error': 'Request too large',
                'message': 'Request body exceeds maximum allowed size'
            }), 413
        
        # Validate content type for POST requests
        if request.method == 'POST':
            content_type = request.headers.get('Content-Type', '')
            if not content_type.startswith('application/json'):
                log_security_event(
                    'INVALID_CONTENT_TYPE',
                    f'Content-Type: {content_type}',
                    'WARNING'
                )
                return jsonify({
                    'error': 'Invalid content type',
                    'message': 'Content-Type must be application/json'
                }), 415
        
        # Log request
        logger.info(f"Request: {request.method} {request.path} from {ip_address}")
    except Exception as e:
        logger.error(f"Error in security_checks: {e}", exc_info=True)
        # Don't block requests if security checks fail
        return None


@app.after_request
def after_request(response):
    """Add security headers to all responses and cleanup connections"""
    # Cleanup connection tracking
    ip_address = RateLimiter.get_client_ip()
    DDoSProtection.check_concurrent_connections(ip_address, 'disconnect')
    
    # Add security headers first
    response = add_security_headers(response)
    
    # Then ALWAYS add CORS headers (must be last to not get overwritten)
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With, Accept'
    response.headers['Access-Control-Max-Age'] = '3600'
    
    return response


@app.teardown_appcontext
def cleanup_security_data(exception=None):
    """Periodic cleanup of security tracking data"""
    DDoSProtection.cleanup_old_data()


@app.errorhandler(429)
def ratelimit_handler(e):
    """Handle rate limit exceeded"""
    log_security_event(
        'RATE_LIMIT_EXCEEDED',
        f'Endpoint: {request.path}',
        'WARNING'
    )
    return jsonify({
        'error': 'Rate limit exceeded',
        'message': 'Too many requests. Please try again later.'
    }), 429


@app.after_request
def optimize_response(response):
    """Optimize response for low bandwidth and memory"""
    # Add cache headers for responses
    response.headers['Cache-Control'] = 'public, max-age=3600'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Vary'] = 'Accept-Encoding'  # Cache by encoding
    
    # NOTE: Removed Content-Encoding: gzip - was causing "Failed to fetch" 
    # because data wasn't actually compressed. Flask-Compress handles real compression.
    
    # Cleanup memory after request
    try:
        mem = get_memory_usage()
        if mem > 200:  # If using more than 200MB
            cleanup_memory()
    except Exception as e:
        logger.debug(f"Memory cleanup check failed: {e}")
        pass
    
    return response


@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({
        'error': 'Not found',
        'message': 'Endpoint does not exist'
    }), 404


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    logger.error(f"Internal server error: {str(error)}")
    cleanup_memory()  # Force cleanup on errors
    return jsonify({
        'error': 'Internal server error',
        'message': 'An unexpected error occurred'
    }), 500



# ========================
# PUBLIC ENDPOINTS
# ========================


@app.route('/health', methods=['GET'])
@limiter.limit("200 per minute")
def health_check():
    """
    Health check endpoint (public)
    
    Returns:
        JSON with status and model information
    """
    return jsonify({
        'status': 'online',
        'timestamp': datetime.utcnow().isoformat(),
        'model_loaded': model_loaded,
        'security': 'enabled',
        'message': 'Model ready' if model_loaded else 'Model not loaded'
    }), 200


@app.route('/demo-login', methods=['POST'])
def demo_login():
    """
    Demo login endpoint - DISABLED FOR SECURITY
    This endpoint has been removed to prevent authentication bypass.
    """
    logger.warning(f"Attempted access to disabled /demo-login endpoint from {RateLimiter.get_client_ip()}")
    return jsonify({
        'error': 'Forbidden',
        'message': 'This endpoint is not available'
    }), 403


@app.route('/login', methods=['POST', 'OPTIONS'])
def login():
    """
    User authentication endpoint with enterprise-level security
    
    Features:
    - Progressive account lockout
    - Device fingerprinting & trust
    - Anomaly detection
    - MFA support
    - Login history tracking
    
    Request JSON:
        {
            "username": "admin",
            "password": "password123",
            "mfa_code": "123456",  // Optional - required if MFA enabled
            "trust_device": true   // Optional - remember this device
        }
    
    Response JSON:
        {
            "success": true,
            "token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
            "expires_in": 86400,
            "message": "Authentication successful",
            "security": {
                "device_trusted": true,
                "anomaly_score": 0,
                "mfa_enabled": false,
                "new_device": false
            }
        }
    """
    # Handle CORS preflight
    if request.method == 'OPTIONS':
        logger.debug("OPTIONS preflight for /login")
        return '', 200
    
    try:
        # Get client IP
        ip_address = RateLimiter.get_client_ip()
        
        # Validate request
        if not request.is_json:
            return jsonify({
                'success': False,
                'error': 'Invalid request',
                'message': 'Content-Type must be application/json'
            }), 400
        
        data = request.get_json()
        
        # Validate required fields
        if 'username' not in data or 'password' not in data:
            return jsonify({
                'success': False,
                'error': 'Missing fields',
                'message': 'Username and password are required'
            }), 400
        
        username = data['username'].strip() if isinstance(data['username'], str) else ''
        password = data['password'] if isinstance(data['password'], str) else ''
        mfa_code = data.get('mfa_code', '').strip() if isinstance(data.get('mfa_code'), str) else ''
        trust_device = data.get('trust_device', False)
        
        # Validate input types
        if not isinstance(username, str) or not isinstance(password, str):
            return jsonify({
                'success': False,
                'error': 'Invalid input',
                'message': 'Username and password must be strings'
            }), 400
        
        # Check for empty values
        if not username or not password:
            return jsonify({
                'success': False,
                'error': 'Invalid input',
                'message': 'Username and password cannot be empty'
            }), 400
        
        # ============================================
        # ENTERPRISE-LEVEL SECURITY CHECK (Pre-auth)
        # ============================================
        security_check = good_security_check(request, username, password)
        
        # Check if account is locked
        if not security_check['allowed']:
            log_security_event(
                'ACCOUNT_LOCKED',
                f'Username: {username}, IP: {ip_address}, Lockout: {security_check["lockout_seconds"]}s',
                'WARNING'
            )
            return jsonify({
                'success': False,
                'error': 'Account locked',
                'message': security_check['message'],
                'lockout_seconds': security_check['lockout_seconds'],
                'remaining_attempts': 0
            }), 429
        
        # Validate username format
        is_valid, error_msg = SecurityValidator.validate_username(username)
        if not is_valid:
            log_security_event(
                'INVALID_USERNAME_FORMAT',
                f'Username: {username[:50]}, Error: {error_msg}',
                'WARNING'
            )
            record_login_result(username, ip_address, security_check['device_fingerprint'], 
                              security_check['device_info'], False)
            return jsonify({
                'success': False,
                'error': 'Invalid username format',
                'message': error_msg,
                'remaining_attempts': security_check['remaining_attempts'] - 1
            }), 400
        
        # Check for suspicious patterns
        if SecurityValidator.check_suspicious_input(username):
            log_security_event(
                'SUSPICIOUS_LOGIN_ATTEMPT',
                f'Username: {username[:50]}, Anomaly Score: {security_check["anomaly_score"]}',
                'WARNING'
            )
            record_login_result(username, ip_address, security_check['device_fingerprint'],
                              security_check['device_info'], False)
            return jsonify({
                'success': False,
                'error': 'Invalid credentials',
                'message': 'Authentication failed',
                'remaining_attempts': security_check['remaining_attempts'] - 1
            }), 401
        
        # ============================================
        # AUTHENTICATE USER
        # ============================================
        is_authenticated, token, error = AuthenticationManager.authenticate_user(
            username,
            password
        )
        
        if not is_authenticated:
            # Record failed attempt with security system
            record_login_result(username, ip_address, security_check['device_fingerprint'],
                              security_check['device_info'], False)
            
            # Get remaining attempts
            remaining = AccountLockout.get_remaining_attempts(ip_address)
            
            log_security_event(
                'FAILED_LOGIN',
                f'Username: {username}, Remaining attempts: {remaining}, Device: {security_check["device_info"]["browser"]}',
                'WARNING'
            )
            
            return jsonify({
                'success': False,
                'error': 'Authentication failed',
                'message': error or 'Invalid username or password',
                'remaining_attempts': remaining,
                'security': {
                    'anomaly_score': security_check['anomaly_score'],
                    'alerts': [a['message'] for a in security_check['security_alerts']]
                }
            }), 401
        
        # ============================================
        # MFA VERIFICATION (if enabled)
        # ============================================
        mfa_enabled = is_mfa_enabled(username)
        requires_mfa = mfa_enabled or (security_check['requires_mfa'] and security_check['anomaly_score'] >= 50)
        
        if requires_mfa and mfa_enabled:
            if not mfa_code:
                # MFA required but not provided
                log_security_event(
                    'MFA_REQUIRED',
                    f'Username: {username}, Anomaly Score: {security_check["anomaly_score"]}',
                    'INFO'
                )
                return jsonify({
                    'success': False,
                    'mfa_required': True,
                    'challenge_id': security_check.get('challenge_id'),
                    'message': 'MFA verification required',
                    'security': {
                        'anomaly_score': security_check['anomaly_score'],
                        'new_device': not security_check['device_trusted'],
                        'alerts': [a['message'] for a in security_check['security_alerts']]
                    }
                }), 200  # 200 to indicate partial success
            
            # Verify MFA code
            mfa_valid, mfa_message = verify_mfa(username, mfa_code)
            if not mfa_valid:
                record_login_result(username, ip_address, security_check['device_fingerprint'],
                                  security_check['device_info'], False)
                log_security_event(
                    'MFA_FAILED',
                    f'Username: {username}, Reason: {mfa_message}',
                    'WARNING'
                )
                return jsonify({
                    'success': False,
                    'error': 'MFA verification failed',
                    'message': mfa_message,
                    'mfa_required': True
                }), 401
        
        # ============================================
        # LOGIN SUCCESS - Record and Create Session
        # ============================================
        
        # Record successful login with security system
        record_login_result(
            username, ip_address, 
            security_check['device_fingerprint'],
            security_check['device_info'], 
            True, 
            trust_device=trust_device
        )
        
        log_security_event(
            'SUCCESSFUL_LOGIN',
            f'Username: {username}, Device: {security_check["device_info"]["browser"]}/{security_check["device_info"]["os"]}, Trusted: {security_check["device_trusted"]}',
            'INFO'
        )
        
        # Create IP-bound session
        user_agent = get_user_agent()
        session_id = IPSessionManager.create_session(
            username=username,
            token=token,
            ip_address=normalize_ip(ip_address),
            user_agent=user_agent,
            session_timeout_minutes=SecurityConfig.SESSION_TIMEOUT_MINUTES
        )
        
        is_privileged = IPSessionManager.is_device_whitelisted(ip_address)
        device_name = IPSessionManager.get_device_name(ip_address)
        
        # Get session data to extract CSRF token
        session_data = IPSessionManager.get_session_info(session_id)
        csrf_token = session_data.get('csrf_token') if session_data else None
        
        # Get recent login history for security notification
        recent_logins = LoginHistory.get_recent_logins(username, 5)
        
        logger.info(f"✅ Login successful - User: {username}, Session: {session_id}, IP: {ip_address}, Privileged: {is_privileged}")
        
        return jsonify({
            'success': True,
            'token': token,
            'session_id': session_id,
            'csrf_token': csrf_token,
            'expires_in': SecurityConfig.SESSION_TIMEOUT_MINUTES * 60,
            'message': 'Authentication successful',
            'privileged': is_privileged,
            'device_name': device_name,
            'security': {
                'device_trusted': security_check['device_trusted'] or trust_device,
                'device_fingerprint': security_check['device_fingerprint'][:8] + '...',
                'anomaly_score': security_check['anomaly_score'],
                'mfa_enabled': mfa_enabled,
                'new_device': not security_check['device_trusted'],
                'recent_logins': len(recent_logins),
                'alerts': [a['message'] for a in security_check['security_alerts']] if security_check['security_alerts'] else []
            }
        }), 200
    
    except Exception as e:
        logger.exception(f"Login error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Authentication failed',
            'message': 'An error occurred during authentication'
        }), 500


# ========================
# SECURITY MANAGEMENT ENDPOINTS
# ========================

@app.route('/security/status', methods=['GET', 'OPTIONS'])
@require_auth
def security_status():
    """Get user's security status including devices, login history, MFA status"""
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        username = g.get('current_user', 'unknown')
        status = get_user_security_status(username)
        
        return jsonify({
            'success': True,
            'security': status
        }), 200
    except Exception as e:
        logger.error(f"Security status error: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/security/mfa/enable', methods=['POST', 'OPTIONS'])
@require_auth
def enable_mfa_endpoint():
    """Enable MFA for current user"""
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        username = g.get('current_user', 'unknown')
        mfa_setup = enable_mfa(username)
        
        log_security_event('MFA_ENABLED', f'User: {username}', 'INFO')
        
        return jsonify({
            'success': True,
            'mfa': {
                'secret': mfa_setup['secret'],
                'provisioning_uri': mfa_setup['provisioning_uri'],
                'backup_codes': mfa_setup['backup_codes']
            },
            'message': 'MFA enabled successfully. Save your backup codes!'
        }), 200
    except Exception as e:
        logger.error(f"MFA enable error: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/security/devices', methods=['GET', 'OPTIONS'])
@require_auth
def get_trusted_devices():
    """Get list of trusted devices"""
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        username = g.get('current_user', 'unknown')
        devices = DeviceTrustManager.get_trusted_devices(username)
        
        return jsonify({
            'success': True,
            'devices': devices
        }), 200
    except Exception as e:
        logger.error(f"Get devices error: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/security/devices/revoke', methods=['POST', 'OPTIONS'])
@require_auth
def revoke_device():
    """Revoke a trusted device"""
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        username = g.get('current_user', 'unknown')
        data = request.get_json()
        fingerprint = data.get('fingerprint')
        
        if data.get('all'):
            DeviceTrustManager.revoke_all_devices(username)
            log_security_event('ALL_DEVICES_REVOKED', f'User: {username}', 'WARNING')
            return jsonify({'success': True, 'message': 'All devices revoked'}), 200
        
        if fingerprint:
            DeviceTrustManager.revoke_device(username, fingerprint)
            log_security_event('DEVICE_REVOKED', f'User: {username}, Device: {fingerprint[:8]}', 'INFO')
            return jsonify({'success': True, 'message': 'Device revoked'}), 200
        
        return jsonify({'success': False, 'message': 'No device specified'}), 400
    except Exception as e:
        logger.error(f"Revoke device error: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/security/history', methods=['GET', 'OPTIONS'])
@require_auth
def get_login_history():
    """Get login history for current user"""
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        username = g.get('current_user', 'unknown')
        limit = request.args.get('limit', 20, type=int)
        history = LoginHistory.get_recent_logins(username, limit)
        
        return jsonify({
            'success': True,
            'history': history
        }), 200
    except Exception as e:
        logger.error(f"Login history error: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500


# ========================
# PROTECTED ENDPOINTS
# ========================

@app.route('/phishtank/stats', methods=['GET'])
@require_auth
def phishtank_stats():
    """
    Get PhishTank database statistics (PROTECTED)
    
    Headers:
        Authorization: Bearer <jwt_token>
    
    Response JSON:
        {
            "total_entries": 12345,
            "last_update": "2025-10-22T10:30:00",
            "cache_exists": true,
            "cache_size_mb": 15.3
        }
    """
    try:
        db = get_phishtank_db()
        stats = db.get_stats()
        return jsonify(stats), 200
    except Exception as e:
        logger.error(f"PhishTank stats error: {str(e)}")
        return jsonify({
            'error': 'Failed to get stats',
            'message': 'An error occurred while retrieving statistics'
        }), 500


@app.route('/phishtank/update', methods=['POST'])
@require_auth
@limiter.limit("1 per hour")
def phishtank_update():
    """
    Manually trigger PhishTank database update (PROTECTED, RATE LIMITED)
    
    Headers:
        Authorization: Bearer <jwt_token>
    
    Response JSON:
        {
            "success": true,
            "message": "Database updated successfully",
            "total_entries": 12345
        }
    """
    try:
        db = get_phishtank_db()
        success = db.update_database(force=True)
        
        if success:
            stats = db.get_stats()
            log_security_event(
                'PHISHTANK_UPDATE',
                f'Database updated: {stats["total_entries"]} entries',
                'INFO'
            )
            return jsonify({
                'success': True,
                'message': 'Database updated successfully',
                'total_entries': stats['total_entries'],
                'last_update': stats['last_update']
            }), 200
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to update database'
            }), 500
            
    except Exception as e:
        logger.error(f"PhishTank update error: {str(e)}")
        return jsonify({
            'error': 'Update failed',
            'message': 'An error occurred during update'
        }), 500

@app.route('/predict', methods=['POST', 'OPTIONS'])
@limiter.limit("30 per minute")
def predict():
    """
    Predict whether a URL is phishing or legitimate
    
    For authenticated users: Full features with higher rate limits
    For anonymous users: Basic scan with rate limiting
    
    Headers (optional):
        Authorization: Bearer <jwt_token>
    
    Request JSON:
        {
            "url": "https://example.com"
        }
    
    Response JSON:
        {
            "url": "...",
            "label": 0 or 1,
            "prediction": "legitimate" or "phishing",
            "probability": 0.0 to 1.0,
            "probability_percent": 0.0 to 100.0,
            "reason": "explanation",
            "features": {...},
            "website_status": {...}
        }
    """
    # Handle CORS preflight
    if request.method == 'OPTIONS':
        response = app.make_default_options_response()
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, Accept'
        # Always return a minimal JSON body for frontend compatibility
        return jsonify({"status": "ok"}), 200
    
    try:
        # Check if model is loaded
        if not model_loaded or model is None:
            return jsonify({
                'error': 'Model not loaded',
                'message': 'ML model is not available. Please contact administrator.'
            }), 503
        
        # Validate request
        if not request.is_json:
            return jsonify({
                'error': 'Invalid request',
                'message': 'Content-Type must be application/json'
            }), 400
        
        data = request.get_json()
        
        # Validate URL field exists
        if 'url' not in data:
            return jsonify({
                'error': 'Missing field',
                'message': 'Request must include "url" field'
            }), 400
        
        url = data['url']
        
        # Validate and sanitize URL
        is_valid, sanitized_url, error = SecurityValidator.validate_url(url)
        
        if not is_valid:
            log_security_event(
                'INVALID_URL_SUBMISSION',
                f'URL: {url[:100]}, Error: {error}',
                'WARNING'
            )
            return jsonify({
                'error': 'Invalid URL',
                'message': error
            }), 400
        
        # Log prediction request
        logger.info(f"Prediction request for URL: {sanitized_url}")
        
        # ===== CHECK PHISHTANK DATABASE FIRST =====
        phishtank_result = check_phishtank(sanitized_url)
        
        if phishtank_result:
            # URL found in PhishTank - it's verified phishing!
            logger.warning(f"⚠️ URL found in PhishTank database: {sanitized_url}")
            
            # Check website status
            website_status = check_website_live(sanitized_url, timeout=5)
            
            # Get risk assessment for verified phishing
            risk_assessment = get_professional_risk_assessment(0.99, 1, {})
            
            response = {
                'url': sanitized_url,
                'label': 1,  # Phishing
                'prediction': 'phishing',
                'probability': 0.99,  # Very high confidence in phishing
                'confidence_percent': 99.0,  # 99% confident it's phishing
                'reason': f"⚠️ VERIFIED PHISHING by PhishTank | Target: {phishtank_result['target']} | Phish ID: {phishtank_result['phish_id']}",
                'confidence_level': 'high',
                'risk_assessment': risk_assessment,  # Professional risk evaluation
                'phishtank_verified': True,
                'phishtank_data': {
                    'phish_id': phishtank_result['phish_id'],
                    'target': phishtank_result['target'],
                    'submission_time': phishtank_result['submission_time'],
                    'verification_time': phishtank_result['verification_time'],
                    'detail_url': phishtank_result['phish_detail_url']
                },
                'features': {},
                'website_status': website_status,
                'scanned_at': datetime.utcnow().isoformat()
            }
            
            log_security_event(
                'PHISHTANK_MATCH',
                f'URL: {sanitized_url}, Phish ID: {phishtank_result["phish_id"]}, Target: {phishtank_result["target"]}',
                'CRITICAL'
            )
            
            cleanup_memory()  # Clean up after PhishTank check
            return jsonify(response), 200
        
        # Not in PhishTank, proceed with ML prediction
        try:
            # Make prediction
            logger.info(f"Calling predict_url() for: {sanitized_url}")
            label, probability, features = predict_url(sanitized_url, model)
            logger.info(f"✅ Prediction complete: label={label}, prob={probability}")
        except Exception as e:
            logger.error(f"❌ Prediction error: {str(e)}")
            logger.error(f"Error type: {type(e).__name__}")
            logger.exception("Prediction exception details:")
            return jsonify({
                'error': 'Prediction failed',
                'message': f'Failed to predict: {str(e)}'
            }), 500
        
        # Check website status
        try:
            logger.info(f"Checking website status: {sanitized_url}")
            website_status = check_website_live(sanitized_url, timeout=5)
            logger.info(f"✅ Website status checked")
        except Exception as e:
            logger.error(f"⚠️ Website status check error: {str(e)}")
            website_status = {'is_live': False, 'error': str(e)}
        
        # Get explanation
        try:
            logger.info(f"Getting top feature explanation")
            reason = get_top_feature(features)
            logger.info(f"✅ Reason: {reason}")
        except Exception as e:
            logger.error(f"⚠️ Feature explanation error: {str(e)}")
            reason = f"Prediction: {'phishing' if label == 1 else 'legitimate'}"
        
        # Prepare response
        # The probability from predict_url is already confidence (inverted for legit URLs in phish_detector.py)
        # For phishing (label=1): probability = combined_phish_prob
        # For legitimate (label=0): probability = 1.0 - combined_phish_prob (already inverted!)
        safe_probability = max(0.0, min(1.0, probability))
        
        # Use the confidence as-is (it's already properly inverted by predict_url)
        display_confidence = safe_probability
        confidence_percent = round(display_confidence * 100, 2)
        
        # For risk assessment, pass the combined phishing probability directly
        # The function will interpret it correctly based on the label
        combined_phish_prob = features.get('combined_phish_prob', 0.5)
        
        # Get professional risk assessment
        risk_assessment = get_professional_risk_assessment(combined_phish_prob, label, features)
        
        response = {
            'url': sanitized_url,
            'label': label,
            'prediction': 'phishing' if label == 1 else 'legitimate',
            'probability': round(safe_probability, 4),  # Confidence in the prediction
            'confidence_percent': confidence_percent,  # Confidence percentage (0-100)
            'reason': reason,
            'confidence_level': 'high' if display_confidence > 0.8 else ('low' if display_confidence < 0.2 else 'medium'),
            'risk_assessment': risk_assessment,  # Professional risk evaluation
            'phishtank_verified': False,  # Not in PhishTank database
            'features': features,
            'website_status': website_status,
            'scanned_at': datetime.utcnow().isoformat()
        }
        
        log_security_event(
            'URL_PREDICTION',
            f'URL: {sanitized_url}, Result: {response["prediction"]}',
            'INFO'
        )
        
        cleanup_memory()  # Clean up after prediction
        logger.info(f"✅ Returning prediction response")
        return jsonify(response), 200
    
    except Exception as e:
        cleanup_memory()  # Clean up on error
        logger.error(f"❌ Prediction endpoint error: {str(e)}")
        logger.error(f"Error type: {type(e).__name__}")
        logger.exception("Prediction endpoint exception details:")
        return jsonify({
            'error': 'Prediction failed',
            'message': f'An error occurred: {str(e)}'
        }), 500


@app.route('/scan-subdomains', methods=['POST', 'OPTIONS'])
@require_auth
@limiter.limit("30 per minute")
def scan_subdomains():
    """
    Advanced subdomain scanner endpoint (PROTECTED)
    
    Headers:
        Authorization: Bearer <jwt_token>
    
    Request JSON:
        {
            "url": "https://example.com"
        }
    
    Response JSON:
        {
            "domain": "example.com",
            "scan_date": "2025-10-21 10:30:00",
            "subdomain_count": 50,
            "scan_time": 45.2,
            "subdomains": [...],
            "ip_statistics": {...}
        }
    """
    try:
        # Validate request
        if not request.is_json:
            return jsonify({
                'error': 'Invalid request',
                'message': 'Content-Type must be application/json'
            }), 400
        
        data = request.get_json()
        
        # Validate URL field
        if 'url' not in data:
            return jsonify({
                'error': 'Missing field',
                'message': 'Request must include "url" field'
            }), 400
        
        url = data['url']
        
        # Extract and validate domain
        domain = url.replace('https://', '').replace('http://', '').split('/')[0]
        is_valid, sanitized_domain, error = SecurityValidator.validate_domain(domain)
        
        if not is_valid:
            log_security_event(
                'INVALID_DOMAIN_SCAN',
                f'Domain: {domain[:100]}, Error: {error}',
                'WARNING'
            )
            return jsonify({
                'error': 'Invalid domain',
                'message': error
            }), 400
        
        logger.info(f"Subdomain scan request for domain: {sanitized_domain}")
        
        # Initialize scanner
        scanner = SubdomainScanner()
        
        # Perform comprehensive real-world scan
        # Enable all scanning methods for maximum subdomain discovery
        results = scanner.scan_domain(
            sanitized_domain,
            use_certificate=True,   # Certificate Transparency logs
            use_bruteforce=True,    # Comprehensive wordlist brute force
            use_dns=True            # DNS enumeration techniques
        )
        
        # Add security metadata
        results['scanned_at'] = datetime.utcnow().isoformat()
        results['scanned_by'] = g.user.get('username') if hasattr(g, 'user') else 'anonymous'
        
        log_security_event(
            'SUBDOMAIN_SCAN',
            f'Domain: {sanitized_domain}, Subdomains found: {results["subdomain_count"]}',
            'INFO'
        )
        
        logger.info(f"Scan complete: {results['subdomain_count']} subdomains found")
        
        cleanup_memory()  # Clean up after subdomain scan
        return jsonify(results), 200
    
    except Exception as e:
        cleanup_memory()  # Clean up on error
        logger.error(f"Subdomain scan error: {str(e)}")
        logger.exception("Subdomain scan exception details:")
        return jsonify({
            'error': 'Scan failed',
            'message': 'An error occurred during subdomain scanning'
        }), 500


@app.route('/logout', methods=['POST'])
@require_auth
@limiter.limit("100 per minute")
def logout():
    """
    Logout endpoint (PROTECTED)
    Invalidates the JWT token by adding it to the blacklist.
    
    Headers:
        Authorization: Bearer <jwt_token>
    
    Response JSON:
        {
            "success": true,
            "message": "Logout successful"
        }
    """
    try:
        username = g.user.get('username')
        
        # Get the token from the request and blacklist it
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header[7:].strip()
            # Import and use the blacklist function
            from security_utils import AuthenticationManager
            AuthenticationManager.blacklist_token(token)
        
        log_security_event(
            'USER_LOGOUT',
            f'Username: {username} - Token invalidated',
            'INFO'
        )
        
        return jsonify({
            'success': True,
            'message': 'Logout successful'
        }), 200
    
    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
        return jsonify({
            'error': 'Logout failed',
            'message': 'An error occurred during logout'
        }), 500


@app.route('/security/stats', methods=['GET'])
@require_auth
@limiter.limit("20 per minute")
def security_stats():
    """
    Get security statistics (PROTECTED - Admin only)
    
    Headers:
        Authorization: Bearer <jwt_token>
    
    Response JSON:
        {
            "tracked_ips": 5,
            "active_connections": 2,
            "suspicious_ips": 1,
            "permanent_blocks": 0,
            "whitelist_enabled": false,
            "whitelisted_ips": 2
        }
    """
    try:
        stats = DDoSProtection.get_security_stats()
        
        log_security_event(
            'SECURITY_STATS_REQUESTED',
            f'By user: {g.user.get("username")}',
            'INFO'
        )
        
        return jsonify({
            'success': True,
            'stats': stats,
            'timestamp': datetime.utcnow().isoformat()
        }), 200
    
    except Exception as e:
        logger.error(f"Security stats error: {str(e)}")
        return jsonify({
            'error': 'Failed to retrieve stats',
            'message': 'An error occurred while fetching security statistics'
        }), 500


# ========================
# ADMIN PRIVILEGE ENDPOINTS
# ========================

@app.route('/admin/devices', methods=['GET', 'OPTIONS'])
@require_session
@require_privilege
def list_devices():
    """
    List all whitelisted devices (ADMIN ONLY)
    Requires privileged session from whitelisted IP
    """
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        devices = IPSessionManager.WHITELISTED_DEVICES
        return jsonify({
            'success': True,
            'devices': devices,
            'count': len(devices)
        }), 200
    except Exception as e:
        logger.error(f"Error listing devices: {str(e)}")
        return jsonify({
            'error': 'Failed to list devices',
            'message': str(e)
        }), 500


@app.route('/admin/devices/add', methods=['POST', 'OPTIONS'])
@require_session
@require_privilege
def add_device():
    """
    Add a new whitelisted device (ADMIN ONLY)
    Requires: {"ip": "192.168.1.100", "name": "Work Computer", "description": "..."}
    """
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400
        
        data = request.get_json()
        
        ip_address = data.get('ip', '').strip()
        device_name = data.get('name', '').strip()
        description = data.get('description', '').strip()
        
        # Validate IP format
        import ipaddress
        try:
            ipaddress.ip_address(ip_address)
        except ValueError:
            return jsonify({
                'error': 'Invalid IP address',
                'message': f'{ip_address} is not a valid IP address'
            }), 400
        
        if not device_name:
            return jsonify({
                'error': 'Device name required',
                'message': 'Device name cannot be empty'
            }), 400
        
        # Add device
        success = IPSessionManager.add_whitelisted_device(ip_address, device_name, description)
        
        if success:
            log_security_event(
                'DEVICE_WHITELISTED',
                f'IP: {ip_address}, Name: {device_name}',
                'INFO'
            )
            return jsonify({
                'success': True,
                'message': f'Device {device_name} added to whitelist',
                'ip': ip_address
            }), 201
        else:
            return jsonify({'error': 'Failed to add device'}), 500
    
    except Exception as e:
        logger.error(f"Error adding device: {str(e)}")
        return jsonify({
            'error': 'Failed to add device',
            'message': str(e)
        }), 500


@app.route('/admin/devices/remove', methods=['POST', 'OPTIONS'])
@require_session
@require_privilege
def remove_device():
    """
    Remove a whitelisted device (ADMIN ONLY)
    Requires: {"ip": "192.168.1.100"}
    """
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400
        
        data = request.get_json()
        ip_address = data.get('ip', '').strip()
        
        if not ip_address:
            return jsonify({'error': 'IP address required'}), 400
        
        # Remove device
        success = IPSessionManager.remove_whitelisted_device(ip_address)
        
        if success:
            log_security_event(
                'DEVICE_REMOVED',
                f'IP: {ip_address}',
                'INFO'
            )
            return jsonify({
                'success': True,
                'message': f'Device {ip_address} removed from whitelist'
            }), 200
        else:
            return jsonify({
                'error': 'Device not found',
                'message': f'IP {ip_address} is not in whitelist'
            }), 404
    
    except Exception as e:
        logger.error(f"Error removing device: {str(e)}")
        return jsonify({
            'error': 'Failed to remove device',
            'message': str(e)
        }), 500


@app.route('/admin/sessions', methods=['GET', 'OPTIONS'])
@require_session
@require_privilege
def list_sessions():
    """
    List all active sessions (ADMIN ONLY)
    """
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        # Clean up expired sessions first
        IPSessionManager.cleanup_expired_sessions()
        
        sessions = []
        for session_id, session_data in IPSessionManager.SESSION_STORE.items():
            sessions.append({
                'session_id': session_id,
                'username': session_data['username'],
                'ip_address': session_data['ip_address'],
                'device_name': session_data['device_name'],
                'is_privileged': session_data['is_privileged'],
                'created_at': session_data['created_at'],
                'expires_at': session_data['expires_at'],
                'last_activity': session_data['last_activity'],
                'request_count': session_data['request_count']
            })
        
        return jsonify({
            'success': True,
            'sessions': sessions,
            'count': len(sessions)
        }), 200
    except Exception as e:
        logger.error(f"Error listing sessions: {str(e)}")
        return jsonify({
            'error': 'Failed to list sessions',
            'message': str(e)
        }), 500


@app.route('/admin/sessions/revoke', methods=['POST', 'OPTIONS'])
@require_session
@require_privilege
def revoke_session():
    """
    Revoke a specific session (ADMIN ONLY)
    Requires: {"session_id": "..."}
    """
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400
        
        data = request.get_json()
        session_id = data.get('session_id', '').strip()
        
        if not session_id:
            return jsonify({'error': 'Session ID required'}), 400
        
        # Don't allow revoking your own session
        if session_id == g.session_id:
            return jsonify({
                'error': 'Cannot revoke own session',
                'message': 'You cannot revoke your current session'
            }), 400
        
        success = IPSessionManager.destroy_session(session_id)
        
        if success:
            log_security_event(
                'SESSION_REVOKED',
                f'Session ID: {session_id}',
                'INFO'
            )
            return jsonify({
                'success': True,
                'message': 'Session revoked'
            }), 200
        else:
            return jsonify({
                'error': 'Session not found',
                'message': f'Session ID {session_id} not found'
            }), 404
    
    except Exception as e:
        logger.error(f"Error revoking session: {str(e)}")
        return jsonify({
            'error': 'Failed to revoke session',
            'message': str(e)
        }), 500


if __name__ == '__main__':
    print("\n" + "="*70)
    print("🔒 SECURE PHISHING DETECTOR API")
    print("="*70)
    print(f"📍 API URL: http://localhost:5000")
    print(f"🏥 Health check: http://localhost:5000/health")
    print(f"🔐 Login endpoint: http://localhost:5000/login")
    print(f"🔮 Prediction endpoint: http://localhost:5000/predict (PROTECTED)")
    print(f"🔍 Subdomain scanner: http://localhost:5000/scan-subdomains (PROTECTED)")
    print("="*70)
    print("\n🛡️  Security Features Enabled:")
    print("   ✅ JWT Authentication")
    print("   ✅ Rate Limiting")
    print("   ✅ Input Validation & Sanitization")
    print("   ✅ XSS Protection")
    print("   ✅ SQL Injection Prevention")
    print("   ✅ CSRF Protection")
    print("   ✅ Secure Headers")
    print("   ✅ IP-based Blocking")
    print("   ✅ Request Size Limits")
    print("   ✅ Security Logging")
    print("="*70)
    print("\n🛡️  ADVANCED DDoS/DoS PROTECTION:")
    print(f"   ✅ Rate Limiting: {AdvancedSecurityConfig.MAX_REQUESTS_PER_SECOND}/sec, {AdvancedSecurityConfig.MAX_REQUESTS_PER_MINUTE}/min")
    print(f"   ✅ Concurrent Connections: Max {AdvancedSecurityConfig.MAX_CONCURRENT_CONNECTIONS} per IP")
    print(f"   ✅ Attack Pattern Detection: Enabled")
    print(f"   ✅ IP Whitelisting: {'ENABLED' if AdvancedSecurityConfig.WHITELIST_ENABLED else 'DISABLED'}")
    print(f"   ✅ Auto-Blocking: {AdvancedSecurityConfig.AUTO_BLOCK_THRESHOLD} violations = block")
    print(f"   ✅ Temporary Block Duration: {AdvancedSecurityConfig.TEMPORARY_BLOCK_DURATION}s")
    print(f"   ✅ Client Fingerprinting: {'ENABLED' if AdvancedSecurityConfig.ENABLE_FINGERPRINTING else 'DISABLED'}")
    print(f"   ✅ Port Scanning Detection: {'ENABLED' if AdvancedSecurityConfig.DETECT_PORT_SCANNING else 'DISABLED'}")
    print("="*70)
    print("\n[!] Set credentials via environment variables or credentials.json")
    print("    See SECURITY.md for setup instructions")
    if AdvancedSecurityConfig.WHITELIST_ENABLED:
        print(f"\n🔒 IP Whitelist: {len(AdvancedSecurityConfig.WHITELISTED_IPS)} IPs whitelisted")
        print("   Add your IP to WHITELISTED_IPS in advanced_security.py")
    else:
        print("\n⚠️  IP Whitelist DISABLED - Enable in advanced_security.py for personal use")
    print("="*70 + "\n")
    
    # Run Flask app
    print("✓ Starting Flask server on 0.0.0.0:5000 (Production Mode)...")
    print("   Accessible at: http://localhost:5000")
    print("   Network access: http://<your-ip>:5000")
    print("Waiting for connections... (Press Ctrl+C to stop)")
    sys.stdout.flush()
    sys.stderr.flush()
    
    import threading
    import time
    import signal
    
    def run_flask():
        """Run Flask in a separate thread"""
        try:
            # Bind to 0.0.0.0 for production - accessible from network
            app.run(
                host='0.0.0.0',  # Listen on all interfaces for production
                port=5000,
                debug=False,
                use_reloader=False,
                use_debugger=False,
                threaded=True
            )
        except KeyboardInterrupt:
            pass
        except Exception as e:
            logger.exception(f"ERROR in Flask thread: {e}")
    
    # Start Flask in a background thread
    flask_thread = threading.Thread(target=run_flask, daemon=False)
    flask_thread.start()
    
    # Keep the main thread alive indefinitely
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[INFO] Server stopped by user")
        sys.exit(0)
