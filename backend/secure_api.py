"""
Secure Phishing Detection API Server

Enterprise-grade API with multi-layer security:
- JWT authentication & session management
- Rate limiting & DDoS protection
- Input validation & sanitization
- CSRF protection & secure headers

Deployment: gunicorn -c backend/gunicorn_config.py backend.secure_api:app
"""

from flask import Flask, request, jsonify, g, send_from_directory
# Using manual CORS headers instead of flask-cors for better control
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os
import sys
from datetime import datetime
import gc  # Memory optimization
import requests  # For HTTP requests with connection pooling
import logging


if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')


# Configure logging
logger = logging.getLogger(__name__)


def cleanup_memory():
    """Force garbage collection and memory cleanup"""
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

# Import ML modules
from phish_detector import (
    load_model,
    predict_url,
    get_top_feature,
    extract_subdomain_info,
    check_website_live,
    get_professional_risk_assessment
)

# Import PhishTank integration
from phishtank_integration import check_phishtank, get_phishtank_db
from subdomain_scanner import SubdomainScanner

# Memory optimization utilities
try:
    from memory_optimizer import cleanup_memory, get_memory_usage, memory_efficient
except ImportError:
    # Fallback if memory_optimizer not available
    def cleanup_memory(): gc.collect()
    def get_memory_usage(): return 0
    def memory_efficient(f): return f

# Connection pooling for 50 concurrent users
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

def create_session_with_pool():
    """Create requests session with connection pooling for 50 users"""
    session = requests.Session()
    # Pool size: 25 connections per worker x 2 workers = 50 concurrent connections
    adapter = HTTPAdapter(
        pool_connections=25,  # Max connections to pool
        pool_maxsize=25,      # Max connections per pool
        max_retries=Retry(total=2, backoff_factor=0.5)
    )
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

# Global session with connection pooling
REQUESTS_SESSION = create_session_with_pool()

# Initialize Flask app with security config
app = Flask(__name__)
app.config.from_object(SecurityConfig)

# Enable response compression for low bandwidth
try:
    from flask_compress import Compress
    Compress(app)
except ImportError as e:
        logger.warning(f"Flask-Compress not available - skipping compression: {str(e)}")

# Configure CORS - Production ready configuration
# Don't use flask-cors extension, use manual headers instead for better control
# CORS(app, ...) is commented out to avoid conflicts

# CORS - Wide open for development
@app.after_request
def after_request_cors(response):
    """Allow all CORS requests"""
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = '*'
    response.headers['Access-Control-Allow-Headers'] = '*'
    response.headers['Access-Control-Expose-Headers'] = '*'
    return response

# Initialize rate limiter with global protection
limiter = Limiter(
    app=app,
    key_func=lambda: get_client_ip(),  # Use custom IP extraction
    storage_uri=SecurityConfig.RATE_LIMIT_STORAGE_URL,
    default_limits=[
        f"{SecurityConfig.RATE_LIMIT_PER_MINUTE} per minute",
        f"{SecurityConfig.RATE_LIMIT_PER_HOUR} per hour"
    ],
    enabled=SecurityConfig.RATE_LIMIT_ENABLED,
    in_memory_fallback_enabled=True  # Fallback if Redis unavailable
)

# Global model variable
model = None
model_loaded = False
# Use absolute path for model file - works both locally and on Render
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'phish_model.pkl')


def initialize_model():
    """Load the ML model at application startup"""
    global model, model_loaded
    
    logger.info("🔄 Initializing secure phishing detector API...")
    model = load_model(MODEL_PATH)
    
    if model is not None:
        model_loaded = True
        logger.info("✅ API ready with trained model")
    else:
        model_loaded = False
        logger.warning("⚠️  API started but model not loaded")


# Initialize IP session security
IPSessionManager.load_whitelisted_devices()
logger.info("✅ IP Session Security initialized")

# Load model when app starts
initialize_model()

# Setup frontend serving
FRONTEND_DIR = os.path.join(os.path.dirname(__file__), '..', 'frontend')

@app.route('/')
def serve_index():
    """Serve the main index.html"""
    return send_from_directory(FRONTEND_DIR, 'index.html')

@app.route('/<path:filename>')
def serve_static(filename):
    """Serve static files (CSS, JS, HTML, images)"""
    # Prevent path traversal attacks
    import os.path
    if '..' in filename or filename.startswith('/'):
        logger.warning(f"Attempted path traversal: {filename}")
        return jsonify({'error': 'Invalid path'}), 403
    
    # List of allowed file extensions
    allowed_extensions = {'.html', '.css', '.js', '.json', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff', '.woff2', '.ttf'}
    
    # Check file extension
    file_ext = os.path.splitext(filename)[1].lower()
    if file_ext not in allowed_extensions:
        return jsonify({'error': 'File type not allowed'}), 403
    
    try:
        return send_from_directory(FRONTEND_DIR, filename)
    except FileNotFoundError:
        # If file not found, serve index.html for SPA routing
        if filename.endswith('.html'):
            return send_from_directory(FRONTEND_DIR, 'index.html')
        return jsonify({'error': 'File not found'}), 404
    except Exception as e:
        logger.error(f"Error serving file {filename}: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.before_request
def security_checks():
    """
    Perform advanced security checks before each request
    Includes DDoS/DoS protection and IP whitelisting
    """
    # Allow CORS preflight requests to pass through without security checks
    if request.method == 'OPTIONS':
        logger.debug(f"CORS preflight request: {request.path}")
        return None
    
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
    
    return add_security_headers(response)


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
    # Add compression headers for responses
    response.headers['Cache-Control'] = 'public, max-age=3600'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Vary'] = 'Accept-Encoding'  # Cache by encoding
    
    # Set minimal content-type for JSON
    if response.content_type and 'application/json' in response.content_type:
        response.headers['Content-Encoding'] = 'gzip'
    
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

@app.route('/', methods=['GET'])
@limiter.limit("100 per minute")
def root():
    """Root endpoint - serves index.html"""
    return send_from_directory(FRONTEND_DIR, 'index.html')


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
    Quick login endpoint for development/demo purposes only
    DISABLED IN PRODUCTION - Only works if ENVIRONMENT != 'production'
    """
    import os
    if os.getenv('ENVIRONMENT') == 'production':
        logger.warning("Attempted access to /demo-login in production!")
        return jsonify({
            'error': 'Forbidden',
            'message': 'This endpoint is not available'
        }), 403
    
    try:
        ip_address = RateLimiter.get_client_ip()
        
        # Generate token with demo username
        token = AuthenticationManager.generate_token('demo')
        expires_in = SecurityConfig.SESSION_TIMEOUT_MINUTES * 60
        
        if token:
            log_security_event(
                'DEMO_LOGIN_SUCCESS',
                f'Demo mode login from {ip_address}',
                'INFO'
            )
            return jsonify({
                'success': True,
                'message': 'Demo login successful',
                'token': token,
                'expires_in': expires_in,
                'username': 'demo'
            }), 200
        else:
            return jsonify({
                'error': 'Token generation failed',
                'message': 'Could not generate authentication token'
            }), 500
    
    except Exception as e:
        logger.error(f"Demo login error: {str(e)}")
        return jsonify({
            'error': 'Login failed',
            'message': 'An error occurred during authentication'
        }), 500


@app.route('/login', methods=['POST', 'OPTIONS'])
def login():
    """
    User authentication endpoint
    
    Request JSON:
        {
            "username": "admin",
            "password": "password123"
        }
    
    Response JSON:
        {
            "success": true,
            "token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
            "expires_in": 86400,
            "message": "Authentication successful"
        }
    """
    # Handle CORS preflight
    if request.method == 'OPTIONS':
        logger.debug("OPTIONS preflight for /login")
        return '', 200
    
    try:
        # Get client IP
        ip_address = RateLimiter.get_client_ip()
        
        # SECURITY CHECKS DISABLED FOR DEVELOPMENT
        # Skip rate limiting to allow unrestricted access
        
        # Validate request
        if not request.is_json:
            return jsonify({
                'error': 'Invalid request',
                'message': 'Content-Type must be application/json'
            }), 400
        
        data = request.get_json()
        
        # Validate required fields
        if 'username' not in data or 'password' not in data:
            return jsonify({
                'error': 'Missing fields',
                'message': 'Username and password are required'
            }), 400
        
        username = data['username'].strip() if isinstance(data['username'], str) else ''
        password = data['password'] if isinstance(data['password'], str) else ''
        
        # Validate input types
        if not isinstance(username, str) or not isinstance(password, str):
            return jsonify({
                'error': 'Invalid input',
                'message': 'Username and password must be strings'
            }), 400
        
        # Check for empty values
        if not username or not password:
            return jsonify({
                'error': 'Invalid input',
                'message': 'Username and password cannot be empty'
            }), 400
        
        # Validate username format
        is_valid, error_msg = SecurityValidator.validate_username(username)
        if not is_valid:
            log_security_event(
                'INVALID_USERNAME_FORMAT',
                f'Username: {username[:50]}, Error: {error_msg}',
                'WARNING'
            )
            RateLimiter.record_failed_attempt(ip_address)
            return jsonify({
                'error': 'Invalid username format',
                'message': error_msg
            }), 400
        
        # Check for suspicious patterns
        if SecurityValidator.check_suspicious_input(username):
            log_security_event(
                'SUSPICIOUS_LOGIN_ATTEMPT',
                f'Username: {username[:50]}',
                'WARNING'
            )
            RateLimiter.record_failed_attempt(ip_address)
            return jsonify({
                'error': 'Invalid credentials',
                'message': 'Authentication failed'
            }), 401
        
        # Authenticate user
        is_authenticated, token, error = AuthenticationManager.authenticate_user(
            username,
            password
        )
        
        if not is_authenticated:
            # Record failed attempt
            RateLimiter.record_failed_attempt(ip_address)
            
            # Check remaining attempts
            _, remaining, _ = RateLimiter.check_login_attempts(ip_address)
            
            log_security_event(
                'FAILED_LOGIN',
                f'Username: {username}, Remaining attempts: {remaining}',
                'WARNING'
            )
            
            return jsonify({
                'error': 'Authentication failed',
                'message': error,
                'remaining_attempts': remaining
            }), 401
        
        # Clear failed attempts on successful login
        RateLimiter.clear_failed_attempts(ip_address)
        
        log_security_event(
            'SUCCESSFUL_LOGIN',
            f'Username: {username}',
            'INFO'
        )
        
        # Create IP-bound session
        user_agent = get_user_agent()
        session_id = IPSessionManager.create_session(
            username=username,
            token=token,
            ip_address=normalize_ip(ip_address),  # Normalize IP for IPv6 support
            user_agent=user_agent,
            session_timeout_minutes=SecurityConfig.SESSION_TIMEOUT_MINUTES
        )
        
        is_privileged = IPSessionManager.is_device_whitelisted(ip_address)
        device_name = IPSessionManager.get_device_name(ip_address)
        
        # Get session data to extract CSRF token
        session_data = IPSessionManager.get_session_info(session_id)
        csrf_token = session_data.get('csrf_token') if session_data else None
        
        logger.info(f"✅ Login successful - Session ID: {session_id}, IP: {ip_address}, Privileged: {is_privileged}")
        
        return jsonify({
            'success': True,
            'token': token,
            'session_id': session_id,
            'csrf_token': csrf_token,
            'expires_in': SecurityConfig.SESSION_TIMEOUT_MINUTES * 60,
            'message': 'Authentication successful',
            'privileged': is_privileged,
            'device_name': device_name
        }), 200
    
    except Exception as e:
        logger.exception(f"Login error: {str(e)}")
        return jsonify({
            'error': 'Authentication failed',
            'message': 'An error occurred during authentication'
        }), 500


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

@app.route('/predict', methods=['POST'])
@require_auth
@limiter.limit("30 per minute")
def predict():
    """
    Predict whether a URL is phishing or legitimate (PROTECTED)
    
    Headers:
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


@app.route('/scan-subdomains', methods=['POST'])
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
        
        log_security_event(
            'USER_LOGOUT',
            f'Username: {username}',
            'INFO'
        )
        
        # In production, you would invalidate the token in a blacklist
        # For now, we just log the logout
        
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
    print(f"\n🔑 Default Login: {SecurityConfig.ADMIN_USERNAME} / phishing123")
    print("⚠️  CHANGE PASSWORD IN PRODUCTION!")
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
