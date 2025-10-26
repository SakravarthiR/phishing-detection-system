"""
Main API server for the phishing detector.

This handles all the web requests and security stuff. I spent way too long
getting the DDoS protection to work right lol. Make sure credentials.json
is in the right place or auth won't work.

Run with: python secure_api.py (in the venv obviously)
"""

from flask import Flask, request, jsonify, g
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os
import sys
import traceback
from datetime import datetime


if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

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

# Import ML modules
from phish_detector import (
    load_model,
    predict_url,
    get_top_feature,
    extract_subdomain_info,
    check_website_live
)

# Import PhishTank integration
from phishtank_integration import check_phishtank, get_phishtank_db
from subdomain_scanner import SubdomainScanner

# Initialize Flask app with security config
app = Flask(__name__)
app.config.from_object(SecurityConfig)

# Configure CORS - Allow all origins for development (restrict in production)
CORS(app, resources={
    r"/*": {
        "origins": "*",  # Allow all origins for local development
        "methods": ["GET", "POST", "OPTIONS", "PUT", "DELETE"],
        "allow_headers": ["Content-Type", "Authorization"],
        "supports_credentials": False,  # Set to False when using origins: "*"
        "max_age": 3600
    }
})

# Initialize rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri=SecurityConfig.RATE_LIMIT_STORAGE_URL,
    default_limits=[
        f"{SecurityConfig.RATE_LIMIT_PER_MINUTE} per minute",
        f"{SecurityConfig.RATE_LIMIT_PER_HOUR} per hour"
    ],
    enabled=SecurityConfig.RATE_LIMIT_ENABLED
)

# Global model variable
model = None
model_loaded = False
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


# Load model when app starts
initialize_model()


@app.before_request
def security_checks():
    """
    Perform advanced security checks before each request
    Includes DDoS/DoS protection and IP whitelisting
    """
    # Get client IP
    ip_address = RateLimiter.get_client_ip()
    
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
    """Root endpoint with API information"""
    return jsonify({
        'name': 'Secure Phishing URL Detector API',
        'version': '2.0',
        'security': 'Enhanced',
        'endpoints': {
            '/health': 'GET - Check API status (public)',
            '/login': 'POST - Authenticate user',
            '/predict': 'POST - Predict if URL is phishing (requires auth)',
            '/scan-subdomains': 'POST - Advanced subdomain scanner (requires auth)'
        },
        'model_status': 'loaded' if model_loaded else 'not loaded'
    }), 200


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


@app.route('/login', methods=['POST'])
@limiter.limit(f"{SecurityConfig.LOGIN_RATE_LIMIT} per 15 minutes")
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
    try:
        # Get client IP
        ip_address = RateLimiter.get_client_ip()
        
        # Check if IP is blocked
        is_allowed, remaining, lockout_time = RateLimiter.check_login_attempts(ip_address)
        
        if not is_allowed:
            log_security_event(
                'BLOCKED_IP_LOGIN_ATTEMPT',
                f'Lockout time: {lockout_time}s',
                'WARNING'
            )
            return jsonify({
                'error': 'Too many failed attempts',
                'message': f'Account temporarily locked. Try again in {lockout_time // 60} minutes.',
                'retry_after': lockout_time
            }), 429
        
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
        
        username = data['username']
        password = data['password']
        
        # Validate input types
        if not isinstance(username, str) or not isinstance(password, str):
            return jsonify({
                'error': 'Invalid input',
                'message': 'Username and password must be strings'
            }), 400
        
        # Check for empty values
        if not username.strip() or not password.strip():
            return jsonify({
                'error': 'Invalid input',
                'message': 'Username and password cannot be empty'
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
        
        return jsonify({
            'success': True,
            'token': token,
            'expires_in': SecurityConfig.SESSION_TIMEOUT_MINUTES * 60,
            'message': 'Authentication successful'
        }), 200
    
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        traceback.print_exc()
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
            'message': str(e)
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
            'message': str(e)
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
            
            response = {
                'url': sanitized_url,
                'label': 1,  # Phishing
                'prediction': 'phishing',
                'probability': 0.99,  # Very high confidence
                'probability_percent': 99.0,
                'reason': f"⚠️ VERIFIED PHISHING by PhishTank | Target: {phishtank_result['target']} | Phish ID: {phishtank_result['phish_id']}",
                'confidence': 'very_high',
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
            
            return jsonify(response), 200
        
        # Not in PhishTank, proceed with ML prediction
        # Make prediction
        label, probability, features = predict_url(sanitized_url, model)
        
        # Check website status
        logger.info(f"Checking website status: {sanitized_url}")
        website_status = check_website_live(sanitized_url, timeout=5)
        
        # Get explanation
        reason = get_top_feature(features)
        
        # Prepare response
        response = {
            'url': sanitized_url,
            'label': label,
            'prediction': 'phishing' if label == 1 else 'legitimate',
            'probability': round(probability, 4),
            'probability_percent': round(probability * 100, 2),
            'reason': reason,
            'confidence': 'high' if probability > 0.8 or probability < 0.2 else 'medium',
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
        
        return jsonify(response), 200
    
    except Exception as e:
        logger.error(f"Prediction error: {str(e)}")
        traceback.print_exc()
        return jsonify({
            'error': 'Prediction failed',
            'message': 'An error occurred while analyzing the URL'
        }), 500


@app.route('/scan-subdomains', methods=['POST'])
@require_auth
@limiter.limit("10 per hour")
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
        
        # Perform scan
        results = scanner.scan_domain(
            sanitized_domain,
            use_certificate=True,
            use_bruteforce=True
        )
        
        # Add security metadata
        results['scanned_at'] = datetime.utcnow().isoformat()
        results['scanned_by'] = g.user.get('username')
        
        log_security_event(
            'SUBDOMAIN_SCAN',
            f'Domain: {sanitized_domain}, Subdomains found: {results["subdomain_count"]}',
            'INFO'
        )
        
        logger.info(f"Scan complete: {results['subdomain_count']} subdomains found")
        
        return jsonify(results), 200
    
    except Exception as e:
        logger.error(f"Subdomain scan error: {str(e)}")
        traceback.print_exc()
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
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=SecurityConfig.DEBUG,
        threaded=True
    )
