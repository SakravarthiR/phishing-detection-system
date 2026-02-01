"""DDoS protection and rate limiting"""

import time
import hashlib
from datetime import datetime, timedelta
from collections import defaultdict
from threading import Lock
from security_utils import logger

try:
    from credentials_loader import CredentialsLoader
    EXTERNAL_CREDENTIALS_LOADED = True
except ImportError:
    EXTERNAL_CREDENTIALS_LOADED = False

request_lock = Lock()
connection_lock = Lock()

request_tracker = defaultdict(list)
connection_tracker = defaultdict(int)
request_patterns = defaultdict(lambda: defaultdict(int))
suspicious_ips = set()
permanent_blocks = set()


class AdvancedSecurityConfig:
    if EXTERNAL_CREDENTIALS_LOADED:
        _external_config = CredentialsLoader.get_advanced_security_config()
        WHITELIST_ENABLED = False
        WHITELISTED_IPS = ['127.0.0.1', '::1', 'localhost', 'localhost:5000']
        MAX_REQUESTS_PER_SECOND = _external_config.get('max_requests_per_second', 10)
        MAX_REQUESTS_PER_MINUTE = _external_config.get('max_requests_per_minute', 100)
        MAX_REQUESTS_PER_HOUR = _external_config.get('max_requests_per_hour', 1000)
        MAX_CONCURRENT_CONNECTIONS = _external_config.get('max_concurrent_connections', 5)
        AUTO_BLOCK_THRESHOLD = _external_config.get('auto_block_threshold', 3)
        TEMPORARY_BLOCK_DURATION = _external_config.get('temporary_block_duration', 3600)
    else:
        WHITELIST_ENABLED = False
        WHITELISTED_IPS = ['127.0.0.1', '::1', 'localhost']
        MAX_REQUESTS_PER_SECOND = 10
        MAX_REQUESTS_PER_MINUTE = 100
        MAX_REQUESTS_PER_HOUR = 1000
        MAX_CONCURRENT_CONNECTIONS = 5
        AUTO_BLOCK_THRESHOLD = 3
        TEMPORARY_BLOCK_DURATION = 3600
    
    SUSPICIOUS_PATTERN_THRESHOLD = 100
    PATTERN_TIME_WINDOW = 10
    MAX_REQUEST_SIZE = 1048576
    MAX_URL_LENGTH = 2048
    MAX_JSON_DEPTH = 5
    REQUEST_TIMEOUT = 10
    SLOW_REQUEST_THRESHOLD = 5
    RATE_LIMIT_WINDOWS = {'second': 1, 'minute': 60, 'hour': 3600}
    
    ALLOWED_COUNTRIES = []
    DETECT_PORT_SCANNING = True
    DETECT_SQL_INJECTION = True
    DETECT_XSS_ATTACKS = True
    DETECT_DIRECTORY_TRAVERSAL = True
    SUSPICIOUS_REQUEST_DELAY = 2
    BLOCKED_REQUEST_DELAY = 5
    ENABLE_FINGERPRINTING = True
    FINGERPRINT_HEADERS = ['User-Agent', 'Accept', 'Accept-Encoding', 'Accept-Language']


class DDoSProtection:
    @staticmethod
    def get_client_fingerprint(request):
        if not AdvancedSecurityConfig.ENABLE_FINGERPRINTING:
            return None
        fingerprint_data = []
        for header in AdvancedSecurityConfig.FINGERPRINT_HEADERS:
            fingerprint_data.append(request.headers.get(header, ''))
        fingerprint_string = '|'.join(fingerprint_data)
        return hashlib.sha256(fingerprint_string.encode()).hexdigest()[:16]
    
    @staticmethod
    def is_whitelisted(ip_address):
        if not AdvancedSecurityConfig.WHITELIST_ENABLED:
            return False
        return ip_address in AdvancedSecurityConfig.WHITELISTED_IPS
    
    @staticmethod
    def is_blocked(ip_address):
        if ip_address in permanent_blocks:
            logger.critical(f"Permanently blocked IP attempted access: {ip_address}")
            return True, 'permanent', None
        
        if ip_address in suspicious_ips:
            with request_lock:
                if ip_address in request_tracker:
                    last_block = request_tracker[ip_address]
                    if last_block and isinstance(last_block[-1], dict):
                        block_info = last_block[-1]
                        if 'block_until' in block_info:
                            if datetime.now() < block_info['block_until']:
                                remaining = (block_info['block_until'] - datetime.now()).seconds
                                logger.warning(f"Temporarily blocked IP attempted access: {ip_address}")
                                return True, 'temporary', remaining
                            else:
                                suspicious_ips.discard(ip_address)
        
        return False, None, None
    
    @staticmethod
    def check_request_rate(ip_address):
        """
        Check if request rate is within limits
        Returns: (is_allowed, violation_type, current_rate)
        """
        current_time = time.time()
        
        with request_lock:
            # Get request history for this IP
            requests = request_tracker[ip_address]
            
            # Clean old requests
            cutoff_hour = current_time - AdvancedSecurityConfig.RATE_LIMIT_WINDOWS['hour']
            requests = [req for req in requests if isinstance(req, (int, float)) and req > cutoff_hour]
            request_tracker[ip_address] = requests
            
            # Add current request
            requests.append(current_time)
            
            # Check rates
            second_ago = current_time - 1
            minute_ago = current_time - 60
            hour_ago = current_time - 3600
            
            requests_last_second = sum(1 for req in requests if isinstance(req, (int, float)) and req > second_ago)
            requests_last_minute = sum(1 for req in requests if isinstance(req, (int, float)) and req > minute_ago)
            requests_last_hour = sum(1 for req in requests if isinstance(req, (int, float)) and req > hour_ago)
            
            # Check thresholds
            if requests_last_second > AdvancedSecurityConfig.MAX_REQUESTS_PER_SECOND:
                logger.warning(f"DDoS detected: {ip_address} - {requests_last_second} req/sec")
                return False, 'per_second', requests_last_second
            
            if requests_last_minute > AdvancedSecurityConfig.MAX_REQUESTS_PER_MINUTE:
                logger.warning(f"DoS detected: {ip_address} - {requests_last_minute} req/min")
                return False, 'per_minute', requests_last_minute
            
            if requests_last_hour > AdvancedSecurityConfig.MAX_REQUESTS_PER_HOUR:
                logger.warning(f"Excessive requests: {ip_address} - {requests_last_hour} req/hour")
                return False, 'per_hour', requests_last_hour
        
        return True, None, 0
    
    @staticmethod
    def check_concurrent_connections(ip_address, action='connect'):
        """
        Track concurrent connections per IP
        action: 'connect' or 'disconnect'
        """
        with connection_lock:
            if action == 'connect':
                connection_tracker[ip_address] += 1
                current_connections = connection_tracker[ip_address]
                
                if current_connections > AdvancedSecurityConfig.MAX_CONCURRENT_CONNECTIONS:
                    logger.warning(f"Too many concurrent connections: {ip_address} - {current_connections}")
                    return False, current_connections
                
            elif action == 'disconnect':
                if connection_tracker[ip_address] > 0:
                    connection_tracker[ip_address] -= 1
        
        return True, connection_tracker.get(ip_address, 0)
    
    @staticmethod
    def detect_attack_pattern(ip_address, endpoint, method):
        """
        Detect suspicious request patterns
        Returns: (is_suspicious, pattern_type)
        """
        current_time = time.time()
        pattern_key = f"{endpoint}:{method}"
        
        with request_lock:
            # Track pattern
            patterns = request_patterns[ip_address]
            patterns[pattern_key] += 1
            
            # Clean old patterns
            for key in list(patterns.keys()):
                if patterns[key] == 0:
                    del patterns[key]
            
            # Check if same endpoint is being hammered
            if patterns[pattern_key] > AdvancedSecurityConfig.SUSPICIOUS_PATTERN_THRESHOLD:
                logger.warning(f"Suspicious pattern detected: {ip_address} - {pattern_key} x{patterns[pattern_key]}")
                return True, 'endpoint_hammering'
            
            # Check if multiple different endpoints (port scanning)
            if AdvancedSecurityConfig.DETECT_PORT_SCANNING:
                if len(patterns) > 10:  # Hitting many different endpoints
                    logger.warning(f"Port scanning detected: {ip_address} - {len(patterns)} endpoints")
                    return True, 'port_scanning'
        
        return False, None
    
    @staticmethod
    def block_ip(ip_address, reason, duration='temporary'):
        """
        Block an IP address
        duration: 'temporary' or 'permanent'
        """
        if duration == 'permanent':
            permanent_blocks.add(ip_address)
            logger.critical(f"IP permanently blocked: {ip_address} - Reason: {reason}")
        else:
            suspicious_ips.add(ip_address)
            block_until = datetime.now() + timedelta(seconds=AdvancedSecurityConfig.TEMPORARY_BLOCK_DURATION)
            
            with request_lock:
                request_tracker[ip_address].append({
                    'block_until': block_until,
                    'reason': reason,
                    'blocked_at': datetime.now()
                })
            
            logger.warning(f"IP temporarily blocked: {ip_address} - Reason: {reason} - Duration: {AdvancedSecurityConfig.TEMPORARY_BLOCK_DURATION}s")
    
    @staticmethod
    def handle_violation(ip_address, violation_type):
        """
        Handle security violation
        Implement progressive blocking
        """
        # Count violations
        violations = 0
        with request_lock:
            for entry in request_tracker[ip_address]:
                if isinstance(entry, dict) and 'violation' in entry:
                    violations += 1
            
            # Record this violation
            request_tracker[ip_address].append({
                'violation': violation_type,
                'timestamp': datetime.now()
            })
        
        violations += 1
        
        # Progressive blocking
        if violations >= AdvancedSecurityConfig.AUTO_BLOCK_THRESHOLD:
            DDoSProtection.block_ip(ip_address, f"Multiple violations: {violation_type}", 'permanent')
        else:
            DDoSProtection.block_ip(ip_address, violation_type, 'temporary')
    
    @staticmethod
    def cleanup_old_data():
        """Periodic cleanup of old tracking data"""
        current_time = time.time()
        cutoff = current_time - 3600  # Keep last hour of data
        
        with request_lock:
            for ip in list(request_tracker.keys()):
                request_tracker[ip] = [
                    req for req in request_tracker[ip] 
                    if isinstance(req, dict) or (isinstance(req, (int, float)) and req > cutoff)
                ]
                
                if not request_tracker[ip]:
                    del request_tracker[ip]
        
        with connection_lock:
            for ip in list(connection_tracker.keys()):
                if connection_tracker[ip] == 0:
                    del connection_tracker[ip]
    
    @staticmethod
    def get_security_stats():
        """Get current security statistics"""
        return {
            'tracked_ips': len(request_tracker),
            'active_connections': sum(connection_tracker.values()),
            'suspicious_ips': len(suspicious_ips),
            'permanent_blocks': len(permanent_blocks),
            'whitelist_enabled': AdvancedSecurityConfig.WHITELIST_ENABLED,
            'whitelisted_ips': len(AdvancedSecurityConfig.WHITELISTED_IPS)
        }


def advanced_security_check(request, ip_address):
    """
    Comprehensive security check
    Returns: (is_allowed, error_response, http_code)
    """
    # 1. Check whitelist first - SKIP ALL CHECKS IF WHITELISTED
    if DDoSProtection.is_whitelisted(ip_address):
        # Whitelisted IP - bypass all security checks
        return True, None, None
    
    # 2. Check if IP is blocked
    is_blocked, block_type, remaining = DDoSProtection.is_blocked(ip_address)
    if is_blocked:
        time.sleep(AdvancedSecurityConfig.BLOCKED_REQUEST_DELAY)
        
        if block_type == 'permanent':
            return False, {
                'error': 'Access Permanently Denied',
                'message': 'Your IP has been permanently blocked due to suspicious activity',
                'code': 'IP_PERMANENTLY_BLOCKED'
            }, 403
        else:
            return False, {
                'error': 'Temporarily Blocked',
                'message': f'Too many violations. Try again in {remaining} seconds',
                'retry_after': remaining,
                'code': 'IP_TEMPORARILY_BLOCKED'
            }, 429
    
    # 3. Check request rate (DDoS detection)
    is_allowed, violation_type, rate = DDoSProtection.check_request_rate(ip_address)
    if not is_allowed:
        DDoSProtection.handle_violation(ip_address, f"Rate limit: {violation_type}")
        return False, {
            'error': 'Too Many Requests',
            'message': f'Rate limit exceeded: {rate} requests {violation_type}',
            'code': 'RATE_LIMIT_EXCEEDED'
        }, 429
    
    # 4. Check concurrent connections
    is_allowed, connections = DDoSProtection.check_concurrent_connections(ip_address, 'connect')
    if not is_allowed:
        DDoSProtection.handle_violation(ip_address, "Too many concurrent connections")
        return False, {
            'error': 'Too Many Connections',
            'message': f'Maximum concurrent connections exceeded: {connections}',
            'code': 'CONNECTION_LIMIT_EXCEEDED'
        }, 429
    
    # 5. Check attack patterns
    endpoint = request.path
    method = request.method
    is_suspicious, pattern_type = DDoSProtection.detect_attack_pattern(ip_address, endpoint, method)
    
    if is_suspicious:
        time.sleep(AdvancedSecurityConfig.SUSPICIOUS_REQUEST_DELAY)
        DDoSProtection.handle_violation(ip_address, f"Suspicious pattern: {pattern_type}")
        return False, {
            'error': 'Suspicious Activity Detected',
            'message': 'Your request pattern appears suspicious',
            'code': 'SUSPICIOUS_PATTERN'
        }, 403
    
    # All checks passed
    return True, None, None
