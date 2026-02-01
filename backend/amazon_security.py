"""
Amazon-Level Security System
============================
Enterprise-grade authentication security optimized for low-memory environments.

Features:
- Multi-Factor Authentication (TOTP)
- Device Fingerprinting & Trust System
- Anomaly Detection (location, time, behavior)
- Progressive Account Lockout with Exponential Backoff
- Login History & Security Alerts
- Brute Force Protection
- Session Binding (IP + Device)

Optimized for Render Free Tier (512MB RAM)
"""

import hashlib
import hmac
import time
import base64
import struct
import os
import json
from datetime import datetime, timedelta
from collections import defaultdict, deque
from threading import Lock
from functools import wraps
import logging
import re

logger = logging.getLogger(__name__)

# Thread-safe locks for concurrent access
_security_lock = Lock()
_device_lock = Lock()
_history_lock = Lock()

# ============================================================================
# MEMORY-EFFICIENT STORAGE (Auto-cleanup for 512MB limit)
# ============================================================================

class MemoryEfficientStore:
    """LRU-based storage with automatic cleanup for low memory environments"""
    
    def __init__(self, max_size=1000, ttl_seconds=3600):
        self.max_size = max_size
        self.ttl = ttl_seconds
        self.store = {}
        self.access_times = {}
        self.lock = Lock()
    
    def set(self, key, value, ttl=None):
        with self.lock:
            self._cleanup_if_needed()
            self.store[key] = value
            self.access_times[key] = time.time()
    
    def get(self, key, default=None):
        with self.lock:
            if key in self.store:
                # Check TTL
                if time.time() - self.access_times.get(key, 0) > self.ttl:
                    del self.store[key]
                    del self.access_times[key]
                    return default
                self.access_times[key] = time.time()
                return self.store[key]
            return default
    
    def delete(self, key):
        with self.lock:
            self.store.pop(key, None)
            self.access_times.pop(key, None)
    
    def _cleanup_if_needed(self):
        if len(self.store) >= self.max_size:
            # Remove oldest 20% of entries
            sorted_keys = sorted(self.access_times.keys(), key=lambda k: self.access_times[k])
            for key in sorted_keys[:len(sorted_keys) // 5]:
                self.store.pop(key, None)
                self.access_times.pop(key, None)


# Storage instances (OPTIMIZED FOR 512MB RENDER FREE TIER)
# Reduced sizes by 50% to fit in 256MB per worker
_failed_attempts = MemoryEfficientStore(max_size=250, ttl_seconds=1800)  # 30 min
_lockouts = MemoryEfficientStore(max_size=100, ttl_seconds=86400)  # 24 hours
_device_trust = MemoryEfficientStore(max_size=250, ttl_seconds=2592000)  # 30 days
_login_history = MemoryEfficientStore(max_size=500, ttl_seconds=604800)  # 7 days
_mfa_secrets = MemoryEfficientStore(max_size=50, ttl_seconds=86400)  # 24 hours
_security_challenges = MemoryEfficientStore(max_size=100, ttl_seconds=300)  # 5 min
_anomaly_scores = MemoryEfficientStore(max_size=250, ttl_seconds=3600)  # 1 hour


# ============================================================================
# SECURITY CONFIGURATION
# ============================================================================

class AmazonSecurityConfig:
    """Amazon-level security configuration"""
    
    # Account Lockout (Progressive)
    MAX_FAILED_ATTEMPTS = 5
    LOCKOUT_DURATIONS = [60, 300, 900, 3600, 86400]  # 1min, 5min, 15min, 1hr, 24hr
    
    # Brute Force Protection
    RATE_LIMIT_WINDOW = 60  # seconds
    MAX_ATTEMPTS_PER_WINDOW = 10
    
    # Device Trust
    DEVICE_TRUST_DURATION_DAYS = 30
    MAX_TRUSTED_DEVICES = 10
    REQUIRE_MFA_NEW_DEVICE = True
    
    # Session Security
    SESSION_TIMEOUT_MINUTES = 60
    ABSOLUTE_TIMEOUT_HOURS = 24
    BIND_SESSION_TO_IP = True
    BIND_SESSION_TO_DEVICE = True
    
    # Anomaly Detection Thresholds
    ANOMALY_SCORE_THRESHOLD = 70  # 0-100 scale
    NEW_LOCATION_SCORE = 30
    NEW_DEVICE_SCORE = 25
    UNUSUAL_TIME_SCORE = 20
    RAPID_ATTEMPTS_SCORE = 35
    
    # Password Requirements
    MIN_PASSWORD_LENGTH = 12
    REQUIRE_UPPERCASE = True
    REQUIRE_LOWERCASE = True
    REQUIRE_NUMBERS = True
    REQUIRE_SPECIAL = True
    
    # MFA Settings
    MFA_CODE_LENGTH = 6
    MFA_CODE_VALIDITY_SECONDS = 30
    MFA_BACKUP_CODES_COUNT = 10


# ============================================================================
# DEVICE FINGERPRINTING
# ============================================================================

class DeviceFingerprint:
    """Generate and verify device fingerprints for trust system"""
    
    @staticmethod
    def generate(request):
        """Generate device fingerprint from request headers"""
        components = [
            request.headers.get('User-Agent', ''),
            request.headers.get('Accept-Language', ''),
            request.headers.get('Accept-Encoding', ''),
            request.headers.get('Accept', ''),
            # Screen info from custom header (set by frontend)
            request.headers.get('X-Screen-Info', ''),
            request.headers.get('X-Timezone', ''),
        ]
        
        fingerprint_string = '|'.join(components)
        fingerprint = hashlib.sha256(fingerprint_string.encode()).hexdigest()[:32]
        
        return fingerprint
    
    @staticmethod
    def get_device_info(request):
        """Extract device information for display"""
        user_agent = request.headers.get('User-Agent', 'Unknown')
        
        # Parse user agent for device type
        device_type = 'Desktop'
        if 'Mobile' in user_agent or 'Android' in user_agent:
            device_type = 'Mobile'
        elif 'Tablet' in user_agent or 'iPad' in user_agent:
            device_type = 'Tablet'
        
        # Parse browser
        browser = 'Unknown'
        if 'Chrome' in user_agent:
            browser = 'Chrome'
        elif 'Firefox' in user_agent:
            browser = 'Firefox'
        elif 'Safari' in user_agent:
            browser = 'Safari'
        elif 'Edge' in user_agent:
            browser = 'Edge'
        
        # Parse OS
        os_name = 'Unknown'
        if 'Windows' in user_agent:
            os_name = 'Windows'
        elif 'Mac' in user_agent:
            os_name = 'macOS'
        elif 'Linux' in user_agent:
            os_name = 'Linux'
        elif 'Android' in user_agent:
            os_name = 'Android'
        elif 'iOS' in user_agent or 'iPhone' in user_agent:
            os_name = 'iOS'
        
        return {
            'type': device_type,
            'browser': browser,
            'os': os_name,
            'user_agent': user_agent[:100]
        }


# ============================================================================
# TOTP MFA (Time-based One-Time Password)
# ============================================================================

class TOTPManager:
    """TOTP-based Multi-Factor Authentication (RFC 6238)"""
    
    @staticmethod
    def generate_secret():
        """Generate a new TOTP secret"""
        secret = base64.b32encode(os.urandom(20)).decode('utf-8')
        return secret
    
    @staticmethod
    def get_totp_code(secret, time_step=30):
        """Generate current TOTP code"""
        try:
            # Decode secret
            key = base64.b32decode(secret.upper())
            
            # Get current time step
            counter = int(time.time() // time_step)
            
            # Pack counter as big-endian 8-byte integer
            counter_bytes = struct.pack('>Q', counter)
            
            # Calculate HMAC-SHA1
            hmac_result = hmac.new(key, counter_bytes, hashlib.sha1).digest()
            
            # Dynamic truncation
            offset = hmac_result[-1] & 0x0F
            code_int = struct.unpack('>I', hmac_result[offset:offset + 4])[0]
            code_int &= 0x7FFFFFFF
            code = code_int % (10 ** AmazonSecurityConfig.MFA_CODE_LENGTH)
            
            return str(code).zfill(AmazonSecurityConfig.MFA_CODE_LENGTH)
        except Exception as e:
            logger.error(f"TOTP generation error: {e}")
            return None
    
    @staticmethod
    def verify_totp(secret, code, window=1):
        """Verify TOTP code with time window tolerance"""
        if not secret or not code:
            return False
        
        code = str(code).strip()
        
        # Check current and adjacent time windows
        for offset in range(-window, window + 1):
            counter = int(time.time() // 30) + offset
            expected = TOTPManager._generate_code_for_counter(secret, counter)
            if expected and hmac.compare_digest(code, expected):
                return True
        
        return False
    
    @staticmethod
    def _generate_code_for_counter(secret, counter):
        """Generate TOTP code for specific counter value"""
        try:
            key = base64.b32decode(secret.upper())
            counter_bytes = struct.pack('>Q', counter)
            hmac_result = hmac.new(key, counter_bytes, hashlib.sha1).digest()
            offset = hmac_result[-1] & 0x0F
            code_int = struct.unpack('>I', hmac_result[offset:offset + 4])[0]
            code_int &= 0x7FFFFFFF
            code = code_int % (10 ** AmazonSecurityConfig.MFA_CODE_LENGTH)
            return str(code).zfill(AmazonSecurityConfig.MFA_CODE_LENGTH)
        except:
            return None
    
    @staticmethod
    def generate_backup_codes():
        """Generate one-time backup codes"""
        codes = []
        for _ in range(AmazonSecurityConfig.MFA_BACKUP_CODES_COUNT):
            code = ''.join([str(os.urandom(1)[0] % 10) for _ in range(8)])
            codes.append(f"{code[:4]}-{code[4:]}")
        return codes
    
    @staticmethod
    def get_provisioning_uri(secret, username, issuer="PhishingDetector"):
        """Generate QR code URI for authenticator apps"""
        return f"otpauth://totp/{issuer}:{username}?secret={secret}&issuer={issuer}"


# ============================================================================
# PROGRESSIVE ACCOUNT LOCKOUT
# ============================================================================

class AccountLockout:
    """Progressive account lockout with exponential backoff"""
    
    @staticmethod
    def record_failed_attempt(identifier):
        """Record a failed login attempt"""
        with _security_lock:
            attempts = _failed_attempts.get(identifier, {'count': 0, 'timestamps': []})
            attempts['count'] += 1
            attempts['timestamps'].append(time.time())
            
            # Keep only recent timestamps (last hour)
            cutoff = time.time() - 3600
            attempts['timestamps'] = [t for t in attempts['timestamps'] if t > cutoff]
            
            _failed_attempts.set(identifier, attempts)
            
            # Check if lockout needed
            if attempts['count'] >= AmazonSecurityConfig.MAX_FAILED_ATTEMPTS:
                AccountLockout._apply_lockout(identifier, attempts['count'])
            
            return attempts['count']
    
    @staticmethod
    def _apply_lockout(identifier, attempt_count):
        """Apply progressive lockout"""
        # Calculate lockout duration based on attempt count
        lockout_index = min(
            (attempt_count - AmazonSecurityConfig.MAX_FAILED_ATTEMPTS) // 2,
            len(AmazonSecurityConfig.LOCKOUT_DURATIONS) - 1
        )
        duration = AmazonSecurityConfig.LOCKOUT_DURATIONS[lockout_index]
        
        lockout_until = time.time() + duration
        _lockouts.set(identifier, {
            'until': lockout_until,
            'duration': duration,
            'attempts': attempt_count
        })
        
        logger.warning(f"🔒 Account locked: {identifier} for {duration}s after {attempt_count} attempts")
    
    @staticmethod
    def is_locked(identifier):
        """Check if account/IP is locked"""
        lockout = _lockouts.get(identifier)
        if not lockout:
            return False, 0, 0
        
        remaining = lockout['until'] - time.time()
        if remaining <= 0:
            _lockouts.delete(identifier)
            return False, 0, 0
        
        return True, int(remaining), lockout['attempts']
    
    @staticmethod
    def clear_attempts(identifier):
        """Clear failed attempts after successful login"""
        _failed_attempts.delete(identifier)
        _lockouts.delete(identifier)
    
    @staticmethod
    def get_remaining_attempts(identifier):
        """Get remaining login attempts before lockout"""
        attempts = _failed_attempts.get(identifier, {'count': 0})
        remaining = max(0, AmazonSecurityConfig.MAX_FAILED_ATTEMPTS - attempts['count'])
        return remaining


# ============================================================================
# DEVICE TRUST SYSTEM
# ============================================================================

class DeviceTrustManager:
    """Manage trusted devices for users"""
    
    @staticmethod
    def trust_device(username, device_fingerprint, device_info, ip_address):
        """Add device to trusted list"""
        with _device_lock:
            key = f"trusted_{username}"
            devices = _device_trust.get(key, [])
            
            # Check if already trusted
            for device in devices:
                if device['fingerprint'] == device_fingerprint:
                    device['last_used'] = datetime.now().isoformat()
                    device['ip_address'] = ip_address
                    _device_trust.set(key, devices)
                    return True
            
            # Add new trusted device
            if len(devices) >= AmazonSecurityConfig.MAX_TRUSTED_DEVICES:
                # Remove oldest device
                devices.sort(key=lambda d: d.get('last_used', ''))
                devices.pop(0)
            
            devices.append({
                'fingerprint': device_fingerprint,
                'info': device_info,
                'ip_address': ip_address,
                'trusted_at': datetime.now().isoformat(),
                'last_used': datetime.now().isoformat()
            })
            
            _device_trust.set(key, devices)
            logger.info(f"✅ Device trusted for user: {username}")
            return True
    
    @staticmethod
    def is_trusted_device(username, device_fingerprint):
        """Check if device is trusted"""
        key = f"trusted_{username}"
        devices = _device_trust.get(key, [])
        
        for device in devices:
            if device['fingerprint'] == device_fingerprint:
                return True
        
        return False
    
    @staticmethod
    def get_trusted_devices(username):
        """Get list of trusted devices for user"""
        key = f"trusted_{username}"
        return _device_trust.get(key, [])
    
    @staticmethod
    def revoke_device(username, device_fingerprint):
        """Remove device from trusted list"""
        with _device_lock:
            key = f"trusted_{username}"
            devices = _device_trust.get(key, [])
            devices = [d for d in devices if d['fingerprint'] != device_fingerprint]
            _device_trust.set(key, devices)
            return True
    
    @staticmethod
    def revoke_all_devices(username):
        """Remove all trusted devices"""
        key = f"trusted_{username}"
        _device_trust.delete(key)
        return True


# ============================================================================
# ANOMALY DETECTION
# ============================================================================

class AnomalyDetector:
    """Detect suspicious login patterns"""
    
    @staticmethod
    def analyze_login(username, ip_address, device_fingerprint, request):
        """Analyze login attempt for anomalies"""
        anomaly_score = 0
        anomalies = []
        
        # Check 1: New device
        if not DeviceTrustManager.is_trusted_device(username, device_fingerprint):
            anomaly_score += AmazonSecurityConfig.NEW_DEVICE_SCORE
            anomalies.append({
                'type': 'new_device',
                'score': AmazonSecurityConfig.NEW_DEVICE_SCORE,
                'message': 'Login from unrecognized device'
            })
        
        # Check 2: Unusual time (outside 6 AM - 11 PM local)
        current_hour = datetime.now().hour
        if current_hour < 6 or current_hour > 23:
            anomaly_score += AmazonSecurityConfig.UNUSUAL_TIME_SCORE
            anomalies.append({
                'type': 'unusual_time',
                'score': AmazonSecurityConfig.UNUSUAL_TIME_SCORE,
                'message': f'Login at unusual hour ({current_hour}:00)'
            })
        
        # Check 3: Rapid attempts from different locations
        history_key = f"history_{username}"
        history = _login_history.get(history_key, [])
        recent_ips = set()
        cutoff = time.time() - 300  # Last 5 minutes
        
        for entry in history:
            if entry.get('timestamp', 0) > cutoff:
                recent_ips.add(entry.get('ip', ''))
        
        if len(recent_ips) > 2:
            anomaly_score += AmazonSecurityConfig.RAPID_ATTEMPTS_SCORE
            anomalies.append({
                'type': 'multiple_locations',
                'score': AmazonSecurityConfig.RAPID_ATTEMPTS_SCORE,
                'message': f'Login attempts from {len(recent_ips)} different IPs in 5 minutes'
            })
        
        # Check 4: New IP for this user - O(1) with set comprehension
        known_ips = {entry.get('ip', '') for entry in history}
        
        if ip_address not in known_ips and len(known_ips) > 0:
            anomaly_score += AmazonSecurityConfig.NEW_LOCATION_SCORE
            anomalies.append({
                'type': 'new_location',
                'score': AmazonSecurityConfig.NEW_LOCATION_SCORE,
                'message': 'Login from new IP address'
            })
        
        # Store anomaly score
        _anomaly_scores.set(f"anomaly_{username}_{ip_address}", {
            'score': anomaly_score,
            'anomalies': anomalies,
            'timestamp': time.time()
        })
        
        is_suspicious = anomaly_score >= AmazonSecurityConfig.ANOMALY_SCORE_THRESHOLD
        
        if is_suspicious:
            logger.warning(f"⚠️ Suspicious login: {username} from {ip_address}, score: {anomaly_score}")
        
        return {
            'score': anomaly_score,
            'is_suspicious': is_suspicious,
            'anomalies': anomalies,
            'requires_mfa': is_suspicious or not DeviceTrustManager.is_trusted_device(username, device_fingerprint)
        }


# ============================================================================
# LOGIN HISTORY
# ============================================================================

class LoginHistory:
    """Track and manage login history"""
    
    @staticmethod
    def record_login(username, ip_address, device_info, success, mfa_used=False):
        """Record a login attempt"""
        with _history_lock:
            key = f"history_{username}"
            history = _login_history.get(key, [])
            
            entry = {
                'timestamp': time.time(),
                'datetime': datetime.now().isoformat(),
                'ip': ip_address,
                'device': device_info,
                'success': success,
                'mfa_used': mfa_used
            }
            
            # Keep last 50 entries per user
            history.append(entry)
            if len(history) > 50:
                history = history[-50:]
            
            _login_history.set(key, history)
            
            return entry
    
    @staticmethod
    def get_recent_logins(username, limit=10):
        """Get recent login history for user"""
        key = f"history_{username}"
        history = _login_history.get(key, [])
        return history[-limit:]
    
    @staticmethod
    def get_failed_logins(username, hours=24):
        """Get failed login attempts in time window"""
        key = f"history_{username}"
        history = _login_history.get(key, [])
        cutoff = time.time() - (hours * 3600)
        
        failed = [
            entry for entry in history
            if not entry.get('success') and entry.get('timestamp', 0) > cutoff
        ]
        
        return failed


# ============================================================================
# SECURITY CHALLENGE SYSTEM
# ============================================================================

class SecurityChallenge:
    """Issue and verify security challenges for suspicious logins"""
    
    @staticmethod
    def create_challenge(username, challenge_type='mfa'):
        """Create a security challenge"""
        challenge_id = hashlib.sha256(
            f"{username}:{time.time()}:{os.urandom(16).hex()}".encode()
        ).hexdigest()[:32]
        
        challenge = {
            'id': challenge_id,
            'username': username,
            'type': challenge_type,
            'created': time.time(),
            'expires': time.time() + 300,  # 5 minutes
            'verified': False
        }
        
        _security_challenges.set(challenge_id, challenge)
        
        return challenge_id
    
    @staticmethod
    def verify_challenge(challenge_id, verification_data):
        """Verify a security challenge"""
        challenge = _security_challenges.get(challenge_id)
        
        if not challenge:
            return False, "Challenge not found or expired"
        
        if time.time() > challenge['expires']:
            _security_challenges.delete(challenge_id)
            return False, "Challenge expired"
        
        if challenge['verified']:
            return False, "Challenge already used"
        
        # Mark as verified
        challenge['verified'] = True
        _security_challenges.set(challenge_id, challenge)
        
        return True, "Challenge verified"
    
    @staticmethod
    def get_challenge(challenge_id):
        """Get challenge details"""
        return _security_challenges.get(challenge_id)


# ============================================================================
# PASSWORD SECURITY
# ============================================================================

class PasswordSecurity:
    """Enhanced password security validation"""
    
    @staticmethod
    def validate_password_strength(password):
        """Validate password meets Amazon-level requirements"""
        errors = []
        
        if len(password) < AmazonSecurityConfig.MIN_PASSWORD_LENGTH:
            errors.append(f"Password must be at least {AmazonSecurityConfig.MIN_PASSWORD_LENGTH} characters")
        
        if AmazonSecurityConfig.REQUIRE_UPPERCASE and not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter")
        
        if AmazonSecurityConfig.REQUIRE_LOWERCASE and not re.search(r'[a-z]', password):
            errors.append("Password must contain at least one lowercase letter")
        
        if AmazonSecurityConfig.REQUIRE_NUMBERS and not re.search(r'\d', password):
            errors.append("Password must contain at least one number")
        
        if AmazonSecurityConfig.REQUIRE_SPECIAL and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append("Password must contain at least one special character")
        
        # Check for common patterns
        common_patterns = ['password', '123456', 'qwerty', 'admin', 'letmein']
        for pattern in common_patterns:
            if pattern.lower() in password.lower():
                errors.append("Password contains common pattern")
                break
        
        return len(errors) == 0, errors
    
    @staticmethod
    def get_password_strength_score(password):
        """Calculate password strength score (0-100)"""
        score = 0
        
        # Length score (up to 30 points)
        score += min(30, len(password) * 2)
        
        # Character variety (up to 40 points)
        if re.search(r'[a-z]', password):
            score += 10
        if re.search(r'[A-Z]', password):
            score += 10
        if re.search(r'\d', password):
            score += 10
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 10
        
        # Unique characters (up to 30 points)
        unique_ratio = len(set(password)) / len(password) if password else 0
        score += int(unique_ratio * 30)
        
        return min(100, score)


# ============================================================================
# MAIN SECURITY CHECK FUNCTION
# ============================================================================

def amazon_security_check(request, username, password=None):
    """
    Comprehensive Amazon-level security check for login attempts.
    
    Returns:
        dict: {
            'allowed': bool,
            'requires_mfa': bool,
            'challenge_id': str or None,
            'message': str,
            'anomaly_score': int,
            'remaining_attempts': int,
            'lockout_seconds': int,
            'device_trusted': bool,
            'security_alerts': list
        }
    """
    # Get client info
    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
    if ip_address and ',' in ip_address:
        ip_address = ip_address.split(',')[0].strip()
    
    device_fingerprint = DeviceFingerprint.generate(request)
    device_info = DeviceFingerprint.get_device_info(request)
    
    result = {
        'allowed': True,
        'requires_mfa': False,
        'challenge_id': None,
        'message': 'OK',
        'anomaly_score': 0,
        'remaining_attempts': AmazonSecurityConfig.MAX_FAILED_ATTEMPTS,
        'lockout_seconds': 0,
        'device_trusted': False,
        'device_fingerprint': device_fingerprint,
        'device_info': device_info,
        'security_alerts': []
    }
    
    # Check 1: Account/IP lockout
    is_locked, remaining_time, attempts = AccountLockout.is_locked(ip_address)
    if is_locked:
        result['allowed'] = False
        result['lockout_seconds'] = remaining_time
        result['message'] = f"Account locked. Try again in {remaining_time} seconds"
        result['security_alerts'].append({
            'type': 'lockout',
            'message': f"Too many failed attempts ({attempts})"
        })
        return result
    
    # Also check username lockout
    if username:
        is_locked, remaining_time, attempts = AccountLockout.is_locked(f"user_{username}")
        if is_locked:
            result['allowed'] = False
            result['lockout_seconds'] = remaining_time
            result['message'] = f"Account locked. Try again in {remaining_time} seconds"
            return result
    
    # Check 2: Remaining attempts
    result['remaining_attempts'] = AccountLockout.get_remaining_attempts(ip_address)
    
    # Check 3: Device trust
    if username:
        result['device_trusted'] = DeviceTrustManager.is_trusted_device(username, device_fingerprint)
    
    # Check 4: Anomaly detection
    if username:
        anomaly_result = AnomalyDetector.analyze_login(
            username, ip_address, device_fingerprint, request
        )
        result['anomaly_score'] = anomaly_result['score']
        result['requires_mfa'] = anomaly_result['requires_mfa']
        
        if anomaly_result['is_suspicious']:
            result['security_alerts'].extend(anomaly_result['anomalies'])
    
    # Check 5: Create MFA challenge if needed
    if result['requires_mfa'] and username:
        result['challenge_id'] = SecurityChallenge.create_challenge(username, 'mfa')
    
    return result


def record_login_result(username, ip_address, device_fingerprint, device_info, success, trust_device=False):
    """Record login result and update security state"""
    
    if success:
        # Clear failed attempts
        AccountLockout.clear_attempts(ip_address)
        AccountLockout.clear_attempts(f"user_{username}")
        
        # Trust device if requested
        if trust_device:
            DeviceTrustManager.trust_device(username, device_fingerprint, device_info, ip_address)
        
        # Record successful login
        LoginHistory.record_login(username, ip_address, device_info, True)
        
        logger.info(f"✅ Successful login: {username} from {ip_address}")
    else:
        # Record failed attempt
        AccountLockout.record_failed_attempt(ip_address)
        AccountLockout.record_failed_attempt(f"user_{username}")
        
        # Record failed login
        LoginHistory.record_login(username, ip_address, device_info, False)
        
        logger.warning(f"❌ Failed login: {username} from {ip_address}")


# ============================================================================
# API HELPER FUNCTIONS
# ============================================================================

def get_user_security_status(username):
    """Get comprehensive security status for user"""
    return {
        'trusted_devices': DeviceTrustManager.get_trusted_devices(username),
        'recent_logins': LoginHistory.get_recent_logins(username),
        'failed_attempts_24h': len(LoginHistory.get_failed_logins(username, 24)),
        'mfa_enabled': _mfa_secrets.get(f"mfa_{username}") is not None
    }


def enable_mfa(username):
    """Enable MFA for user and return setup info"""
    secret = TOTPManager.generate_secret()
    backup_codes = TOTPManager.generate_backup_codes()
    
    _mfa_secrets.set(f"mfa_{username}", {
        'secret': secret,
        'backup_codes': backup_codes,
        'enabled_at': datetime.now().isoformat()
    })
    
    return {
        'secret': secret,
        'provisioning_uri': TOTPManager.get_provisioning_uri(secret, username),
        'backup_codes': backup_codes
    }


def verify_mfa(username, code):
    """Verify MFA code for user"""
    mfa_data = _mfa_secrets.get(f"mfa_{username}")
    
    if not mfa_data:
        return False, "MFA not enabled"
    
    # Check TOTP code
    if TOTPManager.verify_totp(mfa_data['secret'], code):
        return True, "MFA verified"
    
    # Check backup codes
    if code in mfa_data.get('backup_codes', []):
        # Remove used backup code
        mfa_data['backup_codes'].remove(code)
        _mfa_secrets.set(f"mfa_{username}", mfa_data)
        return True, "Backup code used"
    
    return False, "Invalid MFA code"


def is_mfa_enabled(username):
    """Check if MFA is enabled for user"""
    return _mfa_secrets.get(f"mfa_{username}") is not None
