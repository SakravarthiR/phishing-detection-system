"""
External Credentials Loader
Loads credentials from external folder for security
"""

import json
import os
import sys
from pathlib import Path

# Determine credentials path based on environment
# On Windows (local dev): Use external secure folder
# On Linux (production): Use project root
if os.name == 'nt':  # Windows
    CREDENTIALS_PATH = r"C:\Users\ASUS\Documents\credential\phishing\credentials.json"
else:  # Linux/Unix (production server)
    # Get project root directory (parent of backend folder)
    PROJECT_ROOT = Path(__file__).parent.parent
    CREDENTIALS_PATH = PROJECT_ROOT / "credentials.json"

# Cache for loaded credentials
_credentials_cache = None


class CredentialsLoader:
    """Load credentials from external secure location"""
    
    @staticmethod
    def load_credentials():
        """
        Load credentials from external JSON file
        Returns: Dictionary with all credentials
        """
        global _credentials_cache
        
        # ALWAYS reload credentials from file (no caching for security)
        # This allows password changes without restarting the API
        
        # Check if credentials file exists
        if not os.path.exists(CREDENTIALS_PATH):
            print(f"⚠️  WARNING: Credentials file not found at: {CREDENTIALS_PATH}")
            print(f"   Using default credentials (INSECURE!)")
            return CredentialsLoader._get_default_credentials()
        
        try:
            # Load credentials from JSON file
            with open(CREDENTIALS_PATH, 'r', encoding='utf-8') as f:
                credentials = json.load(f)
            
            # Note: We intentionally don't cache to allow live credential updates
            # print(f"✅ Credentials loaded from: {CREDENTIALS_PATH}")
            
            return credentials
            
        except json.JSONDecodeError as e:
            print(f"❌ ERROR: Invalid JSON in credentials file: {e}")
            print(f"   Using default credentials (INSECURE!)")
            return CredentialsLoader._get_default_credentials()
            
        except Exception as e:
            print(f"❌ ERROR: Could not load credentials: {e}")
            print(f"   Using default credentials (INSECURE!)")
            return CredentialsLoader._get_default_credentials()
    
    @staticmethod
    def _get_default_credentials():
        """
        Fallback default credentials
        Used only if external file cannot be loaded
        """
        return {
            "admin": {
                "username": "admin",
                "password_hash": "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYqgOCkT0Ci",
                "role": "admin"
            },
            "api_keys": {
                "secret_key": "default-insecure-key-change-immediately",
                "jwt_secret_key": "default-insecure-jwt-key-change-immediately"
            },
            "security": {
                "session_timeout_minutes": 1440,
                "max_login_attempts": 5,
                "lockout_duration_minutes": 15,
                "allowed_origins": ["http://localhost:3000", "http://127.0.0.1:5500"]
            },
            "advanced_security": {
                "whitelist_enabled": False,
                "whitelisted_ips": ["127.0.0.1", "::1"],
                "max_requests_per_second": 10,
                "max_requests_per_minute": 100,
                "max_concurrent_connections": 5,
                "auto_block_threshold": 3,
                "temporary_block_duration": 3600
            }
        }
    
    @staticmethod
    def get_admin_credentials():
        """Get admin username and password hash"""
        creds = CredentialsLoader.load_credentials()
        admin = creds.get('admin', {})
        return {
            'username': admin.get('username', 'admin'),
            'password_hash': admin.get('password_hash', ''),
            'role': admin.get('role', 'admin')
        }
    
    @staticmethod
    def get_api_keys():
        """Get API secret keys"""
        creds = CredentialsLoader.load_credentials()
        keys = creds.get('api_keys', {})
        return {
            'secret_key': keys.get('secret_key', 'default-insecure-key'),
            'jwt_secret_key': keys.get('jwt_secret_key', 'default-insecure-jwt-key')
        }
    
    @staticmethod
    def get_security_config():
        """Get security configuration"""
        creds = CredentialsLoader.load_credentials()
        return creds.get('security', {
            'session_timeout_minutes': 1440,
            'max_login_attempts': 5,
            'lockout_duration_minutes': 15,
            'allowed_origins': []
        })
    
    @staticmethod
    def get_advanced_security_config():
        """Get advanced security configuration"""
        creds = CredentialsLoader.load_credentials()
        return creds.get('advanced_security', {
            'whitelist_enabled': False,
            'whitelisted_ips': ['127.0.0.1'],
            'max_requests_per_second': 10,
            'max_requests_per_minute': 100,
            'max_concurrent_connections': 5,
            'auto_block_threshold': 3,
            'temporary_block_duration': 3600
        })
    
    @staticmethod
    def reload_credentials():
        """Force reload credentials from file"""
        global _credentials_cache
        _credentials_cache = None
        return CredentialsLoader.load_credentials()
    
    @staticmethod
    def validate_credentials_file():
        """
        Validate that credentials file exists and is valid
        Returns: (is_valid, error_message)
        """
        if not os.path.exists(CREDENTIALS_PATH):
            return False, f"Credentials file not found at: {CREDENTIALS_PATH}"
        
        try:
            with open(CREDENTIALS_PATH, 'r', encoding='utf-8') as f:
                credentials = json.load(f)
            
            # Check required fields
            required_keys = ['admin', 'api_keys', 'security', 'advanced_security']
            missing_keys = [key for key in required_keys if key not in credentials]
            
            if missing_keys:
                return False, f"Missing required keys: {', '.join(missing_keys)}"
            
            # Check admin fields
            admin = credentials['admin']
            if 'username' not in admin or 'password_hash' not in admin:
                return False, "Admin credentials incomplete"
            
            return True, "Credentials file is valid"
            
        except json.JSONDecodeError as e:
            return False, f"Invalid JSON: {e}"
        except Exception as e:
            return False, f"Validation error: {e}"


# Utility functions for easy access
def get_admin_username():
    """Get admin username"""
    return CredentialsLoader.get_admin_credentials()['username']


def get_admin_password_hash():
    """Get admin password hash"""
    return CredentialsLoader.get_admin_credentials()['password_hash']


def get_secret_key():
    """Get Flask secret key"""
    return CredentialsLoader.get_api_keys()['secret_key']


def get_jwt_secret_key():
    """Get JWT secret key"""
    return CredentialsLoader.get_api_keys()['jwt_secret_key']


def get_allowed_origins():
    """Get allowed CORS origins"""
    return CredentialsLoader.get_security_config().get('allowed_origins', [])


# Load credentials on module import
print(f"\n{'='*70}")
print(f"🔐 LOADING CREDENTIALS FROM EXTERNAL LOCATION")
print(f"{'='*70}")
print(f"📁 Credentials Path: {CREDENTIALS_PATH}")

is_valid, message = CredentialsLoader.validate_credentials_file()
if is_valid:
    print(f"✅ {message}")
else:
    print(f"⚠️  {message}")
    print(f"⚠️  Using default credentials (CHANGE IMMEDIATELY!)")

# Load credentials
credentials = CredentialsLoader.load_credentials()
print(f"{'='*70}\n")
