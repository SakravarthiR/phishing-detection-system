"""
External Credentials Loader
Loads credentials from external folder for security
"""

import json
import os
import sys
from pathlib import Path

# Determine credentials path based on environment
# Priority: 1) ENV_VAR, 2) External secure folder, 3) Project root
if os.getenv('CREDENTIALS_PATH'):
    CREDENTIALS_PATH = os.getenv('CREDENTIALS_PATH')
elif os.name == 'nt':  # Windows - use secure external folder
    # Use environment variable or default secure location
    CREDENTIALS_PATH = os.getenv('SECURE_CREDENTIALS_DIR', str(Path.home() / '.secure' / 'phishing' / 'credentials.json'))
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
        Load credentials from external JSON file, then environment variables, then defaults
        Returns: Dictionary with all credentials
        """
        global _credentials_cache
        
        # ALWAYS reload credentials from file (no caching for security)
        # This allows password changes without restarting the API
        
        # Try 1: Load from credentials file (preferred method)
        if os.path.exists(CREDENTIALS_PATH):
            try:
                # Load credentials from JSON file
                with open(CREDENTIALS_PATH, 'r', encoding='utf-8') as f:
                    credentials = json.load(f)
                
                print(f"✅ Credentials loaded from file: {CREDENTIALS_PATH}")
                return credentials
                
            except json.JSONDecodeError as e:
                print(f"❌ ERROR: Invalid JSON in credentials file: {e}")
                print(f"   Trying environment variables as fallback...")
            except Exception as e:
                print(f"❌ ERROR: Could not load credentials file: {e}")
                print(f"   Trying environment variables as fallback...")
        else:
            print(f"⚠️  Credentials file not found at: {CREDENTIALS_PATH}")
            print(f"   Trying environment variables as fallback...")
        
        # Try 2: Load from environment variables (fallback for Render/production)
        env_admin_username = os.getenv('ADMIN_USERNAME')
        env_admin_password_hash = os.getenv('ADMIN_PASSWORD_HASH')
        env_secret_key = os.getenv('SECRET_KEY')
        env_jwt_secret = os.getenv('JWT_SECRET_KEY')
        
        if env_admin_username and env_admin_password_hash and env_secret_key and env_jwt_secret:
            print(f"✅ Credentials loaded from environment variables")
            return {
                "admin": {
                    "username": env_admin_username,
                    "password_hash": env_admin_password_hash,
                    "role": "admin",
                    "created_at": "2025-10-21T00:00:00Z"
                },
                "api_keys": {
                    "secret_key": env_secret_key,
                    "jwt_secret_key": env_jwt_secret
                },
                "security": {
                    "session_timeout_minutes": 1440,
                    "max_login_attempts": 5,
                    "lockout_duration_minutes": 15,
                    "allowed_origins": ["http://localhost:3000", "http://localhost:5500", "http://127.0.0.1:5500", "null"]
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
        
        # Try 3: Use default credentials (last resort - INSECURE!)
        print(f"⚠️  WARNING: Could not load credentials from file or environment variables")
        print(f"   Using default/fallback credentials (INSECURE!)")
        return CredentialsLoader._get_default_credentials()
    
    @staticmethod
    def _get_default_credentials():
        """
        Fallback default credentials - GENERATES RANDOM KEYS FOR SECURITY
        Used only if external file cannot be loaded
        WARNING: Password will not work until properly configured!
        """
        import secrets
        import bcrypt
        
        # Generate random secure keys if not configured
        random_secret = secrets.token_hex(32)
        random_jwt = secrets.token_hex(32)
        
        # Generate a random password hash that won't match anything
        # Forces user to configure proper credentials
        unusable_hash = bcrypt.hashpw(secrets.token_bytes(32), bcrypt.gensalt()).decode('utf-8')
        
        print("="*60)
        print("[!] SECURITY WARNING: Using fallback credentials!")
        print("    Login will NOT work until you configure credentials.json")
        print("    or set environment variables: ADMIN_USERNAME, ADMIN_PASSWORD_HASH")
        print("    See SECURITY.md for setup instructions")
        print("="*60)
        
        return {
            "admin": {
                "username": os.getenv('ADMIN_USERNAME', 'admin'),
                "password_hash": unusable_hash,  # Won't match any password
                "role": "admin"
            },
            "api_keys": {
                "secret_key": random_secret,
                "jwt_secret_key": random_jwt
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
