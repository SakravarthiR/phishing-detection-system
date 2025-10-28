"""
Core detection logic - this is where the magic happens.

Extracts a bunch of features from URLs and feeds them to the ML model.
Also added some custom rules because the model sometimes misses obvious stuff
like raw IP addresses or URLs with @ symbols (seriously who uses those?).
"""

import re
import pandas as pd
import joblib
from typing import Dict, Tuple, Optional
import os
import requests
from urllib.parse import urlparse
import ssl
import socket
from datetime import datetime
import sys
import pickle
import io
import warnings

# CRITICAL: Patch sklearn BEFORE any imports that use it
import sklearn
from sklearn import tree, ensemble

# Monkey-patch sklearn classes at import time to remove monotonic_cst
original_dt_setstate = tree.DecisionTreeClassifier.__setstate__
original_rf_setstate = ensemble.RandomForestClassifier.__setstate__

def patched_dt_setstate(self, state):
    """Remove monotonic_cst from old model states"""
    if isinstance(state, dict):
        state.pop('monotonic_cst', None)
        state.pop('monotonic', None)
    return original_dt_setstate(self, state)

def patched_rf_setstate(self, state):
    """Remove monotonic_cst from old model states"""
    if isinstance(state, dict):
        state.pop('monotonic_cst', None)
        state.pop('monotonic', None)
    return original_rf_setstate(self, state)

tree.DecisionTreeClassifier.__setstate__ = patched_dt_setstate
ensemble.RandomForestClassifier.__setstate__ = patched_rf_setstate

print("[+] sklearn __setstate__ patches applied at import")


def check_website_live(url: str, timeout: int = 5) -> dict:
    """
    Check if a website is actually up and grab some intel about it.
    
    This does real HTTP requests so be careful not to spam it.
    Returns a bunch of info like status code, SSL cert, redirects, etc.
    """
    result = {
        'is_reachable': False,
        'status_code': None,
        'response_time': None,
        'has_ssl': False,
        'ssl_valid': False,
        'ssl_issuer': None,
        'ssl_expiry': None,
        'redirects': 0,
        'final_url': None,
        'content_type': None,
        'server': None,
        'suspicious_formats': [],
        'error': None
    }
    
    try:
        # Normalize URL
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        start_time = datetime.now()
        
        # Make request with redirects
        response = requests.get(
            url, 
            timeout=timeout,
            allow_redirects=True,
            verify=False,  # Yeah I know, but we WANT to catch bad SSL certs
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        )
        
        end_time = datetime.now()
        response_time = (end_time - start_time).total_seconds()
        
        # Basic info
        result['is_reachable'] = True
        result['status_code'] = response.status_code
        result['response_time'] = round(response_time, 2)
        result['final_url'] = response.url
        result['redirects'] = len(response.history)
        
        # Headers
        result['content_type'] = response.headers.get('Content-Type', 'Unknown')
        result['server'] = response.headers.get('Server', 'Unknown')
        
        # Check for suspicious response patterns
        if response.status_code >= 400:
            result['suspicious_formats'].append(f'HTTP Error {response.status_code}')
        
        if result['redirects'] > 3:
            result['suspicious_formats'].append(f'Too many redirects ({result["redirects"]}) - kinda sus')
        
        # Check SSL certificate if it's HTTPS
        if url.startswith('https://'):
            result['has_ssl'] = True
            try:
                parsed = urlparse(url)
                hostname = parsed.hostname
                port = parsed.port or 443
                
                context = ssl.create_default_context()
                with socket.create_connection((hostname, port), timeout=timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        result['ssl_valid'] = True
                        result['ssl_issuer'] = dict(x[0] for x in cert['issuer'])['commonName']
                        
                        # Parse expiry date
                        expiry_str = cert['notAfter']
                        expiry_date = datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')
                        result['ssl_expiry'] = expiry_date.strftime('%Y-%m-%d')
                        
                        # Check if expired
                        if expiry_date < datetime.now():
                            result['suspicious_formats'].append('SSL certificate expired')
                            result['ssl_valid'] = False
                            
            except ssl.SSLError as e:
                result['ssl_valid'] = False
                result['suspicious_formats'].append(f'Invalid SSL: {str(e)[:50]}')
            except Exception as e:
                result['ssl_valid'] = False
                result['suspicious_formats'].append('SSL check failed')
        
        # Check content type
        content_type = result['content_type'].lower()
        if 'text/html' not in content_type and 'application/xhtml' not in content_type:
            if response.status_code == 200:
                result['suspicious_formats'].append(f'Unusual content type: {content_type}')
        
    except requests.exceptions.Timeout:
        result['error'] = 'Request timeout - website too slow or unresponsive'
        result['suspicious_formats'].append('Timeout')
    except requests.exceptions.ConnectionError:
        result['error'] = 'Cannot connect - website may be offline'
        result['suspicious_formats'].append('Connection failed')
    except requests.exceptions.TooManyRedirects:
        result['error'] = 'Too many redirects'
        result['suspicious_formats'].append('Redirect loop detected')
    except requests.exceptions.RequestException as e:
        result['error'] = f'Request error: {str(e)[:100]}'
        result['suspicious_formats'].append('Request failed')
    except Exception as e:
        result['error'] = f'Unexpected error: {str(e)[:100]}'
    
    return result


def extract_subdomain_info(url: str) -> dict:
    """
    Extract subdomain information from URL (simplified - just list and count).
    
    Args:
        url: The URL string to analyze
        
    Returns:
        Dictionary with subdomain info:
        - subdomain_count: Number of subdomains
        - subdomains: List of subdomain names
        - full_domain: Complete domain
    """
    url_lower = url.lower()
    
    # Extract domain from URL
    domain_match = re.search(r'(?:https?://)?(?:www\.)?([^/:?#]+)', url_lower)
    
    if not domain_match:
        return {
            'subdomain_count': 0,
            'subdomains': [],
            'full_domain': ''
        }
    
    full_domain = domain_match.group(1)
    domain_parts = full_domain.split('.')
    
    # Calculate subdomain count
    # Typical domain: example.com (2 parts) -> 0 subdomains
    # With subdomain: sub.example.com (3 parts) -> 1 subdomain
    # Multiple: a.b.example.com (4 parts) -> 2 subdomains
    
    subdomain_count = max(0, len(domain_parts) - 2)
    subdomains = domain_parts[:-2] if subdomain_count > 0 else []
    
    return {
        'subdomain_count': subdomain_count,
        'subdomains': subdomains,
        'full_domain': full_domain
    }


def extract_features(url: str) -> pd.DataFrame:
    """
    Extract advanced lexical features from a URL for phishing detection.
    Uses sophisticated regex patterns for accurate feature extraction.
    
    Args:
        url: The URL string to analyze
        
    Returns:
        A pandas DataFrame with one row containing extracted features
        
    Features extracted:
        - url_length: Total character count
        - num_dots: Number of '.' characters
        - num_hyphens: Number of '-' characters
        - num_digits: Count of numeric digits
        - has_ip: Binary flag (1 if URL contains valid IPv4 address)
        - has_ipv6: Binary flag (1 if URL contains IPv6 address)
        - has_suspicious_keyword: Contains phishing-related keywords
        - is_https: Uses HTTPS protocol
        - num_subdomains: Count of subdomains
        - entropy: Shannon entropy (randomness measure)
        - has_port: Contains non-standard port number
        - has_double_slash: Has '//' in path (suspicious)
        - has_at_symbol: Contains '@' (URL obfuscation)
        - has_shortening_service: Known URL shortener domain
        - domain_length: Length of domain name only
        - path_length: Length of URL path
        - has_hex_chars: Contains hexadecimal encoding
        - suspicious_tld: Uses suspicious top-level domain
        - digit_letter_ratio: Ratio of digits to letters
    """
    from collections import Counter
    import math
    
    features = {}
    url_lower = url.lower()
    
    # Basic length features
    features['url_length'] = len(url)
    
    # Advanced regex patterns for accurate detection
    
    # 1. IPv4 Address Detection (RFC compliant with valid range 0-255)
    ipv4_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    features['has_ip'] = 1 if re.search(ipv4_pattern, url) else 0
    
    # 2. IPv6 Address Detection (simplified pattern)
    ipv6_pattern = r'(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4})'
    features['has_ipv6'] = 1 if re.search(ipv6_pattern, url) else 0
    
    # 3. Count special characters
    features['num_dots'] = url.count('.')
    features['num_hyphens'] = url.count('-')
    features['num_underscores'] = url.count('_')
    features['num_slashes'] = url.count('/')
    features['num_at'] = url.count('@')
    features['num_question'] = url.count('?')
    features['num_ampersand'] = url.count('&')
    features['num_equals'] = url.count('=')
    features['num_percent'] = url.count('%')
    
    # 4. Count digits and calculate digit-to-letter ratio
    features['num_digits'] = sum(c.isdigit() for c in url)
    num_letters = sum(c.isalpha() for c in url)
    features['digit_letter_ratio'] = features['num_digits'] / max(num_letters, 1)
    
    # 5. Check for @ symbol (URL obfuscation technique)
    features['has_at_symbol'] = 1 if '@' in url else 0
    
    # 6. Advanced suspicious keyword detection (case-insensitive with word boundaries)
    suspicious_keywords = [
        'login', 'verify', 'account', 'update', 'secure', 'banking', 'signin', 
        'confirm', 'suspend', 'restrict', 'alert', 'unlock', 'validate', 
        'credential', 'password', 'paypal', 'ebay', 'amazon', 'apple', 
        'microsoft', 'wallet', 'billing', 'payment', 'webscr'
    ]
    features['has_suspicious_keyword'] = 1 if any(kw in url_lower for kw in suspicious_keywords) else 0
    
    # 7. Count occurrences of suspicious keywords
    features['suspicious_keyword_count'] = sum(url_lower.count(kw) for kw in suspicious_keywords)
    
    # 8. Protocol detection (HTTPS vs HTTP)
    features['is_https'] = 1 if url_lower.startswith('https://') else 0
    
    # 9. Extract and analyze domain components
    domain_match = re.search(r'(?:https?://)?(?:www\.)?([^/:?#]+)', url_lower)
    if domain_match:
        domain = domain_match.group(1)
        features['domain_length'] = len(domain)
        
        # Count subdomains (more accurate)
        domain_parts = domain.split('.')
        # Typical domain has 2 parts (domain.tld), anything more is subdomains
        features['num_subdomains'] = max(0, len(domain_parts) - 2)
        
        # Check for suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.click', '.link', '.zip']
        features['suspicious_tld'] = 1 if any(domain.endswith(tld) for tld in suspicious_tlds) else 0
        
        # Domain has only digits (highly suspicious)
        features['domain_all_digits'] = 1 if domain.replace('.', '').isdigit() else 0
    else:
        features['domain_length'] = 0
        features['num_subdomains'] = 0
        features['suspicious_tld'] = 0
        features['domain_all_digits'] = 0
    
    # 10. Extract path and query components
    path_match = re.search(r'(?:https?://[^/]+)(/[^?#]*)?', url)
    if path_match and path_match.group(1):
        path = path_match.group(1)
        features['path_length'] = len(path)
        features['path_depth'] = path.count('/')
    else:
        features['path_length'] = 0
        features['path_depth'] = 0
    
    # 11. Port detection (non-standard ports are suspicious)
    port_pattern = r':(\d{2,5})(?:/|$)'
    port_match = re.search(port_pattern, url)
    if port_match:
        port = int(port_match.group(1))
        # Standard ports: 80 (HTTP), 443 (HTTPS), 8080 (HTTP alt)
        features['has_port'] = 1 if port not in [80, 443] else 0
        features['port_number'] = port
    else:
        features['has_port'] = 0
        features['port_number'] = 0
    
    # 12. Check for double slash in path (path confusion attack)
    if '//' in url:
        # Remove protocol part, then check for remaining //
        after_protocol = url.split('://', 1)[-1] if '://' in url else url
        features['has_double_slash_in_path'] = 1 if '//' in after_protocol else 0
    else:
        features['has_double_slash_in_path'] = 0
    
    # 13. URL shortening services detection
    shortening_services = [
        'bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly', 'is.gd', 
        'buff.ly', 'adf.ly', 'bit.do', 'short.io', 'rebrand.ly', 'cutt.ly'
    ]
    features['has_shortening_service'] = 1 if any(service in url_lower for service in shortening_services) else 0
    
    # 14. Hexadecimal/URL encoding detection (obfuscation)
    hex_pattern = r'%[0-9a-fA-F]{2}'
    hex_matches = re.findall(hex_pattern, url)
    features['has_hex_chars'] = 1 if hex_matches else 0
    features['hex_char_count'] = len(hex_matches)
    
    # 15. Punycode detection (internationalized domain names - IDN homograph attack)
    features['has_punycode'] = 1 if 'xn--' in url_lower else 0
    
    # 16. Shannon Entropy (measure of randomness - higher = more random/suspicious)
    if len(url) > 0:
        counter = Counter(url)
        entropy = 0.0
        for count in counter.values():
            probability = count / len(url)
            if probability > 0:
                entropy -= probability * math.log2(probability)
        features['entropy'] = entropy
    else:
        features['entropy'] = 0.0
    
    # 17. Domain entropy (randomness in domain name only)
    if domain_match:
        domain = domain_match.group(1)
        if len(domain) > 0:
            counter = Counter(domain)
            domain_entropy = 0.0
            for count in counter.values():
                probability = count / len(domain)
                if probability > 0:
                    domain_entropy -= probability * math.log2(probability)
            features['domain_entropy'] = domain_entropy
        else:
            features['domain_entropy'] = 0.0
    else:
        features['domain_entropy'] = 0.0
    
    # 18. Check for excessive subdomain hyphens (typosquatting technique)
    features['has_excessive_hyphens'] = 1 if features['num_hyphens'] > 3 else 0
    
    # 19. Check for brand name typosquatting patterns
    brand_names = ['paypal', 'google', 'facebook', 'amazon', 'apple', 'microsoft', 'netflix', 'instagram']
    typo_pattern = r'|'.join([f'{brand}[0-9-]' for brand in brand_names])
    features['has_brand_typo'] = 1 if re.search(typo_pattern, url_lower) else 0
    
    # 20. Query string analysis
    query_match = re.search(r'\?(.+)', url)
    if query_match:
        query = query_match.group(1)
        features['query_length'] = len(query)
        features['num_query_params'] = query.count('&') + 1
    else:
        features['query_length'] = 0
        features['num_query_params'] = 0
    
    # Return as DataFrame (single row)
    return pd.DataFrame([features])


def fix_model_attributes(model):
    """
    Fix monotonic_cst attribute on model and all nested estimators.
    This handles old models that were trained with scikit-learn 1.3.2 but are loaded
    with newer versions like 1.7.2.
    
    Instead of deleting the attribute, we set it to None (the expected default value).
    """
    try:
        # For RandomForest, fix all individual trees
        if hasattr(model, 'estimators_'):
            for tree in model.estimators_:
                if tree is not None:
                    # Set monotonic_cst to None if missing - this is what new sklearn expects
                    if not hasattr(tree, 'monotonic_cst'):
                        tree.monotonic_cst = None
        
        print(f"[+] Model attributes fixed - set monotonic_cst to None on all trees")
        return model
    except Exception as e:
        print(f"[!] Warning: could not fully fix model attributes: {e}")
        return model


def load_model(model_path: str = 'phish_model.pkl'):
    """
    Load the trained phishing detection model from disk.
    sklearn __setstate__ patches are applied at module import.
    Additional fixing of model instances after loading.
    
    Args:
        model_path: Path to the saved model file
        
    Returns:
        The loaded model object, or None if loading fails
    """
    try:
        if not os.path.exists(model_path):
            print(f"[-] Model file not found: {model_path}")
            return None
        
        # Load with joblib (sklearn patches already applied)
        model = joblib.load(model_path)
        print(f"[+] Model loaded successfully from {model_path}")
        
        # Fix attributes on the loaded model instance
        model = fix_model_attributes(model)
        
        return model
        
    except Exception as e:
        print(f"[-] Error loading model: {str(e)}")
        import traceback
        traceback.print_exc()
        return None


def analyze_website_content(url: str, timeout: int = 5) -> Dict:
    """
    Analyze the actual website content to detect phishing indicators.
    
    Checks for:
    - Login forms on suspicious domains
    - External form submission URLs
    - Suspicious JavaScript
    - Certificate issues
    - HTTPS enforcement
    - Meta refresh redirects
    - Hidden form fields
    - Mismatched domain in links/forms
    
    Args:
        url: The website URL to analyze
        timeout: Request timeout in seconds
        
    Returns:
        Dictionary with content analysis indicators
    """
    analysis = {
        'has_login_form': False,
        'has_external_form': False,
        'has_meta_refresh': False,
        'has_hidden_inputs': False,
        'suspicious_scripts': 0,
        'external_links_count': 0,
        'forms_targeting_external': 0,
        'domain_mismatches': 0,
        'phishing_indicators': 0,
        'content_score': 0.0
    }
    
    try:
        # Attempt to fetch the website
        import re as regex_module
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        response = requests.get(url, timeout=timeout, verify=False, headers=headers, allow_redirects=True)
        
        if response.status_code != 200:
            analysis['content_score'] = 0.3  # Bad status = suspicious
            return analysis
        
        html_content = response.text.lower()
        
        # Extract domain from URL for comparison
        parsed_url = urlparse(url)
        main_domain = parsed_url.netloc.replace('www.', '')
        
        # Check 1: Login forms
        if '<form' in html_content:
            # Look for password fields
            if 'type="password"' in html_content or 'type=password' in html_content or 'password' in html_content:
                analysis['has_login_form'] = True
                analysis['phishing_indicators'] += 1
                
                # Check if form action goes to external domain
                import re as regex_module
                form_actions = regex_module.findall(r'<form[^>]*action=["\']?([^"\'\s>]+)', html_content)
                for action in form_actions:
                    if action.startswith('http'):
                        action_domain = urlparse(action).netloc.replace('www.', '')
                        if action_domain != main_domain:
                            analysis['has_external_form'] = True
                            analysis['phishing_indicators'] += 2
                            analysis['forms_targeting_external'] += 1
        
        # Check 2: Meta refresh redirects (common in phishing)
        if '<meta' in html_content and 'refresh' in html_content:
            if 'http' in html_content:  # Redirecting to external URL
                analysis['has_meta_refresh'] = True
                analysis['phishing_indicators'] += 2
        
        # Check 3: Hidden input fields (used to capture data)
        hidden_inputs = len(regex_module.findall(r'type=["\']?hidden["\']?', html_content))
        if hidden_inputs > 3:  # Unusual number of hidden fields
            analysis['has_hidden_inputs'] = True
            analysis['phishing_indicators'] += 1
        
        # Check 4: Suspicious JavaScript patterns
        suspicious_patterns = [
            'keylogger',
            'stealpassword',
            'collect.*password',
            'document\.location.*script',
            'eval\(',
            'createElement.*iframe'
        ]
        for pattern in suspicious_patterns:
            if regex_module.search(pattern, html_content):
                analysis['suspicious_scripts'] += 1
                analysis['phishing_indicators'] += 1
        
        # Check 5: Check for HTTPS enforcement (good sign if present)
        has_hsts = 'strict-transport-security' in response.headers.get('set-cookie', '').lower() or \
                   'strict-transport-security' in ' '.join(response.headers.keys()).lower()
        
        # Check 6: Look for legitimate indicators (reduce suspicion)
        legitimate_indicators = [
            'privacy policy',
            'terms of service',
            'contact us',
            'about us',
            'copyright'
        ]
        legitimate_count = sum(1 for indicator in legitimate_indicators if indicator in html_content)
        
        # Calculate content score
        # Base score: 0.5 (neutral)
        content_score = 0.5
        
        # Reduce score for phishing indicators (increase suspicion)
        content_score += (analysis['phishing_indicators'] * 0.1)  # Each indicator increases phishing likelihood
        
        # Increase score for legitimate indicators (decrease suspicion)
        content_score -= (legitimate_count * 0.08)  # Each legitimate indicator reduces suspicion
        
        # Cap at 0-1 range
        analysis['content_score'] = max(0.0, min(1.0, content_score))
        
        return analysis
        
    except Exception as e:
        print(f"[!] Content analysis error: {str(e)}")
        # If we can't fetch content, assume it's suspicious
        analysis['content_score'] = 0.4
        return analysis


def predict_url(url: str, model) -> Tuple[int, float, Dict]:
    """
    Predict whether a URL is phishing or legitimate with advanced rule-based overrides.
    
    Args:
        url: The URL to analyze
        model: The trained model object
        
    Returns:
        A tuple of (label, probability, features_dict)
        - label: 0 for legitimate, 1 for phishing
        - probability: Confidence score (0.0 to 1.0)
        - features_dict: Dictionary of extracted features
    """
    if model is None:
        raise ValueError("Model is not loaded")
    
    # Extract features
    features_df = extract_features(url)
    features_dict = features_df.to_dict(orient='records')[0]

    # Make ML prediction
    prediction = model.predict(features_df)[0]

    # Get probability vector (confidence for each class)
    prob_vector = model.predict_proba(features_df)[0]
    # ml_phish_prob is model's probability for phishing class
    ml_phish_prob = float(prob_vector[1])
    # ml_legit_prob = float(prob_vector[0])
    
    # ===== ADVANCED RULE-BASED OVERRIDES =====
    # Sometimes the ML model is too trusting, so we add manual checks
    # If any of these trigger, we're pretty sure it's phishing
    phishing_score = 0
    url_lower = url.lower()
    
    # Critical red flags (these are REALLY bad)
    if features_dict.get('has_ip', 0) == 1:
        phishing_score += 50  # Nobody legit uses raw IP addresses lol
    
    if features_dict.get('has_at_symbol', 0) == 1:
        phishing_score += 40  # @ in URL? Yeah that's shady AF
    
    if features_dict.get('has_punycode', 0) == 1:
        phishing_score += 45  # IDN homograph attacks (evil unicode tricks)
    
    # Suspicious TLD + suspicious keywords = definitely up to something
    if features_dict.get('suspicious_tld', 0) == 1 and features_dict.get('has_suspicious_keyword', 0) == 1:
        phishing_score += 35
    
    # Free TLDs (.tk, .ml, etc) are sketchy, especially with security words
    free_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq']
    security_keywords = ['verify', 'account', 'login', 'secure', 'update', 'confirm', 'suspend', 'alert']
    if any(url_lower.endswith(tld) for tld in free_tlds):
        if any(keyword in url_lower for keyword in security_keywords):
            phishing_score += 40  # Yeah this is basically always phishing
    
    # Other bad signs
    if features_dict.get('has_shortening_service', 0) == 1:
        phishing_score += 25  # URL shorteners hiding the real destination
    
    if features_dict.get('num_hyphens', 0) >= 3 and features_dict.get('has_suspicious_keyword', 0) == 1:
        phishing_score += 20  # pay-pal-verify-account.com type stuff
    
    if features_dict.get('suspicious_keyword_count', 0) >= 3:
        phishing_score += 25  # Way too many security buzzwords
    
    if features_dict.get('num_subdomains', 0) >= 4:
        phishing_score += 15  # login.secure.verify.paypal.evil.com vibes
    
    # URL encoding abuse (lots of %20 and stuff)
    if features_dict.get('has_hex_chars', 0) == 1 and features_dict.get('hex_char_count', 0) > 3:
        phishing_score += 15  # Trying to hide the actual URL
    
    # Long URLs with security keywords are usually hiding something
    if features_dict.get('url_length', 0) > 100 and features_dict.get('has_suspicious_keyword', 0) == 1:
        phishing_score += 10
    
    if features_dict.get('digit_letter_ratio', 0) > 0.4:
        phishing_score += 10  # URLs shouldn't have that many numbers
    
    # Brand impersonation check - this catches a LOT of phishing
    major_brands = ['paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook', 'ebay', 'netflix', 'instagram']
    domain_match = re.search(r'(?:https?://)?(?:www\.)?([^/:?#]+)', url_lower)
    if domain_match:
        domain = domain_match.group(1)
        # If the URL mentions PayPal but isn't actually paypal.com, that's sus
        for brand in major_brands:
            if brand in url_lower and not domain.endswith(f'{brand}.com'):
                phishing_score += 30  # Definitely trying to impersonate
                break
    
    # Final decision - override ML if our rules are confident enough
    if phishing_score >= 50:
        # Boost ML phishing probability
        ml_phish_prob = max(ml_phish_prob, min(0.95, 0.75 + (phishing_score / 200)))
    elif phishing_score >= 30 and prediction == 0:
        ml_phish_prob = max(ml_phish_prob, min(0.85, 0.65 + (phishing_score / 250)))

    # Content-based analysis (crawl the page and inspect forms/links/scripts)
    try:
        content_analysis = analyze_website_content(url)
    except Exception:
        content_analysis = {'content_score': 0.5}

    # content_score is higher -> more suspicious (we designed it that way)
    content_suspicion = float(content_analysis.get('content_score', 0.5))

    # Normalize rule-based phishing score to 0-1 (assume max 100)
    rule_suspicion = max(0.0, min(1.0, phishing_score / 100.0))

    # Combine signals: weights tuned for balanced behaviour
    w_ml = 0.55
    w_content = 0.30
    w_rules = 0.15

    combined_phish_prob = (w_ml * ml_phish_prob) + (w_content * content_suspicion) + (w_rules * rule_suspicion)
    combined_phish_prob = max(0.0, min(1.0, combined_phish_prob))

    # Decide final label and confidence
    final_label = 1 if combined_phish_prob >= 0.5 else 0
    final_confidence = combined_phish_prob if final_label == 1 else 1.0 - combined_phish_prob

    # Merge content analysis into features for response/diagnostics
    features_dict.update({f'content_{k}': v for k, v in content_analysis.items()})
    # Also include ML and combined probabilities for transparency
    features_dict['ml_phish_prob'] = round(ml_phish_prob, 4)
    features_dict['combined_phish_prob'] = round(combined_phish_prob, 4)

    return int(final_label), float(final_confidence), features_dict


def get_top_feature(features_dict: Dict) -> str:
    """
    Determine the most indicative features for explanation using advanced analysis.
    Prioritizes critical security indicators for user-friendly output.
    
    Args:
        features_dict: Dictionary of extracted features
        
    Returns:
        A human-readable string describing the top suspicious features
    """
    reasons = []
    
    # Critical indicators (highest priority)
    if features_dict.get('has_ip', 0) == 1:
        reasons.append(" Uses IP address instead of domain name")
    
    if features_dict.get('has_ipv6', 0) == 1:
        reasons.append(" Uses IPv6 address")
    
    if features_dict.get('has_at_symbol', 0) == 1:
        reasons.append(" Contains '@' symbol (URL obfuscation)")
    
    if features_dict.get('has_punycode', 0) == 1:
        reasons.append(" Uses internationalized domain (possible homograph attack)")
    
    if features_dict.get('has_shortening_service', 0) == 1:
        reasons.append(" Uses URL shortening service (hides real destination)")
    
    if features_dict.get('has_brand_typo', 0) == 1:
        reasons.append(" Possible brand name typosquatting detected")
    
    if features_dict.get('domain_all_digits', 0) == 1:
        reasons.append(" Domain contains only numbers")
    
    # High priority indicators
    if features_dict.get('suspicious_keyword_count', 0) >= 2:
        reasons.append(f"Multiple suspicious keywords ({features_dict['suspicious_keyword_count']} found)")
    elif features_dict.get('has_suspicious_keyword', 0) == 1:
        reasons.append("Contains phishing-related keywords (login/verify/account)")
    
    if features_dict.get('suspicious_tld', 0) == 1:
        reasons.append("Uses suspicious top-level domain (.tk, .ml, .xyz, etc.)")
    
    if features_dict.get('has_port', 0) == 1:
        port = features_dict.get('port_number', 0)
        reasons.append(f"Non-standard port number ({port})")
    
    if features_dict.get('has_hex_chars', 0) == 1:
        count = features_dict.get('hex_char_count', 0)
        reasons.append(f"URL encoding detected ({count} hex characters - possible obfuscation)")
    
    if features_dict.get('has_double_slash_in_path', 0) == 1:
        reasons.append("Double slash in path (URL confusion technique)")
    
    # Medium priority indicators
    if features_dict.get('url_length', 0) > 100:
        reasons.append(f"Unusually long URL ({features_dict['url_length']} characters)")
    
    if features_dict.get('has_excessive_hyphens', 0) == 1:
        reasons.append(f"Excessive hyphens ({features_dict['num_hyphens']})")
    
    if features_dict.get('num_subdomains', 0) > 4:
        reasons.append(f"Too many subdomains ({features_dict['num_subdomains']})")
    
    if features_dict.get('domain_entropy', 0) > 4.0:
        reasons.append(f"Highly random domain name (entropy: {features_dict['domain_entropy']:.2f})")
    
    if features_dict.get('digit_letter_ratio', 0) > 0.3:
        reasons.append(f"High digit-to-letter ratio ({features_dict['digit_letter_ratio']:.2f})")
    
    # Lower priority indicators
    if features_dict.get('is_https', 0) == 0:
        reasons.append("Not using HTTPS (insecure)")
    
    if features_dict.get('path_depth', 0) > 5:
        reasons.append(f"Deep path structure ({features_dict['path_depth']} levels)")
    
    if features_dict.get('num_query_params', 0) > 10:
        reasons.append(f"Many query parameters ({features_dict['num_query_params']})")
    
    # Return top 3 most critical reasons
    if reasons:
        return " | ".join(reasons[:3])
    else:
        return "✓ URL appears normal based on lexical analysis"


if __name__ == "__main__":
    # Simple test
    test_urls = [
        "https://www.google.com",
        "http://192.168.1.1/login-verify-account",
        "https://secure-paypal-login-verify.suspicious-domain.com/update"
    ]
    
    print("Testing feature extraction:\n")
    for url in test_urls:
        print(f"URL: {url}")
        features = extract_features(url)
        print(features.to_dict(orient='records')[0])
        print("-" * 80)
