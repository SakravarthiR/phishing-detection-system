"""
Phishing URL Detection Engine - ENHANCED LITE VERSION for 512MB RAM
Pure Python advanced rule-based detection (no ML libraries)

Detection capabilities:
- URL structure analysis with entropy calculation
- Typosquatting detection (Levenshtein distance)
- Brand impersonation detection
- Homograph attack detection (IDN/Punycode)
- Suspicious keyword patterns
- Domain reputation scoring
- SSL/TLS validation
- Path and query analysis
"""

import re
import os
import math
import requests
from urllib.parse import urlparse, parse_qs, unquote
import ssl
import socket
from datetime import datetime
import gc
from collections import Counter
import hashlib

# ============================================================================
# CONFIGURATION
# ============================================================================

VERSION = "2.0.0-enhanced"
MAX_URL_LENGTH = 2048
REQUEST_TIMEOUT = 5

# ============================================================================
# BRAND PROTECTION - Major brands that are commonly impersonated
# ============================================================================

PROTECTED_BRANDS = {
    'paypal': ['paypal.com'],
    'amazon': ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.fr', 'amazon.in'],
    'apple': ['apple.com', 'icloud.com'],
    'microsoft': ['microsoft.com', 'outlook.com', 'live.com', 'office.com', 'xbox.com'],
    'google': ['google.com', 'gmail.com', 'youtube.com', 'googleapis.com'],
    'facebook': ['facebook.com', 'fb.com', 'instagram.com', 'whatsapp.com'],
    'netflix': ['netflix.com'],
    'spotify': ['spotify.com'],
    'twitter': ['twitter.com', 'x.com'],
    'linkedin': ['linkedin.com'],
    'dropbox': ['dropbox.com'],
    'chase': ['chase.com'],
    'wellsfargo': ['wellsfargo.com'],
    'bankofamerica': ['bankofamerica.com', 'bofa.com'],
    'citi': ['citi.com', 'citibank.com'],
    'usps': ['usps.com'],
    'fedex': ['fedex.com'],
    'ups': ['ups.com'],
    'dhl': ['dhl.com'],
    'ebay': ['ebay.com'],
    'alibaba': ['alibaba.com', 'aliexpress.com'],
    'coinbase': ['coinbase.com'],
    'binance': ['binance.com'],
    'blockchain': ['blockchain.com'],
    'steam': ['steampowered.com', 'steamcommunity.com'],
    'discord': ['discord.com', 'discordapp.com'],
    'slack': ['slack.com'],
    'zoom': ['zoom.us'],
    'adobe': ['adobe.com'],
    'walmart': ['walmart.com'],
    'target': ['target.com'],
}

# Flatten brand domains for quick lookup
BRAND_DOMAINS = set()
for domains in PROTECTED_BRANDS.values():
    BRAND_DOMAINS.update(domains)

# ============================================================================
# SUSPICIOUS PATTERNS
# ============================================================================

# High-risk keywords (credential theft indicators)
HIGH_RISK_KEYWORDS = frozenset([
    'login', 'signin', 'sign-in', 'log-in', 'signon', 'sign-on',
    'password', 'passwd', 'credential', 'auth', 'authenticate',
    'verify', 'verification', 'validate', 'confirm', 'confirmation',
    'suspend', 'suspended', 'restrict', 'restricted', 'locked', 'unlock',
    'expire', 'expired', 'update', 'upgrade', 'secure', 'security',
    'alert', 'warning', 'urgent', 'immediately', 'action-required',
    'ssn', 'social-security', 'tax', 'refund', 'irs'
])

# Medium-risk keywords (financial/account indicators)
MEDIUM_RISK_KEYWORDS = frozenset([
    'account', 'banking', 'bank', 'wallet', 'payment', 'billing',
    'invoice', 'receipt', 'transaction', 'transfer', 'wire',
    'card', 'credit', 'debit', 'visa', 'mastercard', 'amex',
    'crypto', 'bitcoin', 'ethereum', 'btc', 'eth', 'usdt',
    'recover', 'recovery', 'reset', 'restore', 'support', 'help',
    'customer', 'service', 'center', 'portal', 'dashboard'
])

# Suspicious TLDs (commonly used in phishing)
SUSPICIOUS_TLDS = frozenset([
    '.tk', '.ml', '.ga', '.cf', '.gq',  # Free TLDs
    '.xyz', '.top', '.work', '.click', '.link', '.zip', '.mov',
    '.info', '.biz', '.cc', '.ws', '.pw', '.su',
    '.online', '.site', '.website', '.space', '.tech',
    '.icu', '.buzz', '.rest', '.fit', '.cam'
])

# Highly trusted TLDs
TRUSTED_TLDS = frozenset([
    '.gov', '.edu', '.mil', '.int', '.museum', '.aero', '.coop'
])

# URL shorteners
URL_SHORTENERS = frozenset([
    'bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly', 'is.gd',
    'buff.ly', 'adf.ly', 'bit.do', 'short.io', 'rebrand.ly', 'cutt.ly',
    'shorturl.at', 'tiny.cc', 'bc.vc', 'j.mp', 'v.gd', 'clck.ru'
])

# Known safe domains (whitelist)
TRUSTED_DOMAINS = frozenset([
    'google.com', 'youtube.com', 'facebook.com', 'amazon.com', 'wikipedia.org',
    'twitter.com', 'x.com', 'instagram.com', 'linkedin.com', 'microsoft.com',
    'apple.com', 'github.com', 'stackoverflow.com', 'reddit.com', 'netflix.com',
    'spotify.com', 'paypal.com', 'ebay.com', 'dropbox.com', 'zoom.us',
    'slack.com', 'discord.com', 'whatsapp.com', 'telegram.org',
    'render.com', 'onrender.com', 'dashboard.render.com',
    'cloudflare.com', 'aws.amazon.com', 'azure.microsoft.com',
    'heroku.com', 'netlify.com', 'vercel.com', 'railway.app',
    'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'citi.com'
])

# Homograph characters (lookalikes)
HOMOGRAPH_MAP = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
    'ѕ': 's', 'і': 'i', 'ј': 'j', 'һ': 'h', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w',
    '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '8': 'b',
    '@': 'a', '$': 's', '!': 'i', '|': 'l'
}

# ============================================================================
# PRE-COMPILED REGEX PATTERNS
# ============================================================================

_IP_PATTERN = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
)
_HEX_PATTERN = re.compile(r'%[0-9a-fA-F]{2}')
_PUNYCODE_PATTERN = re.compile(r'xn--[a-z0-9]+', re.IGNORECASE)
_DOUBLE_EXTENSION = re.compile(r'\.(html?|php|asp|jsp|exe|zip|pdf)\.[a-z]{2,4}$', re.IGNORECASE)
_DATA_URI = re.compile(r'^data:', re.IGNORECASE)
_EXCESSIVE_DOTS = re.compile(r'\.{2,}')
_RANDOM_CHARS = re.compile(r'[a-z0-9]{20,}', re.IGNORECASE)


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def levenshtein_distance(s1: str, s2: str) -> int:
    """
    Calculate Levenshtein distance between two strings.
    Used for typosquatting detection.
    """
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    
    if len(s2) == 0:
        return len(s1)
    
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    
    return previous_row[-1]


def calculate_entropy(text: str) -> float:
    """
    Calculate Shannon entropy of a string.
    Higher entropy = more random = more suspicious.
    """
    if not text:
        return 0.0
    
    freq = Counter(text.lower())
    length = len(text)
    
    entropy = 0.0
    for count in freq.values():
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    
    return round(entropy, 3)


def normalize_homographs(text: str) -> str:
    """
    Convert homograph characters to their ASCII equivalents.
    Helps detect IDN homograph attacks.
    """
    result = []
    for char in text.lower():
        result.append(HOMOGRAPH_MAP.get(char, char))
    return ''.join(result)


def extract_domain_parts(url: str) -> dict:
    """
    Extract and analyze domain components.
    """
    try:
        parsed = urlparse(url.lower())
        netloc = parsed.netloc or ''
        
        # Remove port
        if ':' in netloc:
            netloc = netloc.split(':')[0]
        
        # Remove www
        if netloc.startswith('www.'):
            netloc = netloc[4:]
        
        parts = netloc.split('.')
        
        if len(parts) >= 2:
            tld = '.' + parts[-1]
            # Handle .co.uk, .com.br, etc.
            if len(parts) >= 3 and parts[-2] in ['co', 'com', 'org', 'net', 'gov', 'edu']:
                tld = '.' + parts[-2] + '.' + parts[-1]
                sld = parts[-3] if len(parts) >= 3 else ''
                subdomains = parts[:-3]
            else:
                sld = parts[-2]
                subdomains = parts[:-2]
        else:
            tld = ''
            sld = netloc
            subdomains = []
        
        return {
            'full_domain': netloc,
            'tld': tld,
            'sld': sld,
            'subdomains': subdomains,
            'subdomain_count': len(subdomains),
            'path': parsed.path,
            'query': parsed.query,
            'fragment': parsed.fragment
        }
    except:
        return {
            'full_domain': '',
            'tld': '',
            'sld': '',
            'subdomains': [],
            'subdomain_count': 0,
            'path': '',
            'query': '',
            'fragment': ''
        }


def check_typosquatting(domain: str) -> tuple:
    """
    Check if domain is a typosquat of a known brand.
    Returns (is_typosquat, target_brand, distance)
    """
    # Normalize the domain
    normalized = normalize_homographs(domain)
    
    # Remove common prefixes/suffixes
    test_domain = normalized
    for prefix in ['secure-', 'login-', 'my-', 'account-', 'verify-', 'update-']:
        if test_domain.startswith(prefix):
            test_domain = test_domain[len(prefix):]
    
    for suffix in ['-login', '-secure', '-verify', '-account', '-update', '-support']:
        if test_domain.endswith(suffix):
            test_domain = test_domain[:-len(suffix)]
    
    # Check against protected brands
    for brand, official_domains in PROTECTED_BRANDS.items():
        # Direct brand name in domain
        if brand in test_domain:
            # Check if it's the official domain
            if domain in official_domains:
                return (False, None, 0)
            # It contains the brand but isn't official
            return (True, brand, 1)
        
        # Levenshtein distance check for typos
        for official in official_domains:
            official_name = official.split('.')[0]
            distance = levenshtein_distance(test_domain.split('.')[0], official_name)
            if distance > 0 and distance <= 2:
                return (True, brand, distance)
    
    return (False, None, 0)


def check_brand_impersonation(url: str, domain: str) -> tuple:
    """
    Check if URL is impersonating a known brand.
    Returns (is_impersonating, brand_name, confidence)
    """
    url_lower = url.lower()
    domain_lower = domain.lower()
    
    for brand, official_domains in PROTECTED_BRANDS.items():
        # Check if this IS an official domain
        if any(domain_lower == d or domain_lower.endswith('.' + d) for d in official_domains):
            return (False, None, 0)
        
        # Check if brand name appears in URL but domain is not official
        if brand in url_lower:
            # High confidence if brand in subdomain
            if brand in domain_lower:
                return (True, brand, 0.9)
            # Medium confidence if brand in path
            return (True, brand, 0.7)
    
    return (False, None, 0)


# ============================================================================
# WEBSITE LIVE CHECK
# ============================================================================

def check_website_live(url: str, timeout: int = 5) -> dict:
    """Check if website is accessible and gather intelligence"""
    result = {
        'is_live': False,
        'status_code': None,
        'response_time_ms': None,
        'content_type': '',
        'final_url': url,
        'redirect_count': 0,
        'ssl_valid': False,
        'server': '',
        'suspicious_formats': [],
        'error': None
    }
    
    try:
        start_time = datetime.now()
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            verify=True,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            }
        )
        elapsed = (datetime.now() - start_time).total_seconds() * 1000
        
        result['is_live'] = True
        result['status_code'] = response.status_code
        result['response_time_ms'] = round(elapsed, 2)
        result['content_type'] = response.headers.get('content-type', '')
        result['final_url'] = response.url
        result['redirect_count'] = len(response.history)
        result['ssl_valid'] = url.startswith('https://')
        result['server'] = response.headers.get('server', '')
        
        # Check for suspicious redirects
        if result['redirect_count'] > 3:
            result['suspicious_formats'].append('Excessive redirects')
        
        # Check if final domain differs significantly
        if response.history:
            original_domain = urlparse(url).netloc
            final_domain = urlparse(response.url).netloc
            if original_domain != final_domain:
                result['suspicious_formats'].append(f'Redirected to different domain: {final_domain}')
        
    except requests.exceptions.SSLError as e:
        result['error'] = 'SSL certificate error'
        result['ssl_valid'] = False
        result['suspicious_formats'].append('Invalid SSL certificate')
    except requests.exceptions.Timeout:
        result['error'] = 'Request timeout'
    except requests.exceptions.ConnectionError:
        result['error'] = 'Connection failed'
    except Exception as e:
        result['error'] = str(e)[:100]
    
    return result


def extract_subdomain_info(url: str) -> dict:
    """Extract subdomain information from URL"""
    parts = extract_domain_parts(url)
    return {
        'subdomain_count': parts['subdomain_count'],
        'subdomains': parts['subdomains'],
        'full_domain': parts['full_domain']
    }


# ============================================================================
# FEATURE EXTRACTION
# ============================================================================

def extract_features(url: str) -> dict:
    """
    Extract comprehensive URL features for analysis.
    Pure Python implementation - no pandas/numpy required.
    """
    features = {}
    url_lower = url.lower()
    
    # Parse URL
    try:
        parsed = urlparse(url)
    except:
        parsed = None
    
    # Basic features
    features['url_length'] = len(url)
    features['num_dots'] = url.count('.')
    features['num_hyphens'] = url.count('-')
    features['num_underscores'] = url.count('_')
    features['num_slashes'] = url.count('/')
    features['num_digits'] = sum(c.isdigit() for c in url)
    features['num_special'] = sum(not c.isalnum() for c in url)
    features['num_at'] = url.count('@')
    features['num_percent'] = url.count('%')
    features['num_ampersand'] = url.count('&')
    features['num_equals'] = url.count('=')
    
    # Character ratios
    num_letters = sum(c.isalpha() for c in url)
    features['digit_ratio'] = features['num_digits'] / max(len(url), 1)
    features['letter_ratio'] = num_letters / max(len(url), 1)
    features['special_ratio'] = features['num_special'] / max(len(url), 1)
    
    # Protocol
    features['is_https'] = 1 if url_lower.startswith('https://') else 0
    features['is_http'] = 1 if url_lower.startswith('http://') and not url_lower.startswith('https://') else 0
    
    # IP address detection
    features['has_ip'] = 1 if _IP_PATTERN.search(url) else 0
    
    # Domain analysis
    domain_parts = extract_domain_parts(url)
    domain = domain_parts['full_domain']
    features['domain'] = domain
    features['domain_length'] = len(domain)
    features['num_subdomains'] = domain_parts['subdomain_count']
    features['tld'] = domain_parts['tld']
    
    # TLD checks
    features['suspicious_tld'] = 1 if domain_parts['tld'] in SUSPICIOUS_TLDS else 0
    features['trusted_tld'] = 1 if domain_parts['tld'] in TRUSTED_TLDS else 0
    
    # Trusted domain check
    features['is_trusted_domain'] = 0
    if domain in TRUSTED_DOMAINS:
        features['is_trusted_domain'] = 1
    else:
        for td in TRUSTED_DOMAINS:
            if domain.endswith('.' + td):
                features['is_trusted_domain'] = 1
                break
    
    # URL shortener
    features['is_shortener'] = 1 if domain in URL_SHORTENERS else 0
    
    # Punycode (IDN)
    features['has_punycode'] = 1 if _PUNYCODE_PATTERN.search(domain) else 0
    
    # Entropy calculation
    features['url_entropy'] = calculate_entropy(url)
    features['domain_entropy'] = calculate_entropy(domain)
    
    # High entropy in subdomain is suspicious
    if domain_parts['subdomains']:
        subdomain_str = '.'.join(domain_parts['subdomains'])
        features['subdomain_entropy'] = calculate_entropy(subdomain_str)
    else:
        features['subdomain_entropy'] = 0
    
    # Keyword detection
    high_risk_found = []
    medium_risk_found = []
    
    for keyword in HIGH_RISK_KEYWORDS:
        if keyword in url_lower:
            high_risk_found.append(keyword)
    
    for keyword in MEDIUM_RISK_KEYWORDS:
        if keyword in url_lower:
            medium_risk_found.append(keyword)
    
    features['high_risk_keywords'] = high_risk_found
    features['medium_risk_keywords'] = medium_risk_found
    features['high_risk_keyword_count'] = len(high_risk_found)
    features['medium_risk_keyword_count'] = len(medium_risk_found)
    
    # Typosquatting check
    typo_result = check_typosquatting(domain)
    features['is_typosquat'] = 1 if typo_result[0] else 0
    features['typosquat_target'] = typo_result[1]
    features['typosquat_distance'] = typo_result[2]
    
    # Brand impersonation check
    brand_result = check_brand_impersonation(url, domain)
    features['is_brand_impersonation'] = 1 if brand_result[0] else 0
    features['impersonated_brand'] = brand_result[1]
    features['impersonation_confidence'] = brand_result[2]
    
    # Path analysis
    path = domain_parts['path']
    features['path_length'] = len(path)
    features['path_depth'] = path.count('/') if path else 0
    features['has_double_slash'] = 1 if '//' in path else 0
    
    # Query analysis
    query = domain_parts['query']
    features['query_length'] = len(query)
    features['num_params'] = len(parse_qs(query)) if query else 0
    
    # Suspicious patterns
    features['has_hex_chars'] = 1 if _HEX_PATTERN.search(url) else 0
    features['has_at_symbol'] = 1 if '@' in url else 0
    features['has_double_extension'] = 1 if _DOUBLE_EXTENSION.search(url) else 0
    features['has_data_uri'] = 1 if _DATA_URI.search(url) else 0
    features['has_excessive_dots'] = 1 if _EXCESSIVE_DOTS.search(url) else 0
    features['has_random_string'] = 1 if _RANDOM_CHARS.search(domain) else 0
    
    # Port check
    if parsed and parsed.port:
        features['has_port'] = 1 if parsed.port not in [80, 443] else 0
        features['port_number'] = parsed.port
    else:
        features['has_port'] = 0
        features['port_number'] = 0
    
    # Homograph detection
    normalized = normalize_homographs(domain)
    features['has_homographs'] = 1 if normalized != domain else 0
    
    return features


# ============================================================================
# SCORING ENGINE
# ============================================================================

def calculate_phishing_score(features: dict) -> tuple:
    """
    Calculate phishing probability using enhanced weighted heuristics.
    
    Returns:
        (label, probability, reason, details)
        label: 0 = legitimate, 1 = phishing
        probability: 0.0 to 1.0
        reason: primary explanation
        details: list of all risk factors
    """
    score = 0.0
    risk_factors = []
    
    # ========== WHITELIST CHECKS (Negative Score) ==========
    
    # Trusted domain override
    if features.get('is_trusted_domain'):
        return (0, 0.02, "Verified trusted domain", ["Domain is in trusted whitelist"])
    
    # Government/education TLD
    if features.get('trusted_tld'):
        score -= 0.4
        risk_factors.append("✓ Government/education domain (-0.4)")
    
    # HTTPS present
    if features.get('is_https'):
        score -= 0.05
    else:
        score += 0.15
        risk_factors.append("⚠ No HTTPS (+0.15)")
    
    # ========== CRITICAL RISK FACTORS (High Score) ==========
    
    # Brand impersonation (highest risk)
    if features.get('is_brand_impersonation'):
        brand = features.get('impersonated_brand', 'unknown')
        confidence = features.get('impersonation_confidence', 0)
        score += 0.5 * confidence
        risk_factors.append(f"🚨 Brand impersonation: {brand} (+{0.5 * confidence:.2f})")
    
    # Typosquatting
    if features.get('is_typosquat'):
        target = features.get('typosquat_target', 'unknown')
        score += 0.45
        risk_factors.append(f"🚨 Typosquatting detected: {target} (+0.45)")
    
    # IP address instead of domain
    if features.get('has_ip'):
        score += 0.4
        risk_factors.append("🚨 IP address in URL (+0.4)")
    
    # Homograph attack
    if features.get('has_homographs'):
        score += 0.4
        risk_factors.append("🚨 Homograph characters detected (+0.4)")
    
    # Punycode (IDN)
    if features.get('has_punycode'):
        score += 0.35
        risk_factors.append("🚨 Punycode domain (IDN) (+0.35)")
    
    # ========== HIGH RISK FACTORS ==========
    
    # Suspicious TLD
    if features.get('suspicious_tld'):
        score += 0.35
        risk_factors.append(f"⚠ Suspicious TLD: {features.get('tld', '')} (+0.35)")
    
    # High-risk keywords
    high_risk_count = features.get('high_risk_keyword_count', 0)
    if high_risk_count > 0:
        keyword_score = min(0.4, high_risk_count * 0.12)
        score += keyword_score
        keywords = features.get('high_risk_keywords', [])[:3]
        risk_factors.append(f"⚠ High-risk keywords: {', '.join(keywords)} (+{keyword_score:.2f})")
    
    # URL shortener
    if features.get('is_shortener'):
        score += 0.3
        risk_factors.append("⚠ URL shortener detected (+0.3)")
    
    # @ symbol (URL obfuscation)
    if features.get('has_at_symbol'):
        score += 0.35
        risk_factors.append("⚠ @ symbol in URL (obfuscation) (+0.35)")
    
    # ========== MEDIUM RISK FACTORS ==========
    
    # Medium-risk keywords
    medium_risk_count = features.get('medium_risk_keyword_count', 0)
    if medium_risk_count > 0:
        keyword_score = min(0.25, medium_risk_count * 0.06)
        score += keyword_score
        keywords = features.get('medium_risk_keywords', [])[:3]
        risk_factors.append(f"⚠ Financial keywords: {', '.join(keywords)} (+{keyword_score:.2f})")
    
    # Excessive subdomains
    num_subdomains = features.get('num_subdomains', 0)
    if num_subdomains >= 4:
        score += 0.25
        risk_factors.append(f"⚠ Many subdomains ({num_subdomains}) (+0.25)")
    elif num_subdomains >= 3:
        score += 0.15
        risk_factors.append(f"⚠ Multiple subdomains ({num_subdomains}) (+0.15)")
    
    # High entropy (random strings)
    domain_entropy = features.get('domain_entropy', 0)
    if domain_entropy > 4.0:
        score += 0.2
        risk_factors.append(f"⚠ High domain entropy ({domain_entropy:.1f}) (+0.2)")
    
    subdomain_entropy = features.get('subdomain_entropy', 0)
    if subdomain_entropy > 3.5:
        score += 0.15
        risk_factors.append(f"⚠ Random subdomain pattern (+0.15)")
    
    # Very long URL
    url_length = features.get('url_length', 0)
    if url_length > 150:
        score += 0.15
        risk_factors.append(f"⚠ Very long URL ({url_length} chars) (+0.15)")
    elif url_length > 100:
        score += 0.08
        risk_factors.append(f"⚠ Long URL ({url_length} chars) (+0.08)")
    
    # ========== LOW RISK FACTORS ==========
    
    # Many hyphens
    num_hyphens = features.get('num_hyphens', 0)
    if num_hyphens > 4:
        score += 0.15
        risk_factors.append(f"⚠ Many hyphens ({num_hyphens}) (+0.15)")
    elif num_hyphens > 2:
        score += 0.08
        risk_factors.append(f"⚠ Multiple hyphens ({num_hyphens}) (+0.08)")
    
    # Hex encoding
    if features.get('has_hex_chars'):
        score += 0.1
        risk_factors.append("⚠ URL encoding detected (+0.1)")
    
    # Non-standard port
    if features.get('has_port'):
        port = features.get('port_number', 0)
        score += 0.15
        risk_factors.append(f"⚠ Non-standard port ({port}) (+0.15)")
    
    # Double extension
    if features.get('has_double_extension'):
        score += 0.2
        risk_factors.append("⚠ Double file extension (+0.2)")
    
    # Deep path
    path_depth = features.get('path_depth', 0)
    if path_depth > 5:
        score += 0.1
        risk_factors.append(f"⚠ Deep URL path ({path_depth} levels) (+0.1)")
    
    # Many query parameters
    num_params = features.get('num_params', 0)
    if num_params > 5:
        score += 0.1
        risk_factors.append(f"⚠ Many query parameters ({num_params}) (+0.1)")
    
    # Random string in domain
    if features.get('has_random_string'):
        score += 0.15
        risk_factors.append("⚠ Random string pattern in domain (+0.15)")
    
    # ========== FINAL CALCULATION ==========
    
    # Clamp score between 0 and 1
    probability = max(0.0, min(1.0, score))
    
    # Determine label (threshold: 0.5)
    label = 1 if probability >= 0.5 else 0
    
    # Generate primary reason
    if not risk_factors:
        reason = "No suspicious indicators detected"
    elif len(risk_factors) == 1:
        reason = risk_factors[0].split('(')[0].strip()
    else:
        # Get top 2 factors
        top_factors = [f.split('(')[0].strip() for f in risk_factors[:2]]
        reason = "; ".join(top_factors)
    
    return (label, probability, reason, risk_factors)


# ============================================================================
# MAIN PREDICTION FUNCTION
# ============================================================================

def predict_url(url: str, model=None) -> tuple:
    """
    Analyze URL and predict if it's phishing.
    
    Args:
        url: URL to analyze
        model: Ignored (kept for API compatibility)
    
    Returns:
        (label, probability, features)
    """
    # Validate URL
    if not url or len(url) > MAX_URL_LENGTH:
        return (0, 0.5, {'error': 'Invalid URL'})
    
    # Extract features
    features = extract_features(url)
    
    # Calculate score
    label, probability, reason, risk_factors = calculate_phishing_score(features)
    
    # Add scoring info to features
    features['prediction_reason'] = reason
    features['risk_factors'] = risk_factors
    features['risk_score'] = probability
    
    # Clean up
    gc.collect()
    
    return (label, probability, features)


def load_model(model_path: str = None):
    """
    Compatibility function - returns True to indicate 'model loaded'.
    In enhanced lite mode, we use advanced rule-based detection.
    """
    print(f"[+] Phish Detector ENHANCED LITE v{VERSION}")
    print("    - Advanced rule-based detection (no ML)")
    print("    - Typosquatting detection enabled")
    print("    - Brand impersonation detection enabled")
    print("    - Homograph attack detection enabled")
    return True


def get_top_feature(features: dict) -> str:
    """Get the most significant feature from analysis"""
    if features.get('prediction_reason'):
        return features['prediction_reason']
    return "URL analysis complete"


def get_professional_risk_assessment(label: int, probability: float, features: dict, url: str) -> dict:
    """
    Generate professional risk assessment report.
    """
    # Calculate confidence
    if label == 1:
        confidence = probability
    else:
        confidence = 1.0 - probability
    
    confidence_percent = round(confidence * 100, 1)
    
    # Determine risk level with more granularity
    if probability >= 0.85:
        risk_level = "CRITICAL"
        risk_category = "Confirmed Phishing"
        color = "#dc2626"
        recommendation = "DO NOT visit this website. Report immediately."
    elif probability >= 0.7:
        risk_level = "HIGH"
        risk_category = "Likely Phishing"
        color = "#ea580c"
        recommendation = "Avoid this website. Verify through official channels."
    elif probability >= 0.5:
        risk_level = "MEDIUM-HIGH"
        risk_category = "Suspicious"
        color = "#d97706"
        recommendation = "Exercise extreme caution. Verify legitimacy."
    elif probability >= 0.35:
        risk_level = "MEDIUM"
        risk_category = "Potentially Suspicious"
        color = "#ca8a04"
        recommendation = "Proceed with caution."
    elif probability >= 0.2:
        risk_level = "LOW"
        risk_category = "Probably Safe"
        color = "#65a30d"
        recommendation = "Appears safe but stay vigilant."
    else:
        risk_level = "MINIMAL"
        risk_category = "Verified Safe"
        color = "#16a34a"
        recommendation = "Website appears legitimate."
    
    # Build details
    risk_factors = features.get('risk_factors', [])
    details = f"Risk Score: {round(probability * 100)}% | {len(risk_factors)} indicators found"
    
    # Add specific warnings
    if features.get('is_typosquat'):
        details += f" | Typosquat of: {features.get('typosquat_target')}"
    if features.get('is_brand_impersonation'):
        details += f" | Impersonating: {features.get('impersonated_brand')}"
    
    return {
        'risk_level': risk_level,
        'risk_category': risk_category,
        'confidence': confidence_percent,
        'probability': round(probability * 100, 1),
        'color': color,
        'description': features.get('prediction_reason', 'Analysis complete'),
        'recommendation': recommendation,
        'details': details,
        'is_phishing': label == 1,
        'risk_factors': risk_factors[:5],  # Top 5 factors
        'version': VERSION
    }


def get_cached_model():
    """Always returns True in lite mode"""
    return True
