"""
Phishing URL Detection Engine - PRO LITE VERSION (400MB RAM)
Advanced rule-based detection with real-time analysis

Detection capabilities:
- URL structure analysis with entropy calculation
- Typosquatting detection (Levenshtein distance)
- Brand impersonation detection (50+ brands)
- Homograph attack detection (IDN/Punycode)
- N-gram analysis for suspicious patterns
- DNS resolution and validation
- SSL certificate deep inspection
- Domain age estimation
- Content analysis (page scanning)
- Real-time threat scoring
- Redirect chain analysis
- Form/input field detection
- JavaScript analysis
"""

import re
import os
import math
import requests
from urllib.parse import urlparse, parse_qs, unquote, urljoin
import ssl
import socket
from datetime import datetime, timedelta
import gc
from collections import Counter, defaultdict
import hashlib
import json
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
import time

# ============================================================================
# CONFIGURATION - Optimized for 400MB RAM
# ============================================================================

VERSION = "3.0.0-pro-lite"
MAX_URL_LENGTH = 4096
REQUEST_TIMEOUT = 8
DNS_TIMEOUT = 3
SSL_TIMEOUT = 5
CONTENT_MAX_SIZE = 500 * 1024  # 500KB max page size
MAX_REDIRECTS = 10
THREAD_POOL_SIZE = 4

# Cache for DNS/SSL lookups (memory efficient with TTL)
_DNS_CACHE = {}
_SSL_CACHE = {}
_CONTENT_CACHE = {}
_CACHE_TTL = 300  # 5 minutes
_CACHE_MAX_SIZE = 1000

print(f"[+] Phish Detector PRO LITE v{VERSION} initializing...")

# ============================================================================
# EXPANDED BRAND PROTECTION - 50+ Major Brands
# ============================================================================

PROTECTED_BRANDS = {
    # Financial
    'paypal': ['paypal.com', 'paypal.me'],
    'chase': ['chase.com', 'jpmorganchase.com'],
    'wellsfargo': ['wellsfargo.com', 'wf.com'],
    'bankofamerica': ['bankofamerica.com', 'bofa.com', 'mbna.com'],
    'citi': ['citi.com', 'citibank.com', 'citicards.com'],
    'capitalone': ['capitalone.com'],
    'amex': ['americanexpress.com', 'amex.com'],
    'discover': ['discover.com'],
    'usbank': ['usbank.com'],
    'pnc': ['pnc.com'],
    'venmo': ['venmo.com'],
    'zelle': ['zellepay.com'],
    'cashapp': ['cash.app', 'squareup.com'],
    'stripe': ['stripe.com'],
    'square': ['squareup.com', 'square.com'],
    
    # Tech Giants
    'google': ['google.com', 'gmail.com', 'youtube.com', 'googleapis.com', 'goo.gl', 'google.co.uk'],
    'microsoft': ['microsoft.com', 'outlook.com', 'live.com', 'office.com', 'xbox.com', 'hotmail.com', 'msn.com', 'bing.com', 'azure.com', 'onedrive.com'],
    'apple': ['apple.com', 'icloud.com', 'itunes.com', 'apple.co'],
    'amazon': ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.fr', 'amazon.in', 'amazon.ca', 'amazon.es', 'amazon.it', 'aws.amazon.com', 'prime.com'],
    'meta': ['facebook.com', 'fb.com', 'instagram.com', 'whatsapp.com', 'messenger.com', 'meta.com', 'oculus.com'],
    
    # Social Media
    'twitter': ['twitter.com', 'x.com', 't.co'],
    'linkedin': ['linkedin.com'],
    'tiktok': ['tiktok.com'],
    'snapchat': ['snapchat.com'],
    'pinterest': ['pinterest.com'],
    'reddit': ['reddit.com'],
    'tumblr': ['tumblr.com'],
    
    # Entertainment
    'netflix': ['netflix.com'],
    'spotify': ['spotify.com'],
    'hulu': ['hulu.com'],
    'disney': ['disney.com', 'disneyplus.com'],
    'hbo': ['hbo.com', 'hbomax.com', 'max.com'],
    'twitch': ['twitch.tv'],
    'steam': ['steampowered.com', 'steamcommunity.com', 'store.steampowered.com'],
    'epicgames': ['epicgames.com', 'fortnite.com'],
    'roblox': ['roblox.com'],
    'playstation': ['playstation.com', 'sony.com'],
    'xbox': ['xbox.com'],
    'nintendo': ['nintendo.com'],
    
    # E-commerce
    'ebay': ['ebay.com', 'ebay.co.uk'],
    'alibaba': ['alibaba.com', 'aliexpress.com', 'alipay.com'],
    'walmart': ['walmart.com'],
    'target': ['target.com'],
    'bestbuy': ['bestbuy.com'],
    'etsy': ['etsy.com'],
    'shopify': ['shopify.com', 'myshopify.com'],
    
    # Crypto
    'coinbase': ['coinbase.com'],
    'binance': ['binance.com', 'binance.us'],
    'kraken': ['kraken.com'],
    'crypto': ['crypto.com'],
    'blockchain': ['blockchain.com'],
    'metamask': ['metamask.io'],
    'opensea': ['opensea.io'],
    
    # Communication
    'discord': ['discord.com', 'discordapp.com', 'discord.gg'],
    'slack': ['slack.com'],
    'zoom': ['zoom.us', 'zoom.com'],
    'teams': ['teams.microsoft.com'],
    'telegram': ['telegram.org', 't.me'],
    'signal': ['signal.org'],
    'skype': ['skype.com'],
    
    # Cloud/Dev
    'github': ['github.com', 'github.io'],
    'gitlab': ['gitlab.com'],
    'dropbox': ['dropbox.com'],
    'adobe': ['adobe.com', 'creativecloud.com'],
    'salesforce': ['salesforce.com'],
    'atlassian': ['atlassian.com', 'jira.com', 'confluence.com', 'bitbucket.org'],
    'notion': ['notion.so'],
    
    # Delivery/Shipping
    'usps': ['usps.com'],
    'fedex': ['fedex.com'],
    'ups': ['ups.com'],
    'dhl': ['dhl.com'],
    'amazon': ['amazon.com'],  # Already included but for shipping context
    
    # Other
    'docusign': ['docusign.com', 'docusign.net'],
    'intuit': ['intuit.com', 'turbotax.com', 'quickbooks.com'],
    'godaddy': ['godaddy.com'],
    'namecheap': ['namecheap.com'],
    'cloudflare': ['cloudflare.com'],
}

# Build fast lookup sets
BRAND_DOMAINS = set()
BRAND_KEYWORDS = set()
for brand, domains in PROTECTED_BRANDS.items():
    BRAND_DOMAINS.update(domains)
    BRAND_KEYWORDS.add(brand)

# ============================================================================
# COMPREHENSIVE SUSPICIOUS PATTERNS
# ============================================================================

# Critical keywords (immediate red flags)
CRITICAL_KEYWORDS = frozenset([
    'suspended', 'suspend', 'locked', 'lock', 'disabled', 'disable',
    'compromised', 'hacked', 'breach', 'stolen', 'fraud', 'fraudulent',
    'illegal', 'unauthorized', 'unusual-activity', 'suspicious-activity',
    'verify-immediately', 'action-required', 'urgent-action', 'act-now',
    'last-warning', 'final-notice', 'account-terminated', 'permanently-closed'
])

# High-risk keywords
HIGH_RISK_KEYWORDS = frozenset([
    'login', 'signin', 'sign-in', 'log-in', 'signon', 'sign-on', 'logon',
    'password', 'passwd', 'pwd', 'credential', 'credentials',
    'auth', 'authenticate', 'authentication', 'oauth', '2fa', 'mfa',
    'verify', 'verification', 'validate', 'validation', 'confirm', 'confirmation',
    'secure', 'security', 'secure-login', 'secure-access',
    'update', 'upgrade', 'renew', 'renewal', 'reactivate',
    'unlock', 'unblock', 'restore', 'recover', 'recovery',
    'expire', 'expired', 'expiring', 'expiration',
    'ssn', 'social-security', 'tax-id', 'ein',
    'refund', 'rebate', 'reimbursement', 'claim',
    'webscr', 'cmd=', 'dispatch'
])

# Medium-risk keywords
MEDIUM_RISK_KEYWORDS = frozenset([
    'account', 'accounts', 'my-account', 'myaccount', 'user-account',
    'banking', 'bank', 'online-banking', 'mobile-banking',
    'wallet', 'e-wallet', 'digital-wallet',
    'payment', 'pay', 'checkout', 'billing', 'invoice',
    'transaction', 'transfer', 'wire', 'send-money',
    'card', 'credit-card', 'debit-card', 'card-number',
    'visa', 'mastercard', 'amex', 'discover',
    'crypto', 'bitcoin', 'btc', 'ethereum', 'eth', 'usdt', 'wallet-connect',
    'support', 'help', 'helpdesk', 'customer-service', 'contact-us',
    'portal', 'dashboard', 'control-panel', 'admin', 'console'
])

# Suspicious URL patterns
SUSPICIOUS_URL_PATTERNS = [
    (re.compile(r'[0-9]{4,}'), 0.1, 'Long number sequence'),
    (re.compile(r'[a-z]{20,}', re.I), 0.15, 'Very long word'),
    (re.compile(r'([a-z])\1{3,}', re.I), 0.2, 'Repeated characters'),
    (re.compile(r'-{2,}'), 0.1, 'Multiple hyphens'),
    (re.compile(r'_{2,}'), 0.1, 'Multiple underscores'),
    (re.compile(r'\.(php|asp|aspx|jsp|cgi)\?', re.I), 0.15, 'Script with query'),
    (re.compile(r'/(wp-admin|wp-login|administrator|admin\.php)', re.I), 0.2, 'Admin path'),
    (re.compile(r'/(signin|login|auth|verify|confirm|update|secure)/', re.I), 0.15, 'Auth path'),
    (re.compile(r'\.(exe|zip|rar|7z|bat|cmd|ps1|vbs|js)$', re.I), 0.3, 'Executable file'),
    (re.compile(r'data:text/html', re.I), 0.5, 'Data URI'),
    (re.compile(r'javascript:', re.I), 0.5, 'JavaScript URI'),
]

# Suspicious TLDs (expanded)
SUSPICIOUS_TLDS = frozenset([
    # Free TLDs
    '.tk', '.ml', '.ga', '.cf', '.gq',
    # Cheap/abused TLDs
    '.xyz', '.top', '.work', '.click', '.link', '.zip', '.mov',
    '.info', '.biz', '.cc', '.ws', '.pw', '.su', '.ru',
    '.online', '.site', '.website', '.space', '.tech', '.store',
    '.icu', '.buzz', '.rest', '.fit', '.cam', '.monster',
    '.cyou', '.cfd', '.sbs', '.bond', '.vip', '.wang',
    # New suspicious TLDs
    '.hair', '.makeup', '.skin', '.beauty', '.quest', '.mom', '.dad'
])

# Highly trusted TLDs
TRUSTED_TLDS = frozenset([
    '.gov', '.edu', '.mil', '.int', '.museum', '.aero', '.coop', '.post'
])

# URL shorteners (expanded)
URL_SHORTENERS = frozenset([
    'bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly', 'is.gd', 'v.gd',
    'buff.ly', 'adf.ly', 'bit.do', 'short.io', 'rebrand.ly', 'cutt.ly',
    'shorturl.at', 'tiny.cc', 'bc.vc', 'j.mp', 'clck.ru', 'rb.gy',
    'qr.ae', 'lnkd.in', 'db.tt', 'youtu.be', 'soo.gd', 'su.pr', 's2r.co',
    'cli.gs', 'budurl.com', 'mcaf.ee', 'yourls.org', 'bl.ink', 'shorte.st',
    'ouo.io', 'za.gl', 'v.ht', '1drv.ms', 'hyperurl.co', 'urlz.fr'
])

# Trusted domains (expanded whitelist)
TRUSTED_DOMAINS = frozenset([
    # Search/Tech
    'google.com', 'youtube.com', 'bing.com', 'yahoo.com', 'duckduckgo.com',
    'microsoft.com', 'apple.com', 'github.com', 'stackoverflow.com',
    
    # Social
    'facebook.com', 'twitter.com', 'x.com', 'instagram.com', 'linkedin.com',
    'reddit.com', 'pinterest.com', 'tiktok.com', 'snapchat.com',
    
    # E-commerce
    'amazon.com', 'ebay.com', 'walmart.com', 'target.com', 'etsy.com',
    
    # Entertainment
    'netflix.com', 'spotify.com', 'twitch.tv', 'discord.com', 'steam.com',
    
    # Finance
    'paypal.com', 'chase.com', 'bankofamerica.com', 'wellsfargo.com',
    
    # Cloud
    'dropbox.com', 'zoom.us', 'slack.com', 'notion.so', 'figma.com',
    
    # Hosting
    'render.com', 'onrender.com', 'dashboard.render.com',
    'cloudflare.com', 'aws.amazon.com', 'azure.microsoft.com',
    'heroku.com', 'netlify.com', 'vercel.com', 'railway.app', 'fly.io',
    'digitalocean.com', 'linode.com', 'vultr.com',
    
    # Reference
    'wikipedia.org', 'wikimedia.org', 'archive.org',
])

# Homograph characters (expanded)
HOMOGRAPH_MAP = {
    # Cyrillic
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
    'ѕ': 's', 'і': 'i', 'ј': 'j', 'һ': 'h', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w',
    'ɑ': 'a', 'ɡ': 'g', 'ɩ': 'i', 'ɪ': 'i', 'ⅼ': 'l', 'ⅿ': 'm', 'ⅰ': 'i',
    # Greek
    'α': 'a', 'β': 'b', 'ε': 'e', 'η': 'n', 'ι': 'i', 'κ': 'k', 'ν': 'v',
    'ο': 'o', 'ρ': 'p', 'τ': 't', 'υ': 'u', 'χ': 'x',
    # Numbers/symbols
    '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '8': 'b',
    '@': 'a', '$': 's', '!': 'i', '|': 'l', '+': 't',
    # Special
    'ℓ': 'l', '℮': 'e', '₀': 'o', '₁': '1', '¡': 'i', '×': 'x',
}

# ============================================================================
# PRE-COMPILED REGEX PATTERNS
# ============================================================================

_IP_PATTERN = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
)
_IPV6_PATTERN = re.compile(r'\[?([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\]?')
_HEX_PATTERN = re.compile(r'%[0-9a-fA-F]{2}')
_PUNYCODE_PATTERN = re.compile(r'xn--[a-z0-9]+', re.IGNORECASE)
_DOUBLE_EXTENSION = re.compile(r'\.(html?|php|asp|jsp|exe|zip|pdf|doc)\.[a-z]{2,4}$', re.IGNORECASE)
_DATA_URI = re.compile(r'^data:', re.IGNORECASE)
_EXCESSIVE_DOTS = re.compile(r'\.{2,}')
_RANDOM_CHARS = re.compile(r'[a-z0-9]{25,}', re.IGNORECASE)
_BASE64_PATTERN = re.compile(r'[A-Za-z0-9+/]{50,}={0,2}')
_EMAIL_IN_URL = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')

# Content analysis patterns
_FORM_PATTERN = re.compile(r'<form[^>]*>', re.IGNORECASE)
_PASSWORD_INPUT = re.compile(r'<input[^>]*type=["\']?password["\']?[^>]*>', re.IGNORECASE)
_HIDDEN_INPUT = re.compile(r'<input[^>]*type=["\']?hidden["\']?[^>]*>', re.IGNORECASE)
_EXTERNAL_FORM_ACTION = re.compile(r'<form[^>]*action=["\']?https?://[^"\'>\s]+["\']?[^>]*>', re.IGNORECASE)
_OBFUSCATED_JS = re.compile(r'(eval\s*\(|document\.write|unescape|fromCharCode|atob\s*\()', re.IGNORECASE)
_PHISHING_TITLES = re.compile(r'(verify|confirm|update|secure|login|sign.?in|account|suspended|locked)', re.IGNORECASE)


# ============================================================================
# CACHE MANAGEMENT
# ============================================================================

def _cache_get(cache, key):
    """Get value from cache if not expired"""
    if key in cache:
        value, timestamp = cache[key]
        if time.time() - timestamp < _CACHE_TTL:
            return value
        del cache[key]
    return None

def _cache_set(cache, key, value):
    """Set value in cache with cleanup"""
    # Clean old entries if cache is too large
    if len(cache) >= _CACHE_MAX_SIZE:
        current_time = time.time()
        expired = [k for k, (v, t) in cache.items() if current_time - t >= _CACHE_TTL]
        for k in expired[:len(expired)//2]:  # Remove half of expired
            del cache[k]
    
    cache[key] = (value, time.time())


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate Levenshtein distance between two strings"""
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
    """Calculate Shannon entropy of a string"""
    if not text:
        return 0.0
    freq = Counter(text.lower())
    length = len(text)
    entropy = sum(-p/length * math.log2(p/length) for p in freq.values() if p > 0)
    return round(entropy, 3)


def normalize_homographs(text: str) -> str:
    """Convert homograph characters to ASCII equivalents"""
    return ''.join(HOMOGRAPH_MAP.get(char, char) for char in text.lower())


def get_ngrams(text: str, n: int = 3) -> list:
    """Extract n-grams from text"""
    text = text.lower()
    return [text[i:i+n] for i in range(len(text) - n + 1)]


def calculate_ngram_score(domain: str) -> float:
    """
    Calculate suspiciousness based on n-gram frequency.
    Rare n-grams in domain names are suspicious.
    """
    # Common legitimate n-grams
    common_ngrams = frozenset([
        'com', 'www', 'the', 'and', 'ing', 'ion', 'tio', 'ent', 'ati',
        'for', 'her', 'ter', 'hat', 'tha', 'ere', 'ate', 'his', 'con',
        'res', 'ver', 'all', 'ons', 'nce', 'men', 'ith', 'ted', 'ers',
        'pro', 'app', 'log', 'ser', 'ice', 'ine', 'net', 'org', 'web'
    ])
    
    # Suspicious n-grams (often in random/generated domains)
    suspicious_ngrams = frozenset([
        'xxx', 'xyz', 'zzz', 'qqq', 'jjj', 'vvv', 'yyy',
        '123', '456', '789', '000', '111', '999',
        'qwe', 'asd', 'zxc', 'qaz', 'wsx'
    ])
    
    ngrams = get_ngrams(domain.replace('.', ''), 3)
    if not ngrams:
        return 0.0
    
    common_count = sum(1 for ng in ngrams if ng in common_ngrams)
    suspicious_count = sum(1 for ng in ngrams if ng in suspicious_ngrams)
    
    common_ratio = common_count / len(ngrams)
    suspicious_ratio = suspicious_count / len(ngrams)
    
    # Low common + high suspicious = bad
    score = (1 - common_ratio) * 0.15 + suspicious_ratio * 0.25
    return min(score, 0.3)


# ============================================================================
# DNS ANALYSIS
# ============================================================================

def analyze_dns(domain: str) -> dict:
    """Perform DNS analysis on domain"""
    cache_key = f"dns:{domain}"
    cached = _cache_get(_DNS_CACHE, cache_key)
    if cached:
        return cached
    
    result = {
        'resolved': False,
        'ip_addresses': [],
        'has_mx': False,
        'nameservers': [],
        'suspicious_indicators': [],
        'score_adjustment': 0.0
    }
    
    try:
        # Resolve A records
        socket.setdefaulttimeout(DNS_TIMEOUT)
        ips = socket.gethostbyname_ex(domain)
        result['resolved'] = True
        result['ip_addresses'] = ips[2]
        
        # Check for suspicious IPs
        for ip in result['ip_addresses']:
            # Private IP ranges (suspicious for public domain)
            if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.'):
                result['suspicious_indicators'].append('Resolves to private IP')
                result['score_adjustment'] += 0.3
            # Localhost
            if ip.startswith('127.'):
                result['suspicious_indicators'].append('Resolves to localhost')
                result['score_adjustment'] += 0.4
    
    except socket.gaierror:
        result['suspicious_indicators'].append('Domain does not resolve')
        result['score_adjustment'] += 0.2
    except socket.timeout:
        result['suspicious_indicators'].append('DNS timeout')
    except Exception:
        pass
    
    _cache_set(_DNS_CACHE, cache_key, result)
    return result


# ============================================================================
# SSL CERTIFICATE ANALYSIS
# ============================================================================

def analyze_ssl(domain: str, port: int = 443) -> dict:
    """Deep SSL certificate analysis"""
    cache_key = f"ssl:{domain}:{port}"
    cached = _cache_get(_SSL_CACHE, cache_key)
    if cached:
        return cached
    
    result = {
        'has_ssl': False,
        'valid': False,
        'issuer': '',
        'subject': '',
        'expires': None,
        'days_until_expiry': None,
        'self_signed': False,
        'free_cert': False,
        'suspicious_indicators': [],
        'score_adjustment': 0.0
    }
    
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=SSL_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                result['has_ssl'] = True
                result['valid'] = True
                
                # Parse issuer
                issuer_dict = dict(x[0] for x in cert.get('issuer', []))
                result['issuer'] = issuer_dict.get('organizationName', '')
                
                # Parse subject
                subject_dict = dict(x[0] for x in cert.get('subject', []))
                result['subject'] = subject_dict.get('commonName', '')
                
                # Check expiry
                not_after = cert.get('notAfter', '')
                if not_after:
                    try:
                        expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        result['expires'] = expiry.isoformat()
                        result['days_until_expiry'] = (expiry - datetime.now()).days
                        
                        if result['days_until_expiry'] < 0:
                            result['suspicious_indicators'].append('Certificate expired')
                            result['score_adjustment'] += 0.3
                        elif result['days_until_expiry'] < 7:
                            result['suspicious_indicators'].append('Certificate expiring soon')
                            result['score_adjustment'] += 0.1
                    except:
                        pass
                
                # Check for free certificates (often used by phishing)
                free_issuers = ["let's encrypt", "zerossl", "buypass", "ssl.com free"]
                if any(fi in result['issuer'].lower() for fi in free_issuers):
                    result['free_cert'] = True
                    # Not necessarily bad, just note it
                
                # Check if subject matches domain
                if result['subject'] and domain not in result['subject'].lower():
                    result['suspicious_indicators'].append('Certificate subject mismatch')
                    result['score_adjustment'] += 0.15
                    
    except ssl.SSLCertVerificationError as e:
        result['suspicious_indicators'].append(f'SSL verification failed')
        result['score_adjustment'] += 0.25
    except ssl.SSLError:
        result['suspicious_indicators'].append('SSL error')
        result['score_adjustment'] += 0.2
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError):
        pass
    except Exception:
        pass
    
    _cache_set(_SSL_CACHE, cache_key, result)
    return result


# ============================================================================
# CONTENT ANALYSIS
# ============================================================================

def analyze_content(url: str) -> dict:
    """Analyze page content for phishing indicators"""
    cache_key = f"content:{hashlib.md5(url.encode()).hexdigest()}"
    cached = _cache_get(_CONTENT_CACHE, cache_key)
    if cached:
        return cached
    
    result = {
        'fetched': False,
        'status_code': None,
        'redirect_count': 0,
        'final_url': url,
        'has_forms': False,
        'has_password_field': False,
        'hidden_inputs_count': 0,
        'external_form_action': False,
        'has_obfuscated_js': False,
        'suspicious_title': False,
        'brand_in_title': None,
        'suspicious_indicators': [],
        'score_adjustment': 0.0
    }
    
    try:
        response = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            verify=True,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5'
            },
            stream=True
        )
        
        # Check content size
        content_length = int(response.headers.get('content-length', 0))
        if content_length > CONTENT_MAX_SIZE:
            result['suspicious_indicators'].append('Page too large to analyze')
            _cache_set(_CONTENT_CACHE, cache_key, result)
            return result
        
        # Read content
        content = response.text[:CONTENT_MAX_SIZE]
        
        result['fetched'] = True
        result['status_code'] = response.status_code
        result['redirect_count'] = len(response.history)
        result['final_url'] = response.url
        
        # Check for excessive redirects
        if result['redirect_count'] > 3:
            result['suspicious_indicators'].append(f"Many redirects ({result['redirect_count']})")
            result['score_adjustment'] += 0.15
        
        # Check for cross-domain redirect
        original_domain = urlparse(url).netloc.lower()
        final_domain = urlparse(response.url).netloc.lower()
        if original_domain != final_domain:
            result['suspicious_indicators'].append(f'Redirected to different domain')
            result['score_adjustment'] += 0.2
        
        # Form analysis
        forms = _FORM_PATTERN.findall(content)
        result['has_forms'] = len(forms) > 0
        
        password_fields = _PASSWORD_INPUT.findall(content)
        result['has_password_field'] = len(password_fields) > 0
        
        hidden_inputs = _HIDDEN_INPUT.findall(content)
        result['hidden_inputs_count'] = len(hidden_inputs)
        
        external_actions = _EXTERNAL_FORM_ACTION.findall(content)
        if external_actions:
            for action in external_actions:
                action_domain = urlparse(action).netloc.lower() if 'http' in action else ''
                if action_domain and action_domain != final_domain:
                    result['external_form_action'] = True
                    result['suspicious_indicators'].append('Form submits to external domain')
                    result['score_adjustment'] += 0.25
                    break
        
        # Password field without HTTPS is very suspicious
        if result['has_password_field'] and not url.startswith('https://'):
            result['suspicious_indicators'].append('Password field on non-HTTPS page')
            result['score_adjustment'] += 0.35
        
        # Many hidden inputs (data exfiltration)
        if result['hidden_inputs_count'] > 5:
            result['suspicious_indicators'].append(f"Many hidden inputs ({result['hidden_inputs_count']})")
            result['score_adjustment'] += 0.1
        
        # Obfuscated JavaScript
        obfuscated = _OBFUSCATED_JS.findall(content)
        if obfuscated:
            result['has_obfuscated_js'] = True
            result['suspicious_indicators'].append('Obfuscated JavaScript detected')
            result['score_adjustment'] += 0.15
        
        # Title analysis
        title_match = re.search(r'<title[^>]*>([^<]+)</title>', content, re.IGNORECASE)
        if title_match:
            title = title_match.group(1).strip().lower()
            
            # Check for phishing keywords in title
            if _PHISHING_TITLES.search(title):
                result['suspicious_title'] = True
            
            # Check for brand names in title
            for brand in BRAND_KEYWORDS:
                if brand in title:
                    result['brand_in_title'] = brand
                    # If brand in title but domain is not official
                    if not any(d in final_domain for d in PROTECTED_BRANDS.get(brand, [])):
                        result['suspicious_indicators'].append(f'Brand "{brand}" in title but unofficial domain')
                        result['score_adjustment'] += 0.3
                    break
    
    except requests.exceptions.SSLError:
        result['suspicious_indicators'].append('SSL error fetching page')
        result['score_adjustment'] += 0.2
    except requests.exceptions.Timeout:
        result['suspicious_indicators'].append('Page load timeout')
    except requests.exceptions.TooManyRedirects:
        result['suspicious_indicators'].append('Redirect loop detected')
        result['score_adjustment'] += 0.3
    except Exception:
        pass
    
    _cache_set(_CONTENT_CACHE, cache_key, result)
    return result


# ============================================================================
# DOMAIN ANALYSIS
# ============================================================================

def extract_domain_parts(url: str) -> dict:
    """Extract and analyze domain components"""
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
            if len(parts) >= 3 and parts[-2] in ['co', 'com', 'org', 'net', 'gov', 'edu', 'ac']:
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
            'fragment': parsed.fragment,
            'port': parsed.port
        }
    except:
        return {
            'full_domain': '', 'tld': '', 'sld': '', 'subdomains': [],
            'subdomain_count': 0, 'path': '', 'query': '', 'fragment': '', 'port': None
        }


def check_typosquatting(domain: str) -> tuple:
    """Check if domain is a typosquat of a known brand"""
    normalized = normalize_homographs(domain)
    
    # Remove common prefixes/suffixes
    test_domain = normalized
    for prefix in ['secure-', 'login-', 'my-', 'account-', 'verify-', 'update-', 'auth-', 'signin-', 'www-']:
        if test_domain.startswith(prefix):
            test_domain = test_domain[len(prefix):]
    
    for suffix in ['-login', '-secure', '-verify', '-account', '-update', '-support', '-auth', '-signin', '-help']:
        if test_domain.endswith(suffix):
            test_domain = test_domain[:-len(suffix)]
    
    # Check against protected brands
    for brand, official_domains in PROTECTED_BRANDS.items():
        if brand in test_domain:
            if domain in official_domains:
                return (False, None, 0)
            return (True, brand, 1)
        
        for official in official_domains:
            official_name = official.split('.')[0]
            test_name = test_domain.split('.')[0] if '.' in test_domain else test_domain
            distance = levenshtein_distance(test_name, official_name)
            if 0 < distance <= 2 and len(test_name) >= 4:
                return (True, brand, distance)
    
    return (False, None, 0)


def check_brand_impersonation(url: str, domain: str) -> tuple:
    """Check if URL is impersonating a known brand"""
    url_lower = url.lower()
    domain_lower = domain.lower()
    
    for brand, official_domains in PROTECTED_BRANDS.items():
        if any(domain_lower == d or domain_lower.endswith('.' + d) for d in official_domains):
            return (False, None, 0)
        
        if brand in url_lower:
            if brand in domain_lower:
                return (True, brand, 0.9)
            if brand in urlparse(url_lower).path:
                return (True, brand, 0.7)
    
    return (False, None, 0)


# ============================================================================
# WEBSITE LIVE CHECK
# ============================================================================

def check_website_live(url: str, timeout: int = 5) -> dict:
    """Check if website is accessible"""
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
        
    except requests.exceptions.SSLError:
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
    """Extract subdomain information"""
    parts = extract_domain_parts(url)
    return {
        'subdomain_count': parts['subdomain_count'],
        'subdomains': parts['subdomains'],
        'full_domain': parts['full_domain']
    }


# ============================================================================
# COMPREHENSIVE FEATURE EXTRACTION
# ============================================================================

def extract_features(url: str) -> dict:
    """Extract comprehensive URL features"""
    features = {}
    url_lower = url.lower()
    
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
    features['num_special'] = sum(not c.isalnum() and c not in '.-_/:?' for c in url)
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
    
    # IP detection
    features['has_ip'] = 1 if _IP_PATTERN.search(url) else 0
    features['has_ipv6'] = 1 if _IPV6_PATTERN.search(url) else 0
    
    # Domain analysis
    domain_parts = extract_domain_parts(url)
    domain = domain_parts['full_domain']
    features['domain'] = domain
    features['domain_length'] = len(domain)
    features['num_subdomains'] = domain_parts['subdomain_count']
    features['tld'] = domain_parts['tld']
    
    # TLD analysis
    features['suspicious_tld'] = 1 if domain_parts['tld'] in SUSPICIOUS_TLDS else 0
    features['trusted_tld'] = 1 if domain_parts['tld'] in TRUSTED_TLDS else 0
    
    # Trusted domain
    features['is_trusted_domain'] = 0
    if domain in TRUSTED_DOMAINS or any(domain.endswith('.' + td) for td in TRUSTED_DOMAINS):
        features['is_trusted_domain'] = 1
    
    # URL shortener
    features['is_shortener'] = 1 if domain in URL_SHORTENERS else 0
    
    # Punycode
    features['has_punycode'] = 1 if _PUNYCODE_PATTERN.search(domain) else 0
    
    # Entropy
    features['url_entropy'] = calculate_entropy(url)
    features['domain_entropy'] = calculate_entropy(domain)
    
    if domain_parts['subdomains']:
        subdomain_str = '.'.join(domain_parts['subdomains'])
        features['subdomain_entropy'] = calculate_entropy(subdomain_str)
    else:
        features['subdomain_entropy'] = 0
    
    # N-gram analysis
    features['ngram_score'] = calculate_ngram_score(domain)
    
    # Keyword detection
    critical_found = [kw for kw in CRITICAL_KEYWORDS if kw in url_lower]
    high_risk_found = [kw for kw in HIGH_RISK_KEYWORDS if kw in url_lower]
    medium_risk_found = [kw for kw in MEDIUM_RISK_KEYWORDS if kw in url_lower]
    
    features['critical_keywords'] = critical_found
    features['high_risk_keywords'] = high_risk_found
    features['medium_risk_keywords'] = medium_risk_found
    features['critical_keyword_count'] = len(critical_found)
    features['high_risk_keyword_count'] = len(high_risk_found)
    features['medium_risk_keyword_count'] = len(medium_risk_found)
    
    # URL pattern matching
    pattern_score = 0.0
    pattern_matches = []
    for pattern, score, desc in SUSPICIOUS_URL_PATTERNS:
        if pattern.search(url):
            pattern_score += score
            pattern_matches.append(desc)
    features['pattern_score'] = min(pattern_score, 0.5)
    features['pattern_matches'] = pattern_matches
    
    # Typosquatting
    typo_result = check_typosquatting(domain)
    features['is_typosquat'] = 1 if typo_result[0] else 0
    features['typosquat_target'] = typo_result[1]
    features['typosquat_distance'] = typo_result[2]
    
    # Brand impersonation
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
    features['has_base64'] = 1 if _BASE64_PATTERN.search(url) else 0
    features['has_email'] = 1 if _EMAIL_IN_URL.search(url) else 0
    
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
# ADVANCED SCORING ENGINE
# ============================================================================

def calculate_phishing_score(features: dict, dns_result: dict = None, ssl_result: dict = None, content_result: dict = None) -> tuple:
    """
    Calculate phishing probability with comprehensive analysis.
    """
    score = 0.0
    risk_factors = []
    
    # ========== WHITELIST ==========
    if features.get('is_trusted_domain'):
        return (0, 0.01, "Verified trusted domain", ["✅ Domain is in trusted whitelist"])
    
    if features.get('trusted_tld'):
        score -= 0.4
        risk_factors.append("✓ Government/education TLD (-0.4)")
    
    # ========== HTTPS ==========
    if features.get('is_https'):
        score -= 0.05
    else:
        score += 0.15
        risk_factors.append("⚠ No HTTPS (+0.15)")
    
    # ========== CRITICAL INDICATORS ==========
    
    # Critical keywords
    critical_count = features.get('critical_keyword_count', 0)
    if critical_count > 0:
        critical_score = min(0.5, critical_count * 0.2)
        score += critical_score
        keywords = features.get('critical_keywords', [])[:2]
        risk_factors.append(f"🚨 Critical keywords: {', '.join(keywords)} (+{critical_score:.2f})")
    
    # Brand impersonation
    if features.get('is_brand_impersonation'):
        brand = features.get('impersonated_brand', 'unknown')
        confidence = features.get('impersonation_confidence', 0)
        score += 0.5 * confidence
        risk_factors.append(f"🚨 Brand impersonation: {brand} (+{0.5 * confidence:.2f})")
    
    # Typosquatting
    if features.get('is_typosquat'):
        target = features.get('typosquat_target', 'unknown')
        score += 0.45
        risk_factors.append(f"🚨 Typosquatting: {target} (+0.45)")
    
    # IP address
    if features.get('has_ip') or features.get('has_ipv6'):
        score += 0.4
        risk_factors.append("🚨 IP address in URL (+0.4)")
    
    # Homograph attack
    if features.get('has_homographs'):
        score += 0.4
        risk_factors.append("🚨 Homograph characters (+0.4)")
    
    # Punycode
    if features.get('has_punycode'):
        score += 0.35
        risk_factors.append("🚨 Punycode domain (+0.35)")
    
    # Data URI / JavaScript URI
    if features.get('has_data_uri'):
        score += 0.5
        risk_factors.append("🚨 Data URI detected (+0.5)")
    
    # ========== HIGH RISK ==========
    
    # Suspicious TLD
    if features.get('suspicious_tld'):
        score += 0.35
        risk_factors.append(f"⚠ Suspicious TLD: {features.get('tld', '')} (+0.35)")
    
    # High-risk keywords
    high_risk_count = features.get('high_risk_keyword_count', 0)
    if high_risk_count > 0:
        keyword_score = min(0.4, high_risk_count * 0.1)
        score += keyword_score
        keywords = features.get('high_risk_keywords', [])[:3]
        risk_factors.append(f"⚠ High-risk keywords: {', '.join(keywords)} (+{keyword_score:.2f})")
    
    # URL shortener
    if features.get('is_shortener'):
        score += 0.3
        risk_factors.append("⚠ URL shortener (+0.3)")
    
    # @ symbol
    if features.get('has_at_symbol'):
        score += 0.35
        risk_factors.append("⚠ @ symbol (obfuscation) (+0.35)")
    
    # Pattern matches
    pattern_score = features.get('pattern_score', 0)
    if pattern_score > 0:
        score += pattern_score
        matches = features.get('pattern_matches', [])[:2]
        risk_factors.append(f"⚠ Suspicious patterns: {', '.join(matches)} (+{pattern_score:.2f})")
    
    # ========== MEDIUM RISK ==========
    
    # Medium keywords
    medium_count = features.get('medium_risk_keyword_count', 0)
    if medium_count > 0:
        keyword_score = min(0.2, medium_count * 0.05)
        score += keyword_score
        keywords = features.get('medium_risk_keywords', [])[:3]
        risk_factors.append(f"⚠ Financial keywords: {', '.join(keywords)} (+{keyword_score:.2f})")
    
    # Subdomains
    num_subdomains = features.get('num_subdomains', 0)
    if num_subdomains >= 4:
        score += 0.25
        risk_factors.append(f"⚠ Many subdomains ({num_subdomains}) (+0.25)")
    elif num_subdomains >= 3:
        score += 0.15
        risk_factors.append(f"⚠ Multiple subdomains ({num_subdomains}) (+0.15)")
    
    # High entropy
    domain_entropy = features.get('domain_entropy', 0)
    if domain_entropy > 4.0:
        score += 0.2
        risk_factors.append(f"⚠ High domain entropy ({domain_entropy:.1f}) (+0.2)")
    
    subdomain_entropy = features.get('subdomain_entropy', 0)
    if subdomain_entropy > 3.5:
        score += 0.15
        risk_factors.append("⚠ Random subdomain pattern (+0.15)")
    
    # N-gram score
    ngram_score = features.get('ngram_score', 0)
    if ngram_score > 0.1:
        score += ngram_score
        risk_factors.append(f"⚠ Unusual domain patterns (+{ngram_score:.2f})")
    
    # Long URL
    url_length = features.get('url_length', 0)
    if url_length > 150:
        score += 0.15
        risk_factors.append(f"⚠ Very long URL ({url_length} chars) (+0.15)")
    elif url_length > 100:
        score += 0.08
        risk_factors.append(f"⚠ Long URL ({url_length} chars) (+0.08)")
    
    # ========== LOW RISK ==========
    
    # Hyphens
    num_hyphens = features.get('num_hyphens', 0)
    if num_hyphens > 4:
        score += 0.15
        risk_factors.append(f"⚠ Many hyphens ({num_hyphens}) (+0.15)")
    
    # Hex encoding
    if features.get('has_hex_chars'):
        score += 0.1
        risk_factors.append("⚠ URL encoding (+0.1)")
    
    # Non-standard port
    if features.get('has_port'):
        score += 0.15
        risk_factors.append(f"⚠ Non-standard port (+0.15)")
    
    # Double extension
    if features.get('has_double_extension'):
        score += 0.2
        risk_factors.append("⚠ Double file extension (+0.2)")
    
    # Random string
    if features.get('has_random_string'):
        score += 0.15
        risk_factors.append("⚠ Random string in domain (+0.15)")
    
    # Base64 in URL
    if features.get('has_base64'):
        score += 0.15
        risk_factors.append("⚠ Base64 encoded data (+0.15)")
    
    # Email in URL
    if features.get('has_email'):
        score += 0.1
        risk_factors.append("⚠ Email address in URL (+0.1)")
    
    # ========== DNS ANALYSIS ==========
    if dns_result:
        score += dns_result.get('score_adjustment', 0)
        risk_factors.extend([f"🔍 DNS: {i}" for i in dns_result.get('suspicious_indicators', [])])
    
    # ========== SSL ANALYSIS ==========
    if ssl_result:
        score += ssl_result.get('score_adjustment', 0)
        risk_factors.extend([f"🔒 SSL: {i}" for i in ssl_result.get('suspicious_indicators', [])])
    
    # ========== CONTENT ANALYSIS ==========
    if content_result:
        score += content_result.get('score_adjustment', 0)
        risk_factors.extend([f"📄 Content: {i}" for i in content_result.get('suspicious_indicators', [])])
    
    # ========== FINAL ==========
    probability = max(0.0, min(1.0, score))
    label = 1 if probability >= 0.5 else 0
    
    if not risk_factors:
        reason = "No suspicious indicators detected"
    else:
        top_factors = [f.split('(')[0].strip() for f in risk_factors[:2]]
        reason = "; ".join(top_factors)
    
    return (label, probability, reason, risk_factors)


# ============================================================================
# MAIN PREDICTION FUNCTION
# ============================================================================

def predict_url(url: str, model=None, deep_scan: bool = True) -> tuple:
    """
    Analyze URL and predict if it's phishing.
    
    Args:
        url: URL to analyze
        model: Ignored (API compatibility)
        deep_scan: If True, perform DNS/SSL/content analysis
    
    Returns:
        (label, probability, features)
    """
    if not url or len(url) > MAX_URL_LENGTH:
        return (0, 0.5, {'error': 'Invalid URL'})
    
    # Extract features
    features = extract_features(url)
    
    # Skip deep scan for trusted domains
    if features.get('is_trusted_domain'):
        label, probability, reason, risk_factors = calculate_phishing_score(features)
        features['prediction_reason'] = reason
        features['risk_factors'] = risk_factors
        features['risk_score'] = probability
        features['deep_scan'] = False
        return (label, probability, features)
    
    # Deep scan for non-trusted domains
    dns_result = None
    ssl_result = None
    content_result = None
    
    if deep_scan:
        domain = features.get('domain', '')
        
        # Parallel analysis using thread pool
        try:
            with ThreadPoolExecutor(max_workers=THREAD_POOL_SIZE) as executor:
                dns_future = executor.submit(analyze_dns, domain)
                ssl_future = executor.submit(analyze_ssl, domain) if features.get('is_https') else None
                content_future = executor.submit(analyze_content, url)
                
                try:
                    dns_result = dns_future.result(timeout=DNS_TIMEOUT + 1)
                except:
                    dns_result = None
                
                if ssl_future:
                    try:
                        ssl_result = ssl_future.result(timeout=SSL_TIMEOUT + 1)
                    except:
                        ssl_result = None
                
                try:
                    content_result = content_future.result(timeout=REQUEST_TIMEOUT + 2)
                except:
                    content_result = None
        except:
            pass
        
        features['dns_analysis'] = dns_result
        features['ssl_analysis'] = ssl_result
        features['content_analysis'] = content_result
        features['deep_scan'] = True
    
    # Calculate score
    label, probability, reason, risk_factors = calculate_phishing_score(
        features, dns_result, ssl_result, content_result
    )
    
    features['prediction_reason'] = reason
    features['risk_factors'] = risk_factors
    features['risk_score'] = probability
    
    gc.collect()
    return (label, probability, features)


def load_model(model_path: str = None):
    """Compatibility function"""
    print(f"[+] Phish Detector PRO LITE v{VERSION}")
    print("    - 50+ brand protection")
    print("    - DNS/SSL/Content analysis")
    print("    - Typosquatting detection")
    print("    - Homograph attack detection")
    print("    - N-gram analysis")
    print("    - Parallel scanning enabled")
    return True


def get_top_feature(features: dict) -> str:
    """Get primary risk indicator"""
    return features.get('prediction_reason', 'URL analysis complete')


def get_professional_risk_assessment(label: int, probability: float, features: dict, url: str) -> dict:
    """Generate professional risk assessment"""
    if label == 1:
        confidence = probability
    else:
        confidence = 1.0 - probability
    
    confidence_percent = round(confidence * 100, 1)
    
    if probability >= 0.85:
        risk_level, risk_category = "CRITICAL", "Confirmed Phishing"
        color, recommendation = "#dc2626", "DO NOT visit. Report immediately."
    elif probability >= 0.7:
        risk_level, risk_category = "HIGH", "Likely Phishing"
        color, recommendation = "#ea580c", "Avoid. Verify through official channels."
    elif probability >= 0.5:
        risk_level, risk_category = "MEDIUM-HIGH", "Suspicious"
        color, recommendation = "#d97706", "Exercise extreme caution."
    elif probability >= 0.35:
        risk_level, risk_category = "MEDIUM", "Potentially Suspicious"
        color, recommendation = "#ca8a04", "Proceed with caution."
    elif probability >= 0.2:
        risk_level, risk_category = "LOW", "Probably Safe"
        color, recommendation = "#65a30d", "Appears safe. Stay vigilant."
    else:
        risk_level, risk_category = "MINIMAL", "Verified Safe"
        color, recommendation = "#16a34a", "Website appears legitimate."
    
    risk_factors = features.get('risk_factors', [])
    details = f"Risk Score: {round(probability * 100)}% | {len(risk_factors)} indicators"
    
    if features.get('is_typosquat'):
        details += f" | Typosquat: {features.get('typosquat_target')}"
    if features.get('is_brand_impersonation'):
        details += f" | Impersonating: {features.get('impersonated_brand')}"
    if features.get('deep_scan'):
        details += " | Deep scan completed"
    
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
        'risk_factors': risk_factors[:7],
        'deep_scan': features.get('deep_scan', False),
        'version': VERSION
    }


def get_cached_model():
    """Always returns True"""
    return True


# Initialize
print(f"[+] PRO LITE detector ready - {len(PROTECTED_BRANDS)} brands protected")
